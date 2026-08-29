using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Resources;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 讀 .NET assembly 的型別、方法與方法層級呼叫圖。
// 只讀 metadata 與 IL，不執行輸入程式，結果可以直接當證據。
internal static class ManagedSymbolReader
{
    private const int MaxTypes = 5_000;
    private const int MaxCallEdges = 50_000;
    private const int MaxIlInstructions = 400;

    public static async Task<CodeModel?> TryReadAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                useAsync: true);
            using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            if (!peReader.HasMetadata)
            {
                return null;
            }

            var metadata = peReader.GetMetadataReader();
            return Read(peReader, metadata, cancellationToken);
        }
        catch (Exception exception) when (exception is BadImageFormatException or IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private static CodeModel Read(PEReader peReader, MetadataReader metadata, CancellationToken cancellationToken)
    {
        var entryPointMethod = ResolveEntryPoint(peReader, metadata);
        var namespaces = new HashSet<string>(StringComparer.Ordinal);
        var types = new List<TypeModel>();
        var edges = new List<CallEdge>();
        var seenEdges = new HashSet<(string, string, string)>();
        var methodCount = 0;
        var truncated = false;

        foreach (var typeHandle in metadata.TypeDefinitions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var definition = metadata.GetTypeDefinition(typeHandle);

            var name = StripArity(metadata.GetString(definition.Name));
            var namespaceName = GetTypeDefinitionNamespace(metadata, typeHandle);
            if (name == "<Module>")
            {
                continue;
            }

            if (types.Count >= MaxTypes)
            {
                truncated = true;
                break;
            }

            namespaces.Add(namespaceName);
            var fullName = GetTypeDefinitionFullName(metadata, typeHandle);
            var declaringTypeHandle = definition.GetDeclaringType();
            var declaringTypeName = declaringTypeHandle.IsNil
                ? null
                : GetTypeDefinitionFullName(metadata, declaringTypeHandle);
            var baseTypeName = GetTypeName(metadata, definition.BaseType);
            var methods = new List<MethodModel>();

            foreach (var methodHandle in definition.GetMethods())
            {
                var method = metadata.GetMethodDefinition(methodHandle);
                var methodName = metadata.GetString(method.Name);
                var hasBody = method.RelativeVirtualAddress != 0;
                var declaringName = fullName;
                var il = hasBody ? TryReadIl(peReader, method) : null;
                var localTypes = hasBody ? TryReadLocalTypes(peReader, method) : [];
                var exceptionRegions = hasBody ? TryReadExceptionRegions(peReader, metadata, method) : [];

                var model = BuildMethod(metadata, methodHandle, method, methodName, hasBody, entryPointMethod.Handle);
                if (il is { Length: > 0 })
                {
                    var (instructions, ilTruncated) = Disassemble(metadata, il);
                    model = model with { Il = instructions, IlTruncated = ilTruncated };

                    if (methodName is not (".ctor" or ".cctor"))
                    {
                        var isInstance = !method.Attributes.HasFlag(MethodAttributes.Static);
                        var body = TryReconstructLinearBody(
                            metadata,
                            il,
                            isInstance,
                            ReadParameterNames(metadata, method),
                            model.Parameters.Select(parameter => parameter.Type).ToArray(),
                            model.ReturnType,
                            localTypes,
                            exceptionRegions);
                        if (body is not null)
                        {
                            model = model with { Body = body, BodyReconstructed = true };
                        }
                    }
                }

                methods.Add(model);
                methodCount++;

                if (il is { Length: > 0 })
                {
                    if (edges.Count < MaxCallEdges)
                    {
                        CollectCalls(metadata, il, $"{declaringName}.{methodName}", edges, seenEdges);
                    }
                    else
                    {
                        truncated = true;
                    }
                }
            }

            var attributes = definition.Attributes;
            var kind = GetTypeKind(attributes, baseTypeName);
            var isAbstract = attributes.HasFlag(TypeAttributes.Abstract);
            var isSealed = attributes.HasFlag(TypeAttributes.Sealed);
            types.Add(new TypeModel
            {
                FullName = fullName,
                Namespace = namespaceName,
                Name = name,
                Kind = kind,
                Accessibility = GetTypeAccessibility(attributes),
                IsStatic = kind == "class" && isAbstract && isSealed,
                IsAbstract = isAbstract,
                IsSealed = isSealed,
                IsRefLike = HasCustomAttribute(
                    metadata,
                    definition.GetCustomAttributes(),
                    "System.Runtime.CompilerServices.IsByRefLikeAttribute"),
                IsNested = !declaringTypeHandle.IsNil,
                DeclaringType = declaringTypeName,
                InheritedGenericParameterCount = declaringTypeHandle.IsNil
                    ? 0
                    : metadata.GetTypeDefinition(declaringTypeHandle).GetGenericParameters().Count,
                BaseType = baseTypeName,
                Interfaces = ReadInterfaces(metadata, definition),
                GenericParameters = ReadTypeGenericParameters(metadata, definition),
                Fields = ReadFields(metadata, definition),
                Properties = ReadProperties(metadata, definition),
                Events = ReadEvents(metadata, definition),
                Methods = methods
            });
        }

        return new CodeModel
        {
            Kind = "managed",
            EntryPointMethod = entryPointMethod.FullName,
            NamespaceCount = namespaces.Count,
            TypeCount = types.Count,
            MethodCount = methodCount,
            CallEdgeCount = edges.Count,
            Truncated = truncated,
            Types = types,
            CallGraph = edges,
            Resources = ReadManifestResources(peReader, metadata)
        };
    }

    private const int MaxResources = 2_000;
    private const int MaxResourceEntries = 5_000;
    private const int MaxResourceTableBytes = 32 * 1024 * 1024;
    private const int MaxResourceValueLength = 4_096;

    // 讀 assembly 的 manifest 資源清單：名稱、可見性、放在哪、內嵌的話再讀出大小。
    private static IReadOnlyList<ManagedResourceModel> ReadManifestResources(
        PEReader peReader,
        MetadataReader metadata)
    {
        if (metadata.ManifestResources.Count == 0)
        {
            return [];
        }

        var resourcesDirectory = peReader.PEHeaders.CorHeader?.ResourcesDirectory;
        var resources = new List<ManagedResourceModel>();
        var remainingResourceEntries = MaxResourceEntries;

        foreach (var handle in metadata.ManifestResources)
        {
            if (resources.Count >= MaxResources)
            {
                break;
            }

            var resource = metadata.GetManifestResource(handle);
            var name = metadata.GetString(resource.Name);
            var visibility = resource.Attributes.HasFlag(ManifestResourceAttributes.Public)
                ? "public"
                : "private";

            var (location, size) = ResolveResourceLocation(peReader, metadata, resource, resourcesDirectory);
            var entries = Array.Empty<ManagedResourceEntryModel>();
            var entriesTruncated = false;
            string? entriesError = null;
            if (location == "embedded" && name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
            {
                var table = ReadEmbeddedResourceTable(
                    peReader,
                    resource.Offset,
                    size,
                    resourcesDirectory,
                    remainingResourceEntries);
                entries = table.Entries.ToArray();
                entriesTruncated = table.Truncated;
                entriesError = table.Error;
                remainingResourceEntries -= entries.Length;
            }

            resources.Add(new ManagedResourceModel
            {
                Name = name,
                Visibility = visibility,
                Location = location,
                Kind = ClassifyResourceKind(name),
                Size = size,
                Entries = entries,
                EntriesTruncated = entriesTruncated,
                EntriesError = entriesError
            });
        }

        return resources;
    }

    private static (string Location, long? Size) ResolveResourceLocation(
        PEReader peReader,
        MetadataReader metadata,
        ManifestResource resource,
        DirectoryEntry? resourcesDirectory)
    {
        var implementation = resource.Implementation;

        if (implementation.IsNil)
        {
            // 內嵌在本檔：從 CorHeader 的 resources 目錄按位移讀 4 byte 長度前綴。
            var size = TryReadEmbeddedResourceSize(peReader, resource.Offset, resourcesDirectory);
            return ("embedded", size);
        }

        return implementation.Kind switch
        {
            HandleKind.AssemblyFile => ($"file:{ReadAssemblyFileName(metadata, (AssemblyFileHandle)implementation)}", null),
            HandleKind.AssemblyReference => ($"assembly:{ReadAssemblyReferenceName(metadata, (AssemblyReferenceHandle)implementation)}", null),
            _ => ("external", null)
        };
    }

    private static long? TryReadEmbeddedResourceSize(
        PEReader peReader,
        long offset,
        DirectoryEntry? resourcesDirectory)
    {
        if (resourcesDirectory is not { Size: > 0 } directory)
        {
            return null;
        }

        try
        {
            var block = peReader.GetSectionData(directory.RelativeVirtualAddress);
            if (offset < 0 || offset + sizeof(int) > directory.Size || offset + sizeof(int) > block.Length)
            {
                return null;
            }

            var reader = block.GetReader((int)offset, sizeof(int));
            var length = reader.ReadInt32();
            return length >= 0 ? length : null;
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static ResourceTableReadResult ReadEmbeddedResourceTable(
        PEReader peReader,
        long offset,
        long? size,
        DirectoryEntry? resourcesDirectory,
        int entryLimit)
    {
        if (entryLimit <= 0)
        {
            return new([], true, null);
        }

        if (size is null)
        {
            return new([], false, "找不到完整的內嵌資源資料。");
        }

        if (size > MaxResourceTableBytes)
        {
            return new([], false, $"資源表超過 {MaxResourceTableBytes / 1024 / 1024} MB 安全解析上限。");
        }

        var data = TryReadEmbeddedResourceData(peReader, offset, (int)size.Value, resourcesDirectory);
        if (data is null)
        {
            return new([], false, "找不到完整的內嵌資源資料。");
        }

        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = new ResourceReader(stream);
            var enumerator = reader.GetEnumerator();
            var entries = new List<ManagedResourceEntryModel>();
            var truncated = false;

            while (enumerator.MoveNext())
            {
                if (entries.Count >= entryLimit)
                {
                    truncated = true;
                    break;
                }

                if (enumerator.Key is not string key)
                {
                    continue;
                }

                try
                {
                    reader.GetResourceData(key, out var type, out var resourceData);
                    entries.Add(DecodeResourceEntry(key, type, resourceData));
                }
                catch (Exception exception) when (exception is ArgumentException or BadImageFormatException or FormatException or InvalidOperationException or IOException)
                {
                    entries.Add(new ManagedResourceEntryModel
                    {
                        Name = key,
                        Type = "unknown",
                        Status = "invalid",
                        Error = "無法讀取這筆資源的型別與原始資料。"
                    });
                }
            }

            return new(
                entries.OrderBy(entry => entry.Name, StringComparer.Ordinal).ToArray(),
                truncated,
                null);
        }
        catch (Exception exception) when (exception is ArgumentException or BadImageFormatException or FormatException or InvalidOperationException or IOException or OverflowException)
        {
            return new([], false, "資源表格式損壞或不受支援。");
        }
    }

    private static byte[]? TryReadEmbeddedResourceData(
        PEReader peReader,
        long offset,
        int size,
        DirectoryEntry? resourcesDirectory)
    {
        if (resourcesDirectory is not { Size: > 0 } directory || size < 0)
        {
            return null;
        }

        try
        {
            var block = peReader.GetSectionData(directory.RelativeVirtualAddress);
            var dataOffset = offset + sizeof(int);
            if (offset < 0
                || dataOffset + size > directory.Size
                || dataOffset + size > block.Length)
            {
                return null;
            }

            return block.GetReader((int)dataOffset, size).ReadBytes(size);
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    internal static ManagedResourceEntryModel DecodeResourceEntry(string name, string type, byte[] data)
    {
        const string prefix = "ResourceTypeCode.";
        if (!type.StartsWith(prefix, StringComparison.Ordinal))
        {
            return new ManagedResourceEntryModel
            {
                Name = name,
                Type = type,
                Status = "unsupported",
                DataSize = data.Length,
                Error = "自訂資源型別未反序列化，僅保留型別與原始資料大小。"
            };
        }

        try
        {
            using var stream = new MemoryStream(data, writable: false);
            using var reader = new BinaryReader(stream);
            var typeCode = type[prefix.Length..];

            return typeCode switch
            {
                "Null" => CreateDecodedResourceEntry(name, type, null),
                "String" => CreateDecodedResourceEntry(name, type, reader.ReadString()),
                "Boolean" => CreateDecodedResourceEntry(name, type, reader.ReadBoolean() ? "true" : "false"),
                "Char" => CreateDecodedResourceEntry(name, type, FormatResourceChar(reader.ReadChar())),
                "Byte" => CreateDecodedResourceEntry(name, type, reader.ReadByte().ToString(CultureInfo.InvariantCulture)),
                "SByte" => CreateDecodedResourceEntry(name, type, reader.ReadSByte().ToString(CultureInfo.InvariantCulture)),
                "Int16" => CreateDecodedResourceEntry(name, type, reader.ReadInt16().ToString(CultureInfo.InvariantCulture)),
                "UInt16" => CreateDecodedResourceEntry(name, type, reader.ReadUInt16().ToString(CultureInfo.InvariantCulture)),
                "Int32" => CreateDecodedResourceEntry(name, type, reader.ReadInt32().ToString(CultureInfo.InvariantCulture)),
                "UInt32" => CreateDecodedResourceEntry(name, type, reader.ReadUInt32().ToString(CultureInfo.InvariantCulture)),
                "Int64" => CreateDecodedResourceEntry(name, type, reader.ReadInt64().ToString(CultureInfo.InvariantCulture)),
                "UInt64" => CreateDecodedResourceEntry(name, type, reader.ReadUInt64().ToString(CultureInfo.InvariantCulture)),
                "Single" => CreateDecodedResourceEntry(name, type, reader.ReadSingle().ToString("R", CultureInfo.InvariantCulture)),
                "Double" => CreateDecodedResourceEntry(name, type, reader.ReadDouble().ToString("R", CultureInfo.InvariantCulture)),
                "Decimal" => CreateDecodedResourceEntry(name, type, reader.ReadDecimal().ToString(CultureInfo.InvariantCulture)),
                "DateTime" => CreateDecodedResourceEntry(
                    name,
                    type,
                    DateTime.FromBinary(reader.ReadInt64()).ToString("O", CultureInfo.InvariantCulture)),
                "TimeSpan" => CreateDecodedResourceEntry(
                    name,
                    type,
                    TimeSpan.FromTicks(reader.ReadInt64()).ToString("c", CultureInfo.InvariantCulture)),
                "ByteArray" or "Stream" => CreateBinaryResourceEntry(name, type, data, reader),
                _ => new ManagedResourceEntryModel
                {
                    Name = name,
                    Type = type,
                    Status = "unsupported",
                    DataSize = data.Length,
                    Error = "這個 ResourceTypeCode 尚未支援，僅保留原始資料大小。"
                }
            };
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidDataException or IOException or OverflowException)
        {
            return new ManagedResourceEntryModel
            {
                Name = name,
                Type = type,
                Status = "invalid",
                DataSize = data.Length,
                Error = "資料格式與宣告的資源型別不一致。"
            };
        }
    }

    private static ManagedResourceEntryModel CreateDecodedResourceEntry(string name, string type, string? value)
    {
        var truncated = value is { Length: > MaxResourceValueLength };
        return new ManagedResourceEntryModel
        {
            Name = name,
            Type = type,
            Status = "decoded",
            Value = truncated ? value![..MaxResourceValueLength] : value,
            ValueTruncated = truncated
        };
    }

    private static ManagedResourceEntryModel CreateBinaryResourceEntry(
        string name,
        string type,
        byte[] data,
        BinaryReader reader)
    {
        var size = ReadBinaryResourceLength(reader);
        var payloadOffset = checked((int)reader.BaseStream.Position);
        var baml = name.EndsWith(".baml", StringComparison.OrdinalIgnoreCase)
            ? BamlSummaryReader.Read(data.AsSpan(payloadOffset, size))
            : null;

        return new ManagedResourceEntryModel
        {
            Name = name,
            Type = type,
            Status = "binary",
            DataSize = size,
            Baml = baml
        };
    }

    private static int ReadBinaryResourceLength(BinaryReader reader)
    {
        var length = reader.ReadInt32();
        if (length < 0 || length > reader.BaseStream.Length - reader.BaseStream.Position)
        {
            throw new InvalidDataException("Invalid binary resource length.");
        }

        return length;
    }

    private static string FormatResourceChar(char value) =>
        char.IsControl(value) ? $"\\u{(int)value:X4}" : value.ToString();

    private readonly record struct ResourceTableReadResult(
        IReadOnlyList<ManagedResourceEntryModel> Entries,
        bool Truncated,
        string? Error);

    private static string ReadAssemblyFileName(MetadataReader metadata, AssemblyFileHandle handle)
    {
        var file = metadata.GetAssemblyFile(handle);
        return metadata.GetString(file.Name);
    }

    private static string ReadAssemblyReferenceName(MetadataReader metadata, AssemblyReferenceHandle handle)
    {
        var reference = metadata.GetAssemblyReference(handle);
        return metadata.GetString(reference.Name);
    }

    // 依副檔名／慣例判斷資源用途，僅供閱讀，不保證精確。
    private static string ClassifyResourceKind(string name)
    {
        if (name.EndsWith(".g.resources", StringComparison.OrdinalIgnoreCase))
        {
            return "WPF 資源集";
        }

        if (name.EndsWith(".baml", StringComparison.OrdinalIgnoreCase))
        {
            return "WPF BAML";
        }

        if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase))
        {
            return ".NET 資源表";
        }

        if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return "內嵌組件";
        }

        if (name.EndsWith(".config", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
        {
            return "設定檔";
        }

        return "內嵌資料";
    }

    private static (MethodDefinitionHandle Handle, string? FullName) ResolveEntryPoint(
        PEReader peReader,
        MetadataReader metadata)
    {
        var corHeader = peReader.PEHeaders.CorHeader;
        if (corHeader is null || corHeader.Flags.HasFlag(CorFlags.NativeEntryPoint))
        {
            return (default, null);
        }

        var token = corHeader.EntryPointTokenOrRelativeVirtualAddress;
        if (token == 0 || (token & 0xFF000000) != 0x06000000)
        {
            return (default, null);
        }

        var handle = (MethodDefinitionHandle)MetadataTokens.Handle(token);
        var method = metadata.GetMethodDefinition(handle);
        var fullName = GetTypeDefinitionFullName(metadata, method.GetDeclaringType());
        return (handle, $"{fullName}.{metadata.GetString(method.Name)}");
    }

    private static byte[]? TryReadIl(PEReader peReader, MethodDefinition method)
    {
        try
        {
            return peReader.GetMethodBody(method.RelativeVirtualAddress).GetILBytes();
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> TryReadLocalTypes(PEReader peReader, MethodDefinition method)
    {
        try
        {
            var body = peReader.GetMethodBody(method.RelativeVirtualAddress);
            if (body.LocalSignature.IsNil)
            {
                return [];
            }

            var metadata = peReader.GetMetadataReader();
            var signature = metadata.GetStandaloneSignature(body.LocalSignature);
            return signature.DecodeLocalSignature(SignatureTypeNameProvider.Instance, null);
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            return [];
        }
    }

    private static IReadOnlyList<ExceptionRegionInfo> TryReadExceptionRegions(
        PEReader peReader,
        MetadataReader metadata,
        MethodDefinition method)
    {
        try
        {
            return peReader
                .GetMethodBody(method.RelativeVirtualAddress)
                .ExceptionRegions
                .Select(region => new ExceptionRegionInfo(
                    region.Kind,
                    region.TryOffset,
                    region.TryLength,
                    region.HandlerOffset,
                    region.HandlerLength,
                    region.Kind == ExceptionRegionKind.Catch && !region.CatchType.IsNil
                        ? GetTypeName(metadata, region.CatchType)
                        : null,
                    region.Kind == ExceptionRegionKind.Filter ? region.FilterOffset : -1))
                .ToArray();
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            return [];
        }
    }

    private static void CollectCalls(
        MetadataReader metadata,
        byte[] il,
        string caller,
        List<CallEdge> edges,
        HashSet<(string, string, string)> seenEdges)
    {
        foreach (var instruction in EnumerateInstructions(il))
        {
            if (edges.Count >= MaxCallEdges)
            {
                return;
            }

            var kind = CallKind(instruction.OpValue);
            if (kind is null || instruction.OperandOffset + 4 > il.Length)
            {
                continue;
            }

            var token = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4));
            var callee = ResolveMemberName(metadata, token);
            if (callee is null)
            {
                continue;
            }

            var edge = (caller, callee, kind);
            if (seenEdges.Add(edge))
            {
                edges.Add(new CallEdge { Caller = caller, Callee = callee, Kind = kind });
            }
        }
    }

    private static (IReadOnlyList<string> Instructions, bool Truncated) Disassemble(MetadataReader metadata, byte[] il)
    {
        var instructions = new List<string>();
        var truncated = false;
        foreach (var instruction in EnumerateInstructions(il))
        {
            if (instructions.Count >= MaxIlInstructions)
            {
                truncated = true;
                break;
            }

            if (!OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode))
            {
                continue;
            }

            var operand = FormatOperand(metadata, il, instruction, opCode.OperandType);
            instructions.Add($"IL_{instruction.Offset:X4}: {opCode.Name}{operand}");
        }

        return (instructions, truncated);
    }

    private readonly record struct IlInstruction(int Offset, short OpValue, int OperandOffset, int OperandSize);

    private static IEnumerable<IlInstruction> EnumerateInstructions(byte[] il)
    {
        var position = 0;
        while (position < il.Length)
        {
            var offset = position;
            short opValue;
            var first = il[position++];
            if (first == 0xFE)
            {
                if (position >= il.Length)
                {
                    yield break;
                }

                opValue = (short)(0xFE00 | il[position++]);
            }
            else
            {
                opValue = first;
            }

            if (!OperandSizes.TryGetValue(opValue, out var operandSize))
            {
                yield break;
            }

            if (operandSize == OperandSwitch)
            {
                if (position + 4 > il.Length)
                {
                    yield break;
                }

                var count = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(position, 4));
                if (count < 0 || count > (il.Length - position - 4) / 4)
                {
                    yield break;
                }

                var total = 4 + (count * 4);
                yield return new IlInstruction(offset, opValue, position, total);
                position += total;
                continue;
            }

            if (operandSize < 0 || position + operandSize > il.Length)
            {
                yield break;
            }

            yield return new IlInstruction(offset, opValue, position, operandSize);
            position += operandSize;
        }
    }

    private static string FormatOperand(MetadataReader metadata, byte[] il, IlInstruction instruction, OperandType operandType)
    {
        var offset = instruction.OperandOffset;
        if (operandType == OperandType.InlineNone || offset + instruction.OperandSize > il.Length)
        {
            return string.Empty;
        }

        switch (operandType)
        {
            case OperandType.InlineMethod:
            case OperandType.InlineField:
            case OperandType.InlineType:
            case OperandType.InlineTok:
                return $" {ResolveTokenName(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}";
            case OperandType.InlineString:
                return $" {FormatUserString(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}";
            case OperandType.InlineSig:
                return $" sig(0x{BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)):X8})";
            case OperandType.InlineI:
                return $" {BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4))}";
            case OperandType.InlineI8:
                return $" {BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8))}";
            case OperandType.InlineR:
                return $" {BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8)))}";
            case OperandType.ShortInlineR:
                return $" {BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}";
            case OperandType.InlineVar:
                return $" {BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2))}";
            case OperandType.ShortInlineVar:
                return $" {il[offset]}";
            case OperandType.ShortInlineI:
                return $" {(sbyte)il[offset]}";
            case OperandType.InlineBrTarget:
                return $" IL_{offset + 4 + BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)):X4}";
            case OperandType.ShortInlineBrTarget:
                return $" IL_{offset + 1 + (sbyte)il[offset]:X4}";
            case OperandType.InlineSwitch:
                var switchTargets = ReadSwitchTargets(il, instruction);
                return switchTargets is null
                    ? " (invalid targets)"
                    : $" ({string.Join(", ", switchTargets.Select(target => $"IL_{target:X4}"))})";
            default:
                return string.Empty;
        }
    }

    private static int[]? ReadSwitchTargets(byte[] il, IlInstruction instruction)
    {
        if (instruction.OperandSize < 4 ||
            instruction.OperandOffset + instruction.OperandSize > il.Length)
        {
            return null;
        }

        var count = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4));
        if (count < 0 || instruction.OperandSize != 4 + (count * 4))
        {
            return null;
        }

        var targets = new int[count];
        var baseOffset = instruction.OperandOffset + instruction.OperandSize;
        for (var index = 0; index < count; index++)
        {
            var deltaOffset = instruction.OperandOffset + 4 + (index * 4);
            targets[index] = baseOffset + BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(deltaOffset, 4));
        }

        return targets;
    }

    private static string FormatUserString(MetadataReader metadata, int token)
    {
        try
        {
            var value = metadata.GetUserString(MetadataTokens.UserStringHandle(token));
            var escaped = value
                .Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("\"", "\\\"", StringComparison.Ordinal)
                .ReplaceLineEndings(" ");
            if (escaped.Length > 120)
            {
                escaped = escaped[..120] + "…";
            }

            return $"\"{escaped}\"";
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
        {
            return $"str(0x{token:X8})";
        }
    }

    private static string ResolveTokenName(MetadataReader metadata, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
            case HandleKind.MemberReference:
            case HandleKind.MethodSpecification:
                return ResolveMemberName(metadata, token) ?? $"token(0x{token:X8})";

            case HandleKind.FieldDefinition:
                var field = metadata.GetFieldDefinition((FieldDefinitionHandle)handle);
                var declaringType = GetTypeName(metadata, field.GetDeclaringType());
                var fieldName = metadata.GetString(field.Name);
                return declaringType is null ? fieldName : $"{declaringType}.{fieldName}";

            case HandleKind.TypeDefinition:
            case HandleKind.TypeReference:
            case HandleKind.TypeSpecification:
                return GetTypeName(metadata, handle) ?? $"token(0x{token:X8})";

            default:
                return $"token(0x{token:X8})";
        }
    }

    private const int MaxBodyStatements = 80;

    private sealed record CallInfo(
        string DeclaringType,
        string Name,
        int ParamCount,
        bool HasThis,
        string ReturnType,
        bool ReturnsVoid,
        IReadOnlyList<string> ParameterTypes,
        IReadOnlyList<string> GenericArguments);

    private const int MaxStructureDepth = 32;

    private readonly record struct Instr(
        int Offset,
        string Name,
        int OperandOffset,
        bool IsBranch,
        int Target,
        IReadOnlyList<int> SwitchTargets);

    private readonly record struct StructuredSwitch(IReadOnlyList<string> Statements, int NextIndex);

    private readonly record struct StructuredException(IReadOnlyList<string> Statements, int NextIndex);

    private readonly record struct ExceptionLeaveRedirect(int JoinOffset, int TargetOffset);

    private sealed record CatchHandlerShape(
        string CatchType,
        int BodyStartIndex,
        int BodyEndIndex,
        int? ExceptionLocalIndex,
        string? ExceptionVariableName,
        string? FilterCondition);

    private sealed record CatchFilterPrologue(
        string CatchType,
        int ExceptionLocalIndex,
        int PredicateStartIndex,
        int PredicateEndIndex,
        int? PredicateTemporaryLocalIndex);

    private sealed record CatchFilterShape(
        string CatchType,
        int ExceptionLocalIndex,
        string ExceptionVariableName,
        string Condition);

    private sealed class FilterControlFlowBudget
    {
        public int RemainingNodes { get; set; } = MaxIlInstructions;
    }

    internal readonly record struct ExceptionRegionInfo(
        ExceptionRegionKind Kind,
        int TryOffset,
        int TryLength,
        int HandlerOffset,
        int HandlerLength,
        string? CatchType = null,
        int FilterOffset = -1);

    private sealed record ReconContext(
        MetadataReader Metadata,
        byte[] Il,
        Dictionary<int, string> ParameterNames,
        IReadOnlyList<string> ParameterTypes,
        bool IsInstance,
        string ReturnType,
        IReadOnlyList<string> LocalTypes,
        IReadOnlyList<ExceptionRegionInfo> ExceptionRegions,
        IReadOnlyDictionary<int, string> LocalNames,
        Dictionary<string, string> ExpressionTypes,
        HashSet<string> UnsignedIntegralExpressions,
        ExceptionLeaveRedirect? LeaveRedirect,
        int CatchDepth);

    // 測試用進入點：以現成的 MetadataReader 直接餵 IL bytes 驗證還原結果。
    internal static IReadOnlyList<string>? ReconstructBodyForTest(
        MetadataReader metadata,
        byte[] il,
        bool isInstance,
        string returnType,
        IReadOnlyList<string>? localTypes = null,
        IReadOnlyList<ExceptionRegionInfo>? exceptionRegions = null,
        IReadOnlyList<string>? parameterTypes = null) =>
        TryReconstructLinearBody(
            metadata,
            il,
            isInstance,
            new Dictionary<int, string>(),
            parameterTypes ?? [],
            returnType,
            localTypes ?? [],
            exceptionRegions ?? []);

    // 把方法的 IL 還原成 C#。先解碼成指令陣列，再用區間遞迴結構化還原 if／if-else（可巢狀）。
    // 採全有或全無：遇到無法安全切開的迴圈、非終止型 switch、不支援的例外區域或任何無法結構化的跳轉就整個方法放棄，
    // 退回 IL 註解，寧可不還原也不要產出語意錯誤的程式碼。輸出的 C# 不保證能編譯，但語意貼近原程式。
    private static IReadOnlyList<string>? TryReconstructLinearBody(
        MetadataReader metadata,
        byte[] il,
        bool isInstance,
        Dictionary<int, string> parameterNames,
        IReadOnlyList<string> parameterTypes,
        string returnType,
        IReadOnlyList<string> localTypes,
        IReadOnlyList<ExceptionRegionInfo> exceptionRegions)
    {
        var instructions = new List<Instr>();
        var offsetToIndex = new Dictionary<int, int>();
        foreach (var instruction in EnumerateInstructions(il))
        {
            if (!OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode))
            {
                return null;
            }

            var operandType = opCode.OperandType;

            var target = -1;
            IReadOnlyList<int> switchTargets = [];
            if (operandType == OperandType.ShortInlineBrTarget)
            {
                target = instruction.OperandOffset + 1 + (sbyte)il[instruction.OperandOffset];
            }
            else if (operandType == OperandType.InlineBrTarget)
            {
                target = instruction.OperandOffset + 4 + BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4));
            }
            else if (operandType == OperandType.InlineSwitch)
            {
                switchTargets = ReadSwitchTargets(il, instruction) ?? [];
                if (switchTargets.Count == 0)
                {
                    return null;
                }
            }

            offsetToIndex[instruction.Offset] = instructions.Count;
            instructions.Add(new Instr(
                instruction.Offset,
                opCode.Name!,
                instruction.OperandOffset,
                target >= 0 || switchTargets.Count > 0,
                target,
                switchTargets));
        }

        offsetToIndex[il.Length] = instructions.Count;
        var context = new ReconContext(
            metadata,
            il,
            parameterNames,
            parameterTypes,
            isInstance,
            returnType,
            localTypes,
            exceptionRegions,
            new Dictionary<int, string>(),
            new Dictionary<string, string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            LeaveRedirect: null,
            CatchDepth: 0);
        return TryStructure(context, [.. instructions], offsetToIndex, 0, instructions.Count, new HashSet<int>(), 0);
    }

    private static List<string>? TryStructure(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int start,
        int end,
        HashSet<int> declaredLocals,
        int depth)
    {
        if (depth > MaxStructureDepth)
        {
            return null;
        }

        var stack = new Stack<string>();
        var statements = new List<string>();
        var index = start;
        var terminated = false;

        while (index < end)
        {
            if (terminated || statements.Count > MaxBodyStatements)
            {
                return null;
            }

            var instr = instructions[index];

            // 先按 metadata 的保護區域邊界還原標準 try/catch/finally/fault；沒有明確區域資料時不猜測。
            if (stack.Count == 0)
            {
                var startingRegions = context.ExceptionRegions
                    .Where(region => region.TryOffset == instr.Offset)
                    .ToArray();
                if (startingRegions.Length > 0)
                {
                    var outerCleanup = TryFindOuterCleanup(startingRegions);
                    var structuredException = startingRegions.All(region =>
                            region.Kind is ExceptionRegionKind.Catch or ExceptionRegionKind.Filter)
                        ? TryStructureCatch(
                            context,
                            instructions,
                            offsetToIndex,
                            index,
                            end,
                            startingRegions,
                            declaredLocals,
                            depth + 1)
                        : outerCleanup is ExceptionRegionInfo cleanupRegion
                            ? TryStructureCleanup(
                                context,
                                instructions,
                                offsetToIndex,
                                index,
                                end,
                                cleanupRegion,
                                declaredLocals,
                                depth + 1)
                            : null;
                    if (structuredException is null ||
                        statements.Count + structuredException.Value.Statements.Count > MaxBodyStatements)
                    {
                        return null;
                    }

                    statements.AddRange(structuredException.Value.Statements);
                    index = structuredException.Value.NextIndex;
                    continue;
                }
            }

            // do-while（底測式）：此處是某個往回跳條件分支的目標，且中間為直線。
            if (stack.Count == 0)
            {
                var doWhileEnd = TryMatchDoWhileLoop(instructions, index, end);
                if (doWhileEnd is int branchIndex)
                {
                    var processed = TryProcessStraightLine(context, instructions, index, branchIndex, declaredLocals);
                    if (processed is null ||
                        !TryBuildTakenCondition(context, instructions[branchIndex].Name, processed.Value.Stack, out var doCondition) ||
                        processed.Value.Stack.Count != 0)
                    {
                        return null;
                    }

                    statements.Add("do");
                    statements.Add("{");
                    statements.AddRange(processed.Value.Statements.Select(line => $"    {line}"));
                    statements.Add($"}} while ({doCondition});");
                    index = branchIndex + 1;
                    continue;
                }
            }

            if (instr.Name == "switch")
            {
                if (!TryPop(stack, out var selector) || stack.Count != 0)
                {
                    return null;
                }

                var structuredSwitch = TryStructureSwitch(
                    context,
                    instructions,
                    offsetToIndex,
                    index,
                    end,
                    selector,
                    declaredLocals,
                    depth + 1);
                if (structuredSwitch is null)
                {
                    return null;
                }

                if (statements.Count + structuredSwitch.Value.Statements.Count > MaxBodyStatements)
                {
                    return null;
                }

                statements.AddRange(structuredSwitch.Value.Statements);
                index = structuredSwitch.Value.NextIndex;
                continue;
            }

            if (!instr.IsBranch)
            {
                if (!ApplySimpleInstruction(context, instr, stack, statements, declaredLocals, out var terminal))
                {
                    return null;
                }

                terminated = terminal;
                index++;
                continue;
            }

            if (instr.Name is "br" or "br.s")
            {
                // 跳到下一個指令或本區間結尾都不改變控制流程，略過即可。
                if (offsetToIndex.TryGetValue(instr.Target, out var branchIndex) &&
                    (branchIndex == index + 1 || branchIndex == end))
                {
                    index++;
                    continue;
                }

                // 否則嘗試比對「先跳到條件測試」的 while／for 迴圈形狀。
                var loop = TryMatchWhileLoop(instructions, offsetToIndex, index, end);
                if (loop is null || stack.Count != 0)
                {
                    return null;
                }

                var loopCondition = TryBuildLoopCondition(context, instructions, loop.Value.CondStart, loop.Value.BranchIndex, declaredLocals);
                if (loopCondition is null)
                {
                    return null;
                }

                var loopBody = TryStructure(context, instructions, offsetToIndex, loop.Value.BodyStart, loop.Value.BodyEnd, declaredLocals, depth + 1);
                if (loopBody is null)
                {
                    return null;
                }

                statements.Add($"while ({loopCondition})");
                statements.Add("{");
                statements.AddRange(loopBody.Select(line => $"    {line}"));
                statements.Add("}");
                index = loop.Value.JoinIndex;
                continue;
            }

            // 條件分支：往前跳才可能是 if。回跳代表迴圈，直接放棄。
            if (instr.Target <= instr.Offset ||
                !offsetToIndex.TryGetValue(instr.Target, out var targetIndex) ||
                targetIndex > end ||
                targetIndex <= index)
            {
                return null;
            }

            if (!TryBuildCondition(context, instr.Name, stack, out var condition) || stack.Count != 0)
            {
                return null;
            }

            var thenEnd = targetIndex;
            var joinIndex = targetIndex;
            var elseStart = -1;
            var elseEnd = -1;
            var beforeTarget = instructions[targetIndex - 1];
            if (beforeTarget.Name is "br" or "br.s" &&
                beforeTarget.Target > beforeTarget.Offset &&
                offsetToIndex.TryGetValue(beforeTarget.Target, out var elseJoin) &&
                elseJoin >= targetIndex &&
                elseJoin <= end)
            {
                thenEnd = targetIndex - 1;
                elseStart = targetIndex;
                elseEnd = elseJoin;
                joinIndex = elseJoin;
            }

            if (thenEnd < index + 1)
            {
                return null;
            }

            var thenStatements = TryStructure(context, instructions, offsetToIndex, index + 1, thenEnd, declaredLocals, depth + 1);
            if (thenStatements is null)
            {
                return null;
            }

            List<string>? elseStatements = null;
            if (elseStart >= 0)
            {
                elseStatements = TryStructure(context, instructions, offsetToIndex, elseStart, elseEnd, declaredLocals, depth + 1);
                if (elseStatements is null)
                {
                    return null;
                }
            }

            statements.Add($"if ({condition})");
            statements.Add("{");
            statements.AddRange(thenStatements.Select(line => $"    {line}"));
            statements.Add("}");
            if (elseStatements is not null)
            {
                statements.Add("else");
                statements.Add("{");
                statements.AddRange(elseStatements.Select(line => $"    {line}"));
                statements.Add("}");
            }

            index = joinIndex;
        }

        return stack.Count == 0 ? statements : null;
    }

    // 編譯器會把 try/catch/finally 編譯成內層 catch regions，再以較大的 finally region
    // 包住整段 try/catch。fault 也使用相同的外層保護形狀。只有所有同起點的其他區域都完整
    // 落在單一 cleanup region 的保護範圍內時才接受。
    private static ExceptionRegionInfo? TryFindOuterCleanup(IReadOnlyList<ExceptionRegionInfo> startingRegions)
    {
        var cleanupRegions = startingRegions
            .Where(region => region.Kind is ExceptionRegionKind.Finally or ExceptionRegionKind.Fault)
            .ToArray();
        if (cleanupRegions.Length != 1)
        {
            return null;
        }

        var outerCleanup = cleanupRegions[0];
        var outerTryEnd = outerCleanup.TryOffset + outerCleanup.TryLength;
        if (startingRegions.Any(region =>
                region != outerCleanup &&
                (region.Kind is not (ExceptionRegionKind.Catch or ExceptionRegionKind.Filter) ||
                 region.TryOffset != outerCleanup.TryOffset ||
                 region.TryLength >= outerCleanup.TryLength ||
                 ExceptionClauseStartOffset(region) < region.TryOffset + region.TryLength ||
                 region.HandlerOffset + region.HandlerLength > outerTryEnd)))
        {
            return null;
        }

        return outerCleanup;
    }

    private static int ExceptionClauseStartOffset(ExceptionRegionInfo region) =>
        region.Kind == ExceptionRegionKind.Filter ? region.FilterOffset : region.HandlerOffset;

    // 同一個 try 的 catch handlers 會在 metadata 中共用保護區間，並依序排列到共同 join；
    // 保護區尾端可用 leave 正常離開，或以 throw／合法 rethrow 直接終止。
    // handler 入口的例外物件只接受 pop（未命名）或 stloc（具名）兩種標準形狀。
    private static StructuredException? TryStructureCatch(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int tryStartIndex,
        int end,
        IReadOnlyList<ExceptionRegionInfo> regions,
        HashSet<int> declaredLocals,
        int depth)
    {
        if (depth > MaxStructureDepth || regions.Count == 0)
        {
            return null;
        }

        var orderedRegions = regions
            .OrderBy(ExceptionClauseStartOffset)
            .ToArray();
        var firstRegion = orderedRegions[0];
        if (orderedRegions.Any(region =>
                region.Kind is not (ExceptionRegionKind.Catch or ExceptionRegionKind.Filter) ||
                region.TryOffset != firstRegion.TryOffset ||
                region.TryLength != firstRegion.TryLength ||
                (region.Kind == ExceptionRegionKind.Catch &&
                 (string.IsNullOrWhiteSpace(region.CatchType) || IsGeneratedName(region.CatchType)))))
        {
            return null;
        }

        var tryEndOffset = firstRegion.TryOffset + firstRegion.TryLength;
        var joinOffset = orderedRegions[^1].HandlerOffset + orderedRegions[^1].HandlerLength;
        var leaveTarget = context.LeaveRedirect is ExceptionLeaveRedirect redirect &&
                          redirect.JoinOffset == joinOffset
            ? redirect.TargetOffset
            : joinOffset;
        if (!offsetToIndex.TryGetValue(tryEndOffset, out var tryEndIndex) ||
            !offsetToIndex.TryGetValue(joinOffset, out var joinIndex) ||
            tryStartIndex >= tryEndIndex ||
            tryEndIndex > joinIndex ||
            joinIndex > end ||
            ExceptionClauseStartOffset(orderedRegions[0]) != tryEndOffset)
        {
            return null;
        }

        var tryTerminator = instructions[tryEndIndex - 1];
        int tryBodyEnd;
        if (tryTerminator.Name is "leave" or "leave.s")
        {
            if (tryTerminator.Target != leaveTarget)
            {
                return null;
            }

            tryBodyEnd = tryEndIndex - 1;
        }
        else if (tryTerminator.Name is "throw" or "rethrow")
        {
            tryBodyEnd = tryEndIndex;
        }
        else
        {
            return null;
        }

        var handlers = new List<CatchHandlerShape>();
        for (var handlerOrdinal = 0; handlerOrdinal < orderedRegions.Length; handlerOrdinal++)
        {
            var region = orderedRegions[handlerOrdinal];
            var clauseStartOffset = ExceptionClauseStartOffset(region);
            var handlerEndOffset = region.HandlerOffset + region.HandlerLength;
            if (!offsetToIndex.TryGetValue(clauseStartOffset, out var clauseStartIndex) ||
                !offsetToIndex.TryGetValue(region.HandlerOffset, out var handlerStartIndex) ||
                !offsetToIndex.TryGetValue(handlerEndOffset, out var handlerEndIndex) ||
                clauseStartIndex > handlerStartIndex ||
                handlerStartIndex >= handlerEndIndex ||
                handlerEndIndex > joinIndex ||
                (handlerOrdinal + 1 < orderedRegions.Length
                    ? handlerEndOffset != ExceptionClauseStartOffset(orderedRegions[handlerOrdinal + 1])
                    : handlerEndOffset != joinOffset))
            {
                return null;
            }

            var handlerLast = instructions[handlerEndIndex - 1];
            int handlerBodyEnd;
            if (handlerLast.Name is "leave" or "leave.s")
            {
                if (handlerLast.Target != leaveTarget)
                {
                    return null;
                }

                handlerBodyEnd = handlerEndIndex - 1;
            }
            else if (handlerLast.Name is "throw" or "rethrow")
            {
                handlerBodyEnd = handlerEndIndex;
            }
            else
            {
                return null;
            }

            var prologue = instructions[handlerStartIndex];
            var handlerBodyStart = handlerStartIndex + 1;
            int? exceptionLocalIndex = null;
            string? exceptionVariableName = null;
            string catchType;
            string? filterCondition = null;
            if (region.Kind == ExceptionRegionKind.Filter)
            {
                var filter = TryStructureCatchFilter(
                    context,
                    instructions,
                    offsetToIndex,
                    region,
                    handlerOrdinal,
                    declaredLocals);
                if (filter is null || prologue.Name != "pop")
                {
                    return null;
                }

                catchType = filter.CatchType;
                exceptionLocalIndex = filter.ExceptionLocalIndex;
                exceptionVariableName = filter.ExceptionVariableName;
                filterCondition = filter.Condition;
            }
            else
            {
                catchType = region.CatchType!;
                if (prologue.Name != "pop")
                {
                    exceptionLocalIndex = TryGetStoredLocalIndex(context, prologue);
                    if (exceptionLocalIndex is null || catchType == "System.Object")
                    {
                        return null;
                    }

                    exceptionVariableName = CreateCatchVariableName(context, handlerOrdinal);
                }
            }

            if (handlerBodyStart > handlerBodyEnd)
            {
                return null;
            }

            handlers.Add(new CatchHandlerShape(
                catchType,
                handlerBodyStart,
                handlerBodyEnd,
                exceptionLocalIndex,
                exceptionVariableName,
                filterCondition));
        }

        var tryStoredLocals = instructions[tryStartIndex..tryBodyEnd]
            .Select(instruction => TryGetStoredLocalIndex(context, instruction))
            .Where(localIndex => localIndex is not null)
            .Select(localIndex => localIndex!.Value)
            .ToArray();
        var exceptionLocals = handlers
            .Where(handler => handler.ExceptionLocalIndex is not null)
            .Select(handler => handler.ExceptionLocalIndex!.Value)
            .ToHashSet();
        if (tryStoredLocals.Any(exceptionLocals.Contains))
        {
            return null;
        }

        var storedLocals = tryStoredLocals
            .Concat(handlers.SelectMany(handler => instructions[handler.BodyStartIndex..handler.BodyEndIndex]
                .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                .Where(localIndex => localIndex is not null)
                .Select(localIndex => localIndex!.Value)))
            .Where(localIndex => !exceptionLocals.Contains(localIndex))
            .Distinct()
            .Order()
            .ToArray();

        var statements = new List<string>();
        foreach (var localIndex in storedLocals)
        {
            if (declaredLocals.Contains(localIndex))
            {
                continue;
            }

            var type = LocalDeclarationType(context, localIndex);
            if (type == "var" || IsGeneratedName(type))
            {
                return null;
            }

            declaredLocals.Add(localIndex);
            statements.Add(DeclareLocalWithDefault(context, localIndex, type));
        }

        var currentRegions = orderedRegions.ToHashSet();
        var nestedContext = context with
        {
            ExceptionRegions = context.ExceptionRegions
                .Where(candidate => !currentRegions.Contains(candidate))
                .ToArray()
        };
        var tryBody = TryStructure(
            nestedContext,
            instructions,
            offsetToIndex,
            tryStartIndex,
            tryBodyEnd,
            new HashSet<int>(declaredLocals),
            depth);
        if (tryBody is null)
        {
            return null;
        }

        statements.Add("try");
        statements.Add("{");
        statements.AddRange(tryBody.Select(line => $"    {line}"));
        statements.Add("}");

        foreach (var handler in handlers)
        {
            var catchType = handler.CatchType;
            if (catchType == "System.Object")
            {
                statements.Add("catch");
            }
            else
            {
                var variable = handler.ExceptionVariableName is null ? "" : $" {handler.ExceptionVariableName}";
                var filter = handler.FilterCondition is null ? "" : $" when ({handler.FilterCondition})";
                statements.Add($"catch ({catchType}{variable}){filter}");
            }

            var handlerLocals = new HashSet<int>(declaredLocals);
            var handlerContext = nestedContext with { CatchDepth = nestedContext.CatchDepth + 1 };
            if (handler.ExceptionLocalIndex is int exceptionLocalIndex)
            {
                handlerLocals.Add(exceptionLocalIndex);
                handlerContext = handlerContext with
                {
                    LocalNames = handlerContext.LocalNames
                        .Where(pair => pair.Key != exceptionLocalIndex)
                        .Append(new KeyValuePair<int, string>(exceptionLocalIndex, handler.ExceptionVariableName!))
                        .ToDictionary(pair => pair.Key, pair => pair.Value)
                };
            }

            var handlerBody = TryStructure(
                handlerContext,
                instructions,
                offsetToIndex,
                handler.BodyStartIndex,
                handler.BodyEndIndex,
                handlerLocals,
                depth);
            if (handlerBody is null)
            {
                return null;
            }

            statements.Add("{");
            statements.AddRange(handlerBody.Select(line => $"    {line}"));
            statements.Add("}");
        }

        return new StructuredException(statements, joinIndex);
    }

    // Roslyn 的標準 catch filter：isinst → 保存具型別例外 → 純運算式 predicate →
    // ldc.i4.0/cgt.un → endfilter。Debug 會在 predicate 尾端多一組 stloc/ldloc 布林暫存。
    private static CatchFilterShape? TryStructureCatchFilter(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        ExceptionRegionInfo region,
        int handlerOrdinal,
        HashSet<int> declaredLocals)
    {
        var prologue = TryReadCatchFilterPrologue(context, instructions, offsetToIndex, region);
        if (prologue is null)
        {
            return null;
        }

        var variableName = CreateCatchVariableName(context, handlerOrdinal);
        var filterContext = context with
        {
            LocalNames = context.LocalNames
                .Where(pair => pair.Key != prologue.ExceptionLocalIndex)
                .Append(new KeyValuePair<int, string>(prologue.ExceptionLocalIndex, variableName))
                .ToDictionary(pair => pair.Key, pair => pair.Value)
        };
        var filterLocals = new HashSet<int>(declaredLocals)
        {
            prologue.ExceptionLocalIndex
        };
        var condition = TryBuildCatchFilterCondition(
            filterContext,
            instructions,
            offsetToIndex,
            prologue.PredicateStartIndex,
            prologue.PredicateEndIndex,
            filterLocals);
        if (condition is null)
        {
            return null;
        }

        return new CatchFilterShape(
            prologue.CatchType,
            prologue.ExceptionLocalIndex,
            variableName,
            condition);
    }

    private static string? TryBuildCatchFilterCondition(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int start,
        int end,
        HashSet<int> declaredLocals) =>
        TryBuildCatchFilterControlFlow(
            context,
            instructions,
            offsetToIndex,
            start,
            end,
            declaredLocals,
            new HashSet<int>(),
            new FilterControlFlowBudget(),
            depth: 0);

    private static string? TryBuildCatchFilterControlFlow(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int start,
        int end,
        HashSet<int> declaredLocals,
        HashSet<int> activeStarts,
        FilterControlFlowBudget budget,
        int depth)
    {
        if (depth > MaxStructureDepth ||
            budget.RemainingNodes-- <= 0 ||
            start >= end ||
            !activeStarts.Add(start))
        {
            return null;
        }

        try
        {
            var branchIndex = -1;
            for (var index = start; index < end; index++)
            {
                if (instructions[index].IsBranch)
                {
                    branchIndex = index;
                    break;
                }
            }

            if (branchIndex < 0)
            {
                var straightLine = TryProcessStraightLine(
                    context,
                    instructions,
                    start,
                    end,
                    new HashSet<int>(declaredLocals));
                return straightLine is not null &&
                       straightLine.Value.Statements.Count == 0 &&
                       straightLine.Value.Stack.Count == 1
                    ? NormalizeFilterCondition(straightLine.Value.Stack.Pop())
                    : null;
            }

            var branch = instructions[branchIndex];
            if (branch.Name is "br" or "br.s")
            {
                if (!TryFollowFilterJoinBranches(instructions, offsetToIndex, branch.Target, end))
                {
                    return null;
                }

                var leaf = TryProcessStraightLine(
                    context,
                    instructions,
                    start,
                    branchIndex,
                    new HashSet<int>(declaredLocals));
                return leaf is not null && leaf.Value.Statements.Count == 0 && leaf.Value.Stack.Count == 1
                    ? NormalizeFilterCondition(leaf.Value.Stack.Pop())
                    : null;
            }

            if (!offsetToIndex.TryGetValue(branch.Target, out var takenStart) ||
                takenStart <= branchIndex ||
                takenStart >= end)
            {
                return null;
            }

            var condition = TryProcessStraightLine(
                context,
                instructions,
                start,
                branchIndex,
                new HashSet<int>(declaredLocals));
            if (condition is null || condition.Value.Statements.Count != 0)
            {
                return null;
            }

            var takenStack = new Stack<string>(condition.Value.Stack.Reverse());
            var fallThroughStack = new Stack<string>(condition.Value.Stack.Reverse());
            if (!TryBuildTakenCondition(context, branch.Name, takenStack, out var takenCondition) ||
                !TryBuildCondition(context, branch.Name, fallThroughStack, out var fallThroughCondition) ||
                takenStack.Count != 0 ||
                fallThroughStack.Count != 0)
            {
                return null;
            }

            var taken = TryBuildCatchFilterControlFlow(
                context,
                instructions,
                offsetToIndex,
                takenStart,
                end,
                declaredLocals,
                activeStarts,
                budget,
                depth + 1);
            var fallThrough = TryBuildCatchFilterControlFlow(
                context,
                instructions,
                offsetToIndex,
                branchIndex + 1,
                end,
                declaredLocals,
                activeStarts,
                budget,
                depth + 1);
            if (taken is null || fallThrough is null)
            {
                return null;
            }

            return (taken, fallThrough) switch
            {
                ("false", _) => $"({fallThroughCondition} && {fallThrough})",
                ("true", _) => $"({takenCondition} || {fallThrough})",
                (_, "false") => $"({takenCondition} && {taken})",
                (_, "true") => $"({fallThroughCondition} || {taken})",
                _ => $"({takenCondition} ? {taken} : {fallThrough})"
            };
        }
        finally
        {
            activeStarts.Remove(start);
        }
    }

    // Debug 版 Roslyn 有時會讓 leaf 先跳到另一個空的 br，再進入 predicate join。
    // 只追蹤不碰堆疊、持續往前的無條件分支鏈，其他中介區塊一律拒絕。
    private static bool TryFollowFilterJoinBranches(
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int targetOffset,
        int end)
    {
        var seen = new HashSet<int>();
        while (offsetToIndex.TryGetValue(targetOffset, out var targetIndex) && seen.Add(targetIndex))
        {
            if (targetIndex == end)
            {
                return true;
            }

            if (targetIndex > end || instructions[targetIndex].Name is not ("br" or "br.s"))
            {
                return false;
            }

            var nextOffset = instructions[targetIndex].Target;
            if (!offsetToIndex.TryGetValue(nextOffset, out var nextIndex) || nextIndex <= targetIndex)
            {
                return false;
            }

            targetOffset = nextOffset;
        }

        return false;
    }

    private static string NormalizeFilterCondition(string condition) => condition switch
    {
        "0" => "false",
        "1" => "true",
        _ => condition
    };

    private static CatchFilterPrologue? TryReadCatchFilterPrologue(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        ExceptionRegionInfo region)
    {
        if (region.Kind != ExceptionRegionKind.Filter ||
            region.FilterOffset < 0 ||
            !offsetToIndex.TryGetValue(region.FilterOffset, out var filterStartIndex) ||
            !offsetToIndex.TryGetValue(region.HandlerOffset, out var handlerStartIndex) ||
            filterStartIndex + 6 >= handlerStartIndex)
        {
            return null;
        }

        var isInstance = instructions[filterStartIndex];
        var duplicate = instructions[filterStartIndex + 1];
        var hasType = instructions[filterStartIndex + 2];
        var discardFailedCast = instructions[filterStartIndex + 3];
        var falseValue = instructions[filterStartIndex + 4];
        var skipPredicate = instructions[filterStartIndex + 5];
        if (isInstance.Name != "isinst" ||
            duplicate.Name != "dup" ||
            hasType.Name is not ("brtrue" or "brtrue.s") ||
            discardFailedCast.Name != "pop" ||
            falseValue.Name != "ldc.i4.0" ||
            skipPredicate.Name is not ("br" or "br.s") ||
            !offsetToIndex.TryGetValue(hasType.Target, out var storeExceptionIndex) ||
            storeExceptionIndex != filterStartIndex + 6)
        {
            return null;
        }

        var catchType = GetTypeName(
            context.Metadata,
            MetadataTokens.EntityHandle(BinaryPrimitives.ReadInt32LittleEndian(
                context.Il.AsSpan(isInstance.OperandOffset, 4))));
        var exceptionLocalIndex = TryGetStoredLocalIndex(context, instructions[storeExceptionIndex]);
        var endFilterIndex = handlerStartIndex - 1;
        var normalizeIndex = endFilterIndex - 1;
        var normalizeValueIndex = endFilterIndex - 2;
        if (string.IsNullOrWhiteSpace(catchType) ||
            IsGeneratedName(catchType) ||
            exceptionLocalIndex is null ||
            normalizeValueIndex <= storeExceptionIndex ||
            instructions[endFilterIndex].Name != "endfilter" ||
            skipPredicate.Target != instructions[endFilterIndex].Offset ||
            instructions[normalizeValueIndex].Name != "ldc.i4.0" ||
            instructions[normalizeIndex].Name != "cgt.un")
        {
            return null;
        }

        var predicateStartIndex = storeExceptionIndex + 1;
        var predicateEndIndex = normalizeValueIndex;
        int? predicateTemporaryLocalIndex = null;
        if (predicateEndIndex - predicateStartIndex >= 2)
        {
            var storedTemporary = TryGetStoredLocalIndex(context, instructions[predicateEndIndex - 2]);
            var loadedTemporary = TryGetLoadedLocalIndex(context, instructions[predicateEndIndex - 1]);
            if (storedTemporary is not null && loadedTemporary == storedTemporary)
            {
                predicateTemporaryLocalIndex = storedTemporary;
                predicateEndIndex -= 2;
            }
        }

        if (predicateStartIndex >= predicateEndIndex)
        {
            return null;
        }

        return new CatchFilterPrologue(
            catchType,
            exceptionLocalIndex.Value,
            predicateStartIndex,
            predicateEndIndex,
            predicateTemporaryLocalIndex);
    }

    private static string CreateCatchVariableName(ReconContext context, int ordinal)
    {
        var usedNames = context.ParameterNames.Values
            .Concat(context.LocalNames.Values)
            .ToHashSet(StringComparer.Ordinal);
        var name = $"caughtException{ordinal}";
        while (!usedNames.Add(name))
        {
            name += "_";
        }

        return name;
    }

    // finally 與 fault 的控制流程由 exception region metadata 決定。只接受標準的
    // try 尾端 leave／throw／合法 rethrow → handler 尾端 endfinally 形狀，避免靠跳轉猜區塊。
    // C# 沒有 fault 語法，因此輸出語意等價的 catch { handler; throw; }。
    private static StructuredException? TryStructureCleanup(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int tryStartIndex,
        int end,
        ExceptionRegionInfo region,
        HashSet<int> declaredLocals,
        int depth)
    {
        if (depth > MaxStructureDepth ||
            region.Kind is not (ExceptionRegionKind.Finally or ExceptionRegionKind.Fault))
        {
            return null;
        }

        var tryEndOffset = region.TryOffset + region.TryLength;
        var handlerEndOffset = region.HandlerOffset + region.HandlerLength;
        if (!offsetToIndex.TryGetValue(tryEndOffset, out var tryEndIndex) ||
            !offsetToIndex.TryGetValue(region.HandlerOffset, out var handlerStartIndex) ||
            !offsetToIndex.TryGetValue(handlerEndOffset, out var handlerEndIndex) ||
            tryStartIndex >= tryEndIndex ||
            tryEndIndex != handlerStartIndex ||
            handlerStartIndex >= handlerEndIndex ||
            handlerEndIndex > end)
        {
            return null;
        }

        var tryTerminator = instructions[tryEndIndex - 1];
        var endFinally = instructions[handlerEndIndex - 1];
        var tryLeaves = tryTerminator.Name is "leave" or "leave.s";
        var tryTerminates = tryTerminator.Name is "throw" or "rethrow";
        if ((!tryLeaves && !tryTerminates) ||
            (tryLeaves && tryTerminator.Target != handlerEndOffset) ||
            endFinally.Name != "endfinally")
        {
            return null;
        }

        // Release 最佳化會讓內層 try/catch 的所有 leave 直接跳過外層 cleanup handler，且最後一個
        // catch handler 恰好結束在 cleanup handler 起點；此時尾端 leave 屬於 catch，不能先剝掉。
        var nestedCatchEndsAtTryEnd = context.ExceptionRegions.Any(candidate =>
            candidate.Kind is ExceptionRegionKind.Catch or ExceptionRegionKind.Filter &&
            candidate.TryOffset == region.TryOffset &&
            candidate.HandlerOffset + candidate.HandlerLength == tryEndOffset);
        var tryBodyEnd = nestedCatchEndsAtTryEnd || tryTerminates ? tryEndIndex : tryEndIndex - 1;
        var cleanupBodyEnd = handlerEndIndex - 1;
        var nestedCatchExceptionLocals = new HashSet<int>();
        foreach (var nestedCatch in context.ExceptionRegions.Where(candidate =>
                     candidate.Kind is ExceptionRegionKind.Catch or ExceptionRegionKind.Filter &&
                     candidate.TryOffset >= region.TryOffset &&
                     candidate.TryOffset + candidate.TryLength <= tryEndOffset &&
                     ExceptionClauseStartOffset(candidate) >= region.TryOffset &&
                     candidate.HandlerOffset + candidate.HandlerLength <= tryEndOffset))
        {
            if (nestedCatch.Kind == ExceptionRegionKind.Filter)
            {
                var filter = TryReadCatchFilterPrologue(context, instructions, offsetToIndex, nestedCatch);
                if (filter is null)
                {
                    return null;
                }

                nestedCatchExceptionLocals.Add(filter.ExceptionLocalIndex);
                if (filter.PredicateTemporaryLocalIndex is int predicateTemporaryLocalIndex)
                {
                    nestedCatchExceptionLocals.Add(predicateTemporaryLocalIndex);
                }

                continue;
            }

            if (!offsetToIndex.TryGetValue(nestedCatch.HandlerOffset, out var nestedHandlerStartIndex))
            {
                return null;
            }

            var prologue = instructions[nestedHandlerStartIndex];
            if (prologue.Name == "pop")
            {
                continue;
            }

            var exceptionLocalIndex = TryGetStoredLocalIndex(context, prologue);
            if (exceptionLocalIndex is null)
            {
                return null;
            }

            nestedCatchExceptionLocals.Add(exceptionLocalIndex.Value);
        }

        var storedLocals = instructions[tryStartIndex..tryBodyEnd]
            .Concat(instructions[handlerStartIndex..cleanupBodyEnd])
            .Select(instruction => TryGetStoredLocalIndex(context, instruction))
            .Where(localIndex => localIndex is not null)
            .Select(localIndex => localIndex!.Value)
            .Where(localIndex => !nestedCatchExceptionLocals.Contains(localIndex))
            .Distinct()
            .Order()
            .ToArray();

        var statements = new List<string>();
        foreach (var localIndex in storedLocals)
        {
            if (declaredLocals.Contains(localIndex))
            {
                continue;
            }

            var type = LocalDeclarationType(context, localIndex);
            if (type == "var" || IsGeneratedName(type))
            {
                return null;
            }

            declaredLocals.Add(localIndex);
            statements.Add(DeclareLocalWithDefault(context, localIndex, type));
        }

        var nestedContext = context with
        {
            ExceptionRegions = context.ExceptionRegions
                .Where(candidate => candidate != region)
                .ToArray()
        };
        var tryBody = TryStructure(
            nestedCatchEndsAtTryEnd
                ? nestedContext with
                {
                    LeaveRedirect = new ExceptionLeaveRedirect(tryEndOffset, handlerEndOffset)
                }
                : nestedContext,
            instructions,
            offsetToIndex,
            tryStartIndex,
            tryBodyEnd,
            new HashSet<int>(declaredLocals),
            depth);
        var cleanupBody = TryStructure(
            nestedContext with { LeaveRedirect = context.LeaveRedirect },
            instructions,
            offsetToIndex,
            handlerStartIndex,
            cleanupBodyEnd,
            new HashSet<int>(declaredLocals),
            depth);
        if (tryBody is null || cleanupBody is null)
        {
            return null;
        }

        statements.Add("try");
        statements.Add("{");
        statements.AddRange(tryBody.Select(line => $"    {line}"));
        statements.Add("}");
        statements.Add(region.Kind == ExceptionRegionKind.Finally ? "finally" : "catch");
        statements.Add("{");
        statements.AddRange(cleanupBody.Select(line => $"    {line}"));
        if (region.Kind == ExceptionRegionKind.Fault)
        {
            statements.Add("    throw;");
        }

        statements.Add("}");
        return new StructuredException(statements, handlerEndIndex);
    }

    // 支援 Roslyn 常見的 switch：default 先跳到自己的區塊，各 case 直接結束，或寫入區域變數後跳到共同 join。
    // 共用的區域變數會先提升到 switch 外並以 default 初始化，兼顧 C# 作用域與 IL locals init 語意。
    private static StructuredSwitch? TryStructureSwitch(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int switchIndex,
        int end,
        string selector,
        HashSet<int> declaredLocals,
        int depth)
    {
        if (depth > MaxStructureDepth || switchIndex + 1 >= end)
        {
            return null;
        }

        var instruction = instructions[switchIndex];
        var caseTargets = new List<(int Value, int Index)>();
        for (var value = 0; value < instruction.SwitchTargets.Count; value++)
        {
            var target = instruction.SwitchTargets[value];
            if (!offsetToIndex.TryGetValue(target, out var targetIndex) ||
                targetIndex <= switchIndex ||
                targetIndex >= end)
            {
                return null;
            }

            caseTargets.Add((value, targetIndex));
        }

        var fallThroughIndex = switchIndex + 1;
        var defaultIndex = fallThroughIndex;
        var fallThrough = instructions[fallThroughIndex];
        if (fallThrough.Name is "br" or "br.s")
        {
            if (!offsetToIndex.TryGetValue(fallThrough.Target, out defaultIndex) ||
                defaultIndex <= fallThroughIndex ||
                defaultIndex >= end)
            {
                return null;
            }

            fallThroughIndex++;
        }

        var blockStarts = caseTargets
            .Select(target => target.Index)
            .Append(defaultIndex)
            .Distinct()
            .Order()
            .ToArray();
        if (blockStarts.Length == 0 || blockStarts[0] != fallThroughIndex)
        {
            return null;
        }

        var joinCandidates = new List<int>();
        for (var block = 0; block < blockStarts.Length - 1; block++)
        {
            var boundary = blockStarts[block + 1];
            var last = instructions[boundary - 1];
            if (last.Name is not ("br" or "br.s") ||
                !offsetToIndex.TryGetValue(last.Target, out var candidate) ||
                candidate <= blockStarts[^1] ||
                candidate >= end)
            {
                continue;
            }

            joinCandidates.Add(candidate);
        }

        var distinctJoins = joinCandidates.Distinct().ToArray();
        if (distinctJoins.Length > 1)
        {
            return null;
        }

        int? joinIndex = distinctJoins.Length == 1 ? distinctJoins[0] : null;
        var blocks = new List<(int Start, int BodyEnd, bool AddBreak)>();
        for (var block = 0; block < blockStarts.Length; block++)
        {
            var blockStart = blockStarts[block];
            var naturalEnd = block + 1 < blockStarts.Length
                ? blockStarts[block + 1]
                : joinIndex ?? end;
            if (blockStart >= naturalEnd)
            {
                return null;
            }

            var last = instructions[naturalEnd - 1];
            if (last.Name is "ret" or "throw")
            {
                blocks.Add((blockStart, naturalEnd, false));
                continue;
            }

            if (joinIndex is null)
            {
                return null;
            }

            if (last.Name is "br" or "br.s")
            {
                if (!offsetToIndex.TryGetValue(last.Target, out var targetIndex) || targetIndex != joinIndex)
                {
                    return null;
                }

                blocks.Add((blockStart, naturalEnd - 1, true));
                continue;
            }

            if (naturalEnd != joinIndex)
            {
                return null;
            }

            blocks.Add((blockStart, naturalEnd, true));
        }

        var statements = new List<string>();
        if (joinIndex is not null)
        {
            var storedLocals = blocks
                .Where(block => block.AddBreak)
                .SelectMany(block => instructions[block.Start..block.BodyEnd])
                .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                .Where(index => index is not null)
                .Select(index => index!.Value)
                .Distinct()
                .Order()
                .ToArray();
            foreach (var localIndex in storedLocals)
            {
                if (!declaredLocals.Add(localIndex))
                {
                    continue;
                }

                var type = LocalDeclarationType(context, localIndex);
                if (type == "var" || IsGeneratedName(type))
                {
                    return null;
                }

                statements.Add(DeclareLocalWithDefault(context, localIndex, type));
            }
        }

        statements.Add($"switch ({selector})");
        statements.Add("{");
        foreach (var block in blocks)
        {
            var blockStart = block.Start;

            foreach (var (value, _) in caseTargets.Where(target => target.Index == blockStart))
            {
                statements.Add($"    case {RenderSwitchCaseValue(context, selector, value)}:");
            }

            if (defaultIndex == blockStart)
            {
                statements.Add("    default:");
            }

            var body = TryStructure(
                context,
                instructions,
                offsetToIndex,
                blockStart,
                block.BodyEnd,
                new HashSet<int>(declaredLocals),
                depth);
            if (body is null)
            {
                return null;
            }

            statements.AddRange(body.Select(line => $"        {line}"));
            if (block.AddBreak)
            {
                statements.Add("        break;");
            }
        }

        statements.Add("}");
        return new StructuredSwitch(statements, joinIndex ?? end);
    }

    private static string RenderSwitchCaseValue(ReconContext context, string selector, int value)
    {
        if (context.ExpressionTypes.TryGetValue(selector, out var selectorType) && IsPotentialEnumType(selectorType))
        {
            return $"unchecked(({selectorType}){value})";
        }

        return value.ToString(CultureInfo.InvariantCulture);
    }

    private static int? TryGetStoredLocalIndex(ReconContext context, Instr instruction) => instruction.Name switch
    {
        "stloc.0" => 0,
        "stloc.1" => 1,
        "stloc.2" => 2,
        "stloc.3" => 3,
        "stloc.s" => context.Il[instruction.OperandOffset],
        "stloc" => BinaryPrimitives.ReadUInt16LittleEndian(context.Il.AsSpan(instruction.OperandOffset, 2)),
        _ => null
    };

    private static int? TryGetLoadedLocalIndex(ReconContext context, Instr instruction) => instruction.Name switch
    {
        "ldloc.0" => 0,
        "ldloc.1" => 1,
        "ldloc.2" => 2,
        "ldloc.3" => 3,
        "ldloc.s" => context.Il[instruction.OperandOffset],
        "ldloc" => BinaryPrimitives.ReadUInt16LittleEndian(context.Il.AsSpan(instruction.OperandOffset, 2)),
        _ => null
    };

    // 依分支指令算出「順順落下（fall-through）」時的 C# 條件，也就是不跳轉時該執行 then 區塊的條件。
    private static bool TryBuildCondition(ReconContext context, string name, Stack<string> stack, out string condition)
    {
        condition = string.Empty;
        switch (name)
        {
            case "brtrue":
            case "brtrue.s":
                if (!TryPop(stack, out var truthy))
                {
                    return false;
                }

                condition = RenderBranchCondition(context, truthy, branchWhenTrue: false);
                return true;
            case "brfalse":
            case "brfalse.s":
                if (!TryPop(stack, out var falsy))
                {
                    return false;
                }

                condition = RenderBranchCondition(context, falsy, branchWhenTrue: true);
                return true;
        }

        if (!TryPop(stack, out var right) || !TryPop(stack, out var left))
        {
            return false;
        }

        condition = name switch
        {
            "beq" or "beq.s" => $"{left} != {right}",
            "bne.un" or "bne.un.s" => $"{left} == {right}",
            "bge" or "bge.s" or "bge.un" or "bge.un.s" => $"{left} < {right}",
            "bgt" or "bgt.s" or "bgt.un" or "bgt.un.s" => $"{left} <= {right}",
            "ble" or "ble.s" or "ble.un" or "ble.un.s" => $"{left} > {right}",
            "blt" or "blt.s" or "blt.un" or "blt.un.s" => $"{left} >= {right}",
            _ => string.Empty
        };

        return condition.Length > 0;
    }

    // 比對 Roslyn 的 while／for 形狀：br→條件、主體、條件、往回跳主體的條件分支。
    private static (int CondStart, int BranchIndex, int BodyStart, int BodyEnd, int JoinIndex)? TryMatchWhileLoop(
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int headerIndex,
        int end)
    {
        var header = instructions[headerIndex];
        if (!offsetToIndex.TryGetValue(header.Target, out var condStart) || condStart <= headerIndex || condStart > end)
        {
            return null;
        }

        var bodyStart = headerIndex + 1;
        if (bodyStart > condStart || bodyStart >= instructions.Length)
        {
            return null;
        }

        var bodyStartOffset = instructions[bodyStart].Offset;

        // 條件區塊必須是直線，最後以「往回跳主體開頭」的條件分支收尾。
        for (var index = condStart; index < end; index++)
        {
            var instr = instructions[index];
            if (!instr.IsBranch)
            {
                continue;
            }

            if (instr.Name is "br" or "br.s" || instr.Target != bodyStartOffset)
            {
                return null;
            }

            return (condStart, index, bodyStart, condStart, index + 1);
        }

        return null;
    }

    // do-while：從 loopStart 往後第一個分支若是往回跳到 loopStart 的條件分支，且中間全是直線，就是底測式迴圈。
    // 回傳收尾條件分支的索引，否則 null。
    private static int? TryMatchDoWhileLoop(Instr[] instructions, int loopStart, int end)
    {
        var loopStartOffset = instructions[loopStart].Offset;
        for (var index = loopStart; index < end; index++)
        {
            var instr = instructions[index];
            if (!instr.IsBranch)
            {
                continue;
            }

            if (index == loopStart || instr.Name is "br" or "br.s" || instr.Target != loopStartOffset)
            {
                return null;
            }

            return index;
        }

        return null;
    }

    private static (List<string> Statements, Stack<string> Stack)? TryProcessStraightLine(
        ReconContext context,
        Instr[] instructions,
        int start,
        int end,
        HashSet<int> declaredLocals)
    {
        var stack = new Stack<string>();
        var statements = new List<string>();
        for (var index = start; index < end; index++)
        {
            var instr = instructions[index];
            if (instr.IsBranch || !ApplySimpleInstruction(context, instr, stack, statements, declaredLocals, out var terminal) || terminal)
            {
                return null;
            }
        }

        return (statements, stack);
    }

    private static string? TryBuildLoopCondition(
        ReconContext context,
        Instr[] instructions,
        int condStart,
        int branchIndex,
        HashSet<int> declaredLocals)
    {
        var stack = new Stack<string>();
        var statements = new List<string>();
        for (var index = condStart; index < branchIndex; index++)
        {
            var instr = instructions[index];
            if (instr.IsBranch || !ApplySimpleInstruction(context, instr, stack, statements, declaredLocals, out var terminal) || terminal)
            {
                return null;
            }
        }

        // 迴圈條件必須是純運算式，不能夾帶副作用陳述式。
        if (statements.Count != 0 || !TryBuildTakenCondition(context, instructions[branchIndex].Name, stack, out var condition) || stack.Count != 0)
        {
            return null;
        }

        return condition;
    }

    // 分支「成立時」的 C# 條件；用於迴圈（往回跳＝再跑一次主體）。
    private static bool TryBuildTakenCondition(ReconContext context, string name, Stack<string> stack, out string condition)
    {
        condition = string.Empty;
        switch (name)
        {
            case "brtrue":
            case "brtrue.s":
                if (!TryPop(stack, out var truthy))
                {
                    return false;
                }

                condition = RenderBranchCondition(context, truthy, branchWhenTrue: true);
                return true;
            case "brfalse":
            case "brfalse.s":
                if (!TryPop(stack, out var falsy))
                {
                    return false;
                }

                condition = RenderBranchCondition(context, falsy, branchWhenTrue: false);
                return true;
        }

        if (!TryPop(stack, out var right) || !TryPop(stack, out var left))
        {
            return false;
        }

        condition = name switch
        {
            "beq" or "beq.s" => $"{left} == {right}",
            "bne.un" or "bne.un.s" => $"{left} != {right}",
            "bge" or "bge.s" or "bge.un" or "bge.un.s" => $"{left} >= {right}",
            "bgt" or "bgt.s" or "bgt.un" or "bgt.un.s" => $"{left} > {right}",
            "ble" or "ble.s" or "ble.un" or "ble.un.s" => $"{left} <= {right}",
            "blt" or "blt.s" or "blt.un" or "blt.un.s" => $"{left} < {right}",
            _ => string.Empty
        };

        return condition.Length > 0;
    }

    // brtrue／brfalse 可直接判斷 bool、整數、managed pointer 與 object reference，C# 則要求 bool 條件。
    // 已知參考型別用 null pattern；其他具名值以 default 比較，保留 CLR 的零值判斷語意。
    private static string RenderBranchCondition(ReconContext context, string expression, bool branchWhenTrue)
    {
        if (!context.ExpressionTypes.TryGetValue(expression, out var type) || type == "bool")
        {
            return branchWhenTrue ? expression : $"!({expression})";
        }

        if (IsKnownReferenceType(context.Metadata, type))
        {
            return $"{expression} is {(branchWhenTrue ? "not null" : "null")}";
        }

        if (type.StartsWith('!') ||
            type.StartsWith("ref ", StringComparison.Ordinal) ||
            type.EndsWith('*') ||
            type is "TypedReference" or "method*")
        {
            return branchWhenTrue ? expression : $"!({expression})";
        }

        var isDefault = $"System.Collections.Generic.EqualityComparer<{type}>.Default.Equals({expression}, default)";
        return branchWhenTrue ? $"!({isDefault})" : isDefault;
    }

    private static bool IsKnownReferenceType(MetadataReader metadata, string type)
    {
        var normalizedType = type.EndsWith("?", StringComparison.Ordinal) ? type[..^1] : type;
        if (normalizedType is "string" or "object" || normalizedType.EndsWith(']'))
        {
            return true;
        }

        var genericStart = normalizedType.IndexOf('<');
        var definitionName = genericStart >= 0 ? normalizedType[..genericStart] : normalizedType;
        foreach (var handle in metadata.TypeDefinitions)
        {
            if (GetTypeDefinitionFullName(metadata, handle) != definitionName)
            {
                continue;
            }

            var definition = metadata.GetTypeDefinition(handle);
            var baseType = GetTypeName(metadata, definition.BaseType);
            return baseType is not ("System.Enum" or "System.ValueType");
        }

        return false;
    }

    private static string ArgName(ReconContext context, int slot)
    {
        if (context.IsInstance)
        {
            if (slot == 0)
            {
                return "this";
            }

            return context.ParameterNames.TryGetValue(slot, out var name) && !string.IsNullOrEmpty(name) ? name : $"arg{slot - 1}";
        }

        return context.ParameterNames.TryGetValue(slot + 1, out var value) && !string.IsNullOrEmpty(value) ? value : $"arg{slot}";
    }

    private static string? ArgType(ReconContext context, int slot)
    {
        var parameterIndex = context.IsInstance ? slot - 1 : slot;
        return parameterIndex >= 0 && parameterIndex < context.ParameterTypes.Count
            ? context.ParameterTypes[parameterIndex]
            : null;
    }

    private static void PushArgument(ReconContext context, Stack<string> stack, int slot) =>
        PushExpression(context, stack, ArgName(context, slot), ArgType(context, slot));

    private static void PushLocal(ReconContext context, Stack<string> stack, int index) =>
        PushExpression(
            context,
            stack,
            LocalName(context, index),
            index >= 0 && index < context.LocalTypes.Count ? context.LocalTypes[index] : null);

    private static void PushExpression(ReconContext context, Stack<string> stack, string expression, string? type)
    {
        if (!string.IsNullOrEmpty(type))
        {
            context.ExpressionTypes[expression] = type;
        }

        stack.Push(expression);
    }

    private static bool ApplySimpleInstruction(
        ReconContext context,
        Instr instr,
        Stack<string> stack,
        List<string> statements,
        HashSet<int> declaredLocals,
        out bool terminal)
    {
        terminal = false;
        var metadata = context.Metadata;
        var il = context.Il;
        var offset = instr.OperandOffset;
        var name = instr.Name;
        switch (name)
        {
            case "nop":
                return true;

            case "dup":
                return false;

            case "ldarg.0":
                PushArgument(context, stack, 0);
                return true;
            case "ldarg.1":
                PushArgument(context, stack, 1);
                return true;
            case "ldarg.2":
                PushArgument(context, stack, 2);
                return true;
            case "ldarg.3":
                PushArgument(context, stack, 3);
                return true;
            case "ldarg.s":
                PushArgument(context, stack, il[offset]);
                return true;
            case "ldarg":
                PushArgument(context, stack, BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2)));
                return true;
            case "starg.s":
                var argumentSlot = il[offset];
                if (!TryPop(stack, out var stargValue)
                    || !TryRenderTargetExpression(context, stargValue, ArgType(context, argumentSlot), out stargValue))
                {
                    return false;
                }

                statements.Add($"{ArgName(context, argumentSlot)} = {stargValue};");
                return true;

            case "ldnull":
                PushExpression(context, stack, "null", "object");
                return true;
            case "ldstr":
                PushExpression(
                    context,
                    stack,
                    EscapeCSharpString(ReadUserString(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))),
                    "string");
                return true;
            case "ldc.i4.m1":
                PushExpression(context, stack, "-1", "int");
                return true;
            case "ldc.i4.0":
            case "ldc.i4.1":
            case "ldc.i4.2":
            case "ldc.i4.3":
            case "ldc.i4.4":
            case "ldc.i4.5":
            case "ldc.i4.6":
            case "ldc.i4.7":
            case "ldc.i4.8":
                PushExpression(context, stack, name["ldc.i4.".Length..], "int");
                return true;
            case "ldc.i4.s":
                PushExpression(context, stack, ((sbyte)il[offset]).ToString(), "int");
                return true;
            case "ldc.i4":
                PushExpression(context, stack, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)).ToString(), "int");
                return true;
            case "ldc.i8":
                PushExpression(context, stack, $"{BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8))}L", "long");
                return true;
            case "ldc.r4":
                PushExpression(context, stack, $"{BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}f", "float");
                return true;
            case "ldc.r8":
                PushExpression(context, stack, $"{BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8)))}", "double");
                return true;

            case "ldloc.0":
            case "ldloc.1":
            case "ldloc.2":
            case "ldloc.3":
                PushLocal(context, stack, int.Parse(name["ldloc.".Length..]));
                return true;
            case "ldloc.s":
                PushLocal(context, stack, il[offset]);
                return true;
            case "ldloc":
                PushLocal(context, stack, BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2)));
                return true;
            case "stloc.0":
            case "stloc.1":
            case "stloc.2":
            case "stloc.3":
                return TryStoreLocal(context, stack, statements, declaredLocals, int.Parse(name["stloc.".Length..]));
            case "stloc.s":
                return TryStoreLocal(context, stack, statements, declaredLocals, il[offset]);
            case "stloc":
                return TryStoreLocal(context, stack, statements, declaredLocals, BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2)));

            case "ldsfld":
                var loadStatic = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (loadStatic is null || IsGeneratedName(loadStatic.Value.DeclaringType) || IsGeneratedName(loadStatic.Value.Name))
                {
                    return false;
                }

                PushExpression(
                    context,
                    stack,
                    $"{loadStatic.Value.DeclaringType}.{loadStatic.Value.Name}",
                    loadStatic.Value.Type);
                return true;
            case "ldfld":
                var loadField = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (loadField is null || IsGeneratedName(loadField.Value.Name) || !TryPop(stack, out var fieldTarget))
                {
                    return false;
                }

                PushExpression(context, stack, $"{fieldTarget}.{loadField.Value.Name}", loadField.Value.Type);
                return true;
            case "stsfld":
                var storeStatic = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (storeStatic is null
                    || IsGeneratedName(storeStatic.Value.DeclaringType)
                    || IsGeneratedName(storeStatic.Value.Name)
                    || !TryPop(stack, out var storeStaticValue)
                    || !TryRenderTargetExpression(
                        context,
                        storeStaticValue,
                        storeStatic.Value.Type,
                        out storeStaticValue))
                {
                    return false;
                }

                statements.Add($"{storeStatic.Value.DeclaringType}.{storeStatic.Value.Name} = {storeStaticValue};");
                return true;
            case "stfld":
                var storeField = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (storeField is null
                    || IsGeneratedName(storeField.Value.Name)
                    || !TryPop(stack, out var storeFieldValue)
                    || !TryPop(stack, out var storeFieldTarget)
                    || !TryRenderTargetExpression(
                        context,
                        storeFieldValue,
                        storeField.Value.Type,
                        out storeFieldValue))
                {
                    return false;
                }

                statements.Add($"{storeFieldTarget}.{storeField.Value.Name} = {storeFieldValue};");
                return true;

            case "add":
            case "sub":
            case "mul":
            case "div":
            case "rem":
            case "and":
            case "or":
            case "xor":
            case "shl":
            case "shr":
            case "shr.un":
                return TryBinary(context, stack, BinaryOperator(name));
            case "div.un":
            case "rem.un":
                return TryUnsignedIntegralBinary(
                    context,
                    stack,
                    name == "div.un" ? "/" : "%");
            case "ceq":
                return TryBinary(context, stack, "==", "bool");
            case "cgt":
                return TryBinary(context, stack, ">", "bool");
            case "cgt.un":
                return TryUnsignedReferenceNullComparison(context, stack);
            case "clt":
                return TryBinary(context, stack, "<", "bool");
            case "clt.un":
                return false;
            case "neg":
                return TryUnary(context, stack, "-");
            case "not":
                return TryUnary(context, stack, "~");

            case "conv.i1":
            case "conv.i2":
            case "conv.i4":
            case "conv.i8":
            case "conv.u1":
            case "conv.u2":
            case "conv.u4":
            case "conv.u8":
            case "conv.r4":
            case "conv.r8":
                return TryUnaryCast(context, stack, ConversionType(name));

            case "castclass":
                var castType = GetTypeName(metadata, MetadataTokens.EntityHandle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4))));
                if (castType is null || IsGeneratedName(castType) || !TryPop(stack, out var castValue))
                {
                    return false;
                }

                PushExpression(context, stack, $"(({castType}){castValue})", castType);
                return true;
            case "isinst":
                var instType = GetTypeName(metadata, MetadataTokens.EntityHandle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4))));
                if (instType is null || IsGeneratedName(instType) || !TryPop(stack, out var instValue))
                {
                    return false;
                }

                PushExpression(context, stack, $"({instValue} as {instType})", instType);
                return true;

            case "call":
            case "callvirt":
                return TryEmitCall(context, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)), stack, statements);
            case "newobj":
                return TryEmitNewObject(context, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)), stack);

            case "pop":
                if (!TryPop(stack, out var discarded))
                {
                    return false;
                }

                statements.Add($"{discarded};");
                return true;
            case "throw":
                if (!TryPop(stack, out var thrown))
                {
                    return false;
                }

                statements.Add($"throw {thrown};");
                terminal = true;
                return true;
            case "rethrow":
                if (context.CatchDepth == 0 || stack.Count != 0)
                {
                    return false;
                }

                statements.Add("throw;");
                terminal = true;
                return true;
            case "ret":
                if (context.ReturnType == "void")
                {
                    if (stack.Count != 0)
                    {
                        return false;
                    }
                }
                else
                {
                    if (stack.Count != 1)
                    {
                        return false;
                    }

                    var value = stack.Pop();
                    if (context.ReturnType == "bool" && value is "0" or "1")
                    {
                        value = value == "1" ? "true" : "false";
                    }
                    else if (IsPotentialEnumType(context.ReturnType) && IsIntegerExpression(context, value))
                    {
                        value = $"unchecked(({context.ReturnType}){value})";
                    }
                    else if (!TryRenderTargetExpression(context, value, context.ReturnType, out value))
                    {
                        return false;
                    }

                    statements.Add($"return {value};");
                }

                terminal = true;
                return true;

            default:
                return false;
        }
    }

    private static bool TryPop(Stack<string> stack, out string value)
    {
        if (stack.Count == 0)
        {
            value = string.Empty;
            return false;
        }

        value = stack.Pop();
        return true;
    }

    private static bool TryBinary(
        ReconContext context,
        Stack<string> stack,
        string op,
        string? resultType = null)
    {
        if (stack.Count < 2)
        {
            return false;
        }

        var right = stack.Pop();
        var left = stack.Pop();
        context.ExpressionTypes.TryGetValue(left, out var leftType);
        context.ExpressionTypes.TryGetValue(right, out var rightType);
        if (op == "==" && TryNormalizeBooleanEquality(left, leftType, right, rightType, out var booleanEquality))
        {
            PushExpression(context, stack, booleanEquality, "bool");
            return true;
        }

        if (op is "&" or "|" or "^")
        {
            if (IsPotentialEnumType(leftType) && IsIntegerLiteral(right))
            {
                right = $"unchecked(({leftType}){right})";
                resultType ??= leftType;
            }
            else if (IsPotentialEnumType(rightType) && IsIntegerLiteral(left))
            {
                left = $"unchecked(({rightType}){left})";
                resultType ??= rightType;
            }
        }

        if (resultType is null)
        {
            resultType = leftType;
        }

        PushExpression(context, stack, $"({left} {op} {right})", resultType);
        return true;
    }

    private static bool TryUnsignedIntegralBinary(
        ReconContext context,
        Stack<string> stack,
        string op)
    {
        if (stack.Count < 2)
        {
            return false;
        }

        var right = stack.Pop();
        var left = stack.Pop();
        if (!context.ExpressionTypes.TryGetValue(left, out var leftType)
            || !context.ExpressionTypes.TryGetValue(right, out var rightType))
        {
            return false;
        }

        var stackFamily = IntegralStackFamily(leftType);
        if (stackFamily < 0 || stackFamily != IntegralStackFamily(rightType))
        {
            return false;
        }

        var unsignedType = stackFamily switch
        {
            0 => "uint",
            1 => "ulong",
            2 => "nuint",
            _ => null
        };
        if (unsignedType is null)
        {
            return false;
        }

        var expression =
            $"(unchecked(({unsignedType}){left}) {op} unchecked(({unsignedType}){right}))";
        PushExpression(context, stack, expression, unsignedType);
        context.UnsignedIntegralExpressions.Add(expression);
        return true;
    }

    private static bool TryNormalizeBooleanEquality(
        string left,
        string? leftType,
        string right,
        string? rightType,
        out string expression)
    {
        if (leftType == "bool" && TryReadIlBooleanLiteral(right, rightType, out var rightValue))
        {
            expression = rightValue ? left : $"!({left})";
            return true;
        }

        if (rightType == "bool" && TryReadIlBooleanLiteral(left, leftType, out var leftValue))
        {
            expression = leftValue ? right : $"!({right})";
            return true;
        }

        expression = string.Empty;
        return false;
    }

    private static bool TryReadIlBooleanLiteral(string expression, string? type, out bool value)
    {
        if (type == "int" && expression is "0" or "1")
        {
            value = expression == "1";
            return true;
        }

        value = false;
        return false;
    }

    private static bool TryUnsignedReferenceNullComparison(ReconContext context, Stack<string> stack)
    {
        if (!TryPop(stack, out var right) || !TryPop(stack, out var left) || right != "null" ||
            !context.ExpressionTypes.TryGetValue(left, out var leftType) ||
            !IsKnownReferenceType(context.Metadata, leftType))
        {
            return false;
        }

        PushExpression(context, stack, $"({left} is not null)", "bool");
        return true;
    }

    private static bool IsIntegerLiteral(string expression)
    {
        var value = expression.TrimEnd('L', 'l', 'U', 'u');
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);
    }

    private static bool IsIntegerExpression(ReconContext context, string expression) =>
        IsIntegerLiteral(expression) ||
        (context.ExpressionTypes.TryGetValue(expression, out var type) && type is
            "char" or
            "sbyte" or
            "byte" or
            "short" or
            "ushort" or
            "int" or
            "uint" or
            "long" or
            "ulong" or
            "nint" or
            "nuint");

    private static bool IsPotentialEnumType(string? type) => type is not null
        && type is not ("bool" or "char" or "sbyte" or "byte" or "short" or "ushort" or "int" or "uint"
            or "long" or "ulong" or "nint" or "nuint" or "float" or "double" or "decimal" or "string"
            or "object" or "TypedReference" or "method*")
        && !type.StartsWith('!')
        && !type.StartsWith("ref ", StringComparison.Ordinal)
        && !type.EndsWith('*')
        && !type.EndsWith(']');

    private static bool TryUnary(ReconContext context, Stack<string> stack, string op)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        context.ExpressionTypes.TryGetValue(value, out var type);
        PushExpression(context, stack, $"({op}{value})", type);
        return true;
    }

    private static bool TryUnaryCast(ReconContext context, Stack<string> stack, string type)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        PushExpression(context, stack, $"({type})({value})", type);
        return true;
    }

    private static bool TryStoreLocal(ReconContext context, Stack<string> stack, List<string> statements, HashSet<int> declaredLocals, int index)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        var localType = index >= 0 && index < context.LocalTypes.Count
            ? context.LocalTypes[index]
            : null;
        if (!TryRenderTargetExpression(context, value, localType, out value))
        {
            return false;
        }

        if (declaredLocals.Add(index))
        {
            statements.Add($"{LocalDeclarationType(context, index)} {LocalName(context, index)} = {value};");
        }
        else
        {
            statements.Add($"{LocalName(context, index)} = {value};");
        }

        return true;
    }

    private static string LocalName(ReconContext context, int index) =>
        context.LocalNames.TryGetValue(index, out var name) ? name : $"v{index}";

    private static string DeclareLocalWithDefault(ReconContext context, int index, string type) =>
        $"{type} {LocalName(context, index)} = {(IsKnownReferenceType(context.Metadata, type) ? "default!" : "default")};";

    // 有讀到區域變數型別就用實際型別宣告，否則退回 var。ref／編譯器產生的型別一律用 var 比較安全。
    private static string LocalDeclarationType(ReconContext context, int index)
    {
        if (index < 0 || index >= context.LocalTypes.Count)
        {
            return "var";
        }

        var type = context.LocalTypes[index];
        if (string.IsNullOrEmpty(type) || type.StartsWith("ref ", StringComparison.Ordinal) || IsGeneratedName(type))
        {
            return "var";
        }

        return type;
    }

    // 編譯器產生的名稱（狀態機、lambda、匿名型別）沒辦法在 C# 直接寫出來，碰到就放棄整個方法。
    private static bool IsGeneratedName(string name) =>
        name.StartsWith('<') || name.Contains(".<", StringComparison.Ordinal) || name.Contains("<>", StringComparison.Ordinal);

    private static bool TryEmitCall(ReconContext context, int token, Stack<string> stack, List<string> statements)
    {
        var metadata = context.Metadata;
        var info = ResolveCall(metadata, token);
        if (info is null || info.Name is ".ctor" or ".cctor" || IsGeneratedName(info.Name))
        {
            return false;
        }

        if (!info.HasThis && IsGeneratedName(info.DeclaringType))
        {
            return false;
        }

        var args = new string[info.ParamCount];
        for (var index = info.ParamCount - 1; index >= 0; index--)
        {
            if (!TryPop(stack, out var argument))
            {
                return false;
            }

            args[index] = RenderArgument(
                context,
                argument,
                index < info.ParameterTypes.Count ? info.ParameterTypes[index] : null);
            if (RequiresNullForgivingComparerArgument(context, info, argument))
            {
                args[index] += "!";
            }
        }

        string? receiver = null;
        if (info.HasThis && !TryPop(stack, out receiver))
        {
            return false;
        }

        if (info.Name.StartsWith("op_", StringComparison.Ordinal))
        {
            return TryEmitOperator(context, info, args, stack);
        }

        var target = info.HasThis
            ? RenderInstanceCallTarget(context, receiver!, info.DeclaringType)
            : info.DeclaringType;

        if (info.Name.StartsWith("get_", StringComparison.Ordinal))
        {
            if (info.ParamCount == 0)
            {
                PushExpression(context, stack, $"{target}.{info.Name["get_".Length..]}", info.ReturnType);
                return true;
            }

            if (!info.HasThis)
            {
                return false;
            }

            PushExpression(context, stack, $"{target}[{string.Join(", ", args)}]", info.ReturnType);
            return true;
        }

        if (info.Name.StartsWith("set_", StringComparison.Ordinal))
        {
            if (!info.ReturnsVoid || info.ParamCount == 0)
            {
                return false;
            }

            if (info.ParamCount == 1)
            {
                statements.Add($"{target}.{info.Name["set_".Length..]} = {args[0]};");
                return true;
            }

            if (!info.HasThis)
            {
                return false;
            }

            statements.Add($"{target}[{string.Join(", ", args[..^1])}] = {args[^1]};");
            return true;
        }

        var methodName = info.GenericArguments.Count == 0
            ? info.Name
            : $"{info.Name}<{string.Join(", ", info.GenericArguments)}>";
        var call = $"{target}.{methodName}({string.Join(", ", args)})";
        if (info.ReturnsVoid)
        {
            statements.Add($"{call};");
        }
        else
        {
            PushExpression(context, stack, call, info.ReturnType);
        }

        return true;
    }

    private static string RenderInstanceCallTarget(
        ReconContext context,
        string receiver,
        string declaringType)
    {
        if (string.IsNullOrEmpty(declaringType) ||
            IsGeneratedName(declaringType) ||
            !IsPotentialInterfaceType(context.Metadata, declaringType) ||
            !context.ExpressionTypes.TryGetValue(receiver, out var receiverType) ||
            receiverType == declaringType)
        {
            return receiver;
        }

        // IL callvirt 會保留宣告 slot；C# 若直接用 concrete receiver，可能改綁到同名 public member。
        // 明確轉成 metadata declaring interface，保留 explicit interface dispatch、overload 與回傳型別。
        return $"(({declaringType}){receiver})";
    }

    private static bool IsPotentialInterfaceType(MetadataReader metadata, string type)
    {
        var definitionName = RemoveTypeArguments(type);
        foreach (var handle in metadata.TypeDefinitions)
        {
            if (GetTypeDefinitionFullName(metadata, handle) == definitionName)
            {
                var definition = metadata.GetTypeDefinition(handle);
                return definition.Attributes.HasFlag(TypeAttributes.Interface) &&
                       (definition.GetGenericParameters().Count == 0 || type.Contains('<', StringComparison.Ordinal));
            }
        }

        // 外部 assembly 不在本次 metadata reader 中；以標準 .NET 介面命名慣例保守辨識。
        var separator = definitionName.LastIndexOf('.');
        var simpleName = definitionName[(separator + 1)..];
        return simpleName.Length > 1 && simpleName[0] == 'I' && char.IsUpper(simpleName[1]);
    }

    private static string RemoveTypeArguments(string type)
    {
        var builder = new StringBuilder(type.Length);
        var depth = 0;
        foreach (var character in type)
        {
            if (character == '<')
            {
                depth++;
            }
            else if (character == '>')
            {
                if (depth == 0)
                {
                    return type;
                }

                depth--;
            }
            else if (depth == 0)
            {
                builder.Append(character);
            }
        }

        return depth == 0 ? builder.ToString() : type;
    }

    private static bool RequiresNullForgivingComparerArgument(
        ReconContext context,
        CallInfo info,
        string argument) =>
        info.ParamCount == 1 &&
        info.Name == nameof(object.GetHashCode) &&
        info.DeclaringType.StartsWith("System.Collections.Generic.EqualityComparer<", StringComparison.Ordinal) &&
        context.ExpressionTypes.TryGetValue(argument, out var argumentType) &&
        (argumentType.EndsWith("?", StringComparison.Ordinal) ||
         argumentType.StartsWith("System.Nullable<", StringComparison.Ordinal));

    // 把運算子方法（op_Equality 等）還原成運算子語法，避免產生 Type.op_Equality(a, b) 這種非法 C#。
    // 對應不到的運算子就放棄整個方法，退回 IL 註解。
    private static bool TryEmitOperator(ReconContext context, CallInfo info, string[] args, Stack<string> stack)
    {
        if (info.ParamCount == 2 && BinaryOperators.TryGetValue(info.Name, out var binary))
        {
            PushExpression(context, stack, $"({args[0]} {binary} {args[1]})", info.ReturnType);
            return true;
        }

        if (info.ParamCount == 1 && UnaryOperators.TryGetValue(info.Name, out var unary))
        {
            PushExpression(context, stack, $"({unary}{args[0]})", info.ReturnType);
            return true;
        }

        return false;
    }

    private static readonly IReadOnlyDictionary<string, string> BinaryOperators = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["op_Equality"] = "==",
        ["op_Inequality"] = "!=",
        ["op_Addition"] = "+",
        ["op_Subtraction"] = "-",
        ["op_Multiply"] = "*",
        ["op_Division"] = "/",
        ["op_Modulus"] = "%",
        ["op_LessThan"] = "<",
        ["op_GreaterThan"] = ">",
        ["op_LessThanOrEqual"] = "<=",
        ["op_GreaterThanOrEqual"] = ">=",
        ["op_BitwiseAnd"] = "&",
        ["op_BitwiseOr"] = "|",
        ["op_ExclusiveOr"] = "^",
        ["op_LeftShift"] = "<<",
        ["op_RightShift"] = ">>"
    };

    private static readonly IReadOnlyDictionary<string, string> UnaryOperators = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["op_UnaryNegation"] = "-",
        ["op_UnaryPlus"] = "+",
        ["op_LogicalNot"] = "!",
        ["op_OnesComplement"] = "~"
    };

    private static bool TryEmitNewObject(ReconContext context, int token, Stack<string> stack)
    {
        var metadata = context.Metadata;
        var info = ResolveCall(metadata, token);
        if (info is null || IsGeneratedName(info.DeclaringType))
        {
            return false;
        }

        var args = new string[info.ParamCount];
        for (var index = info.ParamCount - 1; index >= 0; index--)
        {
            if (!TryPop(stack, out var argument))
            {
                return false;
            }

            args[index] = RenderArgument(
                context,
                argument,
                index < info.ParameterTypes.Count ? info.ParameterTypes[index] : null);
        }

        PushExpression(context, stack, $"new {info.DeclaringType}({string.Join(", ", args)})", info.DeclaringType);
        return true;
    }

    // bool、char 與 enum 在 IL 中都以整數常值傳遞；依正式參數型別還原成可編譯的 C# 引數。
    private static string RenderArgument(ReconContext context, string argument, string? parameterType)
    {
        var isIntegerLiteral = long.TryParse(
            argument,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value);
        if (isIntegerLiteral && parameterType == "bool" && value is 0 or 1)
        {
            return value == 1 ? "true" : "false";
        }

        if (isIntegerLiteral && parameterType == "char" && value is >= 0 and <= 0xFFFF)
        {
            return FormatCharLiteral((char)value);
        }

        // CLI 在同一 integral stack family 內不區分 signedness／窄型別，C# 呼叫則要求正式型別。
        if (parameterType is not null &&
            context.ExpressionTypes.TryGetValue(argument, out var argumentType) &&
            argumentType != parameterType &&
            IsSameIntegralStackFamily(argumentType, parameterType))
        {
            return $"unchecked(({parameterType}){argument})";
        }

        if (!isIntegerLiteral)
        {
            return argument;
        }

        return IsNumericOrReferenceParameter(parameterType)
            ? argument
            : $"unchecked(({parameterType}){argument})";
    }

    private static bool IsSameIntegralStackFamily(string left, string right)
    {
        var leftFamily = IntegralStackFamily(left);
        return leftFamily >= 0 && leftFamily == IntegralStackFamily(right);
    }

    private static bool TryRenderTargetExpression(
        ReconContext context,
        string expression,
        string? targetType,
        out string rendered)
    {
        rendered = expression;
        if (!context.ExpressionTypes.TryGetValue(expression, out var sourceType)
            || sourceType == targetType
            || !context.UnsignedIntegralExpressions.Contains(expression))
        {
            return true;
        }

        // div.un／rem.un 會把結果標成該 stack family 的無號型別。若接收端是同 family
        // 的 signed／窄型別，必須明確轉回；缺少或跨 family 的目標則不能猜測。
        if (sourceType is not ("uint" or "ulong" or "nuint"))
        {
            return true;
        }

        if (targetType is null || !IsSameIntegralStackFamily(sourceType, targetType))
        {
            return false;
        }

        rendered = $"unchecked(({targetType}){expression})";
        return true;
    }

    private static int IntegralStackFamily(string type) => type switch
    {
        "char" or "sbyte" or "byte" or "short" or "ushort" or "int" or "uint" => 0,
        "long" or "ulong" => 1,
        "nint" or "nuint" => 2,
        _ => -1
    };

    private static bool IsNumericOrReferenceParameter(string? parameterType) => parameterType is null
        or "sbyte"
        or "byte"
        or "short"
        or "ushort"
        or "int"
        or "uint"
        or "long"
        or "ulong"
        or "nint"
        or "nuint"
        or "float"
        or "double"
        or "decimal"
        or "string"
        or "object"
        or "TypedReference"
        || parameterType.StartsWith('!')
        || parameterType.StartsWith("ref ", StringComparison.Ordinal)
        || parameterType.EndsWith('*');

    private static string FormatCharLiteral(char value) => value switch
    {
        '\'' => "'\\''",
        '\\' => "'\\\\'",
        '\n' => "'\\n'",
        '\r' => "'\\r'",
        '\t' => "'\\t'",
        _ when !char.IsControl(value) => $"'{value}'",
        _ => $"'\\u{(int)value:X4}'"
    };

    private static CallInfo? ResolveCall(MetadataReader metadata, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
                var method = metadata.GetMethodDefinition((MethodDefinitionHandle)handle);
                var methodSignature = method.DecodeSignature(SignatureTypeNameProvider.Instance, null);
                return new CallInfo(
                    GetTypeName(metadata, method.GetDeclaringType()) ?? string.Empty,
                    metadata.GetString(method.Name),
                    methodSignature.ParameterTypes.Length,
                    methodSignature.Header.IsInstance,
                    methodSignature.ReturnType,
                    methodSignature.ReturnType == "void",
                    methodSignature.ParameterTypes,
                    []);

            case HandleKind.MemberReference:
                var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                if (member.GetKind() != MemberReferenceKind.Method)
                {
                    return null;
                }

                var memberSignature = member.DecodeMethodSignature(SignatureTypeNameProvider.Instance, null);
                return new CallInfo(
                    GetTypeName(metadata, member.Parent) ?? string.Empty,
                    metadata.GetString(member.Name),
                    memberSignature.ParameterTypes.Length,
                    memberSignature.Header.IsInstance,
                    memberSignature.ReturnType,
                    memberSignature.ReturnType == "void",
                    memberSignature.ParameterTypes,
                    []);

            case HandleKind.MethodSpecification:
                var spec = metadata.GetMethodSpecification((MethodSpecificationHandle)handle);
                var resolved = ResolveCall(metadata, MetadataTokens.GetToken(spec.Method));
                if (resolved is null)
                {
                    return null;
                }

                var genericArguments = spec.DecodeSignature(SignatureTypeNameProvider.Instance, null);
                return resolved with
                {
                    ReturnType = InstantiateMethodSignatureType(resolved.ReturnType, genericArguments),
                    ParameterTypes = resolved.ParameterTypes
                        .Select(type => InstantiateMethodSignatureType(type, genericArguments))
                        .ToArray(),
                    GenericArguments = genericArguments
                };

            default:
                return null;
        }
    }

    private static (string DeclaringType, string Name, string Type)? ResolveField(MetadataReader metadata, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.FieldDefinition:
                var field = metadata.GetFieldDefinition((FieldDefinitionHandle)handle);
                return (
                    GetTypeName(metadata, field.GetDeclaringType()) ?? string.Empty,
                    NormalizeFieldName(metadata.GetString(field.Name)),
                    field.DecodeSignature(SignatureTypeNameProvider.Instance, null));

            case HandleKind.MemberReference:
                var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                if (member.GetKind() != MemberReferenceKind.Field)
                {
                    return null;
                }

                return (
                    GetTypeName(metadata, member.Parent) ?? string.Empty,
                    NormalizeFieldName(metadata.GetString(member.Name)),
                    member.DecodeFieldSignature(SignatureTypeNameProvider.Instance, null));

            default:
                return null;
        }
    }

    // auto-property 的隱藏欄位 <Name>k__BackingField，直接還原成屬性名稱 Name。
    private static string NormalizeFieldName(string name)
    {
        if (name.StartsWith('<') && name.EndsWith(">k__BackingField", StringComparison.Ordinal))
        {
            return name[1..name.IndexOf('>', StringComparison.Ordinal)];
        }

        return name;
    }

    private static string ReadUserString(MetadataReader metadata, int token)
    {
        try
        {
            return metadata.GetUserString(MetadataTokens.UserStringHandle(token));
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
        {
            return string.Empty;
        }
    }

    private static string EscapeCSharpString(string value)
    {
        var escaped = value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal)
            .Replace("\t", "\\t", StringComparison.Ordinal);
        return $"\"{escaped}\"";
    }

    private static string BinaryOperator(string name) => name switch
    {
        "add" => "+",
        "sub" => "-",
        "mul" => "*",
        "div" => "/",
        "rem" => "%",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        "shl" => "<<",
        "shr" => ">>",
        "shr.un" => ">>>",
        _ => "?"
    };

    private static string ConversionType(string name) => name switch
    {
        "conv.i1" => "sbyte",
        "conv.i2" => "short",
        "conv.i4" => "int",
        "conv.i8" => "long",
        "conv.u1" => "byte",
        "conv.u2" => "ushort",
        "conv.u4" => "uint",
        "conv.u8" => "ulong",
        "conv.r4" => "float",
        "conv.r8" => "double",
        _ => "object"
    };

    private static string? CallKind(short opValue)
    {
        if (opValue == OpCodes.Call.Value)
        {
            return "call";
        }

        if (opValue == OpCodes.Callvirt.Value)
        {
            return "callvirt";
        }

        if (opValue == OpCodes.Newobj.Value)
        {
            return "newobj";
        }

        return null;
    }

    private static string? ResolveMemberName(MetadataReader metadata, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
                var method = metadata.GetMethodDefinition((MethodDefinitionHandle)handle);
                var typeName = GetTypeDefinitionFullName(metadata, method.GetDeclaringType());
                return $"{typeName}.{metadata.GetString(method.Name)}";

            case HandleKind.MemberReference:
                var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                if (member.GetKind() != MemberReferenceKind.Method)
                {
                    return null;
                }

                var parent = GetTypeName(metadata, member.Parent);
                var memberName = metadata.GetString(member.Name);
                return parent is null ? memberName : $"{parent}.{memberName}";

            case HandleKind.MethodSpecification:
                var spec = metadata.GetMethodSpecification((MethodSpecificationHandle)handle);
                var resolved = ResolveMemberName(metadata, MetadataTokens.GetToken(spec.Method));
                if (resolved is null)
                {
                    return null;
                }

                var genericArguments = spec.DecodeSignature(SignatureTypeNameProvider.Instance, null);
                return genericArguments.Length == 0
                    ? resolved
                    : $"{resolved}<{string.Join(", ", genericArguments)}>";

            default:
                return null;
        }
    }

    internal static string InstantiateMethodSignatureType(
        string signatureType,
        IReadOnlyList<string> genericArguments)
    {
        if (genericArguments.Count == 0 || !signatureType.Contains("!!", StringComparison.Ordinal))
        {
            return signatureType;
        }

        var builder = new System.Text.StringBuilder(signatureType.Length);
        for (var position = 0; position < signatureType.Length;)
        {
            if (signatureType[position] != '!' ||
                position + 2 >= signatureType.Length ||
                signatureType[position + 1] != '!' ||
                !char.IsAsciiDigit(signatureType[position + 2]))
            {
                builder.Append(signatureType[position++]);
                continue;
            }

            var digitEnd = position + 2;
            var argumentIndex = 0;
            var overflow = false;
            while (digitEnd < signatureType.Length && char.IsAsciiDigit(signatureType[digitEnd]))
            {
                var digit = signatureType[digitEnd] - '0';
                if (argumentIndex > (int.MaxValue - digit) / 10)
                {
                    overflow = true;
                }
                else if (!overflow)
                {
                    argumentIndex = (argumentIndex * 10) + digit;
                }

                digitEnd++;
            }

            var hasTokenBoundary = digitEnd == signatureType.Length ||
                !(char.IsLetterOrDigit(signatureType[digitEnd]) || signatureType[digitEnd] == '_');
            if (!overflow && hasTokenBoundary && argumentIndex < genericArguments.Count)
            {
                builder.Append(genericArguments[argumentIndex]);
                position = digitEnd;
                continue;
            }

            builder.Append(signatureType, position, digitEnd - position);
            position = digitEnd;
        }

        return builder.ToString();
    }

    private static string? GetTypeName(MetadataReader metadata, EntityHandle handle)
    {
        if (handle.IsNil)
        {
            return null;
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition:
                return GetTypeDefinitionFullName(metadata, (TypeDefinitionHandle)handle);

            case HandleKind.TypeReference:
                return GetTypeReferenceFullName(metadata, (TypeReferenceHandle)handle);

            case HandleKind.TypeSpecification:
                try
                {
                    var specification = metadata.GetTypeSpecification((TypeSpecificationHandle)handle);
                    return specification.DecodeSignature(SignatureTypeNameProvider.Instance, null);
                }
                catch (BadImageFormatException)
                {
                    return null;
                }

            default:
                return null;
        }
    }

    private static bool HasCustomAttribute(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes,
        string fullName)
    {
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                var attributeType = GetCustomAttributeTypeName(metadata, attribute);
                if (attributeType == fullName)
                {
                    return true;
                }
            }
            catch (BadImageFormatException)
            {
                // 畸形 attribute 不應中止其餘 metadata 分析。
            }
        }

        return false;
    }

    private static string? GetCustomAttributeTypeName(MetadataReader metadata, CustomAttribute attribute) =>
        attribute.Constructor.Kind switch
        {
            HandleKind.MethodDefinition => GetTypeName(
                metadata,
                metadata.GetMethodDefinition((MethodDefinitionHandle)attribute.Constructor).GetDeclaringType()),
            HandleKind.MemberReference => GetTypeName(
                metadata,
                metadata.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent),
            _ => null
        };

    private static string StripArity(string name)
    {
        var backtick = name.IndexOf('`', StringComparison.Ordinal);
        return backtick < 0 ? name : name[..backtick];
    }

    private static string BuildTypeFullName(string namespaceName, string name) =>
        string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";

    private static string GetTypeDefinitionFullName(MetadataReader metadata, TypeDefinitionHandle handle)
    {
        var definition = metadata.GetTypeDefinition(handle);
        var name = StripArity(metadata.GetString(definition.Name));
        var declaringType = definition.GetDeclaringType();
        return declaringType.IsNil
            ? BuildTypeFullName(metadata.GetString(definition.Namespace), name)
            : $"{GetTypeDefinitionFullName(metadata, declaringType)}.{name}";
    }

    private static string GetTypeDefinitionNamespace(MetadataReader metadata, TypeDefinitionHandle handle)
    {
        var definition = metadata.GetTypeDefinition(handle);
        var declaringType = definition.GetDeclaringType();
        return declaringType.IsNil
            ? metadata.GetString(definition.Namespace)
            : GetTypeDefinitionNamespace(metadata, declaringType);
    }

    private static string GetTypeReferenceFullName(MetadataReader metadata, TypeReferenceHandle handle)
    {
        var reference = metadata.GetTypeReference(handle);
        var name = StripArity(metadata.GetString(reference.Name));
        return reference.ResolutionScope.Kind == HandleKind.TypeReference
            ? $"{GetTypeReferenceFullName(metadata, (TypeReferenceHandle)reference.ResolutionScope)}.{name}"
            : BuildTypeFullName(metadata.GetString(reference.Namespace), name);
    }

    private static MethodModel BuildMethod(
        MetadataReader metadata,
        MethodDefinitionHandle methodHandle,
        MethodDefinition method,
        string methodName,
        bool hasBody,
        MethodDefinitionHandle entryPointHandle)
    {
        var returnType = "void";
        var parameters = new List<ParameterModel>();
        var signatureText = $"{methodName}(...)";

        try
        {
            var signature = method.DecodeSignature(SignatureTypeNameProvider.Instance, null);
            var parameterHandles = ReadParameterHandles(metadata, method);
            var nullableContext = ReadNullableContextFlag(metadata, method);
            returnType = ApplyTopLevelNullableAnnotation(
                metadata,
                signature.ReturnType,
                parameterHandles.TryGetValue(0, out var returnHandle) ? returnHandle : default,
                nullableContext);
            var parameterNames = ReadParameterNames(metadata, method);
            for (var index = 0; index < signature.ParameterTypes.Length; index++)
            {
                var name = parameterNames.TryGetValue(index + 1, out var value) && !string.IsNullOrEmpty(value)
                    ? value
                    : $"arg{index}";
                var parameterType = ApplyTopLevelNullableAnnotation(
                    metadata,
                    signature.ParameterTypes[index],
                    parameterHandles.TryGetValue(index + 1, out var parameterHandle) ? parameterHandle : default,
                    nullableContext);
                parameters.Add(new ParameterModel { Name = name, Type = parameterType });
            }

            // 舊式或 compiler-generated metadata 可能把 override Equals 的參數標成 oblivious；
            // 產生 nullable-enabled C# 時仍須符合 System.Object.Equals(object?) 的 contract。
            if (methodName == nameof(object.Equals) &&
                returnType == "bool" &&
                parameters.Count == 1 &&
                parameters[0].Type == "object" &&
                method.Attributes.HasFlag(MethodAttributes.Virtual) &&
                !method.Attributes.HasFlag(MethodAttributes.NewSlot))
            {
                parameters[0] = parameters[0] with { Type = "object?" };
            }

            signatureText = $"{returnType} {methodName}({string.Join(", ", parameters.Select(p => $"{p.Type} {p.Name}"))})";
        }
        catch (BadImageFormatException)
        {
        }

        return new MethodModel
        {
            Name = methodName,
            Signature = signatureText,
            ReturnType = returnType,
            Accessibility = GetMethodAccessibility(method.Attributes),
            IsStatic = method.Attributes.HasFlag(MethodAttributes.Static),
            IsAbstract = method.Attributes.HasFlag(MethodAttributes.Abstract),
            IsVirtual = method.Attributes.HasFlag(MethodAttributes.Virtual),
            IsFinal = method.Attributes.HasFlag(MethodAttributes.Final),
            IsNewSlot = method.Attributes.HasFlag(MethodAttributes.NewSlot),
            IsConstructor = methodName is ".ctor" or ".cctor",
            IsEntryPoint = methodHandle == entryPointHandle,
            HasBody = hasBody,
            GenericParameters = ReadMethodGenericParameters(metadata, method),
            Parameters = parameters
        };
    }

    private static Dictionary<int, ParameterHandle> ReadParameterHandles(
        MetadataReader metadata,
        MethodDefinition method)
    {
        var handles = new Dictionary<int, ParameterHandle>();
        foreach (var handle in method.GetParameters())
        {
            handles[metadata.GetParameter(handle).SequenceNumber] = handle;
        }

        return handles;
    }

    private static string ApplyTopLevelNullableAnnotation(
        MetadataReader metadata,
        string type,
        ParameterHandle parameterHandle,
        byte? nullableContext)
    {
        if (type.EndsWith("?", StringComparison.Ordinal))
        {
            return type;
        }

        var directFlag = parameterHandle.IsNil
            ? null
            : ReadTopLevelNullableFlag(metadata, metadata.GetParameter(parameterHandle).GetCustomAttributes());
        var nullableFlag = directFlag ?? nullableContext;
        return nullableFlag == 2 && (directFlag.HasValue || IsKnownReferenceType(metadata, type) || type.StartsWith('!'))
            ? $"{type}?"
            : type;
    }

    private static byte? ReadNullableContextFlag(MetadataReader metadata, MethodDefinition method)
    {
        var methodContext = ReadSingleByteCustomAttribute(
            metadata,
            method.GetCustomAttributes(),
            "System.Runtime.CompilerServices.NullableContextAttribute");
        if (methodContext.HasValue)
        {
            return methodContext;
        }

        var declaringType = method.GetDeclaringType();
        while (!declaringType.IsNil)
        {
            var definition = metadata.GetTypeDefinition(declaringType);
            var typeContext = ReadSingleByteCustomAttribute(
                metadata,
                definition.GetCustomAttributes(),
                "System.Runtime.CompilerServices.NullableContextAttribute");
            if (typeContext.HasValue)
            {
                return typeContext;
            }

            declaringType = definition.GetDeclaringType();
        }

        return null;
    }

    private static byte? ReadSingleByteCustomAttribute(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes,
        string fullName)
    {
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                if (GetCustomAttributeTypeName(metadata, attribute) != fullName)
                {
                    continue;
                }

                var reader = metadata.GetBlobReader(attribute.Value);
                return reader.ReadUInt16() == 1 && reader.RemainingBytes == 3
                    ? reader.ReadByte()
                    : null;
            }
            catch (BadImageFormatException)
            {
                return null;
            }
        }

        return null;
    }

    private static byte? ReadTopLevelNullableFlag(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes)
    {
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                if (GetCustomAttributeTypeName(metadata, attribute) !=
                    "System.Runtime.CompilerServices.NullableAttribute")
                {
                    continue;
                }

                var reader = metadata.GetBlobReader(attribute.Value);
                if (reader.ReadUInt16() != 1)
                {
                    return null;
                }

                // NullableAttribute 有 byte 與 byte[] 兩種 constructor；第一個 flag 代表最外層型別。
                if (reader.RemainingBytes == 3)
                {
                    return reader.ReadByte();
                }

                var flagCount = reader.ReadInt32();
                return flagCount > 0 && reader.RemainingBytes >= flagCount + 2
                    ? reader.ReadByte()
                    : null;
            }
            catch (BadImageFormatException)
            {
                return null;
            }
        }

        return null;
    }

    private static Dictionary<int, string> ReadParameterNames(MetadataReader metadata, MethodDefinition method)
    {
        var names = new Dictionary<int, string>();
        foreach (var handle in method.GetParameters())
        {
            var parameter = metadata.GetParameter(handle);
            if (parameter.SequenceNumber > 0)
            {
                names[parameter.SequenceNumber] = metadata.GetString(parameter.Name);
            }
        }

        return names;
    }

    private static IReadOnlyList<string> ReadMethodGenericParameters(MetadataReader metadata, MethodDefinition method)
    {
        var handles = method.GetGenericParameters();
        if (handles.Count == 0)
        {
            return [];
        }

        return handles
            .Select(handle => metadata.GetString(metadata.GetGenericParameter(handle).Name))
            .ToArray();
    }

    private static IReadOnlyList<string> ReadTypeGenericParameters(MetadataReader metadata, TypeDefinition definition)
    {
        var handles = definition.GetGenericParameters();
        if (handles.Count == 0)
        {
            return [];
        }

        return handles
            .Select(handle => metadata.GetString(metadata.GetGenericParameter(handle).Name))
            .ToArray();
    }

    private static IReadOnlyList<string> ReadInterfaces(MetadataReader metadata, TypeDefinition definition)
    {
        var interfaces = new List<string>();
        foreach (var handle in definition.GetInterfaceImplementations())
        {
            var implementation = metadata.GetInterfaceImplementation(handle);
            var name = GetTypeName(metadata, implementation.Interface);
            if (!string.IsNullOrEmpty(name))
            {
                interfaces.Add(name);
            }
        }

        return interfaces;
    }

    private static IReadOnlyList<FieldModel> ReadFields(MetadataReader metadata, TypeDefinition definition)
    {
        var fields = new List<FieldModel>();
        foreach (var handle in definition.GetFields())
        {
            var field = metadata.GetFieldDefinition(handle);
            string fieldType;
            try
            {
                fieldType = field.DecodeSignature(SignatureTypeNameProvider.Instance, null);
            }
            catch (BadImageFormatException)
            {
                fieldType = "object";
            }

            fields.Add(new FieldModel
            {
                Name = metadata.GetString(field.Name),
                Type = fieldType,
                Accessibility = GetFieldAccessibility(field.Attributes),
                IsStatic = field.Attributes.HasFlag(FieldAttributes.Static),
                IsConstant = field.Attributes.HasFlag(FieldAttributes.Literal),
                IsReadOnly = field.Attributes.HasFlag(FieldAttributes.InitOnly),
                ConstantValue = ReadConstantValue(metadata, field)
            });
        }

        return fields;
    }

    private static ConstantValueModel? ReadConstantValue(MetadataReader metadata, FieldDefinition field)
    {
        var handle = field.GetDefaultValue();
        if (handle.IsNil)
        {
            return null;
        }

        try
        {
            var constant = metadata.GetConstant(handle);
            var reader = metadata.GetBlobReader(constant.Value);
            string type;
            string? value;
            switch (constant.TypeCode)
            {
                case ConstantTypeCode.Boolean:
                    type = "bool";
                    value = reader.ReadBoolean() ? "true" : "false";
                    break;
                case ConstantTypeCode.Char:
                    type = "char";
                    value = reader.ReadChar().ToString();
                    break;
                case ConstantTypeCode.SByte:
                    type = "sbyte";
                    value = reader.ReadSByte().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Byte:
                    type = "byte";
                    value = reader.ReadByte().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Int16:
                    type = "short";
                    value = reader.ReadInt16().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.UInt16:
                    type = "ushort";
                    value = reader.ReadUInt16().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Int32:
                    type = "int";
                    value = reader.ReadInt32().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.UInt32:
                    type = "uint";
                    value = reader.ReadUInt32().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Int64:
                    type = "long";
                    value = reader.ReadInt64().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.UInt64:
                    type = "ulong";
                    value = reader.ReadUInt64().ToString(CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Single:
                    type = "float";
                    value = reader.ReadSingle().ToString("R", CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.Double:
                    type = "double";
                    value = reader.ReadDouble().ToString("R", CultureInfo.InvariantCulture);
                    break;
                case ConstantTypeCode.String:
                    type = "string";
                    value = reader.ReadUTF16(reader.RemainingBytes);
                    break;
                case ConstantTypeCode.NullReference:
                    type = "object";
                    value = null;
                    break;
                default:
                    return null;
            }

            return new ConstantValueModel { Type = type, Value = value };
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static IReadOnlyList<PropertyModel> ReadProperties(MetadataReader metadata, TypeDefinition definition)
    {
        var properties = new List<PropertyModel>();
        foreach (var handle in definition.GetProperties())
        {
            var property = metadata.GetPropertyDefinition(handle);
            var accessors = property.GetAccessors();
            string propertyType;
            IReadOnlyList<ParameterModel> parameters;
            try
            {
                var signature = property.DecodeSignature(SignatureTypeNameProvider.Instance, null);
                propertyType = signature.ReturnType;
                parameters = ReadPropertyParameters(
                    metadata,
                    accessors.Getter,
                    accessors.Setter,
                    signature.ParameterTypes);
            }
            catch (BadImageFormatException)
            {
                propertyType = "object";
                parameters = [];
            }

            var getter = ReadAccessor(metadata, accessors.Getter);
            var setter = ReadAccessor(metadata, accessors.Setter);
            var accessorShapes = new[] { getter, setter }.OfType<AccessorShape>().ToArray();
            properties.Add(new PropertyModel
            {
                Name = metadata.GetString(property.Name),
                Type = propertyType,
                Accessibility = MostVisibleAccessibility(accessorShapes),
                Parameters = parameters,
                GetterAccessibility = getter?.Accessibility,
                SetterAccessibility = setter?.Accessibility,
                HasGetter = !accessors.Getter.IsNil,
                HasSetter = !accessors.Setter.IsNil,
                IsStatic = accessorShapes.Any(accessor => accessor.IsStatic),
                IsAbstract = accessorShapes.Any(accessor => accessor.IsAbstract),
                IsVirtual = accessorShapes.Any(accessor => accessor.IsVirtual),
                IsFinal = AreAllVirtualAccessors(accessorShapes, accessor => accessor.IsFinal),
                IsNewSlot = AreAllVirtualAccessors(accessorShapes, accessor => accessor.IsNewSlot)
            });
        }

        return properties;
    }

    private static IReadOnlyList<ParameterModel> ReadPropertyParameters(
        MetadataReader metadata,
        MethodDefinitionHandle getterHandle,
        MethodDefinitionHandle setterHandle,
        IReadOnlyList<string> parameterTypes)
    {
        if (parameterTypes.Count == 0)
        {
            return [];
        }

        var accessorHandle = !getterHandle.IsNil ? getterHandle : setterHandle;
        Dictionary<int, string> parameterNames = [];
        Dictionary<int, ParameterHandle> parameterHandles = [];
        byte? nullableContext = null;
        if (!accessorHandle.IsNil)
        {
            var accessor = metadata.GetMethodDefinition(accessorHandle);
            parameterNames = ReadParameterNames(metadata, accessor);
            parameterHandles = ReadParameterHandles(metadata, accessor);
            nullableContext = ReadNullableContextFlag(metadata, accessor);
        }

        var parameters = new List<ParameterModel>(parameterTypes.Count);
        for (var index = 0; index < parameterTypes.Count; index++)
        {
            var name = parameterNames.TryGetValue(index + 1, out var value) && !string.IsNullOrEmpty(value)
                ? value
                : $"arg{index}";
            var type = ApplyTopLevelNullableAnnotation(
                metadata,
                parameterTypes[index],
                parameterHandles.TryGetValue(index + 1, out var parameterHandle) ? parameterHandle : default,
                nullableContext);
            parameters.Add(new ParameterModel { Name = name, Type = type });
        }

        return parameters;
    }

    private static IReadOnlyList<EventModel> ReadEvents(MetadataReader metadata, TypeDefinition definition)
    {
        var events = new List<EventModel>();
        foreach (var handle in definition.GetEvents())
        {
            var eventDefinition = metadata.GetEventDefinition(handle);
            var accessors = eventDefinition.GetAccessors();
            var accessorShapes = new[]
            {
                ReadAccessor(metadata, accessors.Adder),
                ReadAccessor(metadata, accessors.Remover),
                ReadAccessor(metadata, accessors.Raiser)
            }.OfType<AccessorShape>().ToArray();

            events.Add(new EventModel
            {
                Name = metadata.GetString(eventDefinition.Name),
                Type = GetTypeName(metadata, eventDefinition.Type) ?? "object",
                Accessibility = MostVisibleAccessibility(accessorShapes),
                IsStatic = accessorShapes.Any(accessor => accessor.IsStatic),
                IsAbstract = accessorShapes.Any(accessor => accessor.IsAbstract),
                IsVirtual = accessorShapes.Any(accessor => accessor.IsVirtual),
                IsFinal = AreAllVirtualAccessors(accessorShapes, accessor => accessor.IsFinal),
                IsNewSlot = AreAllVirtualAccessors(accessorShapes, accessor => accessor.IsNewSlot)
            });
        }

        return events;
    }

    private readonly record struct AccessorShape(
        string Accessibility,
        bool IsStatic,
        bool IsAbstract,
        bool IsVirtual,
        bool IsFinal,
        bool IsNewSlot);

    private static AccessorShape? ReadAccessor(MetadataReader metadata, MethodDefinitionHandle handle)
    {
        if (handle.IsNil)
        {
            return null;
        }

        var method = metadata.GetMethodDefinition(handle);
        return new AccessorShape(
            GetMethodAccessibility(method.Attributes),
            method.Attributes.HasFlag(MethodAttributes.Static),
            method.Attributes.HasFlag(MethodAttributes.Abstract),
            method.Attributes.HasFlag(MethodAttributes.Virtual),
            method.Attributes.HasFlag(MethodAttributes.Final),
            method.Attributes.HasFlag(MethodAttributes.NewSlot));
    }

    private static bool AreAllVirtualAccessors(
        IReadOnlyList<AccessorShape> accessors,
        Func<AccessorShape, bool> predicate)
    {
        var virtualAccessors = accessors.Where(accessor => accessor.IsVirtual).ToArray();
        return virtualAccessors.Length > 0 && virtualAccessors.All(predicate);
    }

    private static string MostVisibleAccessibility(IReadOnlyList<AccessorShape> accessors) =>
        accessors.Count == 0
            ? "private"
            : accessors.MaxBy(accessor => AccessibilityRank(accessor.Accessibility)).Accessibility;

    private static int AccessibilityRank(string accessibility) => accessibility switch
    {
        "public" => 5,
        "protected internal" => 4,
        "protected" => 3,
        "internal" => 2,
        "private protected" => 1,
        _ => 0
    };

    private static string GetFieldAccessibility(FieldAttributes attributes) =>
        (attributes & FieldAttributes.FieldAccessMask) switch
        {
            FieldAttributes.Public => "public",
            FieldAttributes.Family => "protected",
            FieldAttributes.FamORAssem => "protected internal",
            FieldAttributes.FamANDAssem => "private protected",
            FieldAttributes.Assembly => "internal",
            FieldAttributes.Private => "private",
            _ => "private"
        };

    private static string GetTypeKind(TypeAttributes attributes, string? baseTypeName)
    {
        if (attributes.HasFlag(TypeAttributes.Interface))
        {
            return "interface";
        }

        return baseTypeName switch
        {
            "System.Enum" => "enum",
            "System.ValueType" => "struct",
            "System.MulticastDelegate" or "System.Delegate" => "delegate",
            _ => "class"
        };
    }

    private static string GetTypeAccessibility(TypeAttributes attributes) =>
        (attributes & TypeAttributes.VisibilityMask) switch
        {
            TypeAttributes.Public or TypeAttributes.NestedPublic => "public",
            TypeAttributes.NestedFamily => "protected",
            TypeAttributes.NestedFamORAssem => "protected internal",
            TypeAttributes.NestedFamANDAssem => "private protected",
            TypeAttributes.NestedPrivate => "private",
            _ => "internal"
        };

    private static string GetMethodAccessibility(MethodAttributes attributes) =>
        (attributes & MethodAttributes.MemberAccessMask) switch
        {
            MethodAttributes.Public => "public",
            MethodAttributes.Family => "protected",
            MethodAttributes.FamORAssem => "protected internal",
            MethodAttributes.FamANDAssem => "private protected",
            MethodAttributes.Assembly => "internal",
            MethodAttributes.Private => "private",
            _ => "private"
        };

    private const int OperandSwitch = -1;

    private static readonly IReadOnlyDictionary<short, OpCode> OpCodesByValue = BuildOpCodeTable();

    private static readonly IReadOnlyDictionary<short, int> OperandSizes =
        OpCodesByValue.ToDictionary(pair => pair.Key, pair => OperandLength(pair.Value.OperandType));

    private static IReadOnlyDictionary<short, OpCode> BuildOpCodeTable()
    {
        var map = new Dictionary<short, OpCode>();
        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode opCode)
            {
                map[opCode.Value] = opCode;
            }
        }

        return map;
    }

    private static int OperandLength(OperandType operandType) => operandType switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        OperandType.InlineSwitch => OperandSwitch,
        _ => 4
    };
}

internal sealed class SignatureTypeNameProvider : ISignatureTypeProvider<string, object?>
{
    public static readonly SignatureTypeNameProvider Instance = new();

    public string GetArrayType(string elementType, ArrayShape shape) =>
        $"{elementType}[{new string(',', Math.Max(shape.Rank - 1, 0))}]";

    public string GetByReferenceType(string elementType) => $"ref {elementType}";

    public string GetFunctionPointerType(MethodSignature<string> signature) => "method*";

    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments)
    {
        var segments = genericType.Split('.');
        var rendered = new string[segments.Length];
        var argumentIndex = 0;
        var foundArity = false;
        for (var index = 0; index < segments.Length; index++)
        {
            var segment = segments[index];
            var backtick = segment.LastIndexOf('`');
            if (backtick < 0)
            {
                rendered[index] = segment;
                continue;
            }

            foundArity = true;
            if (!int.TryParse(
                    segment.AsSpan(backtick + 1),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var arity)
                || arity <= 0
                || arity > typeArguments.Length - argumentIndex)
            {
                return FormatLegacyGenericInstantiation(genericType, typeArguments);
            }

            rendered[index] =
                $"{segment[..backtick]}<{string.Join(", ", typeArguments.Skip(argumentIndex).Take(arity))}>";
            argumentIndex += arity;
        }

        return foundArity && argumentIndex == typeArguments.Length
            ? string.Join('.', rendered)
            : FormatLegacyGenericInstantiation(genericType, typeArguments);
    }

    public string GetGenericMethodParameter(object? genericContext, int index) => $"!!{index}";

    public string GetGenericTypeParameter(object? genericContext, int index) => $"!{index}";

    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType;

    public string GetPinnedType(string elementType) => elementType;

    public string GetPointerType(string elementType) => $"{elementType}*";

    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode switch
    {
        PrimitiveTypeCode.Boolean => "bool",
        PrimitiveTypeCode.Byte => "byte",
        PrimitiveTypeCode.SByte => "sbyte",
        PrimitiveTypeCode.Char => "char",
        PrimitiveTypeCode.Int16 => "short",
        PrimitiveTypeCode.UInt16 => "ushort",
        PrimitiveTypeCode.Int32 => "int",
        PrimitiveTypeCode.UInt32 => "uint",
        PrimitiveTypeCode.Int64 => "long",
        PrimitiveTypeCode.UInt64 => "ulong",
        PrimitiveTypeCode.Single => "float",
        PrimitiveTypeCode.Double => "double",
        PrimitiveTypeCode.IntPtr => "nint",
        PrimitiveTypeCode.UIntPtr => "nuint",
        PrimitiveTypeCode.Object => "object",
        PrimitiveTypeCode.String => "string",
        PrimitiveTypeCode.Void => "void",
        PrimitiveTypeCode.TypedReference => "TypedReference",
        _ => typeCode.ToString()
    };

    public string GetSZArrayType(string elementType) => $"{elementType}[]";

    public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind)
    {
        var definition = reader.GetTypeDefinition(handle);
        var name = reader.GetString(definition.Name);
        var declaringType = definition.GetDeclaringType();
        if (!declaringType.IsNil)
        {
            return $"{GetTypeFromDefinition(reader, declaringType, rawTypeKind)}.{name}";
        }

        var namespaceName = reader.GetString(definition.Namespace);
        return string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";
    }

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
    {
        var reference = reader.GetTypeReference(handle);
        var name = reader.GetString(reference.Name);
        if (reference.ResolutionScope.Kind == HandleKind.TypeReference)
        {
            return $"{GetTypeFromReference(reader, (TypeReferenceHandle)reference.ResolutionScope, rawTypeKind)}.{name}";
        }

        var namespaceName = reader.GetString(reference.Namespace);
        return string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";
    }

    private static string FormatLegacyGenericInstantiation(
        string genericType,
        ImmutableArray<string> typeArguments) =>
        $"{StripQualifiedArity(genericType)}<{string.Join(", ", typeArguments)}>";

    private static string StripQualifiedArity(string name) =>
        string.Join('.', name.Split('.').Select(StripArity));

    private static string StripArity(string name)
    {
        var backtick = name.IndexOf('`', StringComparison.Ordinal);
        return backtick < 0 ? name : name[..backtick];
    }

    public string GetTypeFromSpecification(
        MetadataReader reader,
        object? genericContext,
        TypeSpecificationHandle handle,
        byte rawTypeKind) =>
        reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
}
