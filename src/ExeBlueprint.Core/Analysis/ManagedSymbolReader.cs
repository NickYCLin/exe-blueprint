using System.Buffers.Binary;
using System.Collections;
using System.Collections.Immutable;
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Resources;
using System.Security.Cryptography;
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
    private const int MaxIlSwitchTargets = 4_096;
    internal const int MaxRawIlBytes = 32 * 1_024;
    private const int MaxUserStringHeapBytes = 0x0100_0000;
    private const int MaxResolvedUserStrings = 65_536;
    private const int MaxUserStringCharacters = 4_096;
    private const int MaxResolvedUserStringCharacters = 4 * 1_024 * 1_024;
    private const int MaxEnumFieldsToInspect = 1_024;
    private const int MaxEnumFieldsToInspectAcrossAssembly = 100_000;
    private const int MaxConstructorInitializerArguments = 32;
    private const int MaxConstructorArrayLength = 32;
    private const int MaxConstructorTypeSignatureBytes = 64;
    private const int MaxConstructorLocalSignatureBytes = MaxConstructorTypeSignatureBytes + 2;
    private const int MaxAssemblyPublicKeyBytes = 4_096;
    private const int MaxGenericParametersPerOwner = 256;
    private const int MaxGenericConstraintsPerParameter = 256;
    private const int MaxConstraintModifiers = 64;
    private const int MaxGenericParameterRows = 65_536;
    private const int MaxGenericConstraintRows = 16_384;
    private const int MaxGenericMetadataCharacters = 4 * 1_024 * 1_024;
    private const int MaxGenericConstraintRowsPerOwner = 4_096;
    private const int MaxGenericMetadataCharactersPerOwner = 256 * 1_024;
    private const int MaxGenericParameterNameCharacters = 1_024;
    private const int MaxGenericParameterNameUtf8Bytes = MaxGenericParameterNameCharacters * 4;
    private const int MaxGenericCustomAttributesPerTarget = 64;
    private const int MaxGenericAttributeTypeNameCharacters = 1_024;
    private const int MaxGenericAttributeTypeNameUtf8Bytes = MaxGenericAttributeTypeNameCharacters * 4;
    private const int MaxGenericAttributeTypeNameDepth = 64;
    private const int MaxGenericDeclaringTypeDepth = 64;

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
        var genericMetadataBudget = new GenericMetadataBudget();
        var typeGenericParameterResolver = new TypeGenericParameterResolver(metadata, genericMetadataBudget);
        var enumTypes = ReadEnumTypeCatalog(metadata, cancellationToken);
        var userStrings = UserStringCatalog.Create(peReader, metadata);
        var methodCount = 0;
        var truncated = userStrings.Truncated;

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
            var inheritedGenericParameterCount = declaringTypeHandle.IsNil
                ? 0
                : metadata.GetTypeDefinition(declaringTypeHandle).GetGenericParameters().Count;
            var declaringTypeName = declaringTypeHandle.IsNil
                ? null
                : GetTypeDefinitionFullName(metadata, declaringTypeHandle);
            var baseTypeName = GetTypeName(metadata, definition.BaseType);
            var attributes = definition.Attributes;
            var kind = GetTypeKind(attributes, baseTypeName);
            var isAbstract = attributes.HasFlag(TypeAttributes.Abstract);
            var isSealed = attributes.HasFlag(TypeAttributes.Sealed);
            var genericParameterResult = typeGenericParameterResolver.Read(typeHandle);
            var genericParameterDetails = genericParameterResult.Parameters;
            var genericParametersComplete = genericParameterResult.Complete;
            var methods = new List<MethodModel>();
            var constructorCandidates = new Dictionary<MethodDefinitionHandle, ConstructorReconstruction>();

            foreach (var methodHandle in definition.GetMethods())
            {
                var method = metadata.GetMethodDefinition(methodHandle);
                var methodName = metadata.GetString(method.Name);
                var hasBody = method.RelativeVirtualAddress != 0;
                var declaringName = fullName;
                var methodBody = hasBody ? TryReadMethodBody(peReader, method) : null;
                var il = methodBody is null ? null : TryReadIl(methodBody);
                var localVariablesInitialized = methodBody?.LocalVariablesInitialized ?? false;
                var memberReferenceCallerContext = TryCreateMemberReferenceCallerContext(
                    metadata,
                    typeHandle,
                    methodHandle);
                StandaloneSignatureHandle localSignature = default;
                var localTypes = methodBody is not null
                    ? TryReadLocalTypes(
                        metadata,
                        methodBody,
                        enumTypes,
                        memberReferenceCallerContext,
                        out localSignature)
                    : [];
                IReadOnlyList<ExceptionRegionInfo>? exceptionRegionResult = !hasBody
                    ? []
                    : methodBody is null
                        ? null
                        : TryReadExceptionRegions(metadata, methodBody);
                var exceptionRegions = exceptionRegionResult ?? [];

                var model = BuildMethod(
                    metadata,
                    methodHandle,
                    method,
                    methodName,
                    hasBody,
                    entryPointMethod.Handle,
                    genericMetadataBudget);
                var reconstructionSignature = TryReadReconstructionSignature(
                    metadata,
                    method,
                    model,
                    enumTypes,
                    memberReferenceCallerContext);
                if (hasBody && il is null)
                {
                    model = model with { IlTruncated = true };
                    truncated = true;
                }
                else if (il is not null)
                {
                    var decoded = DecodeInstructions(il);
                    var methodIlComplete = decoded.Status == IlDecodeStatus.Complete &&
                                           HasOnlyValidUserStringOperands(
                                               il,
                                               decoded,
                                               userStrings);
                    var (instructions, ilTruncated) = Disassemble(
                        metadata,
                        il,
                        decoded,
                        userStrings,
                        methodIlComplete,
                        memberReferenceCallerContext);
                    model = model with { Il = instructions, IlTruncated = ilTruncated };

                    if (methodIlComplete &&
                        methodName is not (".ctor" or ".cctor") &&
                        reconstructionSignature is not null &&
                        exceptionRegionResult is not null)
                    {
                        var isInstance = !method.Attributes.HasFlag(MethodAttributes.Static);
                        var body = TryReconstructLinearBody(
                            metadata,
                            il,
                            decoded,
                            isInstance,
                            ReadParameterNames(metadata, method),
                            reconstructionSignature.ParameterTypes,
                            reconstructionSignature.ReturnType,
                            localTypes,
                            localVariablesInitialized,
                            exceptionRegions,
                            enumTypes,
                            userStrings,
                            isInstance
                                ? CreateCurrentInstanceCliType(
                                    metadata,
                                    enumTypes,
                                    method.GetDeclaringType(),
                                    memberReferenceCallerContext)
                                : null,
                            out var requiresUnsafeContext,
                            memberReferenceCallerContext: memberReferenceCallerContext);
                        if (body is not null)
                        {
                            model = model with
                            {
                                Body = body,
                                BodyReconstructed = true,
                                RequiresUnsafeContext = requiresUnsafeContext
                            };
                        }
                    }
                    else if (methodIlComplete &&
                             methodName == ".ctor" &&
                             kind == "class" &&
                             reconstructionSignature is not null &&
                             exceptionRegionResult is not null)
                    {
                        var constructor = TryReconstructConstructor(
                            metadata,
                            il,
                            decoded,
                            methodHandle,
                            typeHandle,
                            definition.BaseType,
                            ReadParameterNames(metadata, method),
                            reconstructionSignature,
                            genericParameterResult,
                            localTypes,
                            localVariablesInitialized,
                            localSignature,
                            exceptionRegions,
                            enumTypes,
                            userStrings);
                        if (constructor is not null)
                        {
                            model = model with
                            {
                                ConstructorInitializer = constructor.Initializer,
                                Body = constructor.Body ?? [],
                                BodyReconstructed = constructor.Body is not null,
                                RequiresUnsafeContext = constructor.Body is not null &&
                                                        constructor.RequiresUnsafeContext
                            };
                            constructorCandidates.Add(methodHandle, constructor with { MethodIndex = methods.Count });
                        }
                    }

                    if (!methodIlComplete ||
                        !CollectCalls(
                            metadata,
                            il,
                            decoded,
                            $"{declaringName}.{methodName}",
                            edges,
                            seenEdges,
                            memberReferenceCallerContext))
                    {
                        truncated = true;
                    }
                }

                methods.Add(model);
                methodCount++;
            }

            ValidateConstructorChains(methods, constructorCandidates);
            types.Add(new TypeModel
            {
                TypeDefinitionToken = MetadataTokens.GetToken(typeHandle),
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
                DeclaringTypeDefinitionToken = declaringTypeHandle.IsNil
                    ? null
                    : MetadataTokens.GetToken(declaringTypeHandle),
                InheritedGenericParameterCount = declaringTypeHandle.IsNil
                    ? 0
                    : inheritedGenericParameterCount,
                BaseType = baseTypeName,
                Interfaces = ReadInterfaces(metadata, definition),
                GenericParameters = genericParameterDetails.Select(parameter => parameter.Name).ToArray(),
                GenericParameterDetails = genericParameterDetails,
                GenericParametersComplete = genericParametersComplete,
                GenericParameterDomainComplete = genericParameterResult.DomainComplete,
                GenericParametersError = genericParametersComplete
                    ? null
                    : "泛型參數 metadata 不完整；請檢查 genericParameterDetails 與 code.truncated",
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
            Truncated = truncated || genericMetadataBudget.Truncated || userStrings.Truncated,
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
            ManagedResourceConfigurationModel? configuration = null;
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
            else if (location == "embedded" && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                configuration = ReadEmbeddedJsonConfiguration(
                    peReader,
                    resource.Offset,
                    size,
                    resourcesDirectory);
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
                EntriesError = entriesError,
                Configuration = configuration
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

        return ReadResourceTable(data, entryLimit);
    }

    private static ManagedResourceConfigurationModel ReadEmbeddedJsonConfiguration(
        PEReader peReader,
        long offset,
        long? size,
        DirectoryEntry? resourcesDirectory)
    {
        if (size is not { } resourceSize)
        {
            return EmbeddedJsonConfigurationReader.Unavailable("找不到完整的內嵌 JSON 設定資料。");
        }

        if (resourceSize > EmbeddedJsonConfigurationReader.MaxBytes)
        {
            return EmbeddedJsonConfigurationReader.Unavailable("內嵌 JSON 設定超過 1 MB 安全解析上限。");
        }

        var data = TryReadEmbeddedResourceData(
            peReader,
            offset,
            (int)resourceSize,
            resourcesDirectory);
        return data is null
            ? EmbeddedJsonConfigurationReader.Unavailable("找不到完整的內嵌 JSON 設定資料。")
            : EmbeddedJsonConfigurationReader.Read(data);
    }

    internal static ResourceTableReadResult ReadResourceTable(byte[] data, int entryLimit)
    {
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
        catch (NotSupportedException)
        {
            var preserialized = PreserializedResourceTableReader.TryRead(data, entryLimit);
            if (!preserialized.Matched)
            {
                return new([], false, "資源表使用不受支援的 resource reader。");
            }

            if (preserialized.Error is { } error)
            {
                return new([], false, error);
            }

            return new(
                preserialized.Entries
                    .Select(entry => DecodePreserializedResourceEntry(entry.Name, entry.Type, entry.Data))
                    .OrderBy(entry => entry.Name, StringComparer.Ordinal)
                    .ToArray(),
                preserialized.Truncated,
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

    internal static ManagedResourceEntryModel DecodePreserializedResourceEntry(
        string name,
        string type,
        byte[] data)
    {
        const string resourceTypePrefix = "ResourceTypeCode.";
        if (type.StartsWith(resourceTypePrefix, StringComparison.Ordinal))
        {
            return DecodeResourceEntry(name, type, data);
        }

        var position = 0;
        if (!TryRead7BitEncodedInt(data, ref position, out var formatCode))
        {
            return InvalidPreserializedResourceEntry(name, type, data, "找不到預序列化格式代碼。");
        }

        return formatCode switch
        {
            1 => DecodeLengthPrefixedPreserializedResource(
                name,
                type,
                data,
                position,
                "binary-formatter"),
            2 => DecodeLengthPrefixedPreserializedResource(
                name,
                type,
                data,
                position,
                "type-converter-byte-array"),
            3 => DecodeTypeConverterStringResource(name, type, data, position),
            4 => DecodeLengthPrefixedPreserializedResource(
                name,
                type,
                data,
                position,
                "activator-stream"),
            _ => InvalidPreserializedResourceEntry(name, type, data, "預序列化格式代碼不受支援。")
        };
    }

    private static ManagedResourceEntryModel DecodeLengthPrefixedPreserializedResource(
        string name,
        string type,
        byte[] data,
        int position,
        string format)
    {
        if (!TryRead7BitEncodedInt(data, ref position, out var payloadLength)
            || payloadLength > data.Length - position
            || payloadLength != data.Length - position)
        {
            return InvalidPreserializedResourceEntry(name, type, data, "預序列化 payload 長度不正確。", format);
        }

        var payload = data.AsSpan(position, payloadLength);
        return new ManagedResourceEntryModel
        {
            Name = name,
            Type = type,
            Status = "encoded",
            DataSize = data.Length,
            Serialization = new ManagedResourceSerializationModel
            {
                Format = format,
                PayloadSize = payload.Length,
                PayloadKind = ClassifySerializedPayload(payload),
                Complete = true
            }
        };
    }

    private static ManagedResourceEntryModel DecodeTypeConverterStringResource(
        string name,
        string type,
        byte[] data,
        int position)
    {
        if (!TryReadResourceString(data, ref position, out var value)
            || position != data.Length)
        {
            return InvalidPreserializedResourceEntry(
                name,
                type,
                data,
                "TypeConverterString payload 格式不正確。",
                "type-converter-string");
        }

        var truncated = value.Length > MaxResourceValueLength;
        return new ManagedResourceEntryModel
        {
            Name = name,
            Type = type,
            Status = "encoded",
            Value = truncated ? value[..MaxResourceValueLength] : value,
            ValueTruncated = truncated,
            DataSize = data.Length,
            Serialization = new ManagedResourceSerializationModel
            {
                Format = "type-converter-string",
                PayloadSize = Encoding.UTF8.GetByteCount(value),
                PayloadKind = "text",
                Complete = true
            }
        };
    }

    private static ManagedResourceEntryModel InvalidPreserializedResourceEntry(
        string name,
        string type,
        byte[] data,
        string error,
        string? format = null) =>
        new()
        {
            Name = name,
            Type = type,
            Status = "invalid",
            DataSize = data.Length,
            Error = error,
            Serialization = format is null
                ? null
                : new ManagedResourceSerializationModel
                {
                    Format = format,
                    PayloadSize = 0,
                    PayloadKind = "binary",
                    Complete = false,
                    Error = error
                }
        };

    private static bool TryReadResourceString(byte[] data, ref int position, out string value)
    {
        value = string.Empty;
        if (!TryRead7BitEncodedInt(data, ref position, out var byteLength)
            || byteLength > MaxResourceValueLength * 4
            || byteLength > data.Length - position)
        {
            return false;
        }

        try
        {
            value = new UTF8Encoding(false, true).GetString(data, position, byteLength);
            position += byteLength;
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryRead7BitEncodedInt(byte[] data, ref int position, out int value)
    {
        value = 0;
        uint result = 0;
        for (var index = 0; index < 5; index++)
        {
            if (position >= data.Length)
            {
                return false;
            }

            var current = data[position++];
            if (index == 4 && current > 0x07)
            {
                return false;
            }

            result |= (uint)(current & 0x7F) << (index * 7);
            if ((current & 0x80) == 0)
            {
                if ((index > 0 && result < 1u << (index * 7)) || result > int.MaxValue)
                {
                    return false;
                }

                value = (int)result;
                return true;
            }
        }

        return false;
    }

    private static string ClassifySerializedPayload(ReadOnlySpan<byte> payload)
    {
        if (payload.Length >= 17
            && payload[0] == 0
            && payload[9] == 1
            && payload[10] == 0
            && payload[11] == 0
            && payload[12] == 0
            && payload[13] == 0
            && payload[14] == 0
            && payload[15] == 0
            && payload[16] == 0)
        {
            return "nrbf";
        }

        if (HasPrefix(payload, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
        {
            return "png";
        }

        if (HasPrefix(payload, [0xFF, 0xD8, 0xFF]))
        {
            return "jpeg";
        }

        if (HasPrefix(payload, "GIF8"u8))
        {
            return "gif";
        }

        if (HasPrefix(payload, "BM"u8))
        {
            return "bmp";
        }

        if (HasPrefix(payload, [0, 0, 1, 0]) || HasPrefix(payload, [0, 0, 2, 0]))
        {
            return "ico";
        }

        if (HasPrefix(payload, "PK\x03\x04"u8))
        {
            return "zip";
        }

        if (HasPrefix(payload, "MZ"u8))
        {
            return "pe";
        }

        if (HasPrefix(payload, "%PDF-"u8))
        {
            return "pdf";
        }

        return "binary";
    }

    private static bool HasPrefix(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> prefix) =>
        payload.Length >= prefix.Length && payload[..prefix.Length].SequenceEqual(prefix);

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

    internal readonly record struct ResourceTableReadResult(
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

    private static MethodBodyBlock? TryReadMethodBody(
        PEReader peReader,
        MethodDefinition method)
    {
        try
        {
            return peReader.GetMethodBody(method.RelativeVirtualAddress);
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            return null;
        }
    }

    private static byte[]? TryReadIl(MethodBodyBlock body)
    {
        try
        {
            if (body.GetILReader().Length > MaxRawIlBytes)
            {
                return null;
            }

            return body.GetILBytes();
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            return null;
        }
    }

    private static IReadOnlyList<CliType> TryReadLocalTypes(
        MetadataReader metadata,
        MethodBodyBlock body,
        EnumTypeCatalog enumTypes,
        MemberReferenceCallerContext callerContext,
        out StandaloneSignatureHandle localSignature)
    {
        localSignature = default;
        try
        {
            if (body.LocalSignature.IsNil)
            {
                return [];
            }

            localSignature = body.LocalSignature;
            var signature = metadata.GetStandaloneSignature(body.LocalSignature);
            return signature
                .DecodeLocalSignature(
                    SignatureTypeNameProvider.Instance,
                    callerContext.SignatureContext)
                .Select(type => CreateCliType(type, enumTypes))
                .ToArray();
        }
        catch (Exception exception) when (exception is BadImageFormatException or InvalidOperationException)
        {
            localSignature = default;
            return [];
        }
    }

    private sealed record MethodReconstructionSignature(
        CliType ReturnType,
        IReadOnlyList<CliType> ParameterTypes);

    private sealed record ConstructorParameter(
        CliType Type,
        SignatureTypeName Signature);

    private readonly record struct ConstructorArgument(
        string Expression,
        CliType Type,
        SignatureTypeName? Signature,
        bool IsFoldedExpression = false,
        SignatureTypeName? FoldedArrayElementSignature = null,
        bool RequiresDirectBase = false,
        bool RequiresExactTargetSignature = false);

    private sealed record ConstructorTypeSpecificationContext(
        TypeSpecificationHandle Handle,
        SignatureGenericContext SignatureContext);

    private sealed record ConstructorCallTarget(
        EntityHandle DeclaringType,
        MethodDefinitionHandle Definition,
        IReadOnlyList<ConstructorParameter> Parameters);

    private sealed record ConstructorReconstruction(
        ConstructorInitializerModel Initializer,
        IReadOnlyList<string>? Body,
        bool RequiresUnsafeContext,
        MethodDefinitionHandle ThisTarget,
        int MethodIndex = -1);

    private static MethodReconstructionSignature? TryReadReconstructionSignature(
        MetadataReader metadata,
        MethodDefinition method,
        MethodModel model,
        EnumTypeCatalog enumTypes,
        MemberReferenceCallerContext callerContext)
    {
        try
        {
            var signature = method.DecodeSignature(
                SignatureTypeNameProvider.Instance,
                callerContext.SignatureContext);
            if (signature.ParameterTypes.Length != model.Parameters.Count ||
                signature.ReturnType.HasPinnedQualifier ||
                signature.ParameterTypes.Any(type => type.HasPinnedQualifier) ||
                signature.Header.IsInstance == method.Attributes.HasFlag(MethodAttributes.Static))
            {
                return null;
            }

            var returnType = CreateCliType(signature.ReturnType, enumTypes) with { Text = model.ReturnType };
            var parameterTypes = signature.ParameterTypes
                .Select((type, index) =>
                    CreateCliType(type, enumTypes) with { Text = model.Parameters[index].Type })
                .ToArray();
            return new MethodReconstructionSignature(returnType, parameterTypes);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static MemberReferenceCallerContext TryCreateMemberReferenceCallerContext(
        MetadataReader metadata,
        TypeDefinitionHandle declaringType,
        MethodDefinitionHandle methodHandle)
    {
        try
        {
            if (!TryGetCanonicalTypeDefinitionSignatureParameterCount(
                    metadata,
                    declaringType,
                    out var typeParameterCount))
            {
                return default;
            }

            var method = metadata.GetMethodDefinition(methodHandle);
            var methodParameters = method.GetGenericParameters();
            var methodDomain = ReadGenericParameterDomain(
                metadata,
                methodParameters,
                methodHandle);
            var signature = method.DecodeSignature(
                SignatureTypeNameProvider.Instance,
                genericContext: null);
            if (!methodDomain.Complete ||
                signature.GenericParameterCount != methodDomain.Count)
            {
                return default;
            }

            return new MemberReferenceCallerContext(
                declaringType,
                typeParameterCount,
                methodHandle,
                methodDomain.Count,
                IsAvailable: true);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return default;
        }
    }

    private static bool TryGetCanonicalTypeDefinitionSignatureParameterCount(
        MetadataReader metadata,
        TypeDefinitionHandle declaringType,
        out int parameterCount)
    {
        parameterCount = 0;
        try
        {
            if (declaringType.IsNil)
            {
                return false;
            }

            var typeParameters = metadata
                .GetTypeDefinition(declaringType)
                .GetGenericParameters();
            var typeDomain = ReadGenericParameterDomain(
                metadata,
                typeParameters,
                declaringType);
            if (!typeDomain.Complete ||
                !HasCanonicalConstructorOwnerArity(
                    metadata,
                    declaringType,
                    typeDomain.Count))
            {
                return false;
            }

            parameterCount = typeDomain.Count;
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            parameterCount = 0;
            return false;
        }
    }

    private static ConstructorReconstruction? TryReconstructConstructor(
        MetadataReader metadata,
        byte[] il,
        IlDecodeResult decoded,
        MethodDefinitionHandle methodHandle,
        TypeDefinitionHandle declaringType,
        EntityHandle baseType,
        Dictionary<int, string> parameterNames,
        MethodReconstructionSignature signature,
        TypeGenericParameterReadResult genericParameterResult,
        IReadOnlyList<CliType> localTypes,
        bool localVariablesInitialized,
        StandaloneSignatureHandle localSignature,
        IReadOnlyList<ExceptionRegionInfo> exceptionRegions,
        EnumTypeCatalog enumTypes,
        UserStringCatalog userStrings)
    {
        if (!TryCreateConstructorOwnerContext(
                metadata,
                declaringType,
                genericParameterResult,
                out var ownerContext) ||
            !TryCreateConstructorBaseTypeContext(
                metadata,
                declaringType,
                baseType,
                ownerContext,
                out var baseTypeContext))
        {
            return null;
        }

        var currentConstructor = TryResolveConstructorCall(
            metadata,
            enumTypes,
            MetadataTokens.GetToken(methodHandle),
            ownerContext: ownerContext);
        if (currentConstructor is null ||
            currentConstructor.Definition != methodHandle ||
            currentConstructor.DeclaringType != declaringType ||
            currentConstructor.Parameters.Count != signature.ParameterTypes.Count ||
            signature.ReturnType.PrimitiveType != PrimitiveTypeCode.Void)
        {
            return null;
        }

        var rawInstructions = decoded.Instructions;
        if (decoded.Status != IlDecodeStatus.Complete ||
            rawInstructions.Count == 0 ||
            !TryGetInstructionName(rawInstructions[^1], out var finalName) ||
            finalName != "ret")
        {
            return null;
        }

        var index = 0;
        SkipConstructorNops(rawInstructions, ref index);
        if (index >= rawInstructions.Count ||
            !TryGetInstructionName(rawInstructions[index], out var receiverName) ||
            receiverName != "ldarg.0")
        {
            return null;
        }

        index++;
        var arguments = new List<ConstructorArgument>();
        var foldedLocalSlots = new HashSet<int>();
        var hasFoldedTypeOfArgument = false;
        var currentParameterSignatures = currentConstructor.Parameters
            .Select(parameter => parameter.Signature)
            .ToArray();
        IlInstruction callInstruction = default;
        while (index < rawInstructions.Count)
        {
            SkipConstructorNops(rawInstructions, ref index);
            if (index >= rawInstructions.Count ||
                !TryGetInstructionName(rawInstructions[index], out var name))
            {
                return null;
            }

            if (name == "call")
            {
                callInstruction = rawInstructions[index];
                break;
            }

            if (arguments.Count < MaxConstructorInitializerArguments &&
                TryFoldConstructorConditionalInt32ArrayElementArgument(
                    il,
                    rawInstructions,
                    index,
                    parameterNames,
                    signature.ParameterTypes,
                    currentParameterSignatures,
                    out var conditionalArgument,
                    out var nextIndex))
            {
                arguments.Add(conditionalArgument);
                index = nextIndex;
                continue;
            }

            if (name == "newobj")
            {
                if (arguments.Count == 0 ||
                    !TryFoldNullableConstructorArgument(
                        metadata,
                        enumTypes,
                        il,
                        rawInstructions[index],
                        arguments[^1],
                        out var nullableArgument))
                {
                    return null;
                }

                arguments[^1] = nullableArgument;
                index++;
                continue;
            }

            if (name == "newarr")
            {
                if (arguments.Count == 0 ||
                    !TryFoldInt32ArrayConstructorArgument(
                        metadata,
                        il,
                        rawInstructions[index],
                        arguments[^1],
                        out var arrayArgument))
                {
                    return null;
                }

                arguments[^1] = arrayArgument;
                index++;
                continue;
            }

            if (name == "ldtoken")
            {
                if (arguments.Count >= MaxConstructorInitializerArguments ||
                    !TryFoldTypeOfConstructorArgument(
                        metadata,
                        enumTypes,
                        il,
                        rawInstructions,
                        index,
                        ownerContext,
                        out var typeOfArgument))
                {
                    return null;
                }

                arguments.Add(typeOfArgument);
                hasFoldedTypeOfArgument = true;
                index += 2;
                continue;
            }

            if (name is "ldloca.s" or "ldloca")
            {
                if (arguments.Count >= MaxConstructorInitializerArguments ||
                    !TryFoldDefaultNullableLocalArgument(
                        metadata,
                        enumTypes,
                        il,
                        rawInstructions,
                        index,
                        localSignature,
                        out var nullableArgument,
                        out var localSlot) ||
                    !foldedLocalSlots.Add(localSlot))
                {
                    return null;
                }

                arguments.Add(nullableArgument);
                index += 3;
                continue;
            }

            if (arguments.Count >= MaxConstructorInitializerArguments ||
                !TryReadConstructorArgument(
                    metadata,
                    userStrings,
                    il,
                    rawInstructions[index],
                    name,
                    parameterNames,
                    signature.ParameterTypes,
                    currentParameterSignatures,
                    out var argument))
            {
                return null;
            }

            arguments.Add(argument);
            index++;
        }

        if (callInstruction.OperandSize != 4 || index + 1 >= rawInstructions.Count)
        {
            return null;
        }

        var callEndOffset = callInstruction.OperandOffset + callInstruction.OperandSize;
        if (ConstructorExceptionRegionsAreUnsafe(
                exceptionRegions,
                rawInstructions,
                callEndOffset,
                il.Length) ||
            ConstructorTailHasUnsafeBranches(il, rawInstructions, index + 1, callEndOffset) ||
            ConstructorTailUsesFoldedLocal(
                rawInstructions,
                index + 1,
                foldedLocalSlots))
        {
            return null;
        }

        var target = TryResolveConstructorCall(
            metadata,
            enumTypes,
            BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(callInstruction.OperandOffset, 4)),
            baseTypeContext,
            ownerContext);
        if (target is null || target.Parameters.Count != arguments.Count)
        {
            return null;
        }

        string kind;
        var thisTarget = default(MethodDefinitionHandle);
        if (!baseType.IsNil && target.DeclaringType == baseType)
        {
            kind = "base";
        }
        else if (target.DeclaringType == declaringType &&
                 !target.Definition.IsNil &&
                 target.Definition != methodHandle)
        {
            kind = "this";
            thisTarget = target.Definition;
        }
        else
        {
            return null;
        }

        if ((foldedLocalSlots.Count > 0 ||
             hasFoldedTypeOfArgument ||
             arguments.Any(argument => argument.RequiresDirectBase)) &&
            kind != "base")
        {
            return null;
        }

        var renderedArguments = new string[arguments.Count];
        for (var argumentIndex = 0; argumentIndex < arguments.Count; argumentIndex++)
        {
            var argument = arguments[argumentIndex];
            if (!TryRenderConstructorArgument(
                    metadata,
                    argument.Expression,
                    argument.Type,
                    argument.Signature,
                    argument.FoldedArrayElementSignature,
                    argument.RequiresExactTargetSignature,
                    target.Parameters[argumentIndex],
                    allowVerifiedDirectBaseConversion: kind == "base",
                    out renderedArguments[argumentIndex]))
            {
                return null;
            }
        }

        var callerContext = TryCreateMemberReferenceCallerContext(
            metadata,
            declaringType,
            methodHandle);
        var instanceType = CreateCurrentInstanceCliType(
            metadata,
            enumTypes,
            declaringType,
            callerContext);
        IReadOnlyList<string>? body = null;
        var requiresUnsafeContext = false;
        if (IsCanonicalConstructorTail(
                metadata,
                userStrings,
                il,
                rawInstructions,
                index + 1,
                declaringType))
        {
            body = TryReconstructLinearBody(
                metadata,
                il,
                decoded,
                isInstance: true,
                parameterNames,
                signature.ParameterTypes,
                signature.ReturnType,
                localTypes,
                localVariablesInitialized,
                exceptionRegions,
                enumTypes,
                userStrings,
                instanceType,
                out requiresUnsafeContext,
                callEndOffset,
                callerContext);
        }

        return new ConstructorReconstruction(
            new ConstructorInitializerModel
            {
                Kind = kind,
                Arguments = renderedArguments
            },
            body,
            requiresUnsafeContext,
            thisTarget);
    }

    private static bool IsCanonicalConstructorTail(
        MetadataReader metadata,
        UserStringCatalog userStrings,
        byte[] il,
        IReadOnlyList<IlInstruction> instructions,
        int startIndex,
        TypeDefinitionHandle declaringType)
    {
        var index = startIndex;
        while (index < instructions.Count)
        {
            SkipConstructorNops(instructions, ref index);
            if (index >= instructions.Count ||
                !TryGetInstructionName(instructions[index], out var name))
            {
                return false;
            }

            if (name == "ret")
            {
                return index == instructions.Count - 1;
            }

            if (name != "ldarg.0")
            {
                return false;
            }

            index++;
            SkipConstructorNops(instructions, ref index);
            if (index >= instructions.Count ||
                !TryGetInstructionName(instructions[index], out name) ||
                !IsConstructorValueLoad(
                    metadata,
                    userStrings,
                    il,
                    instructions[index],
                    name))
            {
                return false;
            }

            index++;
            SkipConstructorNops(instructions, ref index);
            if (index >= instructions.Count ||
                !TryGetInstructionName(instructions[index], out name) ||
                name != "stfld" ||
                !IsCanonicalConstructorFieldStore(
                    metadata,
                    il,
                    instructions[index],
                    declaringType))
            {
                return false;
            }

            index++;
        }

        return false;
    }

    private static bool IsCanonicalConstructorFieldStore(
        MetadataReader metadata,
        byte[] il,
        IlInstruction instruction,
        TypeDefinitionHandle declaringType)
    {
        if (instruction.OperandSize != 4)
        {
            return false;
        }

        try
        {
            var handle = MetadataTokens.EntityHandle(
                BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4)));
            if (handle.Kind != HandleKind.FieldDefinition)
            {
                return false;
            }

            var field = metadata.GetFieldDefinition((FieldDefinitionHandle)handle);
            var fieldType = field.DecodeSignature(SignatureTypeNameProvider.Instance, null);
            return field.GetDeclaringType() == declaringType &&
                   !field.Attributes.HasFlag(FieldAttributes.Static) &&
                   !field.Attributes.HasFlag(FieldAttributes.Literal) &&
                   IsCanonicalConstructorFieldType(fieldType);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsCanonicalConstructorFieldType(SignatureTypeName type)
    {
        if (type.OuterCustomModifiers.Length != 0 ||
            type.HasNestedCustomModifiers ||
            type.IsRestrictedGenericArgument ||
            type.HasPinnedQualifier ||
            type.PrimitiveType is PrimitiveTypeCode.Void or PrimitiveTypeCode.TypedReference)
        {
            return false;
        }

        if (type.PrimitiveType is not null)
        {
            return true;
        }

        if (!type.IsExactNamedType ||
            type.NominalHandle.IsNil ||
            IsPrimitiveAliasName(type.Text))
        {
            return false;
        }

        return type.RawTypeKind switch
        {
            (byte)SignatureTypeKind.Class => type.SignatureKind == SignatureTypeKind.Class,
            (byte)SignatureTypeKind.ValueType => type.SignatureKind == SignatureTypeKind.ValueType,
            _ => false
        };
    }

    private static bool IsConstructorValueLoad(
        MetadataReader metadata,
        UserStringCatalog userStrings,
        byte[] il,
        IlInstruction instruction,
        string name)
    {
        if (name is
            "ldarg.1" or
            "ldarg.2" or
            "ldarg.3" or
            "ldnull" or
            "ldc.i4.m1" or
            "ldc.i4.0" or
            "ldc.i4.1" or
            "ldc.i4.2" or
            "ldc.i4.3" or
            "ldc.i4.4" or
            "ldc.i4.5" or
            "ldc.i4.6" or
            "ldc.i4.7" or
            "ldc.i4.8" or
            "ldc.i4.s" or
            "ldc.i4" or
            "ldc.i8" or
            "ldc.r4" or
            "ldc.r8")
        {
            return true;
        }

        if (name == "ldstr")
        {
            if (instruction.OperandSize != 4)
            {
                return false;
            }

            var token = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instruction.OperandOffset, 4));
            return userStrings.TryGet(token, out _);
        }

        return name switch
        {
            "ldarg.s" => il[instruction.OperandOffset] != 0,
            "ldarg" => BinaryPrimitives.ReadUInt16LittleEndian(
                il.AsSpan(instruction.OperandOffset, 2)) != 0,
            _ => false
        };
    }

    private static bool TryCreateConstructorOwnerContext(
        MetadataReader metadata,
        TypeDefinitionHandle declaringType,
        TypeGenericParameterReadResult genericParameterResult,
        out SignatureGenericContext? context)
    {
        context = null;
        try
        {
            var handles = metadata.GetTypeDefinition(declaringType).GetGenericParameters();
            if (!genericParameterResult.Complete ||
                !genericParameterResult.DomainComplete ||
                handles.Count > MaxGenericParametersPerOwner ||
                genericParameterResult.Parameters.Count != handles.Count ||
                genericParameterResult.Parameters.Any(parameter => !parameter.Complete) ||
                !HasCanonicalConstructorOwnerArity(metadata, declaringType, handles.Count))
            {
                return false;
            }

            if (handles.Count > 0)
            {
                context = SignatureGenericContext.ForOwner(declaringType, handles.Count);
            }

            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool HasCanonicalConstructorOwnerArity(
        MetadataReader metadata,
        TypeDefinitionHandle declaringType,
        int expectedParameterCount)
    {
        var chain = new List<TypeDefinitionHandle>();
        var seen = new HashSet<TypeDefinitionHandle>();
        var current = declaringType;
        while (!current.IsNil)
        {
            if (chain.Count >= MaxGenericDeclaringTypeDepth || !seen.Add(current))
            {
                return false;
            }

            chain.Add(current);
            current = metadata.GetTypeDefinition(current).GetDeclaringType();
        }

        var cumulativeArity = 0;
        for (var index = chain.Count - 1; index >= 0; index--)
        {
            var definition = metadata.GetTypeDefinition(chain[index]);
            var name = metadata.GetString(definition.Name);
            var backtick = name.LastIndexOf('`');
            var ownArity = 0;
            if (backtick >= 0 &&
                (backtick == 0 ||
                 name.IndexOf('`') != backtick ||
                 !int.TryParse(
                     name.AsSpan(backtick + 1),
                     NumberStyles.None,
                     CultureInfo.InvariantCulture,
                     out ownArity) ||
                 ownArity <= 0))
            {
                return false;
            }

            if (name.Length > MaxGenericAttributeTypeNameCharacters ||
                IsPrimitiveAliasName(backtick < 0 ? name : name[..backtick]) ||
                ownArity > MaxGenericParametersPerOwner - cumulativeArity)
            {
                return false;
            }

            cumulativeArity += ownArity;
            if (definition.GetGenericParameters().Count != cumulativeArity)
            {
                return false;
            }
        }

        return cumulativeArity == expectedParameterCount;
    }

    private static bool TryCreateConstructorBaseTypeContext(
        MetadataReader metadata,
        TypeDefinitionHandle declaringType,
        EntityHandle baseType,
        SignatureGenericContext? ownerContext,
        out ConstructorTypeSpecificationContext? context)
    {
        context = null;
        if (baseType == declaringType)
        {
            return false;
        }

        if (baseType.Kind != HandleKind.TypeSpecification)
        {
            return true;
        }

        try
        {
            var handle = (TypeSpecificationHandle)baseType;
            var signature = SignatureTypeNameProvider.Instance.GetTypeFromSpecification(
                metadata,
                ownerContext,
                handle,
                rawTypeKind: 0);
            if (!signature.IsCanonicalGenericInstantiation ||
                !AreSameConstructorSignature(signature, signature) ||
                signature.GenericDefinitionHandle == declaringType ||
                signature.GenericDefinitionRawTypeKind != (byte)SignatureTypeKind.Class ||
                signature.GenericDefinitionSignatureKind != SignatureTypeKind.Class ||
                !HasCanonicalLocalGenericDefinitions(metadata, signature))
            {
                return false;
            }

            context = new ConstructorTypeSpecificationContext(
                handle,
                SignatureGenericContext.ForSubstitution(signature.GenericArguments));
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool HasCanonicalLocalGenericDefinitions(
        MetadataReader metadata,
        SignatureTypeName signature)
    {
        var remainingNodes = 512;
        return HasCanonicalLocalGenericDefinitions(
            metadata,
            signature,
            depth: 0,
            ref remainingNodes);
    }

    private static bool HasCanonicalLocalGenericDefinitions(
        MetadataReader metadata,
        SignatureTypeName signature,
        int depth,
        ref int remainingNodes)
    {
        if (depth > MaxStructureDepth || remainingNodes-- <= 0)
        {
            return false;
        }

        if (!signature.IsCanonicalGenericInstantiation)
        {
            return true;
        }

        if (signature.GenericArguments.IsDefaultOrEmpty ||
            signature.GenericArguments.Length > MaxGenericParametersPerOwner)
        {
            return false;
        }

        if (signature.GenericDefinitionHandle.Kind == HandleKind.TypeDefinition)
        {
            var definitionHandle = (TypeDefinitionHandle)signature.GenericDefinitionHandle;
            var definition = metadata.GetTypeDefinition(definitionHandle);
            if (!definition.GetDeclaringType().IsNil)
            {
                return false;
            }

            var handles = definition.GetGenericParameters();
            if (handles.Count != signature.GenericArguments.Length ||
                handles.Count > MaxGenericParametersPerOwner)
            {
                return false;
            }

            var positions = new bool[handles.Count];
            foreach (var parameterHandle in handles)
            {
                var parameter = metadata.GetGenericParameter(parameterHandle);
                if (parameter.Parent != definitionHandle ||
                    parameter.Index < 0 ||
                    parameter.Index >= positions.Length ||
                    positions[parameter.Index])
                {
                    return false;
                }

                positions[parameter.Index] = true;
            }
        }
        else if (signature.GenericDefinitionHandle.Kind != HandleKind.TypeReference)
        {
            return false;
        }

        foreach (var argument in signature.GenericArguments)
        {
            if (!HasCanonicalLocalGenericDefinitions(
                    metadata,
                    argument,
                    depth + 1,
                    ref remainingNodes))
            {
                return false;
            }
        }

        return true;
    }

    private static ConstructorCallTarget? TryResolveConstructorCall(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        int token,
        ConstructorTypeSpecificationContext? typeSpecificationContext = null,
        SignatureGenericContext? ownerContext = null)
    {
        try
        {
            var handle = MetadataTokens.EntityHandle(token);
            switch (handle.Kind)
            {
                case HandleKind.MethodDefinition:
                    var methodHandle = (MethodDefinitionHandle)handle;
                    var method = metadata.GetMethodDefinition(methodHandle);
                    var attributes = method.Attributes;
                    if (metadata.GetString(method.Name) != ".ctor" ||
                        attributes.HasFlag(MethodAttributes.Static) ||
                        attributes.HasFlag(MethodAttributes.Abstract) ||
                        !attributes.HasFlag(MethodAttributes.SpecialName) ||
                        !attributes.HasFlag(MethodAttributes.RTSpecialName) ||
                        method.GetGenericParameters().Count != 0)
                    {
                        return null;
                    }

                    object? methodGenericContext = ownerContext is { } resolvedOwnerContext &&
                                                   method.GetDeclaringType() ==
                                                   resolvedOwnerContext.TypeParameterOwner
                        ? resolvedOwnerContext
                        : null;
                    var methodSignature = method.DecodeSignature(
                        SignatureTypeNameProvider.Instance,
                        methodGenericContext);
                    var methodParameters = TryReadConstructorParameters(
                        metadata,
                        methodSignature,
                        enumTypes);
                    return methodParameters is null
                        ? null
                        : new ConstructorCallTarget(
                            method.GetDeclaringType(),
                            methodHandle,
                            methodParameters);

                case HandleKind.MemberReference:
                    var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                    if (member.GetKind() != MemberReferenceKind.Method ||
                        metadata.GetString(member.Name) != ".ctor" ||
                        member.Parent.Kind is not (
                            HandleKind.TypeDefinition or
                            HandleKind.TypeReference or
                            HandleKind.TypeSpecification))
                    {
                        return null;
                    }

                    object? genericContext = null;
                    if (member.Parent.Kind == HandleKind.TypeSpecification)
                    {
                        if (typeSpecificationContext is null ||
                            member.Parent != typeSpecificationContext.Handle)
                        {
                            return null;
                        }

                        genericContext = typeSpecificationContext.SignatureContext;
                    }
                    var memberSignature = member.DecodeMethodSignature(
                        SignatureTypeNameProvider.Instance,
                        genericContext);
                    var memberParameters = TryReadConstructorParameters(
                        metadata,
                        memberSignature,
                        enumTypes);
                    return memberParameters is null
                        ? null
                        : new ConstructorCallTarget(member.Parent, default, memberParameters);

                default:
                    return null;
            }
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static IReadOnlyList<ConstructorParameter>? TryReadConstructorParameters(
        MetadataReader metadata,
        MethodSignature<SignatureTypeName> signature,
        EnumTypeCatalog enumTypes)
    {
        if (signature.Header.Kind != SignatureKind.Method ||
            !signature.Header.IsInstance ||
            signature.Header.IsGeneric ||
            signature.Header.HasExplicitThis ||
            signature.Header.CallingConvention != SignatureCallingConvention.Default ||
            signature.GenericParameterCount != 0 ||
            signature.RequiredParameterCount != signature.ParameterTypes.Length ||
            signature.ParameterTypes.Length > MaxConstructorInitializerArguments ||
            signature.ReturnType.PrimitiveType != PrimitiveTypeCode.Void ||
            signature.ReturnType.OuterCustomModifiers.Length != 0 ||
            signature.ReturnType.HasNestedCustomModifiers ||
            signature.ReturnType.IsRestrictedGenericArgument ||
            signature.ReturnType.HasPinnedQualifier ||
            signature.ParameterTypes.Any(type =>
                type.OuterCustomModifiers.Length != 0 ||
                type.HasNestedCustomModifiers ||
                type.IsRestrictedGenericArgument ||
                type.HasPinnedQualifier ||
                type.PrimitiveType == PrimitiveTypeCode.Void ||
                !HasCanonicalLocalGenericDefinitions(metadata, type) ||
                (type.IsExactNamedType &&
                 (IsPrimitiveAliasName(type.Text) || type.Text.Contains('`')))))
        {
            return null;
        }

        return signature.ParameterTypes
            .Select(type => new ConstructorParameter(CreateCliType(type, enumTypes), type))
            .ToArray();
    }

    private static bool TryGetInstructionName(IlInstruction instruction, out string name)
    {
        if (OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode) && opCode.Name is not null)
        {
            name = opCode.Name;
            return true;
        }

        name = string.Empty;
        return false;
    }

    private static void SkipConstructorNops(IReadOnlyList<IlInstruction> instructions, ref int index)
    {
        while (index < instructions.Count &&
               TryGetInstructionName(instructions[index], out var name) &&
               name == "nop")
        {
            index++;
        }
    }

    private static bool TryReadConstructorArgument(
        MetadataReader metadata,
        UserStringCatalog userStrings,
        byte[] il,
        IlInstruction instruction,
        string name,
        IReadOnlyDictionary<int, string> parameterNames,
        IReadOnlyList<CliType> parameterTypes,
        IReadOnlyList<SignatureTypeName> parameterSignatures,
        out ConstructorArgument argument)
    {
        if (TryReadConstructorParameterSlot(il, instruction, name, out var slot))
        {
            var parameterIndex = slot - 1;
            if (parameterIndex >= parameterTypes.Count ||
                parameterIndex >= parameterSignatures.Count)
            {
                argument = default;
                return false;
            }

            var parameterName = parameterNames.TryGetValue(slot, out var value) &&
                                !string.IsNullOrEmpty(value)
                ? value
                : $"arg{parameterIndex}";
            argument = new ConstructorArgument(
                parameterName,
                parameterTypes[parameterIndex],
                parameterSignatures[parameterIndex]);
            return true;
        }

        switch (name)
        {
            case "ldnull":
                argument = new ConstructorArgument(
                    "null",
                    new CliType("object", PrimitiveType: PrimitiveTypeCode.Object),
                    Signature: null);
                return true;
            case "ldstr":
                var token = BinaryPrimitives.ReadInt32LittleEndian(
                    il.AsSpan(instruction.OperandOffset, 4));
                if (!userStrings.TryGet(token, out var userString))
                {
                    argument = default;
                    return false;
                }

                argument = new ConstructorArgument(
                    EscapeCSharpString(userString),
                    new CliType("string", PrimitiveType: PrimitiveTypeCode.String),
                    Signature: null);
                return true;
            case "ldc.i4.m1":
                argument = new ConstructorArgument(
                    "-1",
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
                    Signature: null);
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
                argument = new ConstructorArgument(
                    name["ldc.i4.".Length..],
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
                    Signature: null);
                return true;
            case "ldc.i4.s":
                argument = new ConstructorArgument(
                    ((sbyte)il[instruction.OperandOffset]).ToString(CultureInfo.InvariantCulture),
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
                    Signature: null);
                return true;
            case "ldc.i4":
                argument = new ConstructorArgument(
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4))
                        .ToString(CultureInfo.InvariantCulture),
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
                    Signature: null);
                return true;
            case "ldc.i8":
                argument = new ConstructorArgument(
                    $"{BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(instruction.OperandOffset, 8)).ToString(CultureInfo.InvariantCulture)}L",
                    new CliType("long", PrimitiveType: PrimitiveTypeCode.Int64),
                    Signature: null);
                return true;
            case "ldc.r4":
                argument = new ConstructorArgument(
                    FormatSingleLiteral(BitConverter.Int32BitsToSingle(
                        BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4)))),
                    new CliType("float", PrimitiveType: PrimitiveTypeCode.Single),
                    Signature: null);
                return true;
            case "ldc.r8":
                argument = new ConstructorArgument(
                    FormatDoubleLiteral(BitConverter.Int64BitsToDouble(
                        BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(instruction.OperandOffset, 8)))),
                    new CliType("double", PrimitiveType: PrimitiveTypeCode.Double),
                    Signature: null);
                return true;
            default:
                argument = default;
                return false;
        }
    }

    private static bool TryFoldConstructorConditionalInt32ArrayElementArgument(
        byte[] il,
        IReadOnlyList<IlInstruction> instructions,
        int index,
        IReadOnlyDictionary<int, string> parameterNames,
        IReadOnlyList<CliType> parameterTypes,
        IReadOnlyList<SignatureTypeName> parameterSignatures,
        out ConstructorArgument argument,
        out int nextIndex)
    {
        argument = default;
        nextIndex = index;
        const int consumedInstructionCount = 11;
        if (index < 0 ||
            index + consumedInstructionCount >= instructions.Count ||
            !TryGetInstructionName(instructions[index], out var conditionLoadName) ||
            !TryReadConstructorParameterSlot(
                il,
                instructions[index],
                conditionLoadName,
                out var conditionSlot) ||
            !TryGetConstructorParameter(
                conditionSlot,
                parameterTypes,
                parameterSignatures,
                out var conditionType,
                out var conditionSignature) ||
            !IsCanonicalConstructorInt32(conditionType, conditionSignature) ||
            !TryGetInstructionName(instructions[index + 1], out var conditionBranchName) ||
            !TryReadConstructorForwardBranchTarget(
                il,
                instructions[index + 1],
                conditionBranchName,
                "brfalse.s",
                "brfalse",
                out var falseTarget) ||
            !TryGetInstructionName(instructions[index + 2], out var arrayLoadName) ||
            !TryReadConstructorParameterSlot(
                il,
                instructions[index + 2],
                arrayLoadName,
                out var arraySlot) ||
            !TryGetConstructorParameter(
                arraySlot,
                parameterTypes,
                parameterSignatures,
                out var arrayType,
                out var arraySignature) ||
            !IsCanonicalConstructorInt32Array(arrayType, arraySignature) ||
            !TryGetInstructionName(instructions[index + 3], out var indexLoadName) ||
            !TryReadConstructorParameterSlot(
                il,
                instructions[index + 3],
                indexLoadName,
                out var indexSlot) ||
            indexSlot != conditionSlot ||
            !TryGetInstructionName(instructions[index + 4], out var firstConstantName) ||
            !TryGetInstructionName(instructions[index + 5], out var firstOperatorName) ||
            !TryGetInstructionName(instructions[index + 6], out var secondConstantName) ||
            !TryGetInstructionName(instructions[index + 7], out var secondOperatorName) ||
            !TryGetInstructionName(instructions[index + 8], out var elementLoadName) ||
            elementLoadName != "ldelem.i4" ||
            instructions[index + 8].OperandSize != 0 ||
            !TryGetInstructionName(instructions[index + 9], out var joinBranchName) ||
            !TryReadConstructorForwardBranchTarget(
                il,
                instructions[index + 9],
                joinBranchName,
                "br.s",
                "br",
                out var joinTarget) ||
            !TryGetInstructionName(instructions[index + 10], out var falseValueName) ||
            falseValueName != "ldc.i4.0" ||
            instructions[index + 10].OperandSize != 0 ||
            falseTarget != instructions[index + 10].Offset ||
            joinTarget != instructions[index + consumedInstructionCount].Offset)
        {
            return false;
        }

        string indexExpression;
        if (firstConstantName == "ldc.i4.1" &&
            firstOperatorName == "sub" &&
            secondConstantName == "ldc.i4.2" &&
            secondOperatorName == "mul")
        {
            indexExpression =
                $"({GetConstructorParameterName(parameterNames, conditionSlot)} - 1) * 2";
        }
        else if (firstConstantName == "ldc.i4.2" &&
                 firstOperatorName == "mul" &&
                 secondConstantName == "ldc.i4.1" &&
                 secondOperatorName == "sub")
        {
            indexExpression =
                $"{GetConstructorParameterName(parameterNames, conditionSlot)} * 2 - 1";
        }
        else
        {
            return false;
        }

        var conditionName = GetConstructorParameterName(parameterNames, conditionSlot);
        var arrayName = GetConstructorParameterName(parameterNames, arraySlot);
        argument = new ConstructorArgument(
            $"{conditionName} != 0 ? {arrayName}[{indexExpression}] : 0",
            conditionType,
            conditionSignature,
            IsFoldedExpression: true,
            RequiresDirectBase: true,
            RequiresExactTargetSignature: true);
        nextIndex = index + consumedInstructionCount;
        return true;
    }

    private static bool TryReadConstructorParameterSlot(
        byte[] il,
        IlInstruction instruction,
        string name,
        out int slot)
    {
        slot = name switch
        {
            "ldarg.1" when instruction.OperandSize == 0 => 1,
            "ldarg.2" when instruction.OperandSize == 0 => 2,
            "ldarg.3" when instruction.OperandSize == 0 => 3,
            "ldarg.s" when instruction.OperandSize == 1 => il[instruction.OperandOffset],
            "ldarg" when instruction.OperandSize == 2 =>
                BinaryPrimitives.ReadUInt16LittleEndian(
                    il.AsSpan(instruction.OperandOffset, 2)),
            _ => -1
        };
        return slot > 0;
    }

    private static bool TryGetConstructorParameter(
        int slot,
        IReadOnlyList<CliType> parameterTypes,
        IReadOnlyList<SignatureTypeName> parameterSignatures,
        out CliType type,
        out SignatureTypeName signature)
    {
        var index = slot - 1;
        if (index < 0 ||
            index >= parameterTypes.Count ||
            index >= parameterSignatures.Count)
        {
            type = new CliType(string.Empty);
            signature = new SignatureTypeName(string.Empty);
            return false;
        }

        type = parameterTypes[index];
        signature = parameterSignatures[index];
        return true;
    }

    private static string GetConstructorParameterName(
        IReadOnlyDictionary<int, string> parameterNames,
        int slot) =>
        parameterNames.TryGetValue(slot, out var name) && !string.IsNullOrEmpty(name)
            ? name
            : $"arg{slot - 1}";

    private static bool IsCanonicalConstructorInt32(
        CliType type,
        SignatureTypeName signature) =>
        type.Text == "int" &&
        type.EnumUnderlyingType is null &&
        type.NominalHandle.IsNil &&
        type.RawTypeKind == 0 &&
        !type.IsExactNamedType &&
        type.SignatureKind == SignatureTypeKind.Unknown &&
        type.PrimitiveType == PrimitiveTypeCode.Int32 &&
        !type.IsByReference &&
        !type.HasPinnedQualifier &&
        signature.Text == "int" &&
        signature.PrimitiveType == PrimitiveTypeCode.Int32 &&
        signature.OuterCustomModifiers.Length == 0 &&
        !signature.HasNestedCustomModifiers &&
        !signature.IsRestrictedGenericArgument &&
        signature.NominalHandle.IsNil &&
        signature.RawTypeKind == 0 &&
        signature.SignatureKind == SignatureTypeKind.Unknown &&
        !signature.IsExactNamedType &&
        !signature.IsByReference &&
        !signature.HasPinnedQualifier &&
        signature.GenericArguments.IsDefaultOrEmpty &&
        !signature.IsCanonicalGenericInstantiation &&
        signature.GenericDefinitionHandle.IsNil &&
        signature.GenericDefinitionRawTypeKind == 0 &&
        signature.GenericDefinitionSignatureKind == SignatureTypeKind.Unknown &&
        signature.GenericDefinitionText is null &&
        signature.TypeParameterSlot is null &&
        signature.SzArrayElementType is null;

    private static bool IsCanonicalConstructorInt32Array(
        CliType type,
        SignatureTypeName signature) =>
        type.Text == "int[]" &&
        type.EnumUnderlyingType is null &&
        type.NominalHandle.IsNil &&
        type.RawTypeKind == 0 &&
        !type.IsExactNamedType &&
        type.SignatureKind == SignatureTypeKind.Unknown &&
        type.PrimitiveType is null &&
        !type.IsByReference &&
        !type.HasPinnedQualifier &&
        signature.Text == "int[]" &&
        signature.PrimitiveType is null &&
        signature.OuterCustomModifiers.Length == 0 &&
        !signature.HasNestedCustomModifiers &&
        !signature.IsRestrictedGenericArgument &&
        signature.NominalHandle.IsNil &&
        signature.RawTypeKind == 0 &&
        signature.SignatureKind == SignatureTypeKind.Unknown &&
        !signature.IsExactNamedType &&
        !signature.IsByReference &&
        !signature.HasPinnedQualifier &&
        signature.GenericArguments.IsDefaultOrEmpty &&
        !signature.IsCanonicalGenericInstantiation &&
        signature.GenericDefinitionHandle.IsNil &&
        signature.GenericDefinitionRawTypeKind == 0 &&
        signature.GenericDefinitionSignatureKind == SignatureTypeKind.Unknown &&
        signature.GenericDefinitionText is null &&
        signature.TypeParameterSlot is null &&
        signature.SzArrayElementType is { } elementType &&
        IsCanonicalConstructorInt32(
            new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
            elementType);

    private static bool TryReadConstructorForwardBranchTarget(
        byte[] il,
        IlInstruction instruction,
        string name,
        string shortName,
        string longName,
        out int target)
    {
        long candidate;
        if (name == shortName && instruction.OperandSize == 1)
        {
            candidate = (long)instruction.OperandOffset + 1 +
                        (sbyte)il[instruction.OperandOffset];
        }
        else if (name == longName && instruction.OperandSize == 4)
        {
            candidate = (long)instruction.OperandOffset + 4 +
                        BinaryPrimitives.ReadInt32LittleEndian(
                            il.AsSpan(instruction.OperandOffset, 4));
        }
        else
        {
            target = -1;
            return false;
        }

        if (candidate <= instruction.Offset || candidate > int.MaxValue)
        {
            target = -1;
            return false;
        }

        target = (int)candidate;
        return true;
    }

    private static bool TryFoldInt32ArrayConstructorArgument(
        MetadataReader metadata,
        byte[] il,
        IlInstruction instruction,
        ConstructorArgument lengthArgument,
        out ConstructorArgument argument)
    {
        argument = default;
        if (lengthArgument.IsFoldedExpression ||
            lengthArgument.Signature is not null ||
            lengthArgument.Type.PrimitiveType != PrimitiveTypeCode.Int32 ||
            instruction.OperandSize != 4 ||
            !int.TryParse(
                lengthArgument.Expression,
                NumberStyles.AllowLeadingSign,
                CultureInfo.InvariantCulture,
                out var length) ||
            length < 0 ||
            length > MaxConstructorArrayLength)
        {
            return false;
        }

        try
        {
            var token = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instruction.OperandOffset, 4));
            var handle = MetadataTokens.EntityHandle(token);
            if (handle.Kind != HandleKind.TypeReference ||
                !TryReadTrustedSystemRuntimeTypeReference(
                    metadata,
                    (TypeReferenceHandle)handle,
                    "Int32",
                    out _))
            {
                return false;
            }

            var elementSignature = SignatureTypeNameProvider.Instance.GetPrimitiveType(
                PrimitiveTypeCode.Int32);
            argument = new ConstructorArgument(
                $"new int[{length.ToString(CultureInfo.InvariantCulture)}]",
                new CliType("int[]"),
                Signature: null,
                IsFoldedExpression: true,
                FoldedArrayElementSignature: elementSignature);
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            argument = default;
            return false;
        }
    }

    private static bool TryFoldTypeOfConstructorArgument(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        byte[] il,
        IReadOnlyList<IlInstruction> instructions,
        int index,
        SignatureGenericContext? ownerContext,
        out ConstructorArgument argument)
    {
        argument = default;
        if (ownerContext is not { } genericContext ||
            !genericContext.TypeArguments.IsDefault ||
            genericContext.TypeParameterOwner.IsNil ||
            genericContext.TypeParameterCount <= 0 ||
            index + 1 >= instructions.Count ||
            instructions[index].OperandSize != 4 ||
            !TryGetInstructionName(instructions[index + 1], out var callName) ||
            callName != "call" ||
            instructions[index + 1].OperandSize != 4)
        {
            return false;
        }

        try
        {
            var typeToken = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instructions[index].OperandOffset, 4));
            var typeHandle = MetadataTokens.EntityHandle(typeToken);
            var callToken = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instructions[index + 1].OperandOffset, 4));
            var callHandle = MetadataTokens.EntityHandle(callToken);
            if (typeHandle.Kind != HandleKind.TypeSpecification ||
                callHandle.Kind != HandleKind.MemberReference ||
                !TryReadCanonicalConstructorTypeParameter(
                    metadata,
                    (TypeSpecificationHandle)typeHandle,
                    genericContext,
                    out var typeParameter) ||
                !TryReadTrustedGetTypeFromHandle(
                    metadata,
                    (MemberReferenceHandle)callHandle,
                    out var systemType))
            {
                return false;
            }

            argument = new ConstructorArgument(
                $"typeof({typeParameter.Text})",
                CreateCliType(systemType, enumTypes),
                systemType,
                IsFoldedExpression: true);
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            argument = default;
            return false;
        }
    }

    private static bool TryReadCanonicalConstructorTypeParameter(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        SignatureGenericContext ownerContext,
        out SignatureTypeName typeParameter)
    {
        typeParameter = new SignatureTypeName(string.Empty);
        var specification = metadata.GetTypeSpecification(handle);
        var reader = metadata.GetBlobReader(specification.Signature);
        if (reader.Length is < 2 or > MaxConstructorTypeSignatureBytes ||
            reader.ReadByte() != 0x13 || // VAR
            !TryReadCanonicalCompressedInteger(ref reader, out var slot) ||
            reader.RemainingBytes != 0 ||
            slot < 0 ||
            slot >= ownerContext.TypeParameterCount)
        {
            return false;
        }

        typeParameter = specification.DecodeSignature(
            SignatureTypeNameProvider.Instance,
            ownerContext);
        return typeParameter.Text == $"!{slot}" &&
               typeParameter.TypeParameterSlot is { } resolvedSlot &&
               resolvedSlot.Owner == ownerContext.TypeParameterOwner &&
               resolvedSlot.Index == slot &&
               AreSameConstructorSignature(typeParameter, typeParameter);
    }

    private static bool TryReadTrustedGetTypeFromHandle(
        MetadataReader metadata,
        MemberReferenceHandle handle,
        out SignatureTypeName systemType)
    {
        systemType = new SignatureTypeName(string.Empty);
        var member = metadata.GetMemberReference(handle);
        if (member.GetKind() != MemberReferenceKind.Method ||
            !TryReadBoundedGenericAttributeName(metadata, member.Name, out var methodName) ||
            methodName != "GetTypeFromHandle" ||
            member.Parent.Kind != HandleKind.TypeReference)
        {
            return false;
        }

        var reader = metadata.GetBlobReader(member.Signature);
        if (reader.Length is < 6 or > MaxConstructorTypeSignatureBytes ||
            reader.ReadByte() != 0x00 || // static DEFAULT
            reader.ReadByte() != 0x01 || // exactly one parameter, canonical encoding
            reader.ReadByte() != 0x12 || // CLASS return
            !TryReadCanonicalTypeHandle(ref reader, out var returnHandle) ||
            returnHandle != member.Parent ||
            reader.RemainingBytes == 0 ||
            reader.ReadByte() != 0x11 || // VALUETYPE parameter
            !TryReadCanonicalTypeHandle(ref reader, out var parameterHandle) ||
            reader.RemainingBytes != 0 ||
            returnHandle.Kind != HandleKind.TypeReference ||
            parameterHandle.Kind != HandleKind.TypeReference ||
            !TryReadTrustedSystemRuntimeTypeReference(
                metadata,
                (TypeReferenceHandle)returnHandle,
                "Type",
                out var returnAssembly) ||
            !TryReadTrustedSystemRuntimeTypeReference(
                metadata,
                (TypeReferenceHandle)parameterHandle,
                "RuntimeTypeHandle",
                out var parameterAssembly) ||
            returnAssembly != parameterAssembly)
        {
            return false;
        }

        systemType = SignatureTypeNameProvider.Instance.GetTypeFromReference(
            metadata,
            (TypeReferenceHandle)returnHandle,
            rawTypeKind: (byte)SignatureTypeKind.Class);
        var runtimeTypeHandle = SignatureTypeNameProvider.Instance.GetTypeFromReference(
            metadata,
            (TypeReferenceHandle)parameterHandle,
            rawTypeKind: (byte)SignatureTypeKind.ValueType);
        return systemType.IsExactNamedType &&
               systemType.NominalHandle == returnHandle &&
               systemType.RawTypeKind == (byte)SignatureTypeKind.Class &&
               systemType.SignatureKind == SignatureTypeKind.Class &&
               runtimeTypeHandle.IsExactNamedType &&
               runtimeTypeHandle.NominalHandle == parameterHandle &&
               runtimeTypeHandle.RawTypeKind == (byte)SignatureTypeKind.ValueType &&
               runtimeTypeHandle.SignatureKind == SignatureTypeKind.ValueType;
    }

    private static bool TryReadTrustedSystemRuntimeTypeReference(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        string expectedName,
        out AssemblyReferenceHandle assemblyHandle)
    {
        assemblyHandle = default;
        var reference = metadata.GetTypeReference(handle);
        if (!TryReadBoundedGenericAttributeName(metadata, reference.Namespace, out var @namespace) ||
            @namespace != "System" ||
            !TryReadBoundedGenericAttributeName(metadata, reference.Name, out var name) ||
            name != expectedName ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        assemblyHandle = (AssemblyReferenceHandle)reference.ResolutionScope;
        var assembly = metadata.GetAssemblyReference(assemblyHandle);
        if (!TryReadBoundedGenericAttributeName(metadata, assembly.Name, out var assemblyName) ||
            assemblyName != "System.Runtime")
        {
            assemblyHandle = default;
            return false;
        }

        return IsTrustedFrameworkAssembly(
            metadata,
            assemblyName,
            assembly.PublicKeyOrToken,
            assembly.Culture,
            assembly.Flags);
    }

    private static bool TryFoldDefaultNullableLocalArgument(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        byte[] il,
        IReadOnlyList<IlInstruction> instructions,
        int index,
        StandaloneSignatureHandle localSignature,
        out ConstructorArgument argument,
        out int localSlot)
    {
        argument = default;
        localSlot = -1;
        if (localSignature.IsNil || index + 2 >= instructions.Count)
        {
            return false;
        }

        try
        {
            if (!TryGetInstructionName(instructions[index], out var addressName) ||
                !TryReadConstructorLocalSlot(
                    il,
                    instructions[index],
                    addressName,
                    allowAddress: true,
                    allowStore: false,
                    out localSlot) ||
                localSlot != 0 ||
                !TryGetInstructionName(instructions[index + 1], out var initializeName) ||
                initializeName != "initobj" ||
                instructions[index + 1].OperandSize != 4 ||
                !TryGetInstructionName(instructions[index + 2], out var loadName) ||
                !TryReadConstructorLocalSlot(
                    il,
                    instructions[index + 2],
                    loadName,
                    allowAddress: false,
                    allowStore: false,
                    out var loadedSlot) ||
                loadedSlot != localSlot)
            {
                return false;
            }

            var token = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instructions[index + 1].OperandOffset, 4));
            var handle = MetadataTokens.EntityHandle(token);
            if (handle.Kind != HandleKind.TypeSpecification ||
                !TryReadTrustedNullableType(
                    metadata,
                    (TypeSpecificationHandle)handle,
                    out var initializedType,
                    out _) ||
                !TryReadTrustedNullableLocalSignature(
                    metadata,
                    localSignature,
                    out var localType) ||
                !AreSameConstructorSignature(localType, initializedType))
            {
                return false;
            }

            argument = new ConstructorArgument(
                $"default({localType.Text})",
                CreateCliType(localType, enumTypes),
                localType,
                IsFoldedExpression: true);
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            argument = default;
            localSlot = -1;
            return false;
        }
    }

    private static bool TryReadTrustedNullableLocalSignature(
        MetadataReader metadata,
        StandaloneSignatureHandle handle,
        out SignatureTypeName nullableSignature)
    {
        nullableSignature = new SignatureTypeName(string.Empty);
        var signature = metadata.GetStandaloneSignature(handle);
        var reader = metadata.GetBlobReader(signature.Signature);
        if (reader.Length is < 3 or > MaxConstructorLocalSignatureBytes ||
            reader.ReadByte() != 0x07 || // LOCAL_SIG
            reader.ReadByte() != 0x01 || // exactly one local, canonical encoding
            reader.RemainingBytes == 0)
        {
            return false;
        }

        return TryReadTrustedNullableType(
                   metadata,
                   ref reader,
                   out nullableSignature,
                   out _) &&
               reader.RemainingBytes == 0;
    }

    private static bool ConstructorTailUsesFoldedLocal(
        IReadOnlyList<IlInstruction> instructions,
        int startIndex,
        IReadOnlySet<int> foldedLocalSlots)
    {
        if (foldedLocalSlots.Count == 0)
        {
            return false;
        }

        for (var index = startIndex; index < instructions.Count; index++)
        {
            if (!TryGetInstructionName(instructions[index], out var name))
            {
                return true;
            }

            if (IsConstructorLocalAccess(name))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsConstructorLocalAccess(string name) =>
        name is
            "ldloc.0" or "ldloc.1" or "ldloc.2" or "ldloc.3" or
            "ldloc.s" or "ldloc" or "ldloca.s" or "ldloca" or
            "stloc.0" or "stloc.1" or "stloc.2" or "stloc.3" or
            "stloc.s" or "stloc";

    private static bool TryReadConstructorLocalSlot(
        byte[] il,
        IlInstruction instruction,
        string name,
        bool allowAddress,
        bool allowStore,
        out int localSlot)
    {
        localSlot = name switch
        {
            "ldloc.0" when instruction.OperandSize == 0 => 0,
            "ldloc.1" when instruction.OperandSize == 0 => 1,
            "ldloc.2" when instruction.OperandSize == 0 => 2,
            "ldloc.3" when instruction.OperandSize == 0 => 3,
            "ldloc.s" when instruction.OperandSize == 1 => il[instruction.OperandOffset],
            "ldloc" when instruction.OperandSize == 2 =>
                BinaryPrimitives.ReadUInt16LittleEndian(
                    il.AsSpan(instruction.OperandOffset, 2)),
            "ldloca.s" when allowAddress && instruction.OperandSize == 1 =>
                il[instruction.OperandOffset],
            "ldloca" when allowAddress && instruction.OperandSize == 2 =>
                BinaryPrimitives.ReadUInt16LittleEndian(
                    il.AsSpan(instruction.OperandOffset, 2)),
            "stloc.0" when allowStore && instruction.OperandSize == 0 => 0,
            "stloc.1" when allowStore && instruction.OperandSize == 0 => 1,
            "stloc.2" when allowStore && instruction.OperandSize == 0 => 2,
            "stloc.3" when allowStore && instruction.OperandSize == 0 => 3,
            "stloc.s" when allowStore && instruction.OperandSize == 1 =>
                il[instruction.OperandOffset],
            "stloc" when allowStore && instruction.OperandSize == 2 =>
                BinaryPrimitives.ReadUInt16LittleEndian(
                    il.AsSpan(instruction.OperandOffset, 2)),
            _ => -1
        };
        return localSlot >= 0;
    }

    private static bool TryFoldNullableConstructorArgument(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        byte[] il,
        IlInstruction instruction,
        ConstructorArgument source,
        out ConstructorArgument argument)
    {
        argument = default;
        if (source.IsFoldedExpression || instruction.OperandSize != 4)
        {
            return false;
        }

        try
        {
            var token = BinaryPrimitives.ReadInt32LittleEndian(
                il.AsSpan(instruction.OperandOffset, 4));
            var handle = MetadataTokens.EntityHandle(token);
            if (handle.Kind != HandleKind.MemberReference)
            {
                return false;
            }

            var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
            if (member.GetKind() != MemberReferenceKind.Method ||
                metadata.GetString(member.Name) != ".ctor" ||
                member.Parent.Kind != HandleKind.TypeSpecification ||
                !HasExactNullableConstructorSignature(metadata, member.Signature) ||
                !TryReadTrustedNullableType(
                    metadata,
                    (TypeSpecificationHandle)member.Parent,
                    out var nullableSignature,
                    out var elementSignature))
            {
                return false;
            }

            var elementType = CreateCliType(elementSignature, enumTypes);
            if (!IsExactConstructorAssignment(
                    source.Type,
                    elementType,
                    source.Signature,
                    elementSignature))
            {
                return false;
            }

            argument = new ConstructorArgument(
                $"new {nullableSignature.Text}({source.Expression})",
                CreateCliType(nullableSignature, enumTypes),
                nullableSignature,
                IsFoldedExpression: true);
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool HasExactNullableConstructorSignature(
        MetadataReader metadata,
        BlobHandle signature)
    {
        var reader = metadata.GetBlobReader(signature);
        return reader.Length == 5 &&
               reader.ReadByte() == 0x20 && // HASTHIS | DEFAULT
               reader.ReadByte() == 0x01 && // one parameter
               reader.ReadByte() == 0x01 && // VOID
               reader.ReadByte() == 0x13 && // VAR
               reader.ReadByte() == 0x00 && // !0
               reader.RemainingBytes == 0;
    }

    private static bool TryReadTrustedNullableType(
        MetadataReader metadata,
        TypeSpecificationHandle typeSpecification,
        out SignatureTypeName nullableSignature,
        out SignatureTypeName elementSignature)
    {
        nullableSignature = new SignatureTypeName(string.Empty);
        elementSignature = new SignatureTypeName(string.Empty);

        var specification = metadata.GetTypeSpecification(typeSpecification);
        var reader = metadata.GetBlobReader(specification.Signature);
        return reader.Length is > 0 and <= MaxConstructorTypeSignatureBytes &&
               TryReadTrustedNullableType(
                   metadata,
                   ref reader,
                   out nullableSignature,
                   out elementSignature) &&
               reader.RemainingBytes == 0;
    }

    private static bool TryReadTrustedNullableType(
        MetadataReader metadata,
        ref BlobReader reader,
        out SignatureTypeName nullableSignature,
        out SignatureTypeName elementSignature)
    {
        nullableSignature = new SignatureTypeName(string.Empty);
        elementSignature = new SignatureTypeName(string.Empty);
        if (reader.RemainingBytes < 2 ||
            reader.ReadByte() != 0x15 || // GENERICINST
            reader.ReadByte() != 0x11) // VALUETYPE
        {
            return false;
        }

        if (!TryReadCanonicalTypeHandle(ref reader, out var nullableHandle) ||
            nullableHandle.Kind != HandleKind.TypeReference ||
            reader.ReadByte() != 0x01 || // one generic argument, canonical encoding
            !TryReadNullableElementSignature(metadata, ref reader, out elementSignature) ||
            !IsTrustedSystemNullableReference(
                metadata,
                (TypeReferenceHandle)nullableHandle))
        {
            return false;
        }

        var nullableDefinition = SignatureTypeNameProvider.Instance.GetTypeFromReference(
            metadata,
            (TypeReferenceHandle)nullableHandle,
            rawTypeKind: (byte)SignatureTypeKind.ValueType);
        if (!nullableDefinition.IsExactNamedType ||
            nullableDefinition.NominalHandle != nullableHandle ||
            nullableDefinition.RawTypeKind != (byte)SignatureTypeKind.ValueType ||
            nullableDefinition.SignatureKind != SignatureTypeKind.ValueType)
        {
            return false;
        }

        nullableSignature = SignatureTypeNameProvider.Instance.GetGenericInstantiation(
            nullableDefinition,
            [elementSignature]);
        return nullableSignature.IsCanonicalGenericInstantiation &&
               nullableSignature.GenericDefinitionHandle == nullableHandle &&
               nullableSignature.GenericDefinitionRawTypeKind ==
               (byte)SignatureTypeKind.ValueType &&
               nullableSignature.GenericDefinitionSignatureKind ==
               SignatureTypeKind.ValueType &&
               AreSameConstructorSignature(nullableSignature, nullableSignature) &&
               HasCanonicalLocalGenericDefinitions(metadata, nullableSignature);
    }

    private static bool TryReadNullableElementSignature(
        MetadataReader metadata,
        ref BlobReader reader,
        out SignatureTypeName signature)
    {
        signature = new SignatureTypeName(string.Empty);
        if (reader.RemainingBytes == 0)
        {
            return false;
        }

        var elementType = reader.ReadByte();
        var primitiveType = elementType switch
        {
            0x02 => PrimitiveTypeCode.Boolean,
            0x03 => PrimitiveTypeCode.Char,
            0x04 => PrimitiveTypeCode.SByte,
            0x05 => PrimitiveTypeCode.Byte,
            0x06 => PrimitiveTypeCode.Int16,
            0x07 => PrimitiveTypeCode.UInt16,
            0x08 => PrimitiveTypeCode.Int32,
            0x09 => PrimitiveTypeCode.UInt32,
            0x0A => PrimitiveTypeCode.Int64,
            0x0B => PrimitiveTypeCode.UInt64,
            0x0C => PrimitiveTypeCode.Single,
            0x0D => PrimitiveTypeCode.Double,
            0x18 => PrimitiveTypeCode.IntPtr,
            0x19 => PrimitiveTypeCode.UIntPtr,
            _ => (PrimitiveTypeCode?)null
        };
        if (primitiveType is not null)
        {
            signature = SignatureTypeNameProvider.Instance.GetPrimitiveType(
                primitiveType.Value);
            return true;
        }

        if (elementType != 0x11) // VALUETYPE
        {
            return false;
        }

        if (!TryReadCanonicalTypeHandle(ref reader, out var handle) ||
            handle.Kind != HandleKind.TypeDefinition)
        {
            return false;
        }

        var definitionHandle = (TypeDefinitionHandle)handle;
        var definition = metadata.GetTypeDefinition(definitionHandle);
        var attributes = definition.GetCustomAttributes();
        if (!TryReadBoundedGenericAttributeName(
                metadata,
                definition.Name,
                out var name) ||
            !TryReadBoundedGenericAttributeName(
                metadata,
                definition.Namespace,
                out _))
        {
            return false;
        }

        var typeAttributes = definition.Attributes;
        if (!definition.GetDeclaringType().IsNil ||
            definition.GetGenericParameters().Count != 0 ||
            !HasTrustedNullableValueTypeBase(metadata, definition) ||
            (typeAttributes & TypeAttributes.ClassSemanticsMask) == TypeAttributes.Interface ||
            typeAttributes.HasFlag(TypeAttributes.Abstract) ||
            !typeAttributes.HasFlag(TypeAttributes.Sealed) ||
            typeAttributes.HasFlag(TypeAttributes.Import) ||
            typeAttributes.HasFlag(TypeAttributes.WindowsRuntime) ||
            name.Length == 0 ||
            name.Contains('`') ||
            attributes.Count > MaxGenericCustomAttributesPerTarget ||
            HasCustomAttribute(
                metadata,
                attributes,
                "System.Runtime.CompilerServices.IsByRefLikeAttribute"))
        {
            return false;
        }

        signature = SignatureTypeNameProvider.Instance.GetTypeFromDefinition(
            metadata,
            definitionHandle,
            rawTypeKind: (byte)SignatureTypeKind.ValueType);
        return signature.IsExactNamedType &&
               signature.NominalHandle == definitionHandle &&
               signature.RawTypeKind == (byte)SignatureTypeKind.ValueType &&
               signature.SignatureKind == SignatureTypeKind.ValueType &&
               signature.Text.Length <= MaxGenericAttributeTypeNameCharacters;
    }

    private static bool TryReadCanonicalTypeHandle(
        ref BlobReader reader,
        out EntityHandle handle)
    {
        var start = reader.Offset;
        handle = reader.ReadTypeHandle();
        var codedIndex = CodedIndex.TypeDefOrRefOrSpec(handle);
        var expectedBytes = codedIndex switch
        {
            < 0x80 => 1,
            < 0x4000 => 2,
            _ => 4
        };
        return reader.Offset - start == expectedBytes;
    }

    private static bool TryReadCanonicalCompressedInteger(
        ref BlobReader reader,
        out int value)
    {
        var start = reader.Offset;
        if (!reader.TryReadCompressedInteger(out value) || value < 0)
        {
            return false;
        }

        var expectedBytes = value switch
        {
            < 0x80 => 1,
            < 0x4000 => 2,
            _ => 4
        };
        return reader.Offset - start == expectedBytes;
    }

    private static bool HasTrustedNullableValueTypeBase(
        MetadataReader metadata,
        TypeDefinition definition)
    {
        if (definition.BaseType.Kind != HandleKind.TypeReference)
        {
            return false;
        }

        var reference = metadata.GetTypeReference(
            (TypeReferenceHandle)definition.BaseType);
        if (metadata.GetString(reference.Namespace) != "System" ||
            metadata.GetString(reference.Name) != "ValueType" ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        var assembly = metadata.GetAssemblyReference(
            (AssemblyReferenceHandle)reference.ResolutionScope);
        var name = metadata.GetString(assembly.Name);
        return name == "System.Runtime" &&
               IsTrustedFrameworkAssembly(
                   metadata,
                   name,
                   assembly.PublicKeyOrToken,
                   assembly.Culture,
                   assembly.Flags);
    }

    private static bool IsTrustedSystemNullableReference(
        MetadataReader metadata,
        TypeReferenceHandle handle)
    {
        var reference = metadata.GetTypeReference(handle);
        if (metadata.GetString(reference.Namespace) != "System" ||
            metadata.GetString(reference.Name) != "Nullable`1" ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        var assembly = metadata.GetAssemblyReference(
            (AssemblyReferenceHandle)reference.ResolutionScope);
        var name = metadata.GetString(assembly.Name);
        return name == "System.Runtime" &&
               IsTrustedFrameworkAssembly(
                   metadata,
                   name,
                   assembly.PublicKeyOrToken,
                   assembly.Culture,
                   assembly.Flags);
    }

    private static bool TryRenderConstructorArgument(
        MetadataReader metadata,
        string expression,
        CliType sourceType,
        SignatureTypeName? sourceSignature,
        SignatureTypeName? foldedArrayElementSignature,
        bool requiresExactTargetSignature,
        ConstructorParameter target,
        bool allowVerifiedDirectBaseConversion,
        out string rendered)
    {
        var targetType = target.Type;
        rendered = expression;
        if (expression == "null")
        {
            if (targetType.HasPinnedQualifier ||
                target.Signature.HasPinnedQualifier ||
                !IsConstructorReferenceType(targetType, target.Signature))
            {
                return false;
            }

            rendered = $"(({targetType.Text})null!)";
            return true;
        }

        if (foldedArrayElementSignature is not null)
        {
            return allowVerifiedDirectBaseConversion &&
                   target.Signature.OuterCustomModifiers.Length == 0 &&
                   !target.Signature.HasNestedCustomModifiers &&
                   !target.Signature.IsRestrictedGenericArgument &&
                   !target.Signature.IsByReference &&
                   !target.Signature.HasPinnedQualifier &&
                   target.Signature.SzArrayElementType is { } targetElement &&
                   AreSameConstructorSignature(foldedArrayElementSignature, targetElement);
        }

        if (requiresExactTargetSignature)
        {
            return sourceSignature is not null &&
                   AreSameConstructorSignature(sourceSignature, target.Signature) &&
                   IsExactConstructorAssignment(
                       sourceType,
                       targetType,
                       sourceSignature,
                       target.Signature);
        }

        if (IsExactConstructorAssignment(
                sourceType,
                targetType,
                sourceSignature,
                target.Signature))
        {
            if (sourceType.Text.EndsWith('?') && !targetType.Text.EndsWith('?'))
            {
                rendered += "!";
            }

            return true;
        }

        if (allowVerifiedDirectBaseConversion &&
            sourceSignature is not null &&
            IsVerifiedConstructorLocalDirectBaseUpcast(
                metadata,
                sourceSignature,
                target.Signature))
        {
            return true;
        }

        if (allowVerifiedDirectBaseConversion &&
            sourceSignature is not null &&
            IsVerifiedConstructorTrustedIListToIEnumerableUpcast(
                metadata,
                sourceSignature,
                target.Signature))
        {
            rendered = $"({targetType.Text}){expression}";
            return true;
        }

        if (targetType.PrimitiveType == PrimitiveTypeCode.Boolean)
        {
            if (sourceType.PrimitiveType != PrimitiveTypeCode.Int32 ||
                expression is not ("0" or "1"))
            {
                return false;
            }

            rendered = expression == "1" ? "true" : "false";
            return true;
        }

        if (sourceType.PrimitiveType == PrimitiveTypeCode.Boolean)
        {
            return false;
        }

        var sourceIsEnum = TryGetKnownEnumUnderlyingType(sourceType, out var sourceUnderlyingType);
        var targetIsEnum = TryGetKnownEnumUnderlyingType(targetType, out var targetUnderlyingType);
        var sourceFamily = sourceIsEnum
            ? IntegralStackFamily(sourceUnderlyingType)
            : IntegralStackFamily(sourceType.PrimitiveType);
        var targetFamily = targetIsEnum
            ? IntegralStackFamily(targetUnderlyingType)
            : IntegralStackFamily(targetType.PrimitiveType);
        if (sourceFamily < 0 || sourceFamily != targetFamily)
        {
            return false;
        }

        rendered = $"unchecked(({targetType.Text}){expression})";
        return true;
    }

    private static bool IsVerifiedConstructorLocalDirectBaseUpcast(
        MetadataReader metadata,
        SignatureTypeName source,
        SignatureTypeName target)
    {
        if (!source.IsCanonicalGenericInstantiation ||
            source.GenericArguments.IsDefaultOrEmpty ||
            source.GenericArguments.Length > MaxGenericParametersPerOwner ||
            source.GenericDefinitionHandle.Kind != HandleKind.TypeDefinition ||
            source.GenericDefinitionRawTypeKind != (byte)SignatureTypeKind.Class ||
            source.GenericDefinitionSignatureKind != SignatureTypeKind.Class ||
            !target.IsExactNamedType ||
            target.NominalHandle.Kind != HandleKind.TypeDefinition ||
            target.RawTypeKind != (byte)SignatureTypeKind.Class ||
            target.SignatureKind != SignatureTypeKind.Class ||
            !AreSameConstructorSignature(source, source) ||
            !AreSameConstructorSignature(target, target) ||
            !HasCanonicalLocalGenericDefinitions(metadata, source))
        {
            return false;
        }

        try
        {
            var sourceHandle = (TypeDefinitionHandle)source.GenericDefinitionHandle;
            var targetHandle = (TypeDefinitionHandle)target.NominalHandle;
            var sourceDefinition = metadata.GetTypeDefinition(sourceHandle);
            var targetDefinition = metadata.GetTypeDefinition(targetHandle);
            var sourceParameters = sourceDefinition.GetGenericParameters();
            var sourceAttributes = sourceDefinition.Attributes;
            var targetAttributes = targetDefinition.Attributes;
            if (sourceHandle == targetHandle ||
                !sourceDefinition.GetDeclaringType().IsNil ||
                !targetDefinition.GetDeclaringType().IsNil ||
                sourceDefinition.BaseType != targetHandle ||
                sourceParameters.Count != source.GenericArguments.Length ||
                targetDefinition.GetGenericParameters().Count != 0 ||
                (sourceAttributes & TypeAttributes.ClassSemanticsMask) == TypeAttributes.Interface ||
                sourceAttributes.HasFlag(TypeAttributes.Import) ||
                sourceAttributes.HasFlag(TypeAttributes.WindowsRuntime) ||
                (targetAttributes & TypeAttributes.ClassSemanticsMask) == TypeAttributes.Interface ||
                targetAttributes.HasFlag(TypeAttributes.Sealed) ||
                targetAttributes.HasFlag(TypeAttributes.Import) ||
                targetAttributes.HasFlag(TypeAttributes.WindowsRuntime) ||
                !TryReadBoundedGenericAttributeName(
                    metadata,
                    sourceDefinition.Name,
                    out var sourceName) ||
                !TryReadBoundedGenericAttributeName(
                    metadata,
                    sourceDefinition.Namespace,
                    out _) ||
                !TryReadBoundedGenericAttributeName(
                    metadata,
                    targetDefinition.Name,
                    out var targetName) ||
                !TryReadBoundedGenericAttributeName(
                    metadata,
                    targetDefinition.Namespace,
                    out _) ||
                sourceName.Length == 0 ||
                targetName.Length == 0 ||
                targetName.Contains('`') ||
                IsPrimitiveAliasName(targetName))
            {
                return false;
            }

            foreach (var parameterHandle in sourceParameters)
            {
                var parameter = metadata.GetGenericParameter(parameterHandle);
                if (parameter.Parent != sourceHandle ||
                    parameter.Attributes != GenericParameterAttributes.None ||
                    parameter.GetConstraints().Count != 0)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsVerifiedConstructorTrustedIListToIEnumerableUpcast(
        MetadataReader metadata,
        SignatureTypeName source,
        SignatureTypeName target)
    {
        if (!source.IsCanonicalGenericInstantiation ||
            source.GenericArguments.Length != 1 ||
            source.GenericDefinitionHandle.Kind != HandleKind.TypeReference ||
            source.GenericDefinitionRawTypeKind != (byte)SignatureTypeKind.Class ||
            source.GenericDefinitionSignatureKind != SignatureTypeKind.Class ||
            !target.IsCanonicalGenericInstantiation ||
            target.GenericArguments.Length != 1 ||
            target.GenericDefinitionHandle.Kind != HandleKind.TypeReference ||
            target.GenericDefinitionRawTypeKind != (byte)SignatureTypeKind.Class ||
            target.GenericDefinitionSignatureKind != SignatureTypeKind.Class ||
            !AreSameConstructorSignature(source, source) ||
            !AreSameConstructorSignature(target, target) ||
            !AreSameConstructorSignature(source.GenericArguments[0], target.GenericArguments[0]) ||
            !HasCanonicalLocalGenericDefinitions(metadata, source) ||
            !HasCanonicalLocalGenericDefinitions(metadata, target))
        {
            return false;
        }

        try
        {
            if (!TryReadTrustedSystemCollectionsGenericTypeReference(
                    metadata,
                    (TypeReferenceHandle)source.GenericDefinitionHandle,
                    "IList`1",
                    out var sourceAssembly) ||
                !TryReadTrustedSystemCollectionsGenericTypeReference(
                    metadata,
                    (TypeReferenceHandle)target.GenericDefinitionHandle,
                    "IEnumerable`1",
                    out var targetAssembly) ||
                sourceAssembly != targetAssembly ||
                HasLocalSystemCollectionsGenericTypeShadow(metadata))
            {
                return false;
            }

            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryReadTrustedSystemCollectionsGenericTypeReference(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        string expectedName,
        out AssemblyReferenceHandle assemblyHandle)
    {
        assemblyHandle = default;
        var reference = metadata.GetTypeReference(handle);
        if (!TryReadBoundedGenericAttributeName(
                metadata,
                reference.Namespace,
                out var @namespace) ||
            @namespace != "System.Collections.Generic" ||
            !TryReadBoundedGenericAttributeName(metadata, reference.Name, out var name) ||
            name != expectedName ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        assemblyHandle = (AssemblyReferenceHandle)reference.ResolutionScope;
        var assembly = metadata.GetAssemblyReference(assemblyHandle);
        if (!TryReadBoundedGenericAttributeName(metadata, assembly.Name, out var assemblyName) ||
            assemblyName != "System.Runtime" ||
            !IsTrustedFrameworkAssembly(
                metadata,
                assemblyName,
                assembly.PublicKeyOrToken,
                assembly.Culture,
                assembly.Flags))
        {
            assemblyHandle = default;
            return false;
        }

        return true;
    }

    private static bool HasLocalSystemCollectionsGenericTypeShadow(MetadataReader metadata)
    {
        if (metadata.GetTableRowCount(TableIndex.TypeDef) > MaxTypes)
        {
            return true;
        }

        foreach (var handle in metadata.TypeDefinitions)
        {
            var definition = metadata.GetTypeDefinition(handle);
            if (!TryReadBoundedGenericAttributeName(metadata, definition.Name, out var name))
            {
                return true;
            }

            if (name is not ("IList`1" or "IEnumerable`1"))
            {
                continue;
            }

            if (!TryGetBoundedGenericAttributeTypeDefinitionName(
                    metadata,
                    handle,
                    out var fullName,
                    out _) ||
                fullName is "System.Collections.Generic.IList`1" or
                    "System.Collections.Generic.IEnumerable`1")
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsExactConstructorAssignment(
        CliType sourceType,
        CliType targetType,
        SignatureTypeName? sourceSignature,
        SignatureTypeName targetSignature)
    {
        if (sourceType.HasPinnedQualifier ||
            targetType.HasPinnedQualifier ||
            sourceSignature?.HasPinnedQualifier == true ||
            targetSignature.HasPinnedQualifier)
        {
            return false;
        }

        if (sourceType.IsExactNamedType || targetType.IsExactNamedType)
        {
            return IsSameCliType(sourceType, targetType);
        }

        if (sourceType.PrimitiveType is not null &&
            sourceType.PrimitiveType == targetType.PrimitiveType)
        {
            return true;
        }

        return sourceSignature is not null &&
               AreSameConstructorSignature(sourceSignature, targetSignature);
    }

    private static bool AreSameConstructorSignature(
        SignatureTypeName source,
        SignatureTypeName target)
    {
        var remainingNodes = 512;
        return AreSameConstructorSignatureNode(source, target, depth: 0, ref remainingNodes);
    }

    private static bool AreSameConstructorSignatureNode(
        SignatureTypeName source,
        SignatureTypeName target,
        int depth,
        ref int remainingNodes)
    {
        if (depth > MaxStructureDepth ||
            remainingNodes-- <= 0 ||
            source.OuterCustomModifiers.Length != 0 ||
            target.OuterCustomModifiers.Length != 0 ||
            source.HasNestedCustomModifiers ||
            target.HasNestedCustomModifiers ||
            source.IsRestrictedGenericArgument ||
            target.IsRestrictedGenericArgument ||
            source.IsUnsupported ||
            target.IsUnsupported ||
            source.IsByReference ||
            target.IsByReference ||
            source.HasPinnedQualifier ||
            target.HasPinnedQualifier)
        {
            return false;
        }

        if (source.TypeParameterSlot is not null || target.TypeParameterSlot is not null)
        {
            return source.TypeParameterSlot is { } sourceSlot &&
                   target.TypeParameterSlot is { } targetSlot &&
                   !sourceSlot.Owner.IsNil &&
                   sourceSlot.Index >= 0 &&
                   sourceSlot == targetSlot;
        }

        if (source.MethodParameterSlot is not null || target.MethodParameterSlot is not null)
        {
            return source.MethodParameterSlot is { } sourceSlot &&
                   target.MethodParameterSlot is { } targetSlot &&
                   !sourceSlot.Owner.IsNil &&
                   sourceSlot.Index >= 0 &&
                   sourceSlot == targetSlot;
        }

        if (source.ArrayElementType is not null || target.ArrayElementType is not null)
        {
            return source.ArrayElementType is { } sourceElement &&
                   target.ArrayElementType is { } targetElement &&
                   source.ArrayRank > 0 &&
                   source.ArrayRank == target.ArrayRank &&
                   source.ArraySizes.SequenceEqual(target.ArraySizes) &&
                   source.ArrayLowerBounds.SequenceEqual(target.ArrayLowerBounds) &&
                   AreSameConstructorSignatureNode(
                       sourceElement,
                       targetElement,
                       depth + 1,
                       ref remainingNodes);
        }

        if (source.SzArrayElementType is not null || target.SzArrayElementType is not null)
        {
            return source.SzArrayElementType is { } sourceElement &&
                   target.SzArrayElementType is { } targetElement &&
                   AreSameConstructorSignatureNode(
                       sourceElement,
                       targetElement,
                       depth + 1,
                       ref remainingNodes);
        }

        if (source.PrimitiveType is not null || target.PrimitiveType is not null)
        {
            return source.PrimitiveType is not null &&
                   source.PrimitiveType is not (
                       PrimitiveTypeCode.Void or PrimitiveTypeCode.TypedReference) &&
                   source.PrimitiveType == target.PrimitiveType;
        }

        if (source.IsExactNamedType || target.IsExactNamedType)
        {
            return source.IsExactNamedType &&
                   target.IsExactNamedType &&
                   !source.Text.Contains('`', StringComparison.Ordinal) &&
                   !target.Text.Contains('`', StringComparison.Ordinal) &&
                   IsExactSignatureIdentity(
                       source.NominalHandle,
                       source.RawTypeKind,
                       source.SignatureKind,
                       target.NominalHandle,
                       target.RawTypeKind,
                       target.SignatureKind);
        }

        if (!source.IsCanonicalGenericInstantiation ||
            !target.IsCanonicalGenericInstantiation ||
            source.GenericArguments.IsDefaultOrEmpty ||
            target.GenericArguments.IsDefaultOrEmpty ||
            source.GenericArguments.Length != target.GenericArguments.Length ||
            string.IsNullOrEmpty(source.GenericDefinitionText) ||
            string.IsNullOrEmpty(target.GenericDefinitionText) ||
            HasPrimitiveAliasGenericDefinitionSegment(source.GenericDefinitionText) ||
            HasPrimitiveAliasGenericDefinitionSegment(target.GenericDefinitionText) ||
            !IsExactSignatureIdentity(
                source.GenericDefinitionHandle,
                source.GenericDefinitionRawTypeKind,
                source.GenericDefinitionSignatureKind,
                target.GenericDefinitionHandle,
                target.GenericDefinitionRawTypeKind,
                target.GenericDefinitionSignatureKind))
        {
            return false;
        }

        for (var index = 0; index < source.GenericArguments.Length; index++)
        {
            if (!AreSameConstructorSignatureNode(
                    source.GenericArguments[index],
                    target.GenericArguments[index],
                    depth + 1,
                    ref remainingNodes))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasPrimitiveAliasGenericDefinitionSegment(string name) =>
        name.Split('.').Any(segment =>
        {
            var backtick = segment.LastIndexOf('`');
            return backtick > 0 && IsPrimitiveAliasName(segment[..backtick]);
        });

    private static bool IsExactSignatureIdentity(
        EntityHandle sourceHandle,
        byte sourceRawTypeKind,
        SignatureTypeKind sourceSignatureKind,
        EntityHandle targetHandle,
        byte targetRawTypeKind,
        SignatureTypeKind targetSignatureKind) =>
        sourceHandle.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference &&
        targetHandle.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference &&
        sourceHandle == targetHandle &&
        sourceRawTypeKind is (byte)SignatureTypeKind.Class or (byte)SignatureTypeKind.ValueType &&
        sourceRawTypeKind == targetRawTypeKind &&
        sourceSignatureKind is SignatureTypeKind.Class or SignatureTypeKind.ValueType &&
        sourceSignatureKind == targetSignatureKind &&
        sourceSignatureKind == (SignatureTypeKind)sourceRawTypeKind;

    private static bool IsConstructorReferenceType(
        CliType type,
        SignatureTypeName signature)
    {
        return type.PrimitiveType is PrimitiveTypeCode.String or PrimitiveTypeCode.Object ||
               (type.IsExactNamedType &&
                !IsPrimitiveAliasName(type.Text) &&
                type.RawTypeKind == (byte)SignatureTypeKind.Class &&
                type.SignatureKind == SignatureTypeKind.Class) ||
               (signature.GenericDefinitionRawTypeKind == (byte)SignatureTypeKind.Class &&
                signature.GenericDefinitionSignatureKind == SignatureTypeKind.Class &&
                signature.IsCanonicalGenericInstantiation &&
                AreSameConstructorSignature(signature, signature));
    }

    private static bool IsPrimitiveAliasName(string type) => type.TrimEnd('?') is
        "bool" or
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
        "nuint" or
        "float" or
        "double" or
        "decimal" or
        "string" or
        "object" or
        "void";

    private static bool ConstructorExceptionRegionsAreUnsafe(
        IReadOnlyList<ExceptionRegionInfo> regions,
        IReadOnlyList<IlInstruction> instructions,
        int prefixEndOffset,
        int ilLength)
    {
        var boundaries = instructions.Select(instruction => instruction.Offset).ToHashSet();
        boundaries.Add(ilLength);
        foreach (var region in regions)
        {
            if (!IsValidRange(region.TryOffset, region.TryLength) ||
                !IsValidRange(region.HandlerOffset, region.HandlerLength) ||
                region.TryOffset < prefixEndOffset ||
                region.HandlerOffset < prefixEndOffset)
            {
                return true;
            }

            if (region.Kind == ExceptionRegionKind.Filter)
            {
                if (region.FilterOffset < prefixEndOffset ||
                    region.FilterOffset >= region.HandlerOffset ||
                    !boundaries.Contains(region.FilterOffset))
                {
                    return true;
                }
            }
            else if (region.FilterOffset >= 0)
            {
                return true;
            }
        }

        return false;

        bool IsValidRange(int offset, int length)
        {
            if (offset < 0 || length <= 0)
            {
                return false;
            }

            var end = (long)offset + length;
            return end <= ilLength &&
                   boundaries.Contains(offset) &&
                   boundaries.Contains((int)end);
        }
    }

    private static bool ConstructorTailHasUnsafeBranches(
        byte[] il,
        IReadOnlyList<IlInstruction> instructions,
        int startIndex,
        int prefixEndOffset)
    {
        var tailTargets = instructions
            .Skip(startIndex)
            .Select(instruction => instruction.Offset)
            .ToHashSet();
        for (var index = startIndex; index < instructions.Count; index++)
        {
            var instruction = instructions[index];
            if (!OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode))
            {
                return true;
            }

            switch (opCode.OperandType)
            {
                case OperandType.ShortInlineBrTarget:
                    if (instruction.OperandSize != 1 ||
                        !IsValidTarget(
                            (long)instruction.OperandOffset + 1 +
                            (sbyte)il[instruction.OperandOffset]))
                    {
                        return true;
                    }

                    break;
                case OperandType.InlineBrTarget:
                    if (instruction.OperandSize != 4 ||
                        !IsValidTarget(
                            (long)instruction.OperandOffset + 4 +
                            BinaryPrimitives.ReadInt32LittleEndian(
                                il.AsSpan(instruction.OperandOffset, 4))))
                    {
                        return true;
                    }

                    break;
                case OperandType.InlineSwitch:
                    if (instruction.OperandSize < 4)
                    {
                        return true;
                    }

                    var count = BinaryPrimitives.ReadInt32LittleEndian(
                        il.AsSpan(instruction.OperandOffset, 4));
                    if (count < 0 || 4L + ((long)count * 4) != instruction.OperandSize)
                    {
                        return true;
                    }

                    var baseOffset = (long)instruction.OperandOffset + instruction.OperandSize;
                    for (var targetIndex = 0; targetIndex < count; targetIndex++)
                    {
                        var deltaOffset = instruction.OperandOffset + 4 + (targetIndex * 4);
                        if (!IsValidTarget(
                                baseOffset + BinaryPrimitives.ReadInt32LittleEndian(
                                    il.AsSpan(deltaOffset, 4))))
                        {
                            return true;
                        }
                    }

                    break;
            }
        }

        return false;

        bool IsValidTarget(long target) =>
            target >= prefixEndOffset &&
            target < il.Length &&
            target <= int.MaxValue &&
            tailTargets.Contains((int)target);
    }

    private static void ValidateConstructorChains(
        List<MethodModel> methods,
        IReadOnlyDictionary<MethodDefinitionHandle, ConstructorReconstruction> candidates)
    {
        var validation = EvaluateConstructorChains(candidates);
        foreach (var (handle, candidate) in candidates)
        {
            if (validation.GetValueOrDefault(handle))
            {
                continue;
            }

            if (candidate.MethodIndex >= 0 && candidate.MethodIndex < methods.Count)
            {
                methods[candidate.MethodIndex] = methods[candidate.MethodIndex] with
                {
                    ConstructorInitializer = null,
                    Body = [],
                    BodyReconstructed = false,
                    RequiresUnsafeContext = false
                };
            }
        }
    }

    private static IReadOnlyDictionary<MethodDefinitionHandle, bool> EvaluateConstructorChains(
        IReadOnlyDictionary<MethodDefinitionHandle, ConstructorReconstruction> candidates)
    {
        var validation = new Dictionary<MethodDefinitionHandle, bool>();
        foreach (var start in candidates.Keys)
        {
            if (validation.ContainsKey(start))
            {
                continue;
            }

            var path = new List<MethodDefinitionHandle>();
            var active = new HashSet<MethodDefinitionHandle>();
            var current = start;
            var valid = false;
            while (true)
            {
                if (validation.TryGetValue(current, out valid))
                {
                    break;
                }

                if (!candidates.TryGetValue(current, out var candidate) || !active.Add(current))
                {
                    valid = false;
                    break;
                }

                path.Add(current);
                if (candidate.Initializer.Kind == "base")
                {
                    valid = true;
                    break;
                }

                if (candidate.Initializer.Kind != "this" || candidate.ThisTarget.IsNil)
                {
                    valid = false;
                    break;
                }

                current = candidate.ThisTarget;
            }

            foreach (var handle in path)
            {
                validation[handle] = valid;
            }
        }

        return validation;
    }

    private static IReadOnlyList<ExceptionRegionInfo>? TryReadExceptionRegions(
        MetadataReader metadata,
        MethodBodyBlock body)
    {
        try
        {
            return body
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
            return null;
        }
    }

    private static bool CollectCalls(
        MetadataReader metadata,
        byte[] il,
        IlDecodeResult decoded,
        string caller,
        List<CallEdge> edges,
        HashSet<(string, string, string)> seenEdges,
        MemberReferenceCallerContext callerContext)
    {
        if (decoded.Status != IlDecodeStatus.Complete)
        {
            return false;
        }

        var methodEdges = new List<(string Caller, string Callee, string Kind)>();
        var methodSeen = new HashSet<(string, string, string)>();
        foreach (var instruction in decoded.Instructions)
        {
            var kind = CallKind(instruction.OpValue);
            if (kind is null || instruction.OperandSize != 4)
            {
                continue;
            }

            var token = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4));
            var callee = ResolveMemberName(metadata, token, callerContext);
            if (callee is null)
            {
                return false;
            }

            var edge = (caller, callee, kind);
            if (seenEdges.Contains(edge) || !methodSeen.Add(edge))
            {
                continue;
            }

            if (methodEdges.Count >= MaxCallEdges - edges.Count)
            {
                return false;
            }

            methodEdges.Add(edge);
        }

        foreach (var edge in methodEdges)
        {
            seenEdges.Add(edge);
            edges.Add(new CallEdge
            {
                Caller = edge.Caller,
                Callee = edge.Callee,
                Kind = edge.Kind
            });
        }

        return true;
    }

    private static (IReadOnlyList<string> Instructions, bool Truncated) Disassemble(
        MetadataReader metadata,
        byte[] il,
        IlDecodeResult decoded,
        UserStringCatalog userStrings,
        bool methodIlComplete,
        MemberReferenceCallerContext callerContext)
    {
        var instructions = new List<string>(decoded.Instructions.Count);
        foreach (var instruction in decoded.Instructions)
        {
            if (!OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode))
            {
                continue;
            }

            var operand = FormatOperand(
                metadata,
                il,
                instruction,
                opCode.OperandType,
                userStrings,
                callerContext);
            instructions.Add($"IL_{instruction.Offset:X4}: {opCode.Name}{operand}");
        }

        return (instructions, !methodIlComplete);
    }

    private static bool HasOnlyValidUserStringOperands(
        byte[] il,
        IlDecodeResult decoded,
        UserStringCatalog userStrings)
    {
        if (decoded.Status != IlDecodeStatus.Complete)
        {
            return false;
        }

        foreach (var instruction in decoded.Instructions)
        {
            if (!OpCodesByValue.TryGetValue(instruction.OpValue, out var opCode) ||
                opCode.OperandType != OperandType.InlineString)
            {
                continue;
            }

            if (instruction.OperandSize != 4 ||
                !userStrings.TryGet(
                    BinaryPrimitives.ReadInt32LittleEndian(
                        il.AsSpan(instruction.OperandOffset, 4)),
                    out _))
            {
                return false;
            }
        }

        return true;
    }

    private readonly record struct IlInstruction(int Offset, short OpValue, int OperandOffset, int OperandSize);

    private enum IlDecodeStatus
    {
        Complete,
        Malformed,
        BudgetExceeded
    }

    private sealed record IlDecodeResult(
        IlDecodeStatus Status,
        IReadOnlyList<IlInstruction> Instructions,
        int ConsumedOffset);

    private sealed class UserStringCatalog
    {
        private readonly ImmutableArray<byte> _heap;
        private readonly BitArray _entryStarts;
        private readonly Dictionary<int, string> _cache = new();
        private int _resolvedCharacters;

        private UserStringCatalog(
            ImmutableArray<byte> heap,
            BitArray entryStarts,
            bool complete)
        {
            _heap = heap;
            _entryStarts = entryStarts;
            Truncated = !complete;
        }

        public bool Truncated { get; private set; }

        public static UserStringCatalog RejectAll(bool complete = true) =>
            new([], new BitArray(0), complete);

        public static UserStringCatalog Create(
            PEReader peReader,
            MetadataReader metadata)
        {
            try
            {
                var heapSize = metadata.GetHeapSize(HeapIndex.UserString);
                if (heapSize == 0)
                {
                    return RejectAll();
                }

                if (heapSize < 0 || heapSize > MaxUserStringHeapBytes)
                {
                    return RejectAll(complete: false);
                }

                var heapOffset = metadata.GetHeapMetadataOffset(HeapIndex.UserString);
                var metadataBlock = peReader.GetMetadata();
                if (heapOffset < 0 ||
                    heapOffset > metadataBlock.Length - heapSize)
                {
                    return RejectAll(complete: false);
                }

                return Create(metadataBlock.GetContent(heapOffset, heapSize));
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or
                    ArgumentException or
                    ArgumentOutOfRangeException or
                    InvalidOperationException or
                    IOException)
            {
                return RejectAll(complete: false);
            }
        }

        public static UserStringCatalog Create(ImmutableArray<byte> heap)
        {
            if (heap.IsDefault || heap.Length == 0)
            {
                return RejectAll();
            }

            if (heap.Length > MaxUserStringHeapBytes || heap[0] != 0)
            {
                return RejectAll(complete: false);
            }

            var starts = new BitArray(heap.Length);
            var position = 1;
            var complete = true;
            while (position < heap.Length)
            {
                var remaining = heap.Length - position;
                if (remaining <= 3 && IsZeroPadding(heap, position))
                {
                    position = heap.Length;
                    break;
                }

                if (!TryReadCompressedUnsigned(
                        heap,
                        position,
                        out var payloadLength,
                        out var prefixLength) ||
                    payloadLength < 1 ||
                    (payloadLength & 1) == 0 ||
                    prefixLength > remaining ||
                    payloadLength > remaining - prefixLength)
                {
                    complete = false;
                    break;
                }

                var payloadOffset = position + prefixLength;
                var characterBytes = payloadLength - 1;
                var terminal = heap[payloadOffset + characterBytes];
                if (terminal > 1)
                {
                    complete = false;
                    break;
                }

                starts[position] = true;
                position = payloadOffset + payloadLength;
            }

            return new UserStringCatalog(heap, starts, complete && position == heap.Length);
        }

        public bool TryGet(int token, out string value)
        {
            value = string.Empty;
            const uint tokenTypeMask = 0xFF00_0000;
            const uint userStringTokenType = 0x7000_0000;
            const int heapOffsetMask = 0x00FF_FFFF;
            if (((uint)token & tokenTypeMask) != userStringTokenType)
            {
                return false;
            }

            var heapOffset = token & heapOffsetMask;
            if (heapOffset == 0 ||
                heapOffset >= _entryStarts.Length ||
                !_entryStarts[heapOffset])
            {
                return false;
            }

            if (_cache.TryGetValue(heapOffset, out var cached))
            {
                value = cached;
                return true;
            }

            if (!TryReadCompressedUnsigned(
                    _heap,
                    heapOffset,
                    out var payloadLength,
                    out var prefixLength))
            {
                return false;
            }

            var characterCount = (payloadLength - 1) / 2;
            if (characterCount > MaxUserStringCharacters ||
                _cache.Count >= MaxResolvedUserStrings ||
                characterCount > MaxResolvedUserStringCharacters - _resolvedCharacters)
            {
                Truncated = true;
                return false;
            }

            var characterOffset = heapOffset + prefixLength;
            value = string.Create(
                characterCount,
                (Heap: _heap, CharacterOffset: characterOffset),
                static (characters, state) =>
                {
                    var bytes = state.Heap.AsSpan();
                    for (var index = 0; index < characters.Length; index++)
                    {
                        characters[index] = (char)BinaryPrimitives.ReadUInt16LittleEndian(
                            bytes.Slice(state.CharacterOffset + (index * 2), 2));
                    }
                });
            _cache.Add(heapOffset, value);
            _resolvedCharacters += characterCount;
            return true;
        }

        private static bool TryReadCompressedUnsigned(
            ImmutableArray<byte> heap,
            int offset,
            out int value,
            out int bytesRead)
        {
            value = 0;
            bytesRead = 0;
            if ((uint)offset >= (uint)heap.Length)
            {
                return false;
            }

            var first = heap[offset];
            var remaining = heap.Length - offset;
            if ((first & 0x80) == 0)
            {
                value = first;
                bytesRead = 1;
                return true;
            }

            if ((first & 0xC0) == 0x80)
            {
                if (remaining < 2)
                {
                    return false;
                }

                value = ((first & 0x3F) << 8) | heap[offset + 1];
                if (value < 0x80)
                {
                    return false;
                }

                bytesRead = 2;
                return true;
            }

            if ((first & 0xE0) != 0xC0 || remaining < 4)
            {
                return false;
            }

            value = ((first & 0x1F) << 24) |
                    (heap[offset + 1] << 16) |
                    (heap[offset + 2] << 8) |
                    heap[offset + 3];
            if (value < 0x4000)
            {
                value = 0;
                return false;
            }

            bytesRead = 4;
            return true;
        }

        private static bool IsZeroPadding(ImmutableArray<byte> heap, int offset)
        {
            for (var index = offset; index < heap.Length; index++)
            {
                if (heap[index] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }

    private static IlDecodeResult DecodeInstructions(byte[] il)
    {
        var instructions = new List<IlInstruction>(Math.Min(il.Length, MaxIlInstructions));
        var position = 0;
        var switchTargetCount = 0;
        while (position < il.Length)
        {
            if (instructions.Count >= MaxIlInstructions)
            {
                return Finish(IlDecodeStatus.BudgetExceeded, position);
            }

            var offset = position;
            short opValue;
            var first = il[position++];
            if (first == 0xFE)
            {
                if (position >= il.Length)
                {
                    return Finish(IlDecodeStatus.Malformed, offset);
                }

                opValue = (short)(0xFE00 | il[position++]);
            }
            else
            {
                opValue = first;
            }

            if (!OpCodesByValue.TryGetValue(opValue, out var opCode) ||
                opCode.Name is null ||
                opCode.OpCodeType == OpCodeType.Nternal ||
                !OperandSizes.TryGetValue(opValue, out var operandSize))
            {
                return Finish(IlDecodeStatus.Malformed, offset);
            }

            if (operandSize == OperandSwitch)
            {
                if (il.Length - position < 4)
                {
                    return Finish(IlDecodeStatus.Malformed, offset);
                }

                var count = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(position, 4));
                if (count < 0)
                {
                    return Finish(IlDecodeStatus.Malformed, offset);
                }

                if (count > MaxIlSwitchTargets - switchTargetCount)
                {
                    return Finish(IlDecodeStatus.BudgetExceeded, offset);
                }

                var total = 4L + ((long)count * 4);
                if (total > il.Length - position)
                {
                    return Finish(IlDecodeStatus.Malformed, offset);
                }

                var totalSize = (int)total;
                instructions.Add(new IlInstruction(offset, opValue, position, totalSize));
                position += totalSize;
                switchTargetCount += count;
                continue;
            }

            if (operandSize < 0 || operandSize > il.Length - position)
            {
                return Finish(IlDecodeStatus.Malformed, offset);
            }

            instructions.Add(new IlInstruction(offset, opValue, position, operandSize));
            position += operandSize;
        }

        if (instructions.Count == 0)
        {
            return Finish(IlDecodeStatus.Malformed, 0);
        }

        var boundaries = instructions
            .Select(instruction => instruction.Offset)
            .ToHashSet();
        foreach (var instruction in instructions)
        {
            var opCode = OpCodesByValue[instruction.OpValue];
            switch (opCode.OperandType)
            {
                case OperandType.ShortInlineBrTarget:
                    if (!IsValidTarget(
                            (long)instruction.OperandOffset + 1 +
                            (sbyte)il[instruction.OperandOffset]))
                    {
                        return Finish(IlDecodeStatus.Malformed, il.Length);
                    }

                    break;
                case OperandType.InlineBrTarget:
                    if (!IsValidTarget(
                            (long)instruction.OperandOffset + 4 +
                            BinaryPrimitives.ReadInt32LittleEndian(
                                il.AsSpan(instruction.OperandOffset, 4))))
                    {
                        return Finish(IlDecodeStatus.Malformed, il.Length);
                    }

                    break;
                case OperandType.InlineSwitch:
                    var count = BinaryPrimitives.ReadInt32LittleEndian(
                        il.AsSpan(instruction.OperandOffset, 4));
                    var baseOffset = (long)instruction.OperandOffset + instruction.OperandSize;
                    for (var targetIndex = 0; targetIndex < count; targetIndex++)
                    {
                        var deltaOffset = instruction.OperandOffset + 4 + (targetIndex * 4);
                        if (!IsValidTarget(
                                baseOffset + BinaryPrimitives.ReadInt32LittleEndian(
                                    il.AsSpan(deltaOffset, 4))))
                        {
                            return Finish(IlDecodeStatus.Malformed, il.Length);
                        }
                    }

                    break;
            }
        }

        return Finish(IlDecodeStatus.Complete, il.Length);

        bool IsValidTarget(long target) =>
            target >= 0 &&
            target < il.Length &&
            target <= int.MaxValue &&
            boundaries.Contains((int)target);

        IlDecodeResult Finish(IlDecodeStatus status, int consumedOffset) =>
            new(status, [.. instructions], consumedOffset);
    }

    private static string FormatOperand(
        MetadataReader metadata,
        byte[] il,
        IlInstruction instruction,
        OperandType operandType,
        UserStringCatalog userStrings,
        MemberReferenceCallerContext callerContext)
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
                return $" {ResolveTokenName(
                    metadata,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    callerContext)}";
            case OperandType.InlineString:
                return $" {FormatUserString(
                    userStrings,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}";
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

    private static string FormatUserString(
        UserStringCatalog userStrings,
        int token)
    {
        if (!userStrings.TryGet(token, out var value))
        {
            return $"str(0x{token:X8})";
        }

        const int maxPreviewCharacters = 120;
        var previewTruncated = value.Length > maxPreviewCharacters;
        if (previewTruncated)
        {
            value = value[..maxPreviewCharacters];
        }

        var escaped = EscapeCSharpString(value);
        return previewTruncated
            ? escaped[..^1] + "…\""
            : escaped;
    }

    private static string ResolveTokenName(
        MetadataReader metadata,
        int token,
        MemberReferenceCallerContext callerContext)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
            case HandleKind.MemberReference:
            case HandleKind.MethodSpecification:
                return ResolveMemberName(metadata, token, callerContext) ?? $"token(0x{token:X8})";

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
        CliType DeclaringCliType,
        EntityHandle DeclaringHandle,
        string Name,
        int ParamCount,
        bool HasThis,
        CliType ReturnType,
        bool ReturnsVoid,
        IReadOnlyList<CliType> ParameterTypes,
        IReadOnlyList<string> GenericArguments,
        int GenericParameterCount,
        MethodAttributes? DefinitionAttributes,
        ArrayPseudoMemberInfo? ArrayPseudoMember = null);

    private readonly record struct FieldInfo(
        string DeclaringType,
        CliType DeclaringCliType,
        EntityHandle DeclaringHandle,
        int DeclaringGenericArity,
        string Name,
        CliType Type,
        FieldAttributes? DefinitionAttributes);

    private readonly record struct CallGraphMemberName(
        string Text,
        int GenericParameterCount);

    private enum ArrayPseudoMemberKind
    {
        Get,
        Set,
        Constructor
    }

    private sealed record ArrayPseudoMemberInfo(
        ArrayPseudoMemberKind Kind,
        string ElementType,
        int Rank);

    private readonly record struct MemberReferenceCallerContext(
        TypeDefinitionHandle TypeParameterOwner,
        int TypeParameterCount,
        MethodDefinitionHandle MethodParameterOwner,
        int MethodParameterCount,
        bool IsAvailable)
    {
        public object? SignatureContext =>
            IsAvailable
                ? SignatureGenericContext.ForCaller(
                    TypeParameterOwner,
                    TypeParameterCount,
                    MethodParameterOwner,
                    MethodParameterCount)
                : null;
    }

    private const int MaxStructureDepth = 32;
    private const int MaxInstantiatedMethodSignatureCharacters = 64 * 1_024;

    private readonly record struct Instr(
        int Offset,
        string Name,
        int OperandOffset,
        bool IsBranch,
        int Target,
        IReadOnlyList<int> SwitchTargets);

    private readonly record struct StructuredSwitch(IReadOnlyList<string> Statements, int NextIndex);

    private readonly record struct StructuredException(IReadOnlyList<string> Statements, int NextIndex);

    private sealed record BranchStoreFlow(
        bool HasNormalExit,
        HashSet<int> DefinitelyStored,
        HashSet<int> StoredAnywhere,
        HashSet<int> ReadBeforeStore);

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

    private sealed class ReconstructionState
    {
        public bool RequiresUnsafeContext { get; set; }
    }

    private sealed record EnumTypeCatalog(
        IReadOnlyDictionary<TypeDefinitionHandle, string> UnderlyingTypes,
        IReadOnlyDictionary<string, TypeDefinitionHandle> TestTypeHandles)
    {
        public static EnumTypeCatalog Empty { get; } = new(
            new Dictionary<TypeDefinitionHandle, string>(),
            new Dictionary<string, TypeDefinitionHandle>(StringComparer.Ordinal));
    }

    private sealed record CliType(
        string Text,
        string? EnumUnderlyingType = null,
        EntityHandle NominalHandle = default,
        byte RawTypeKind = 0,
        bool IsExactNamedType = false,
        SignatureTypeKind SignatureKind = SignatureTypeKind.Unknown,
        PrimitiveTypeCode? PrimitiveType = null,
        bool IsByReference = false,
        bool HasPinnedQualifier = false,
        SignatureTypeName? StructuralSignature = null)
    {
        public static implicit operator string(CliType value) => value.Text;

        public static implicit operator CliType(string value) => new(value);

        public override string ToString() => Text;
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
        IReadOnlyList<CliType> ParameterTypes,
        bool IsInstance,
        CliType? InstanceType,
        CliType ReturnType,
        IReadOnlyList<CliType> LocalTypes,
        IReadOnlyList<ExceptionRegionInfo> ExceptionRegions,
        IReadOnlyDictionary<int, string> LocalNames,
        Dictionary<string, CliType> ExpressionTypes,
        HashSet<string> UnknownExpressionTypes,
        HashSet<string> AmbiguousExpressionTypes,
        HashSet<string> UnsignedIntegralExpressions,
        HashSet<string> StatementExpressions,
        EnumTypeCatalog EnumTypes,
        UserStringCatalog UserStrings,
        MemberReferenceCallerContext MemberReferenceCallerContext,
        ReconstructionState State,
        ExceptionLeaveRedirect? LeaveRedirect,
        int CatchDepth);

    internal readonly record struct IlDecodeTestResult(
        string Status,
        int InstructionCount,
        int ConsumedOffset);

    internal readonly record struct UserStringReadTestResult(
        bool Success,
        string Value,
        bool Truncated);

    internal static IlDecodeTestResult DecodeIlForTest(byte[] il)
    {
        var decoded = DecodeInstructions(il);
        return new IlDecodeTestResult(
            decoded.Status.ToString(),
            decoded.Instructions.Count,
            decoded.ConsumedOffset);
    }

    internal static UserStringReadTestResult ReadUserStringForTest(
        byte[] heap,
        int token)
    {
        var catalog = UserStringCatalog.Create(ImmutableArray.CreateRange(heap));
        var success = catalog.TryGet(token, out var value);
        return new UserStringReadTestResult(success, value, catalog.Truncated);
    }

    // 測試用進入點：以現成的 MetadataReader 直接餵 IL bytes 驗證還原結果。
    internal static IReadOnlyList<string>? ReconstructBodyForTest(
        MetadataReader metadata,
        byte[] il,
        bool isInstance,
        string returnType,
        IReadOnlyList<string>? localTypes = null,
        IReadOnlyList<ExceptionRegionInfo>? exceptionRegions = null,
        IReadOnlyList<string>? parameterTypes = null,
        PEReader? peReader = null,
        bool localVariablesInitialized = true)
    {
        var enumTypes = ReadEnumTypeCatalog(metadata);
        var userStrings = peReader is null
            ? UserStringCatalog.RejectAll()
            : UserStringCatalog.Create(peReader, metadata);
        var decoded = DecodeInstructions(il);
        if (!HasOnlyValidUserStringOperands(il, decoded, userStrings))
        {
            return null;
        }

        return TryReconstructLinearBody(
            metadata,
            il,
            decoded,
            isInstance,
            new Dictionary<int, string>(),
            (parameterTypes ?? []).Select(type => CreateTestCliType(type, enumTypes)).ToArray(),
            CreateTestCliType(returnType, enumTypes),
            (localTypes ?? []).Select(type => CreateTestCliType(type, enumTypes)).ToArray(),
            localVariablesInitialized,
            exceptionRegions ?? [],
            enumTypes,
            userStrings,
            isInstance ? new CliType("<test-instance>") : null,
            out _);
    }

    internal static IReadOnlyList<string>? ReconstructMethodForTest(
        MetadataReader metadata,
        byte[] il,
        MethodDefinitionHandle methodHandle,
        PEReader? peReader = null,
        bool localVariablesInitialized = true)
    {
        try
        {
            var enumTypes = ReadEnumTypeCatalog(metadata);
            var userStrings = peReader is null
                ? UserStringCatalog.RejectAll()
                : UserStringCatalog.Create(peReader, metadata);
            var decoded = DecodeInstructions(il);
            if (!HasOnlyValidUserStringOperands(il, decoded, userStrings))
            {
                return null;
            }

            var method = metadata.GetMethodDefinition(methodHandle);
            var declaringType = method.GetDeclaringType();
            var callerContext = TryCreateMemberReferenceCallerContext(
                metadata,
                declaringType,
                methodHandle);
            var signature = method.DecodeSignature(
                SignatureTypeNameProvider.Instance,
                callerContext.SignatureContext);
            var isInstance = signature.Header.IsInstance &&
                             !method.Attributes.HasFlag(MethodAttributes.Static);
            return TryReconstructLinearBody(
                metadata,
                il,
                decoded,
                isInstance,
                ReadParameterNames(metadata, method),
                signature.ParameterTypes.Select(type => CreateCliType(type, enumTypes)).ToArray(),
                CreateCliType(signature.ReturnType, enumTypes),
                localTypes: [],
                localVariablesInitialized,
                exceptionRegions: [],
                enumTypes,
                userStrings,
                isInstance
                    ? CreateCurrentInstanceCliType(
                        metadata,
                        enumTypes,
                        declaringType,
                        callerContext)
                    : null,
                out _,
                memberReferenceCallerContext: callerContext);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    internal static (bool Complete, int EdgeCount) CollectCallsForTest(
        MetadataReader metadata,
        byte[] il,
        MethodDefinitionHandle callerMethod = default)
    {
        try
        {
            var callerContext = default(MemberReferenceCallerContext);
            if (!callerMethod.IsNil)
            {
                var method = metadata.GetMethodDefinition(callerMethod);
                callerContext = TryCreateMemberReferenceCallerContext(
                    metadata,
                    method.GetDeclaringType(),
                    callerMethod);
            }

            var edges = new List<CallEdge>();
            var complete = CollectCalls(
                metadata,
                il,
                DecodeInstructions(il),
                "Tests.Caller",
                edges,
                [],
                callerContext);
            return (complete, edges.Count);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return (false, 0);
        }
    }

    internal static bool ValidateMemberReferenceMethodForTest(
        MetadataReader metadata,
        MemberReferenceHandle handle,
        MethodDefinitionHandle callerMethod = default)
    {
        var callerContext = default(MemberReferenceCallerContext);
        if (!callerMethod.IsNil)
        {
            var method = metadata.GetMethodDefinition(callerMethod);
            callerContext = TryCreateMemberReferenceCallerContext(
                metadata,
                method.GetDeclaringType(),
                callerMethod);
        }

        return MemberReferenceSignatureValidator.TryValidateMethod(
            metadata,
            handle,
            callerContext,
            out _,
            out _);
    }

    internal sealed record ConstructorReconstructionTestResult(
        ConstructorInitializerModel Initializer,
        IReadOnlyList<string>? Body);

    internal static bool ConstructorTypeParameterSlotsMatchForTest(
        TypeDefinitionHandle sourceOwner,
        int sourceIndex,
        TypeDefinitionHandle targetOwner,
        int targetIndex)
    {
        var source = new SignatureTypeName(
            $"!{sourceIndex}",
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: false,
            TypeParameterSlot: new SignatureTypeParameterSlot(sourceOwner, sourceIndex));
        var target = new SignatureTypeName(
            $"!{targetIndex}",
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: false,
            TypeParameterSlot: new SignatureTypeParameterSlot(targetOwner, targetIndex));
        return AreSameConstructorSignature(source, target);
    }

    internal static IReadOnlyDictionary<int, bool> ValidateConstructorChainsForTest(
        IReadOnlyDictionary<int, int?> chains)
    {
        var candidates = new Dictionary<MethodDefinitionHandle, ConstructorReconstruction>();
        foreach (var (row, targetRow) in chains)
        {
            var handle = MetadataTokens.MethodDefinitionHandle(row);
            candidates.Add(
                handle,
                new ConstructorReconstruction(
                    new ConstructorInitializerModel
                    {
                        Kind = targetRow is null ? "base" : "this"
                    },
                    Body: [],
                    RequiresUnsafeContext: false,
                    targetRow is null
                        ? default
                        : MetadataTokens.MethodDefinitionHandle(targetRow.Value)));
        }

        return EvaluateConstructorChains(candidates).ToDictionary(
            pair => MetadataTokens.GetRowNumber(pair.Key),
            pair => pair.Value);
    }

    internal static ConstructorReconstructionTestResult? ReconstructConstructorForTest(
        MetadataReader metadata,
        byte[] il,
        MethodDefinitionHandle methodHandle,
        IReadOnlyList<ExceptionRegionInfo>? exceptionRegions = null,
        StandaloneSignatureHandle localSignature = default,
        bool requireBaseInitializer = true,
        PEReader? peReader = null,
        bool localVariablesInitialized = true)
    {
        try
        {
            var enumTypes = ReadEnumTypeCatalog(metadata);
            var userStrings = peReader is null
                ? UserStringCatalog.RejectAll()
                : UserStringCatalog.Create(peReader, metadata);
            var decoded = DecodeInstructions(il);
            if (!HasOnlyValidUserStringOperands(il, decoded, userStrings))
            {
                return null;
            }

            var method = metadata.GetMethodDefinition(methodHandle);
            var declaringType = method.GetDeclaringType();
            var definition = metadata.GetTypeDefinition(declaringType);
            var signature = method.DecodeSignature(SignatureTypeNameProvider.Instance, null);
            var genericParameterResult = new TypeGenericParameterResolver(
                    metadata,
                    new GenericMetadataBudget())
                .Read(declaringType);
            var reconstruction = TryReconstructConstructor(
                metadata,
                il,
                decoded,
                methodHandle,
                declaringType,
                definition.BaseType,
                ReadParameterNames(metadata, method),
                new MethodReconstructionSignature(
                    CreateCliType(signature.ReturnType, enumTypes),
                    signature.ParameterTypes.Select(type => CreateCliType(type, enumTypes)).ToArray()),
                genericParameterResult,
                [],
                localVariablesInitialized,
                localSignature,
                exceptionRegions ?? [],
                enumTypes,
                userStrings);
            return reconstruction is null ||
                   (requireBaseInitializer && reconstruction.Initializer.Kind != "base")
                ? null
                : new ConstructorReconstructionTestResult(
                    reconstruction.Initializer,
                    reconstruction.Body);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool HasSupportedMethodTermination(
        IReadOnlyList<IlInstruction> instructions,
        IReadOnlyList<ExceptionRegionInfo> exceptionRegions,
        int ilLength)
    {
        if (TryGetInstructionName(instructions[^1], out var terminalName) &&
            terminalName is "ret" or "throw" or "rethrow")
        {
            return true;
        }

        if (terminalName != "endfinally")
        {
            return false;
        }

        foreach (var region in exceptionRegions)
        {
            if (region.Kind is not (ExceptionRegionKind.Finally or ExceptionRegionKind.Fault) ||
                region.HandlerOffset < 0 ||
                region.HandlerLength <= 0 ||
                (long)region.HandlerOffset + region.HandlerLength != ilLength ||
                region.TryOffset < 0 ||
                region.TryLength <= 0)
            {
                continue;
            }

            var tryEnd = (long)region.TryOffset + region.TryLength;
            if (tryEnd > region.HandlerOffset || tryEnd > int.MaxValue)
            {
                continue;
            }

            var protectedTerminal = instructions.LastOrDefault(instruction =>
                instruction.Offset >= region.TryOffset &&
                (long)instruction.OperandOffset + instruction.OperandSize == tryEnd);
            if (TryGetInstructionName(protectedTerminal, out var protectedTerminalName) &&
                protectedTerminalName is "throw" or "rethrow")
            {
                return true;
            }
        }

        return false;
    }

    // 把方法的 IL 還原成 C#。先解碼成指令陣列，再用區間遞迴結構化還原 if／if-else（可巢狀）。
    // 採全有或全無：遇到無法安全切開的迴圈、非終止型 switch、不支援的例外區域或任何無法結構化的跳轉就整個方法放棄，
    // 退回 IL 註解，寧可不還原也不要產出語意錯誤的程式碼。輸出的 C# 不保證能編譯，但語意貼近原程式。
    private static IReadOnlyList<string>? TryReconstructLinearBody(
        MetadataReader metadata,
        byte[] il,
        IlDecodeResult decoded,
        bool isInstance,
        Dictionary<int, string> parameterNames,
        IReadOnlyList<CliType> parameterTypes,
        CliType returnType,
        IReadOnlyList<CliType> localTypes,
        bool localVariablesInitialized,
        IReadOnlyList<ExceptionRegionInfo> exceptionRegions,
        EnumTypeCatalog enumTypes,
        UserStringCatalog userStrings,
        CliType? instanceType,
        out bool requiresUnsafeContext,
        int startOffset = 0,
        MemberReferenceCallerContext memberReferenceCallerContext = default)
    {
        requiresUnsafeContext = false;
        if (localTypes.Any(type => type.HasPinnedQualifier) ||
            (!localVariablesInitialized && localTypes.Count > 0) ||
            decoded.Status != IlDecodeStatus.Complete ||
            decoded.Instructions.Count == 0 ||
            !HasSupportedMethodTermination(
                decoded.Instructions,
                exceptionRegions,
                il.Length))
        {
            return null;
        }

        var instructions = new List<Instr>();
        var offsetToIndex = new Dictionary<int, int>();
        foreach (var instruction in decoded.Instructions)
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
        if (!offsetToIndex.TryGetValue(startOffset, out var startIndex))
        {
            return null;
        }

        if (instructions.Any(instruction =>
                instruction.Name == "ret" &&
                exceptionRegions.Any(region => IsInsideExceptionRegion(instruction.Offset, region))))
        {
            // ECMA-335 不允許 ret 離開 try/filter/handler；畸形 metadata/IL 若直接輸出
            // C# return，會變成無法編譯或改變 finally 語意，因此整體 fail closed。
            return null;
        }

        var state = new ReconstructionState
        {
            RequiresUnsafeContext = localTypes.Any(type => RequiresUnsafeType(type.Text))
        };
        var context = new ReconContext(
            metadata,
            il,
            parameterNames,
            parameterTypes,
            isInstance,
            instanceType,
            returnType,
            localTypes,
            exceptionRegions,
            new Dictionary<int, string>(),
            new Dictionary<string, CliType>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            enumTypes,
            userStrings,
            memberReferenceCallerContext,
            state,
            LeaveRedirect: null,
            CatchDepth: 0);
        var body = TryStructure(
            context,
            [.. instructions],
            offsetToIndex,
            startIndex,
            instructions.Count,
            new HashSet<int>(),
            0);
        if (body is { Count: > 0 } &&
            returnType.PrimitiveType == PrimitiveTypeCode.Void &&
            body[^1] == "return;")
        {
            // 方法最外層的最後一個 void ret 可以由 C# 區塊結尾隱含；內層
            // if/switch/exception 分支中的 ret 則必須保留，否則會繼續執行 join 後的副作用。
            body.RemoveAt(body.Count - 1);
        }

        if (context.AmbiguousExpressionTypes.Count > 0)
        {
            body = null;
        }

        requiresUnsafeContext = body is not null && state.RequiresUnsafeContext;
        return body;
    }

    private static bool IsInsideExceptionRegion(int offset, ExceptionRegionInfo region) =>
        IsInsideOffsetRange(offset, region.TryOffset, region.TryLength) ||
        IsInsideOffsetRange(offset, region.HandlerOffset, region.HandlerLength) ||
        (region.Kind == ExceptionRegionKind.Filter &&
         region.FilterOffset >= 0 &&
         region.HandlerOffset >= region.FilterOffset &&
         offset >= region.FilterOffset &&
         offset < region.HandlerOffset);

    private static bool IsInsideOffsetRange(int offset, int start, int length) =>
        start >= 0 && length > 0 && offset >= start && offset - start < length;

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
                    var doWhileInstructions = instructions[index..branchIndex];
                    var doWhileLocals = doWhileInstructions
                        .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                        .Where(localIndex => localIndex is not null && !declaredLocals.Contains(localIndex.Value))
                        .Select(localIndex => localIndex!.Value)
                        .Distinct()
                        .Order()
                        .ToArray();
                    foreach (var localIndex in doWhileLocals)
                    {
                        if (localIndex < 0 || localIndex >= context.LocalTypes.Count)
                        {
                            return null;
                        }

                        var firstAccess = doWhileInstructions.First(instruction =>
                            TryGetAccessedLocalIndex(context, instruction) == localIndex);
                        if (TryGetStoredLocalIndex(context, firstAccess) != localIndex)
                        {
                            return null;
                        }

                        var type = LocalDeclarationType(context, localIndex);
                        if (type == "var" || IsGeneratedName(type))
                        {
                            return null;
                        }

                        declaredLocals.Add(localIndex);
                        statements.Add($"{type} {LocalName(context, localIndex)};");
                    }

                    var processed = TryProcessStraightLine(
                        context,
                        instructions,
                        index,
                        branchIndex,
                        new HashSet<int>(declaredLocals));
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
                if (!TryApplyOrderedSimpleInstruction(
                        context,
                        instr,
                        stack,
                        statements,
                        declaredLocals,
                        out var terminal))
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

                var loopScopedLocals = instructions[loop.Value.BodyStart..loop.Value.BodyEnd]
                    .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                    .Where(localIndex => localIndex is not null && !declaredLocals.Contains(localIndex.Value))
                    .Select(localIndex => localIndex!.Value)
                    .ToHashSet();
                var loopContinuationLocals = instructions[loop.Value.JoinIndex..end]
                    .Select(instruction => TryGetAccessedLocalIndex(context, instruction))
                    .Where(localIndex => localIndex is not null && !declaredLocals.Contains(localIndex.Value))
                    .Select(localIndex => localIndex!.Value)
                    .ToHashSet();
                loopScopedLocals.IntersectWith(loopContinuationLocals);
                if (loopScopedLocals.Count > 0)
                {
                    return null;
                }

                var loopBody = TryStructure(
                    context,
                    instructions,
                    offsetToIndex,
                    loop.Value.BodyStart,
                    loop.Value.BodyEnd,
                    new HashSet<int>(declaredLocals),
                    depth + 1);
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

            var continuationLocals = instructions[joinIndex..end]
                .Select(instruction => TryGetAccessedLocalIndex(context, instruction))
                .Where(localIndex => localIndex is not null && !declaredLocals.Contains(localIndex.Value))
                .Select(localIndex => localIndex!.Value)
                .ToHashSet();
            if (continuationLocals.Any(localIndex => localIndex < 0 || localIndex >= context.LocalTypes.Count))
            {
                return null;
            }

            HashSet<int> hoistedLocals = [];
            var potentialCrossScopeLocals = instructions[(index + 1)..thenEnd]
                .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                .Where(localIndex => localIndex is not null)
                .Select(localIndex => localIndex!.Value)
                .ToHashSet();
            if (elseStart >= 0)
            {
                potentialCrossScopeLocals.UnionWith(
                    instructions[elseStart..elseEnd]
                        .Select(instruction => TryGetStoredLocalIndex(context, instruction))
                        .Where(localIndex => localIndex is not null)
                        .Select(localIndex => localIndex!.Value));
            }

            potentialCrossScopeLocals.IntersectWith(continuationLocals);
            if (potentialCrossScopeLocals.Count > 0)
            {
                var thenFlow = TryAnalyzeBranchStores(
                    context,
                    instructions,
                    offsetToIndex,
                    index + 1,
                    thenEnd);
                var elseFlow = elseStart >= 0
                    ? TryAnalyzeBranchStores(context, instructions, offsetToIndex, elseStart, elseEnd)
                    : new BranchStoreFlow(true, [], [], []);
                if (thenFlow is null || elseFlow is null)
                {
                    return null;
                }

                var normalFlows = new[] { thenFlow, elseFlow }
                    .Where(flow => flow.HasNormalExit)
                    .ToArray();
                var definitelyStored = new HashSet<int>();
                if (normalFlows.Length > 0)
                {
                    definitelyStored.UnionWith(normalFlows[0].DefinitelyStored);
                    foreach (var flow in normalFlows.Skip(1))
                    {
                        definitelyStored.IntersectWith(flow.DefinitelyStored);
                    }
                }

                var crossScopeLocals = new HashSet<int>(thenFlow.StoredAnywhere);
                crossScopeLocals.UnionWith(elseFlow.StoredAnywhere);
                crossScopeLocals.IntersectWith(continuationLocals);
                var readBeforeStore = new HashSet<int>(thenFlow.ReadBeforeStore);
                readBeforeStore.UnionWith(elseFlow.ReadBeforeStore);
                if (!crossScopeLocals.IsSubsetOf(definitelyStored) ||
                    crossScopeLocals.Overlaps(readBeforeStore))
                {
                    return null;
                }

                hoistedLocals.UnionWith(crossScopeLocals);
            }

            foreach (var localIndex in hoistedLocals.Order())
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
                statements.Add($"{type} {LocalName(context, localIndex)};");
            }

            var thenStatements = TryStructure(
                context,
                instructions,
                offsetToIndex,
                index + 1,
                thenEnd,
                new HashSet<int>(declaredLocals),
                depth + 1);
            if (thenStatements is null)
            {
                return null;
            }

            List<string>? elseStatements = null;
            if (elseStart >= 0)
            {
                elseStatements = TryStructure(
                    context,
                    instructions,
                    offsetToIndex,
                    elseStart,
                    elseEnd,
                    new HashSet<int>(declaredLocals),
                    depth + 1);
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
        if (context.ExpressionTypes.TryGetValue(selector, out var selectorType) &&
            IsPotentialEnumType(selectorType.Text))
        {
            return $"unchecked(({selectorType.Text}){value})";
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

    private static int? TryGetAccessedLocalIndex(ReconContext context, Instr instruction) =>
        TryGetLoadedLocalIndex(context, instruction) ?? TryGetStoredLocalIndex(context, instruction);

    // if/else 內宣告的 C# local 不會自動跨出大括號；只有每一條能正常抵達 join 的
    // forward path 都已 stloc，才可在 if 前輸出沒有 initializer 的宣告。終止於 ret/throw
    // 的 path 不參與交集，回邊、leave、越界 target 與非法 local index 一律 fail closed。
    private static BranchStoreFlow? TryAnalyzeBranchStores(
        ReconContext context,
        Instr[] instructions,
        Dictionary<int, int> offsetToIndex,
        int start,
        int end)
    {
        if (start < 0 || start > end || end > instructions.Length)
        {
            return null;
        }

        for (var index = start; index < end; index++)
        {
            if (context.ExceptionRegions.Any(region =>
                    IsInsideExceptionRegion(instructions[index].Offset, region)))
            {
                return null;
            }
        }

        if (start == end)
        {
            return new BranchStoreFlow(true, [], [], []);
        }

        var entries = new Dictionary<int, HashSet<int>>
        {
            [start] = []
        };
        HashSet<int>? exitStores = null;
        HashSet<int> storedAnywhere = [];
        HashSet<int> readBeforeStore = [];

        for (var index = start; index < end; index++)
        {
            if (!entries.TryGetValue(index, out var incoming))
            {
                continue;
            }

            var instruction = instructions[index];
            var outgoing = new HashSet<int>(incoming);
            if (TryGetLoadedLocalIndex(context, instruction) is int loadedLocal &&
                !incoming.Contains(loadedLocal))
            {
                readBeforeStore.Add(loadedLocal);
            }

            if (TryGetStoredLocalIndex(context, instruction) is int storedLocal)
            {
                if (storedLocal < 0 || storedLocal >= context.LocalTypes.Count)
                {
                    return null;
                }

                outgoing.Add(storedLocal);
                storedAnywhere.Add(storedLocal);
            }

            if (instruction.Name is "ret" or "throw" or "rethrow")
            {
                continue;
            }

            if (instruction.Name is "br" or "br.s")
            {
                if (!TryMerge(instruction.Target, index, outgoing))
                {
                    return null;
                }

                continue;
            }

            if (instruction.Name == "switch")
            {
                foreach (var target in instruction.SwitchTargets)
                {
                    if (!TryMerge(target, index, outgoing))
                    {
                        return null;
                    }
                }

                if (!TryMergeIndex(index + 1, index, outgoing))
                {
                    return null;
                }

                continue;
            }

            if (instruction.IsBranch)
            {
                if (!IsSupportedConditionalBranch(instruction.Name) ||
                    !TryMerge(instruction.Target, index, outgoing) ||
                    !TryMergeIndex(index + 1, index, outgoing))
                {
                    return null;
                }

                continue;
            }

            if (!TryMergeIndex(index + 1, index, outgoing))
            {
                return null;
            }
        }

        return new BranchStoreFlow(
            exitStores is not null,
            exitStores ?? [],
            storedAnywhere,
            readBeforeStore);

        bool TryMerge(int targetOffset, int predecessor, HashSet<int> stores)
        {
            return offsetToIndex.TryGetValue(targetOffset, out var successor) &&
                   TryMergeIndex(successor, predecessor, stores);
        }

        bool TryMergeIndex(int successor, int predecessor, HashSet<int> stores)
        {
            if (successor == end)
            {
                if (exitStores is null)
                {
                    exitStores = new HashSet<int>(stores);
                }
                else
                {
                    exitStores.IntersectWith(stores);
                }

                return true;
            }

            if (successor < start || successor > end || successor <= predecessor)
            {
                return false;
            }

            if (entries.TryGetValue(successor, out var existing))
            {
                existing.IntersectWith(stores);
            }
            else
            {
                entries[successor] = new HashSet<int>(stores);
            }

            return true;
        }
    }

    private static bool IsSupportedConditionalBranch(string name) => name is
        "brtrue" or "brtrue.s" or
        "brfalse" or "brfalse.s" or
        "beq" or "beq.s" or
        "bne.un" or "bne.un.s" or
        "bge" or "bge.s" or
        "bge.un" or "bge.un.s" or
        "bgt" or "bgt.s" or
        "bgt.un" or "bgt.un.s" or
        "ble" or "ble.s" or
        "ble.un" or "ble.un.s" or
        "blt" or "blt.s" or
        "blt.un" or "blt.un.s";

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

        if (IsUnsignedRelationalBranch(name))
        {
            return TryBuildUnsignedRelationalBranchCondition(
                context,
                name,
                left,
                right,
                branchTaken: false,
                out condition);
        }

        if (name is "beq" or "beq.s" or "bne.un" or "bne.un.s" &&
            !TryNormalizeEqualityOperands(context, ref left, ref right))
        {
            return false;
        }

        condition = name switch
        {
            "beq" or "beq.s" => $"{left} != {right}",
            "bne.un" or "bne.un.s" => $"{left} == {right}",
            "bge" or "bge.s" => $"{left} < {right}",
            "bgt" or "bgt.s" => $"{left} <= {right}",
            "ble" or "ble.s" => $"{left} > {right}",
            "blt" or "blt.s" => $"{left} >= {right}",
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
            if (instr.IsBranch ||
                !TryApplyOrderedSimpleInstruction(
                    context,
                    instr,
                    stack,
                    statements,
                    declaredLocals,
                    out var terminal) ||
                terminal)
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
            if (instr.IsBranch ||
                !TryApplyOrderedSimpleInstruction(
                    context,
                    instr,
                    stack,
                    statements,
                    declaredLocals,
                    out var terminal) ||
                terminal)
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

    private static bool TryApplyOrderedSimpleInstruction(
        ReconContext context,
        Instr instruction,
        Stack<string> stack,
        List<string> statements,
        HashSet<int> declaredLocals,
        out bool terminal)
    {
        var statementCount = statements.Count;
        if (!ApplySimpleInstruction(
                context,
                instruction,
                stack,
                statements,
                declaredLocals,
                out terminal))
        {
            return false;
        }

        // IL 可以先把運算結果留在 evaluation stack，再執行有副作用的指令。
        // 若直接把舊運算式文字留到後方重新求值，副作用可能已改變結果；目前沒有
        // synthetic temporary provenance，因此這種順序必須 fail closed。
        return statements.Count == statementCount || stack.Count == 0;
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

        if (IsUnsignedRelationalBranch(name))
        {
            return TryBuildUnsignedRelationalBranchCondition(
                context,
                name,
                left,
                right,
                branchTaken: true,
                out condition);
        }

        if (name is "beq" or "beq.s" or "bne.un" or "bne.un.s" &&
            !TryNormalizeEqualityOperands(context, ref left, ref right))
        {
            return false;
        }

        condition = name switch
        {
            "beq" or "beq.s" => $"{left} == {right}",
            "bne.un" or "bne.un.s" => $"{left} != {right}",
            "bge" or "bge.s" => $"{left} >= {right}",
            "bgt" or "bgt.s" => $"{left} > {right}",
            "ble" or "ble.s" => $"{left} <= {right}",
            "blt" or "blt.s" => $"{left} < {right}",
            _ => string.Empty
        };

        return condition.Length > 0;
    }

    private static bool IsUnsignedRelationalBranch(string name) => name is
        "bge.un" or "bge.un.s" or
        "bgt.un" or "bgt.un.s" or
        "ble.un" or "ble.un.s" or
        "blt.un" or "blt.un.s";

    private static bool TryBuildUnsignedRelationalBranchCondition(
        ReconContext context,
        string name,
        string left,
        string right,
        bool branchTaken,
        out string condition)
    {
        condition = string.Empty;
        if (!TryGetUnsignedIntegralType(context, left, right, out var unsignedType))
        {
            return false;
        }

        var takenOperator = name switch
        {
            "bge.un" or "bge.un.s" => ">=",
            "bgt.un" or "bgt.un.s" => ">",
            "ble.un" or "ble.un.s" => "<=",
            "blt.un" or "blt.un.s" => "<",
            _ => string.Empty
        };
        var renderedOperator = branchTaken
            ? takenOperator
            : takenOperator switch
            {
                ">=" => "<",
                ">" => "<=",
                "<=" => ">",
                "<" => ">=",
                _ => string.Empty
            };
        if (renderedOperator.Length == 0)
        {
            return false;
        }

        condition =
            $"unchecked(({unsignedType}){left}) {renderedOperator} unchecked(({unsignedType}){right})";
        return true;
    }

    // brtrue／brfalse 可直接判斷 bool、整數、managed pointer 與 object reference，C# 則要求 bool 條件。
    // 已知參考型別用 null pattern；其他具名值以 default 比較，保留 CLR 的零值判斷語意。
    private static string RenderBranchCondition(ReconContext context, string expression, bool branchWhenTrue)
    {
        if (!context.ExpressionTypes.TryGetValue(expression, out var type) ||
            type.PrimitiveType == PrimitiveTypeCode.Boolean)
        {
            return branchWhenTrue ? expression : $"!({expression})";
        }

        if (IsKnownReferenceType(context.Metadata, type.Text))
        {
            return $"{expression} is {(branchWhenTrue ? "not null" : "null")}";
        }

        if (type.Text.EndsWith('*') || type.Text.StartsWith("delegate*", StringComparison.Ordinal))
        {
            return $"{expression} {(branchWhenTrue ? "!=" : "==")} null";
        }

        if (type.Text.StartsWith('!') ||
            type.Text.StartsWith("ref ", StringComparison.Ordinal) ||
            type.Text is "TypedReference" or "method*")
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

    private static CliType? ArgType(ReconContext context, int slot)
    {
        if (context.IsInstance && slot == 0)
        {
            return context.InstanceType;
        }

        var parameterIndex = context.IsInstance ? slot - 1 : slot;
        return parameterIndex >= 0 && parameterIndex < context.ParameterTypes.Count
            ? context.ParameterTypes[parameterIndex]
            : null;
    }

    private static void PushArgument(ReconContext context, Stack<string> stack, int slot) =>
        PushExpression(context, stack, ArgName(context, slot), ArgType(context, slot));

    private static bool TryPushLocal(
        ReconContext context,
        Stack<string> stack,
        HashSet<int> declaredLocals,
        int index)
    {
        if (index < 0 ||
            index >= context.LocalTypes.Count ||
            !declaredLocals.Contains(index))
        {
            return false;
        }

        PushExpression(context, stack, LocalName(context, index), context.LocalTypes[index]);
        return true;
    }

    private static void PushExpression(ReconContext context, Stack<string> stack, string expression, CliType? type)
    {
        if (type is null || type.Text.Length == 0)
        {
            context.UnknownExpressionTypes.Add(expression);
            if (context.ExpressionTypes.ContainsKey(expression))
            {
                context.AmbiguousExpressionTypes.Add(expression);
            }
        }
        else if (context.UnknownExpressionTypes.Contains(expression))
        {
            context.AmbiguousExpressionTypes.Add(expression);
        }
        else if (context.ExpressionTypes.TryGetValue(expression, out var existingType))
        {
            if (!AreSameExpressionType(existingType, type))
            {
                context.AmbiguousExpressionTypes.Add(expression);
            }
        }
        else
        {
            context.ExpressionTypes[expression] = type;
        }

        stack.Push(expression);
    }

    private static void PushExpression(ReconContext context, Stack<string> stack, string expression, string? type) =>
        PushExpression(
            context,
            stack,
            expression,
            type is null
                ? null
                : new CliType(type, PrimitiveType: PrimitiveTypeFromAlias(type.TrimEnd('?'))));

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
                var argumentType = ArgType(context, argumentSlot);
                if (argumentType is null ||
                    !TryPop(stack, out var stargValue) ||
                    !TryRenderTargetExpression(context, stargValue, argumentType, out stargValue))
                {
                    return false;
                }

                statements.Add($"{ArgName(context, argumentSlot)} = {stargValue};");
                return true;
            case "starg":
                var wideArgumentSlot = BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2));
                var wideArgumentType = ArgType(context, wideArgumentSlot);
                if (wideArgumentType is null ||
                    !TryPop(stack, out var wideStargValue)
                    || !TryRenderTargetExpression(
                        context,
                        wideStargValue,
                        wideArgumentType,
                        out wideStargValue))
                {
                    return false;
                }

                statements.Add($"{ArgName(context, wideArgumentSlot)} = {wideStargValue};");
                return true;

            case "ldnull":
                PushExpression(
                    context,
                    stack,
                    "null",
                    new CliType("object", PrimitiveType: PrimitiveTypeCode.Object));
                return true;
            case "ldstr":
                var userStringToken = BinaryPrimitives.ReadInt32LittleEndian(
                    il.AsSpan(offset, 4));
                if (!context.UserStrings.TryGet(userStringToken, out var userString))
                {
                    return false;
                }

                PushExpression(
                    context,
                    stack,
                    EscapeCSharpString(userString),
                    new CliType("string", PrimitiveType: PrimitiveTypeCode.String));
                return true;
            case "ldc.i4.m1":
                PushExpression(
                    context,
                    stack,
                    "-1",
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32));
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
                PushExpression(
                    context,
                    stack,
                    name["ldc.i4.".Length..],
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32));
                return true;
            case "ldc.i4.s":
                PushExpression(
                    context,
                    stack,
                    ((sbyte)il[offset]).ToString(),
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32));
                return true;
            case "ldc.i4":
                PushExpression(
                    context,
                    stack,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)).ToString(),
                    new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32));
                return true;
            case "ldc.i8":
                PushExpression(
                    context,
                    stack,
                    $"{BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8))}L",
                    new CliType("long", PrimitiveType: PrimitiveTypeCode.Int64));
                return true;
            case "ldc.r4":
                PushExpression(
                    context,
                    stack,
                    FormatSingleLiteral(BitConverter.Int32BitsToSingle(
                        BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))),
                    new CliType("float", PrimitiveType: PrimitiveTypeCode.Single));
                return true;
            case "ldc.r8":
                PushExpression(
                    context,
                    stack,
                    FormatDoubleLiteral(BitConverter.Int64BitsToDouble(
                        BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8)))),
                    new CliType("double", PrimitiveType: PrimitiveTypeCode.Double));
                return true;

            case "ldloc.0":
            case "ldloc.1":
            case "ldloc.2":
            case "ldloc.3":
                return TryPushLocal(
                    context,
                    stack,
                    declaredLocals,
                    int.Parse(name["ldloc.".Length..]));
            case "ldloc.s":
                return TryPushLocal(context, stack, declaredLocals, il[offset]);
            case "ldloc":
                return TryPushLocal(
                    context,
                    stack,
                    declaredLocals,
                    BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2)));
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
                var loadStatic = ResolveField(
                    metadata,
                    context.EnumTypes,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    context.MemberReferenceCallerContext);
                if (loadStatic is null ||
                    loadStatic.Value.DefinitionAttributes is { } loadStaticAttributes &&
                    !loadStaticAttributes.HasFlag(FieldAttributes.Static) ||
                    !TryRenderStaticFieldTarget(
                        loadStatic.Value,
                        context.MemberReferenceCallerContext,
                        out var loadStaticTarget) ||
                    IsGeneratedName(loadStaticTarget) ||
                    IsGeneratedName(loadStatic.Value.Name))
                {
                    return false;
                }

                MarkUnsafeType(context, loadStatic.Value.Type);
                PushExpression(
                    context,
                    stack,
                    $"{loadStaticTarget}{loadStatic.Value.Name}",
                    loadStatic.Value.Type);
                return true;
            case "ldfld":
                var loadField = ResolveField(
                    metadata,
                    context.EnumTypes,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    context.MemberReferenceCallerContext);
                if (loadField is null ||
                    loadField.Value.DefinitionAttributes is { } loadFieldAttributes &&
                    loadFieldAttributes.HasFlag(FieldAttributes.Static) ||
                    IsGeneratedName(loadField.Value.Name) ||
                    !TryPop(stack, out var fieldTarget) ||
                    !IsCompatibleConstructedReceiver(
                        context,
                        fieldTarget,
                        loadField.Value.DeclaringCliType))
                {
                    return false;
                }

                MarkUnsafeType(context, loadField.Value.Type);
                PushExpression(context, stack, $"{fieldTarget}.{loadField.Value.Name}", loadField.Value.Type);
                return true;
            case "stsfld":
                var storeStatic = ResolveField(
                    metadata,
                    context.EnumTypes,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    context.MemberReferenceCallerContext);
                if (storeStatic is null
                    || storeStatic.Value.DefinitionAttributes is { } storeStaticAttributes
                    && !storeStaticAttributes.HasFlag(FieldAttributes.Static)
                    || !IsWritableFieldDefinition(
                        context,
                        storeStatic.Value,
                        staticStore: true)
                    || !TryRenderStaticFieldTarget(
                        storeStatic.Value,
                        context.MemberReferenceCallerContext,
                        out var storeStaticTarget)
                    || IsGeneratedName(storeStaticTarget)
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

                MarkUnsafeType(context, storeStatic.Value.Type);
                statements.Add($"{storeStaticTarget}{storeStatic.Value.Name} = {storeStaticValue};");
                return true;
            case "stfld":
                var storeField = ResolveField(
                    metadata,
                    context.EnumTypes,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    context.MemberReferenceCallerContext);
                if (storeField is null
                    || storeField.Value.DefinitionAttributes is { } storeFieldAttributes
                    && storeFieldAttributes.HasFlag(FieldAttributes.Static)
                    || !IsWritableFieldDefinition(
                        context,
                        storeField.Value,
                        staticStore: false)
                    || IsGeneratedName(storeField.Value.Name)
                    || !TryPop(stack, out var storeFieldValue)
                    || !TryPop(stack, out var storeFieldTarget)
                    || !IsCompatibleConstructedReceiver(
                        context,
                        storeFieldTarget,
                        storeField.Value.DeclaringCliType)
                    || !TryRenderTargetExpression(
                        context,
                        storeFieldValue,
                        storeField.Value.Type,
                        out storeFieldValue))
                {
                    return false;
                }

                MarkUnsafeType(context, storeField.Value.Type);
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
                return TryBinary(context, stack, BinaryOperator(name));
            case "shl":
            case "shr":
            case "shr.un":
                return TryShift(context, stack, name);
            case "div.un":
            case "rem.un":
                return TryUnsignedIntegralBinary(
                    context,
                    stack,
                    name == "div.un" ? "/" : "%");
            case "ceq":
                return TryBinary(
                    context,
                    stack,
                    "==",
                    new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean));
            case "cgt":
                return TryBinary(
                    context,
                    stack,
                    ">",
                    new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean));
            case "cgt.un":
                return TryUnsignedComparison(context, stack, ">", allowReferenceNull: true);
            case "clt":
                return TryBinary(
                    context,
                    stack,
                    "<",
                    new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean));
            case "clt.un":
                return TryUnsignedComparison(context, stack, "<", allowReferenceNull: false);
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
                var castHandle = MetadataTokens.EntityHandle(
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (!TryCreateInstructionCliType(
                        metadata,
                        context.EnumTypes,
                        castHandle,
                        context.MemberReferenceCallerContext,
                        out var castType) ||
                    IsGeneratedName(castType.Text) ||
                    !TryPop(stack, out var castValue))
                {
                    return false;
                }

                PushExpression(
                    context,
                    stack,
                    $"(({castType.Text}){castValue})",
                    castType);
                return true;
            case "isinst":
                var instHandle = MetadataTokens.EntityHandle(
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (!TryCreateInstructionCliType(
                        metadata,
                        context.EnumTypes,
                        instHandle,
                        context.MemberReferenceCallerContext,
                        out var instType) ||
                    IsGeneratedName(instType.Text) ||
                    !TryPop(stack, out var instValue))
                {
                    return false;
                }

                PushExpression(
                    context,
                    stack,
                    $"({instValue} as {instType.Text})",
                    instType);
                return true;

            case "call":
            case "callvirt":
                return TryEmitCall(
                    context,
                    BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)),
                    usesVirtualDispatch: name == "callvirt",
                    stack,
                    statements);
            case "newobj":
                return TryEmitNewObject(context, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)), stack);

            case "pop":
                if (!TryPop(stack, out var discarded) ||
                    !context.StatementExpressions.Remove(discarded))
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
                if (context.ReturnType.PrimitiveType == PrimitiveTypeCode.Void)
                {
                    if (stack.Count != 0)
                    {
                        return false;
                    }

                    statements.Add("return;");
                }
                else
                {
                    if (stack.Count != 1)
                    {
                        return false;
                    }

                    var value = stack.Pop();
                    if (!TryRenderTargetExpression(context, value, context.ReturnType, out value))
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
        CliType? resultType = null)
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

        if (op == "==" && !TryNormalizeEqualityOperands(context, ref left, ref right))
        {
            return false;
        }

        if (op is "&" or "|" or "^")
        {
            if (leftType is not null &&
                TryGetKnownEnumUnderlyingType(leftType, out _) &&
                IsIntegerLiteral(right))
            {
                if (!TryRenderTargetExpression(context, right, leftType, out right))
                {
                    return false;
                }

                resultType ??= leftType;
            }
            else if (rightType is not null &&
                     TryGetKnownEnumUnderlyingType(rightType, out _) &&
                     IsIntegerLiteral(left))
            {
                if (!TryRenderTargetExpression(context, left, rightType, out left))
                {
                    return false;
                }

                resultType ??= rightType;
            }
            else if (!TryNormalizeBitwiseOperands(context, ref left, ref right, out var bitwiseResultType))
            {
                return false;
            }
            else
            {
                resultType ??= bitwiseResultType;
            }
        }

        if (resultType is null)
        {
            resultType = leftType;
        }

        PushExpression(context, stack, $"({left} {op} {right})", resultType);
        return true;
    }

    private static bool TryNormalizeBitwiseOperands(
        ReconContext context,
        ref string left,
        ref string right,
        out CliType resultType)
    {
        resultType = new CliType(string.Empty);
        if (context.AmbiguousExpressionTypes.Contains(left) ||
            context.AmbiguousExpressionTypes.Contains(right) ||
            !context.ExpressionTypes.TryGetValue(left, out var leftType) ||
            !context.ExpressionTypes.TryGetValue(right, out var rightType))
        {
            return false;
        }

        if (leftType.PrimitiveType == PrimitiveTypeCode.Boolean &&
            TryReadIlBooleanLiteral(right, rightType, out var rightBoolean))
        {
            right = rightBoolean ? "true" : "false";
            rightType = new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean);
        }
        else if (rightType.PrimitiveType == PrimitiveTypeCode.Boolean &&
                 TryReadIlBooleanLiteral(left, leftType, out var leftBoolean))
        {
            left = leftBoolean ? "true" : "false";
            leftType = new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean);
        }

        if (leftType.PrimitiveType == PrimitiveTypeCode.Boolean ||
            rightType.PrimitiveType == PrimitiveTypeCode.Boolean)
        {
            if (leftType.PrimitiveType != PrimitiveTypeCode.Boolean ||
                rightType.PrimitiveType != PrimitiveTypeCode.Boolean)
            {
                return false;
            }

            resultType = new CliType("bool", PrimitiveType: PrimitiveTypeCode.Boolean);
            return true;
        }

        var leftIsEnum = TryGetKnownEnumUnderlyingType(leftType, out var leftUnderlyingType);
        var rightIsEnum = TryGetKnownEnumUnderlyingType(rightType, out var rightUnderlyingType);
        if (leftIsEnum && rightIsEnum && !IsSameCliType(leftType, rightType))
        {
            return false;
        }

        var leftFamily = IntegralStackFamily(leftIsEnum ? leftUnderlyingType : leftType.Text);
        var rightFamily = IntegralStackFamily(rightIsEnum ? rightUnderlyingType : rightType.Text);
        if (leftFamily < 0 || leftFamily != rightFamily)
        {
            return false;
        }

        resultType = leftIsEnum && rightIsEnum
            ? leftType
            : leftFamily switch
            {
                0 => new CliType("int", PrimitiveType: PrimitiveTypeCode.Int32),
                1 => new CliType("long", PrimitiveType: PrimitiveTypeCode.Int64),
                2 => new CliType("nint", PrimitiveType: PrimitiveTypeCode.IntPtr),
                _ => new CliType(string.Empty)
            };
        if (resultType.Text.Length == 0)
        {
            return false;
        }

        var originalLeft = left;
        var originalRight = right;
        return TryRenderTargetExpression(context, originalLeft, resultType, out left) &&
               TryRenderTargetExpression(context, originalRight, resultType, out right);
    }

    // CLI equality compares integral stack values, while C# does not permit enum/integer equality.
    // Only cast toward an enum whose TypeDef identity and underlying type were proven by the catalog;
    // an enum-looking external or malformed named value instead fails the whole reconstruction.
    private static bool TryNormalizeEqualityOperands(
        ReconContext context,
        ref string left,
        ref string right)
    {
        if (!context.ExpressionTypes.TryGetValue(left, out var leftType) ||
            !context.ExpressionTypes.TryGetValue(right, out var rightType))
        {
            return true;
        }

        var leftIsEnum = TryGetKnownEnumUnderlyingType(leftType, out _);
        var rightIsEnum = TryGetKnownEnumUnderlyingType(rightType, out _);
        if (leftIsEnum && rightIsEnum)
        {
            return IsSameCliType(leftType, rightType);
        }

        if (leftIsEnum)
        {
            return TryRenderTargetExpression(context, right, leftType, out right);
        }

        if (rightIsEnum)
        {
            return TryRenderTargetExpression(context, left, rightType, out left);
        }

        var leftIsIntegral = IntegralStackFamily(leftType.Text) >= 0;
        var rightIsIntegral = IntegralStackFamily(rightType.Text) >= 0;
        return !(leftIsIntegral && IsPotentialEnumType(rightType.Text) ||
                 rightIsIntegral && IsPotentialEnumType(leftType.Text));
    }

    private static bool TryShift(
        ReconContext context,
        Stack<string> stack,
        string operation)
    {
        if (stack.Count < 2)
        {
            return false;
        }

        var right = stack.Pop();
        var left = stack.Pop();
        if (context.AmbiguousExpressionTypes.Contains(left) ||
            context.AmbiguousExpressionTypes.Contains(right) ||
            !context.ExpressionTypes.TryGetValue(left, out var leftType) ||
            !context.ExpressionTypes.TryGetValue(right, out var rightType) ||
            !TryGetShiftCarrier(leftType, out var carrierType) ||
            !TryRenderShiftCount(right, rightType, out right))
        {
            return false;
        }

        var op = operation switch
        {
            "shl" => "<<",
            "shr" => ">>",
            "shr.un" => ">>>",
            _ => string.Empty
        };
        if (op.Length == 0)
        {
            return false;
        }

        if (TryGetKnownEnumUnderlyingType(leftType, out _) || leftType.Text != carrierType)
        {
            left = $"unchecked(({carrierType}){left})";
        }

        PushExpression(context, stack, $"({left} {op} {right})", carrierType);
        return true;
    }

    private static bool TryGetShiftCarrier(CliType type, out string carrierType)
    {
        carrierType = string.Empty;
        var stackType = type.Text;
        if (TryGetKnownEnumUnderlyingType(type, out var underlyingType))
        {
            stackType = underlyingType;
        }
        else if (type.IsExactNamedType)
        {
            return false;
        }

        carrierType = IntegralStackFamily(stackType) switch
        {
            0 => "int",
            1 => "long",
            2 => "nint",
            _ => string.Empty
        };
        return carrierType.Length > 0;
    }

    private static bool TryRenderShiftCount(
        string expression,
        CliType type,
        out string rendered)
    {
        rendered = expression;
        var stackType = type.Text;
        var isEnum = TryGetKnownEnumUnderlyingType(type, out var underlyingType);
        if (isEnum)
        {
            stackType = underlyingType;
        }
        else if (type.IsExactNamedType)
        {
            return false;
        }

        var stackFamily = IntegralStackFamily(stackType);
        if (stackFamily is not (0 or 2))
        {
            return false;
        }

        if (isEnum || type.Text != "int")
        {
            rendered = $"unchecked((int){expression})";
        }

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
        if (!TryGetUnsignedIntegralType(context, left, right, out var unsignedType))
        {
            return false;
        }

        var expression =
            $"(unchecked(({unsignedType}){left}) {op} unchecked(({unsignedType}){right}))";
        PushExpression(context, stack, expression, unsignedType);
        context.UnsignedIntegralExpressions.Add(expression);
        return true;
    }

    private static bool TryUnsignedComparison(
        ReconContext context,
        Stack<string> stack,
        string op,
        bool allowReferenceNull)
    {
        if (stack.Count < 2)
        {
            return false;
        }

        var right = stack.Pop();
        var left = stack.Pop();
        if (allowReferenceNull
            && right == "null"
            && context.ExpressionTypes.TryGetValue(left, out var leftType)
            && IsKnownReferenceType(context.Metadata, leftType.Text))
        {
            PushExpression(context, stack, $"({left} is not null)", "bool");
            return true;
        }

        if (!TryGetUnsignedIntegralType(context, left, right, out var unsignedType))
        {
            return false;
        }

        PushExpression(
            context,
            stack,
            $"(unchecked(({unsignedType}){left}) {op} unchecked(({unsignedType}){right}))",
            "bool");
        return true;
    }

    private static bool TryGetUnsignedIntegralType(
        ReconContext context,
        string left,
        string right,
        out string unsignedType)
    {
        unsignedType = string.Empty;
        if (!context.ExpressionTypes.TryGetValue(left, out var leftType)
            || !context.ExpressionTypes.TryGetValue(right, out var rightType))
        {
            return false;
        }

        var stackFamily = IntegralStackFamily(leftType.Text);
        if (stackFamily < 0 || stackFamily != IntegralStackFamily(rightType.Text))
        {
            return false;
        }

        unsignedType = stackFamily switch
        {
            0 => "uint",
            1 => "ulong",
            2 => "nuint",
            _ => string.Empty
        };
        return unsignedType.Length > 0;
    }

    private static bool TryNormalizeBooleanEquality(
        string left,
        CliType? leftType,
        string right,
        CliType? rightType,
        out string expression)
    {
        if (leftType?.Text == "bool" && TryReadIlBooleanLiteral(right, rightType, out var rightValue))
        {
            expression = rightValue ? left : $"!({left})";
            return true;
        }

        if (rightType?.Text == "bool" && TryReadIlBooleanLiteral(left, leftType, out var leftValue))
        {
            expression = leftValue ? right : $"!({right})";
            return true;
        }

        expression = string.Empty;
        return false;
    }

    private static bool TryReadIlBooleanLiteral(string expression, CliType? type, out bool value)
    {
        if (type?.Text == "int" && expression is "0" or "1")
        {
            value = expression == "1";
            return true;
        }

        value = false;
        return false;
    }

    private static bool IsIntegerLiteral(string expression)
    {
        var value = expression.TrimEnd('L', 'l', 'U', 'u');
        return long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _);
    }

    private static bool IsIntegerExpression(ReconContext context, string expression) =>
        IsIntegerLiteral(expression) ||
        (context.ExpressionTypes.TryGetValue(expression, out var type) && type.Text is
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
        && !type.StartsWith("delegate*", StringComparison.Ordinal)
        && !type.EndsWith('*')
        && !type.EndsWith(']');

    private static bool TryGetKnownEnumUnderlyingType(
        CliType? type,
        out string underlyingType)
    {
        underlyingType = type?.EnumUnderlyingType ?? string.Empty;
        return underlyingType.Length > 0;
    }

    private static CliType CreateCliType(SignatureTypeName type, EnumTypeCatalog enumTypes)
    {
        var underlyingType = type.IsExactNamedType &&
                             type.NominalHandle.Kind == HandleKind.TypeDefinition &&
                             type.RawTypeKind == (byte)SignatureTypeKind.ValueType &&
                             type.SignatureKind == SignatureTypeKind.ValueType &&
                             enumTypes.UnderlyingTypes.TryGetValue(
                                 (TypeDefinitionHandle)type.NominalHandle,
                                 out var knownUnderlyingType)
            ? knownUnderlyingType
            : null;
        return new CliType(
            type.Text,
            underlyingType,
            type.NominalHandle,
            type.RawTypeKind,
            type.IsExactNamedType,
            type.SignatureKind,
            type.PrimitiveType,
            type.IsByReference,
            type.HasPinnedQualifier,
            type);
    }

    private static CliType CreateTestCliType(string type, EnumTypeCatalog enumTypes)
    {
        var primitiveType = PrimitiveTypeFromAlias(type.TrimEnd('?'));
        if (primitiveType is not null)
        {
            return new CliType(type, PrimitiveType: primitiveType);
        }

        if (!enumTypes.TestTypeHandles.TryGetValue(type, out var handle))
        {
            return new CliType(type);
        }

        return new CliType(
            type,
            enumTypes.UnderlyingTypes[handle],
            handle,
            (byte)SignatureTypeKind.ValueType,
            IsExactNamedType: true,
            SignatureKind: SignatureTypeKind.ValueType);
    }

    private static PrimitiveTypeCode? PrimitiveTypeFromAlias(string type) => type switch
    {
        "bool" => PrimitiveTypeCode.Boolean,
        "byte" => PrimitiveTypeCode.Byte,
        "sbyte" => PrimitiveTypeCode.SByte,
        "char" => PrimitiveTypeCode.Char,
        "short" => PrimitiveTypeCode.Int16,
        "ushort" => PrimitiveTypeCode.UInt16,
        "int" => PrimitiveTypeCode.Int32,
        "uint" => PrimitiveTypeCode.UInt32,
        "long" => PrimitiveTypeCode.Int64,
        "ulong" => PrimitiveTypeCode.UInt64,
        "float" => PrimitiveTypeCode.Single,
        "double" => PrimitiveTypeCode.Double,
        "nint" => PrimitiveTypeCode.IntPtr,
        "nuint" => PrimitiveTypeCode.UIntPtr,
        "object" => PrimitiveTypeCode.Object,
        "string" => PrimitiveTypeCode.String,
        "void" => PrimitiveTypeCode.Void,
        "TypedReference" => PrimitiveTypeCode.TypedReference,
        _ => null
    };

    private static EnumTypeCatalog ReadEnumTypeCatalog(
        MetadataReader metadata,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (metadata.GetTableRowCount(TableIndex.TypeDef) > MaxTypes)
            {
                return EnumTypeCatalog.Empty;
            }

            var definitions = new Dictionary<string, TypeDefinitionHandle>(StringComparer.Ordinal);
            var ambiguousNames = new HashSet<string>(StringComparer.Ordinal);
            var typesWithNestedChildren = new HashSet<TypeDefinitionHandle>();
            foreach (var handle in metadata.TypeDefinitions)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!TryGetBoundedTypeDefinitionFullName(metadata, handle, out var name))
                {
                    return EnumTypeCatalog.Empty;
                }

                var declaringType = metadata.GetTypeDefinition(handle).GetDeclaringType();
                if (!declaringType.IsNil)
                {
                    typesWithNestedChildren.Add(declaringType);
                }

                if (ambiguousNames.Contains(name))
                {
                    continue;
                }

                if (!definitions.TryAdd(name, handle))
                {
                    definitions.Remove(name);
                    ambiguousNames.Add(name);
                }
            }

            var underlyingTypes = new Dictionary<TypeDefinitionHandle, string>();
            var testTypeHandles = new Dictionary<string, TypeDefinitionHandle>(StringComparer.Ordinal);
            var inspectedFields = 0;
            foreach (var (name, handle) in definitions)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fieldCount = metadata.GetTypeDefinition(handle).GetFields().Count;
                if (fieldCount > MaxEnumFieldsToInspect ||
                    inspectedFields > MaxEnumFieldsToInspectAcrossAssembly - fieldCount)
                {
                    continue;
                }

                inspectedFields += fieldCount;
                if (typesWithNestedChildren.Contains(handle) ||
                    !HasNonGenericDefinitionChain(metadata, handle) ||
                    !TryReadExactEnumUnderlyingType(metadata, handle, out var underlyingType))
                {
                    continue;
                }

                underlyingTypes.Add(handle, underlyingType);
                testTypeHandles.Add(name, handle);
            }

            return new EnumTypeCatalog(underlyingTypes, testTypeHandles);
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return EnumTypeCatalog.Empty;
        }
    }

    private static bool HasNonGenericDefinitionChain(
        MetadataReader metadata,
        TypeDefinitionHandle handle)
    {
        var seen = new HashSet<TypeDefinitionHandle>();
        var current = handle;
        while (!current.IsNil)
        {
            if (seen.Count >= MaxGenericAttributeTypeNameDepth || !seen.Add(current))
            {
                return false;
            }

            var definition = metadata.GetTypeDefinition(current);
            var name = metadata.GetString(definition.Name);
            if (name.Contains('`', StringComparison.Ordinal) ||
                definition.GetGenericParameters().Count != 0)
            {
                return false;
            }

            current = definition.GetDeclaringType();
        }

        return true;
    }

    private static bool TryReadExactEnumUnderlyingType(
        MetadataReader metadata,
        TypeDefinitionHandle handle,
        out string underlyingType)
    {
        underlyingType = string.Empty;
        var definition = metadata.GetTypeDefinition(handle);
        var attributes = definition.Attributes;
        if (!attributes.HasFlag(TypeAttributes.Sealed) ||
            attributes.HasFlag(TypeAttributes.Abstract) ||
            attributes.HasFlag(TypeAttributes.Interface) ||
            (attributes & TypeAttributes.LayoutMask) != TypeAttributes.AutoLayout ||
            !IsSystemEnumBase(metadata, definition.BaseType) ||
            definition.GetMethods().Count != 0 ||
            definition.GetProperties().Count != 0 ||
            definition.GetEvents().Count != 0 ||
            definition.GetInterfaceImplementations().Count != 0)
        {
            return false;
        }

        var instanceFieldCount = 0;
        var literalConstants = new List<(FieldDefinitionHandle Field, ConstantHandle Constant)>();
        foreach (var fieldHandle in definition.GetFields())
        {
            var field = metadata.GetFieldDefinition(fieldHandle);
            var fieldAttributes = field.Attributes;
            if (fieldAttributes.HasFlag(FieldAttributes.Static))
            {
                const FieldAttributes expected = FieldAttributes.Public |
                                                 FieldAttributes.Static |
                                                 FieldAttributes.Literal |
                                                 FieldAttributes.HasDefault;
                if (fieldAttributes != expected ||
                    field.GetDefaultValue().IsNil ||
                    !IsExactEnumLiteralFieldSignature(metadata, field.Signature, handle))
                {
                    return false;
                }

                literalConstants.Add((fieldHandle, field.GetDefaultValue()));
                continue;
            }

            instanceFieldCount++;
            if (instanceFieldCount != 1 ||
                metadata.GetString(field.Name) != "value__" ||
                fieldAttributes != (FieldAttributes.Public |
                                    FieldAttributes.SpecialName |
                                    FieldAttributes.RTSpecialName) ||
                !TryReadExactEnumFieldSignature(metadata, field.Signature, out underlyingType))
            {
                return false;
            }
        }

        var verifiedUnderlyingType = underlyingType;
        return instanceFieldCount == 1 && literalConstants.All(item =>
            IsExactEnumLiteralConstant(
                metadata,
                item.Field,
                item.Constant,
                verifiedUnderlyingType));
    }

    private static bool IsExactEnumLiteralConstant(
        MetadataReader metadata,
        FieldDefinitionHandle fieldHandle,
        ConstantHandle constantHandle,
        string underlyingType)
    {
        var constant = metadata.GetConstant(constantHandle);
        var expected = underlyingType switch
        {
            "sbyte" => (ConstantTypeCode.SByte, 1),
            "byte" => (ConstantTypeCode.Byte, 1),
            "short" => (ConstantTypeCode.Int16, 2),
            "ushort" => (ConstantTypeCode.UInt16, 2),
            "int" => (ConstantTypeCode.Int32, 4),
            "uint" => (ConstantTypeCode.UInt32, 4),
            "long" => (ConstantTypeCode.Int64, 8),
            "ulong" => (ConstantTypeCode.UInt64, 8),
            _ => (ConstantTypeCode.Invalid, 0)
        };
        return expected.Item2 > 0 &&
               constant.Parent == fieldHandle &&
               constant.TypeCode == expected.Item1 &&
               metadata.GetBlobReader(constant.Value).Length == expected.Item2;
    }

    private static bool IsExactEnumLiteralFieldSignature(
        MetadataReader metadata,
        BlobHandle signature,
        TypeDefinitionHandle enumHandle)
    {
        var reader = metadata.GetBlobReader(signature);
        return reader.RemainingBytes >= 3 &&
               reader.ReadByte() == 0x06 &&
               reader.ReadByte() == 0x11 &&
               reader.ReadTypeHandle() == enumHandle &&
               reader.RemainingBytes == 0;
    }

    private static bool TryReadExactEnumFieldSignature(
        MetadataReader metadata,
        BlobHandle signature,
        out string underlyingType)
    {
        underlyingType = string.Empty;
        var reader = metadata.GetBlobReader(signature);
        if (reader.Length != 2 || reader.ReadByte() != 0x06)
        {
            return false;
        }

        underlyingType = reader.ReadByte() switch
        {
            0x04 => "sbyte",
            0x05 => "byte",
            0x06 => "short",
            0x07 => "ushort",
            0x08 => "int",
            0x09 => "uint",
            0x0A => "long",
            0x0B => "ulong",
            _ => string.Empty
        };
        return underlyingType.Length > 0;
    }

    private static bool IsSystemEnumBase(MetadataReader metadata, EntityHandle handle)
    {
        if (handle.Kind != HandleKind.TypeReference)
        {
            return false;
        }

        var reference = metadata.GetTypeReference((TypeReferenceHandle)handle);
        if (metadata.GetString(reference.Namespace) != "System" ||
            metadata.GetString(reference.Name) != "Enum" ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        var assembly = metadata.GetAssemblyReference((AssemblyReferenceHandle)reference.ResolutionScope);
        return IsTrustedFrameworkAssembly(
            metadata,
            metadata.GetString(assembly.Name),
            assembly.PublicKeyOrToken,
            assembly.Culture,
            assembly.Flags);
    }

    internal static bool IsTrustedFrameworkAssembly(
        MetadataReader metadata,
        string name,
        BlobHandle publicKeyOrToken,
        StringHandle culture,
        AssemblyFlags flags)
    {
        if ((!culture.IsNil && metadata.GetString(culture).Length != 0) ||
            flags.HasFlag(AssemblyFlags.Retargetable) ||
            flags.HasFlag(AssemblyFlags.WindowsRuntime))
        {
            return false;
        }

        var reader = metadata.GetBlobReader(publicKeyOrToken);
        if (reader.Length == 0 || reader.Length > MaxAssemblyPublicKeyBytes)
        {
            return false;
        }

        var keyOrToken = metadata.GetBlobBytes(publicKeyOrToken);
        byte[] token;
        if (flags.HasFlag(AssemblyFlags.PublicKey))
        {
            var hash = SHA1.HashData(keyOrToken);
            token = new byte[8];
            for (var index = 0; index < token.Length; index++)
            {
                token[index] = hash[hash.Length - 1 - index];
            }
        }
        else
        {
            if (keyOrToken.Length != 8)
            {
                return false;
            }

            token = keyOrToken;
        }

        var tokenText = Convert.ToHexString(token);
        return name switch
        {
            "System.Private.CoreLib" => tokenText == "7CEC85D7BEA7798E",
            "System.Runtime" => tokenText == "B03F5F7F11D50A3A",
            "mscorlib" => tokenText == "B77A5C561934E089",
            "netstandard" => tokenText == "CC7B13FFCD2DDD51",
            _ => false
        };
    }

    private static bool TryGetBoundedTypeDefinitionFullName(
        MetadataReader metadata,
        TypeDefinitionHandle handle,
        out string fullName)
    {
        var segments = new List<string>();
        var seen = new HashSet<TypeDefinitionHandle>();
        var current = handle;
        var namespaceName = string.Empty;
        while (!current.IsNil)
        {
            if (segments.Count >= MaxGenericAttributeTypeNameDepth || !seen.Add(current))
            {
                fullName = string.Empty;
                return false;
            }

            var definition = metadata.GetTypeDefinition(current);
            var segment = StripArity(metadata.GetString(definition.Name));
            if (segment.Length == 0 || segment.Length > MaxGenericAttributeTypeNameCharacters)
            {
                fullName = string.Empty;
                return false;
            }

            segments.Add(segment);
            var declaringType = definition.GetDeclaringType();
            if (declaringType.IsNil)
            {
                namespaceName = metadata.GetString(definition.Namespace);
            }

            current = declaringType;
        }

        segments.Reverse();
        fullName = string.IsNullOrEmpty(namespaceName)
            ? string.Join('.', segments)
            : $"{namespaceName}.{string.Join('.', segments)}";
        return fullName.Length <= MaxGenericAttributeTypeNameCharacters;
    }

    private static bool TryGetBoundedTypeReferenceFullName(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        out string fullName)
    {
        var segments = new List<string>();
        var seen = new HashSet<TypeReferenceHandle>();
        var current = handle;
        var namespaceName = string.Empty;
        while (!current.IsNil)
        {
            if (segments.Count >= MaxGenericAttributeTypeNameDepth || !seen.Add(current))
            {
                fullName = string.Empty;
                return false;
            }

            var reference = metadata.GetTypeReference(current);
            var segment = StripArity(metadata.GetString(reference.Name));
            if (segment.Length == 0 || segment.Length > MaxGenericAttributeTypeNameCharacters)
            {
                fullName = string.Empty;
                return false;
            }

            segments.Add(segment);
            if (reference.ResolutionScope.Kind != HandleKind.TypeReference)
            {
                namespaceName = metadata.GetString(reference.Namespace);
                current = default;
            }
            else
            {
                current = (TypeReferenceHandle)reference.ResolutionScope;
            }
        }

        segments.Reverse();
        fullName = string.IsNullOrEmpty(namespaceName)
            ? string.Join('.', segments)
            : $"{namespaceName}.{string.Join('.', segments)}";
        return fullName.Length <= MaxGenericAttributeTypeNameCharacters;
    }

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
        if (index < 0 || index >= context.LocalTypes.Count || !TryPop(stack, out var value))
        {
            return false;
        }

        var localType = context.LocalTypes[index];
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
        if (type.Text.Length == 0 ||
            type.Text.StartsWith("ref ", StringComparison.Ordinal) ||
            IsGeneratedName(type.Text))
        {
            return "var";
        }

        return type.Text;
    }

    // 編譯器產生的名稱（狀態機、lambda、匿名型別）沒辦法在 C# 直接寫出來，碰到就放棄整個方法。
    private static bool IsGeneratedName(string name) =>
        name.StartsWith('<') || name.Contains(".<", StringComparison.Ordinal) || name.Contains("<>", StringComparison.Ordinal);

    private static bool TryEmitCall(
        ReconContext context,
        int token,
        bool usesVirtualDispatch,
        Stack<string> stack,
        List<string> statements)
    {
        var metadata = context.Metadata;
        var info = ResolveCall(
            metadata,
            context.EnumTypes,
            token,
            context.MemberReferenceCallerContext);
        if (info is null || info.Name is ".ctor" or ".cctor" || IsGeneratedName(info.Name))
        {
            return false;
        }

        // C# 的 ref/out/in 呼叫除了型別之外，還需要 managed-address provenance 與
        // parameter pass kind。現有 expression stack 尚未保存這兩項證據，不能只靠
        // 顯示字串前綴猜測修飾詞，否則 hostile IL 可能被還原成不同語意的呼叫。
        if (info.ParameterTypes.Any(type => type.IsByReference))
        {
            return false;
        }

        if (usesVirtualDispatch && !info.HasThis)
        {
            return false;
        }

        if (info.GenericParameterCount != info.GenericArguments.Count)
        {
            return false;
        }

        if (!info.HasThis && IsGeneratedName(info.DeclaringType))
        {
            return false;
        }

        MarkUnsafeSignature(context, info);

        var args = new string[info.ParamCount];
        for (var index = info.ParamCount - 1; index >= 0; index--)
        {
            if (!TryPop(stack, out var argument))
            {
                return false;
            }

            if (!TryRenderArgument(
                    context,
                    argument,
                    index < info.ParameterTypes.Count ? info.ParameterTypes[index] : null,
                    out args[index]))
            {
                return false;
            }
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

        if (info.ArrayPseudoMember is { } arrayPseudoMember)
        {
            return TryEmitArrayPseudoMember(
                context,
                info,
                arrayPseudoMember,
                usesVirtualDispatch,
                receiver,
                args,
                stack,
                statements);
        }

        if (info.Name.StartsWith("op_", StringComparison.Ordinal))
        {
            if (info.HasThis)
            {
                return false;
            }

            return TryEmitOperator(context, info, args, stack);
        }

        var target = info.DeclaringType;
        if (info.HasThis &&
            !TryRenderInstanceCallTarget(
                context,
                receiver!,
                info,
                usesVirtualDispatch,
                out target))
        {
            return false;
        }

        var targetPrefix = $"{target}.";
        if (info.Name.StartsWith("get_", StringComparison.Ordinal))
        {
            if (info.ParamCount == 0)
            {
                PushExpression(context, stack, $"{targetPrefix}{info.Name["get_".Length..]}", info.ReturnType);
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
                statements.Add($"{targetPrefix}{info.Name["set_".Length..]} = {args[0]};");
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
        var call = $"{targetPrefix}{methodName}({string.Join(", ", args)})";
        if (info.ReturnsVoid)
        {
            statements.Add($"{call};");
        }
        else
        {
            PushExpression(context, stack, call, info.ReturnType);
            context.StatementExpressions.Add(call);
        }

        return true;
    }

    private static bool TryEmitArrayPseudoMember(
        ReconContext context,
        CallInfo info,
        ArrayPseudoMemberInfo pseudoMember,
        bool usesVirtualDispatch,
        string? receiver,
        IReadOnlyList<string> arguments,
        Stack<string> stack,
        List<string> statements)
    {
        if (usesVirtualDispatch ||
            receiver is null ||
            pseudoMember.Kind == ArrayPseudoMemberKind.Constructor ||
            context.AmbiguousExpressionTypes.Contains(receiver) ||
            !context.ExpressionTypes.TryGetValue(receiver, out var receiverType) ||
            receiverType.StructuralSignature is not { } receiverSignature ||
            info.DeclaringCliType.StructuralSignature is not { } declaringSignature ||
            !AreSameConstructorSignature(receiverSignature, declaringSignature))
        {
            return false;
        }

        if (pseudoMember.Kind == ArrayPseudoMemberKind.Get &&
            arguments.Count == pseudoMember.Rank)
        {
            PushExpression(
                context,
                stack,
                $"{receiver}[{string.Join(", ", arguments)}]",
                info.ReturnType);
            return true;
        }

        if (pseudoMember.Kind == ArrayPseudoMemberKind.Set &&
            arguments.Count == pseudoMember.Rank + 1 &&
            info.ReturnsVoid)
        {
            statements.Add(
                $"{receiver}[{string.Join(", ", arguments.Take(pseudoMember.Rank))}] = {arguments[^1]};");
            return true;
        }

        return false;
    }

    private static bool TryRenderInstanceCallTarget(
        ReconContext context,
        string receiver,
        CallInfo info,
        bool usesVirtualDispatch,
        out string target)
    {
        target = receiver;
        if (!usesVirtualDispatch && receiver == "this")
        {
            if (!IsExactCurrentInstanceReceiver(context, receiver) ||
                !TryClassifyThisCallOwner(
                    context.Metadata,
                    context.InstanceType,
                    info.DeclaringHandle,
                    out var isBaseCall))
            {
                return false;
            }

            if (isBaseCall)
            {
                if (info.DefinitionAttributes is null ||
                    info.DefinitionAttributes.Value.HasFlag(MethodAttributes.Static) ||
                    info.DefinitionAttributes.Value.HasFlag(MethodAttributes.Abstract) ||
                    info.GenericParameterCount != 0 ||
                    info.GenericArguments.Count != 0)
                {
                    return false;
                }

                target = "base";
                return true;
            }

            if (info.DefinitionAttributes is null ||
                info.DefinitionAttributes.Value.HasFlag(MethodAttributes.Abstract) ||
                (info.DefinitionAttributes.Value.HasFlag(MethodAttributes.Virtual) &&
                 !info.DefinitionAttributes.Value.HasFlag(MethodAttributes.Final)))
            {
                return false;
            }

            return true;
        }

        if (!usesVirtualDispatch)
        {
            return false;
        }

        if (receiver == "this" && !IsExactCurrentInstanceReceiver(context, receiver))
        {
            return false;
        }

        if (string.IsNullOrEmpty(info.DeclaringType) ||
            IsGeneratedName(info.DeclaringType))
        {
            return false;
        }

        var isPotentialInterface = IsPotentialInterfaceType(
            context.Metadata,
            info.DeclaringType);
        if (info.DeclaringCliType.StructuralSignature is
            { IsCanonicalGenericInstantiation: true } &&
            !IsCompatibleConstructedReceiver(
                context,
                receiver,
                info.DeclaringCliType))
        {
            return false;
        }

        if (!isPotentialInterface ||
            !context.ExpressionTypes.TryGetValue(receiver, out var receiverType) ||
            receiverType.Text == info.DeclaringType)
        {
            return true;
        }

        // IL callvirt 會保留宣告 slot；C# 若直接用 concrete receiver，可能改綁到同名 public member。
        // 明確轉成 metadata declaring interface，保留 explicit interface dispatch、overload 與回傳型別。
        target = $"(({info.DeclaringType}){receiver})";
        return true;
    }

    private static bool IsCompatibleConstructedReceiver(
        ReconContext context,
        string receiver,
        CliType declaringType)
    {
        if (declaringType.StructuralSignature is not
            { IsCanonicalGenericInstantiation: true } declaringSignature)
        {
            return true;
        }

        if (context.AmbiguousExpressionTypes.Contains(receiver) ||
            !context.ExpressionTypes.TryGetValue(receiver, out var receiverType))
        {
            return false;
        }

        if (receiverType.StructuralSignature is
            { IsCanonicalGenericInstantiation: true } receiverSignature &&
            receiverSignature.GenericDefinitionHandle ==
                declaringSignature.GenericDefinitionHandle)
        {
            return AreSameExpressionType(receiverType, declaringType);
        }

        // A same-text type from another assembly cannot be disambiguated in emitted C#.
        // Different nominal definitions remain eligible because the receiver may derive
        // from the declaring constructed class or implement the declaring interface.
        return receiverType.Text != declaringType.Text ||
               AreSameExpressionType(receiverType, declaringType);
    }

    private static bool IsExactCurrentInstanceReceiver(ReconContext context, string receiver) =>
        !context.AmbiguousExpressionTypes.Contains(receiver) &&
        !context.ParameterNames.Values.Contains("this", StringComparer.Ordinal) &&
        !context.LocalNames.Values.Contains("this", StringComparer.Ordinal) &&
        context.InstanceType is not null &&
        context.ExpressionTypes.TryGetValue(receiver, out var receiverType) &&
        IsSameCliType(receiverType, context.InstanceType);

    private static bool TryClassifyThisCallOwner(
        MetadataReader metadata,
        CliType? instanceType,
        EntityHandle declaringHandle,
        out bool isBaseCall)
    {
        isBaseCall = false;
        if (instanceType is null || declaringHandle.IsNil)
        {
            return false;
        }

        var current = instanceType.NominalHandle.Kind == HandleKind.TypeDefinition
            ? (TypeDefinitionHandle)instanceType.NominalHandle
            : instanceType.StructuralSignature is
            {
                IsCanonicalGenericInstantiation: true,
                GenericDefinitionHandle.Kind: HandleKind.TypeDefinition
            } signature
                ? (TypeDefinitionHandle)signature.GenericDefinitionHandle
                : default;
        if (current.IsNil)
        {
            return false;
        }

        if (declaringHandle == current)
        {
            return true;
        }

        var baseType = metadata.GetTypeDefinition(current).BaseType;
        if (baseType.Kind == HandleKind.TypeDefinition &&
            declaringHandle.Kind == HandleKind.TypeDefinition &&
            baseType == declaringHandle)
        {
            isBaseCall = true;
            return true;
        }

        return false;
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
        (argumentType.Text.EndsWith("?", StringComparison.Ordinal) ||
         argumentType.Text.StartsWith("System.Nullable<", StringComparison.Ordinal));

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
        var info = ResolveCall(
            metadata,
            context.EnumTypes,
            token,
            context.MemberReferenceCallerContext);
        if (info is null ||
            info.Name != ".ctor" ||
            !info.HasThis ||
            !info.ReturnsVoid ||
            info.GenericParameterCount != 0 ||
            info.GenericArguments.Count != 0 ||
            info.DeclaringHandle.Kind is not (
                HandleKind.TypeDefinition or
                HandleKind.TypeReference or
                HandleKind.TypeSpecification) ||
            (info.DefinitionAttributes is { } attributes &&
             (!attributes.HasFlag(MethodAttributes.SpecialName) ||
              !attributes.HasFlag(MethodAttributes.RTSpecialName) ||
              attributes.HasFlag(MethodAttributes.Static))) ||
            IsGeneratedName(info.DeclaringType))
        {
            return false;
        }

        if (info.ParameterTypes.Any(type => type.IsByReference))
        {
            return false;
        }

        MarkUnsafeSignature(context, info);

        var args = new string[info.ParamCount];
        for (var index = info.ParamCount - 1; index >= 0; index--)
        {
            if (!TryPop(stack, out var argument))
            {
                return false;
            }

            if (!TryRenderArgument(
                    context,
                    argument,
                    index < info.ParameterTypes.Count ? info.ParameterTypes[index] : null,
                    out args[index]))
            {
                return false;
            }
        }

        var expression = info.ArrayPseudoMember is
        { Kind: ArrayPseudoMemberKind.Constructor } arrayConstructor
            ? $"new {arrayConstructor.ElementType}[{string.Join(", ", args)}]"
            : $"new {info.DeclaringType}({string.Join(", ", args)})";
        PushExpression(context, stack, expression, info.DeclaringCliType);
        if (info.ArrayPseudoMember is null)
        {
            context.StatementExpressions.Add(expression);
        }

        return true;
    }

    private static void MarkUnsafeSignature(ReconContext context, CallInfo info)
    {
        if (RequiresUnsafeType(info.ReturnType.Text) ||
            info.ParameterTypes.Any(type => RequiresUnsafeType(type.Text)) ||
            info.GenericArguments.Any(RequiresUnsafeType))
        {
            context.State.RequiresUnsafeContext = true;
        }
    }

    private static void MarkUnsafeType(ReconContext context, string type)
    {
        if (RequiresUnsafeType(type))
        {
            context.State.RequiresUnsafeContext = true;
        }
    }

    private static bool RequiresUnsafeType(string type) => type.Contains('*');

    // bool、char 與 enum 在 IL 中都以整數常值傳遞；依正式參數型別還原成可編譯的 C# 引數。
    private static bool TryRenderArgument(
        ReconContext context,
        string argument,
        CliType? parameterType,
        out string rendered)
    {
        rendered = argument;
        var isIntegerLiteral = long.TryParse(
            argument,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value);
        if (isIntegerLiteral && parameterType?.Text == "bool" && value is 0 or 1)
        {
            rendered = value == 1 ? "true" : "false";
            return true;
        }

        if (isIntegerLiteral && parameterType?.Text == "char" && value is >= 0 and <= 0xFFFF)
        {
            rendered = FormatCharLiteral((char)value);
            return true;
        }

        if (parameterType is not null &&
            context.ExpressionTypes.TryGetValue(argument, out var argumentType))
        {
            if (argumentType.Text == parameterType.Text)
            {
                return AreSameExpressionType(argumentType, parameterType);
            }

            var argumentIsEnum = TryGetKnownEnumUnderlyingType(argumentType, out var argumentUnderlyingType);
            var parameterIsEnum = TryGetKnownEnumUnderlyingType(parameterType, out var parameterUnderlyingType);
            var argumentFamily = IntegralStackFamily(argumentIsEnum ? argumentUnderlyingType : argumentType.Text);
            var parameterFamily = IntegralStackFamily(parameterIsEnum ? parameterUnderlyingType : parameterType.Text);
            var enumLikeMismatch = !isIntegerLiteral && (
                argumentFamily >= 0 && IsPotentialEnumType(parameterType.Text) ||
                parameterFamily >= 0 && IsPotentialEnumType(argumentType.Text));
            if (argumentType.PrimitiveType == PrimitiveTypeCode.Boolean ||
                parameterType.PrimitiveType == PrimitiveTypeCode.Boolean ||
                argumentIsEnum ||
                parameterIsEnum ||
                argumentFamily >= 0 && parameterFamily >= 0 ||
                enumLikeMismatch)
            {
                return TryRenderTargetExpression(context, argument, parameterType, out rendered);
            }
        }

        if (!isIntegerLiteral)
        {
            return true;
        }

        rendered = IsNumericOrReferenceParameter(parameterType?.Text)
            ? argument
            : $"unchecked(({parameterType?.Text}){argument})";
        return true;
    }

    private static bool ContainsUninstantiatedTypeGenericParameter(string type)
    {
        for (var index = 0; index + 1 < type.Length; index++)
        {
            if (type[index] == '!' &&
                (index == 0 || type[index - 1] != '!') &&
                type[index + 1] != '!' &&
                char.IsAsciiDigit(type[index + 1]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsUninstantiatedMethodGenericParameter(string type)
    {
        for (var index = 0; index + 2 < type.Length; index++)
        {
            if (type[index] == '!' &&
                type[index + 1] == '!' &&
                char.IsAsciiDigit(type[index + 2]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSameIntegralStackFamily(string left, string right)
    {
        var leftFamily = IntegralStackFamily(left);
        return leftFamily >= 0 && leftFamily == IntegralStackFamily(right);
    }

    private static bool TryRenderTargetExpression(
        ReconContext context,
        string expression,
        CliType? targetType,
        out string rendered)
    {
        rendered = expression;
        if (targetType is null)
        {
            return false;
        }

        if (context.AmbiguousExpressionTypes.Contains(expression))
        {
            return false;
        }

        if (!context.ExpressionTypes.TryGetValue(expression, out var sourceType))
        {
            return false;
        }

        if (sourceType.Text == targetType.Text)
        {
            return AreSameExpressionType(sourceType, targetType);
        }

        if (targetType.Text == "bool")
        {
            if (!TryReadIlBooleanLiteral(expression, sourceType, out var booleanValue))
            {
                return false;
            }

            rendered = booleanValue ? "true" : "false";
            return true;
        }

        if (sourceType.Text == "bool")
        {
            return false;
        }

        var sourceIsEnum = TryGetKnownEnumUnderlyingType(sourceType, out var sourceUnderlyingType);
        var targetIsEnum = TryGetKnownEnumUnderlyingType(targetType, out var targetUnderlyingType);
        var sourceStackType = sourceIsEnum ? sourceUnderlyingType : sourceType.Text;
        var targetStackType = targetIsEnum ? targetUnderlyingType : targetType.Text;
        var sourceFamily = IntegralStackFamily(sourceStackType);
        var targetFamily = IntegralStackFamily(targetStackType);
        if (sourceFamily < 0 &&
            targetFamily < 0 &&
            (IsExactValueType(sourceType) || IsExactValueType(targetType)))
        {
            return false;
        }

        if (sourceIsEnum || targetIsEnum || (sourceFamily >= 0 && targetFamily >= 0))
        {
            if (sourceFamily < 0 || sourceFamily != targetFamily)
            {
                return false;
            }

            rendered = $"unchecked(({targetType.Text}){expression})";
            return true;
        }

        // 具名型別若無法由目前 assembly 的 metadata 證實為 enum，就不能猜測其
        // underlying stack family 後輸出數值轉型。
        if ((sourceFamily >= 0 && IsPotentialEnumType(targetType.Text)) ||
            (targetFamily >= 0 && IsPotentialEnumType(sourceType.Text)))
        {
            return false;
        }

        if (!context.UnsignedIntegralExpressions.Contains(expression))
        {
            return true;
        }

        // div.un／rem.un 會把結果標成該 stack family 的無號型別。若接收端是同 family
        // 的 signed／窄型別，必須明確轉回；缺少或跨 family 的目標則不能猜測。
        if (sourceType.Text is not ("uint" or "ulong" or "nuint"))
        {
            return true;
        }

        if (!IsSameIntegralStackFamily(sourceType.Text, targetType.Text))
        {
            return false;
        }

        rendered = $"unchecked(({targetType.Text}){expression})";
        return true;
    }

    private static bool IsExactValueType(CliType type) =>
        type.IsExactNamedType && type.RawTypeKind == (byte)SignatureTypeKind.ValueType;

    private static bool IsSameCliType(CliType left, CliType right)
    {
        if (left.Text == right.Text &&
            left.EnumUnderlyingType == right.EnumUnderlyingType &&
            left.NominalHandle == right.NominalHandle &&
            left.RawTypeKind == right.RawTypeKind &&
            left.IsExactNamedType == right.IsExactNamedType &&
            left.SignatureKind == right.SignatureKind &&
            left.PrimitiveType == right.PrimitiveType &&
            left.IsByReference == right.IsByReference &&
            left.HasPinnedQualifier == right.HasPinnedQualifier)
        {
            return true;
        }

        return left.IsExactNamedType &&
               right.IsExactNamedType &&
               !left.NominalHandle.IsNil &&
               left.NominalHandle == right.NominalHandle &&
               (left.RawTypeKind == 0 || right.RawTypeKind == 0 || left.RawTypeKind == right.RawTypeKind) &&
               (left.SignatureKind == SignatureTypeKind.Unknown ||
                right.SignatureKind == SignatureTypeKind.Unknown ||
                left.SignatureKind == right.SignatureKind) &&
               left.EnumUnderlyingType == right.EnumUnderlyingType;
    }

    private static bool AreSameExpressionType(CliType left, CliType right)
    {
        if (!IsSameCliType(left, right))
        {
            return false;
        }

        if (left.StructuralSignature is null || right.StructuralSignature is null)
        {
            return left.StructuralSignature is null && right.StructuralSignature is null ||
                   left.PrimitiveType is not null &&
                   left.PrimitiveType == right.PrimitiveType ||
                   left.IsExactNamedType &&
                   right.IsExactNamedType &&
                   !left.NominalHandle.IsNil &&
                   left.NominalHandle == right.NominalHandle;
        }

        var remainingNodes = 512;
        return AreSameExpressionSignature(
            left.StructuralSignature,
            right.StructuralSignature,
            depth: 0,
            ref remainingNodes);
    }

    private static bool AreSameExpressionSignature(
        SignatureTypeName left,
        SignatureTypeName right,
        int depth,
        ref int remainingNodes)
    {
        if (depth > MaxStructureDepth ||
            remainingNodes-- <= 0 ||
            left.Text != right.Text ||
            left.HasNestedCustomModifiers != right.HasNestedCustomModifiers ||
            left.IsRestrictedGenericArgument != right.IsRestrictedGenericArgument ||
            !HaveCompatibleExpressionNominalIdentity(left, right) ||
            left.PrimitiveType != right.PrimitiveType ||
            left.IsByReference != right.IsByReference ||
            left.IsCanonicalGenericInstantiation != right.IsCanonicalGenericInstantiation ||
            left.GenericDefinitionHandle != right.GenericDefinitionHandle ||
            !HaveCompatibleExpressionSignatureKind(
                left.GenericDefinitionRawTypeKind,
                left.GenericDefinitionSignatureKind,
                right.GenericDefinitionRawTypeKind,
                right.GenericDefinitionSignatureKind) ||
            left.GenericDefinitionText != right.GenericDefinitionText ||
            left.TypeParameterSlot != right.TypeParameterSlot ||
            left.MethodParameterSlot != right.MethodParameterSlot ||
            left.ArrayRank != right.ArrayRank ||
            left.HasPinnedQualifier != right.HasPinnedQualifier ||
            left.IsUnsupported != right.IsUnsupported ||
            !AreSameImmutableValues(left.OuterCustomModifiers, right.OuterCustomModifiers) ||
            !AreSameImmutableValues(left.ArraySizes, right.ArraySizes) ||
            !AreSameImmutableValues(left.ArrayLowerBounds, right.ArrayLowerBounds) ||
            !AreSameOptionalExpressionSignature(
                left.ArrayElementType,
                right.ArrayElementType,
                depth,
                ref remainingNodes) ||
            !AreSameOptionalExpressionSignature(
                left.SzArrayElementType,
                right.SzArrayElementType,
                depth,
                ref remainingNodes) ||
            !AreSameOptionalExpressionSignature(
                left.ByReferenceElementType,
                right.ByReferenceElementType,
                depth,
                ref remainingNodes) ||
            !AreSameOptionalExpressionSignature(
                left.PointerElementType,
                right.PointerElementType,
                depth,
                ref remainingNodes) ||
            !AreSameOptionalFunctionPointerSignature(
                left.FunctionPointerSignature,
                right.FunctionPointerSignature,
                depth,
                ref remainingNodes))
        {
            return false;
        }

        var leftArguments = left.GenericArguments.IsDefault
            ? ImmutableArray<SignatureTypeName>.Empty
            : left.GenericArguments;
        var rightArguments = right.GenericArguments.IsDefault
            ? ImmutableArray<SignatureTypeName>.Empty
            : right.GenericArguments;
        if (leftArguments.Length != rightArguments.Length)
        {
            return false;
        }

        for (var index = 0; index < leftArguments.Length; index++)
        {
            if (!AreSameExpressionSignature(
                    leftArguments[index],
                    rightArguments[index],
                    depth + 1,
                    ref remainingNodes))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HaveCompatibleExpressionNominalIdentity(
        SignatureTypeName left,
        SignatureTypeName right)
    {
        if (left.IsExactNamedType != right.IsExactNamedType ||
            left.NominalHandle != right.NominalHandle)
        {
            return false;
        }

        if (!left.IsExactNamedType)
        {
            return left.RawTypeKind == right.RawTypeKind &&
                   left.SignatureKind == right.SignatureKind;
        }

        return !left.NominalHandle.IsNil &&
               HaveCompatibleExpressionSignatureKind(
                   left.RawTypeKind,
                   left.SignatureKind,
                   right.RawTypeKind,
                   right.SignatureKind);
    }

    private static bool HaveCompatibleExpressionSignatureKind(
        byte leftRawTypeKind,
        SignatureTypeKind leftSignatureKind,
        byte rightRawTypeKind,
        SignatureTypeKind rightSignatureKind) =>
        (leftRawTypeKind == 0 ||
         rightRawTypeKind == 0 ||
         leftRawTypeKind == rightRawTypeKind) &&
        (leftSignatureKind == SignatureTypeKind.Unknown ||
         rightSignatureKind == SignatureTypeKind.Unknown ||
         leftSignatureKind == rightSignatureKind);

    private static bool AreSameOptionalFunctionPointerSignature(
        SignatureFunctionPointer? left,
        SignatureFunctionPointer? right,
        int depth,
        ref int remainingNodes)
    {
        if (left is null || right is null)
        {
            return left is null && right is null;
        }

        if (!left.Header.Equals(right.Header) ||
            left.RequiredParameterCount != right.RequiredParameterCount ||
            left.GenericParameterCount != right.GenericParameterCount ||
            left.ParameterTypes.Length != right.ParameterTypes.Length ||
            !AreSameExpressionSignature(
                left.ReturnType,
                right.ReturnType,
                depth + 1,
                ref remainingNodes))
        {
            return false;
        }

        for (var index = 0; index < left.ParameterTypes.Length; index++)
        {
            if (!AreSameExpressionSignature(
                    left.ParameterTypes[index],
                    right.ParameterTypes[index],
                    depth + 1,
                    ref remainingNodes))
            {
                return false;
            }
        }

        return true;
    }

    private static bool AreSameOptionalExpressionSignature(
        SignatureTypeName? left,
        SignatureTypeName? right,
        int depth,
        ref int remainingNodes) =>
        left is null || right is null
            ? left is null && right is null
            : AreSameExpressionSignature(left, right, depth + 1, ref remainingNodes);

    private static bool AreSameImmutableValues<T>(
        ImmutableArray<T> left,
        ImmutableArray<T> right)
    {
        if (left.IsDefaultOrEmpty || right.IsDefaultOrEmpty)
        {
            return left.IsDefaultOrEmpty && right.IsDefaultOrEmpty;
        }

        return left.SequenceEqual(right);
    }

    private static int IntegralStackFamily(string type) => type switch
    {
        "char" or "sbyte" or "byte" or "short" or "ushort" or "int" or "uint" => 0,
        "long" or "ulong" => 1,
        "nint" or "nuint" => 2,
        _ => -1
    };

    private static int IntegralStackFamily(PrimitiveTypeCode? type) => type switch
    {
        PrimitiveTypeCode.Char or
        PrimitiveTypeCode.SByte or
        PrimitiveTypeCode.Byte or
        PrimitiveTypeCode.Int16 or
        PrimitiveTypeCode.UInt16 or
        PrimitiveTypeCode.Int32 or
        PrimitiveTypeCode.UInt32 => 0,
        PrimitiveTypeCode.Int64 or PrimitiveTypeCode.UInt64 => 1,
        PrimitiveTypeCode.IntPtr or PrimitiveTypeCode.UIntPtr => 2,
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
        || parameterType.EndsWith('*')
        || parameterType.StartsWith("delegate*", StringComparison.Ordinal);

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

    private static string FormatSingleLiteral(float value)
    {
        if (float.IsNaN(value))
        {
            return "float.NaN";
        }

        if (float.IsPositiveInfinity(value))
        {
            return "float.PositiveInfinity";
        }

        if (float.IsNegativeInfinity(value))
        {
            return "float.NegativeInfinity";
        }

        var literal = value.ToString("R", CultureInfo.InvariantCulture);
        if (!literal.Contains('.', StringComparison.Ordinal) &&
            !literal.Contains('E', StringComparison.Ordinal))
        {
            literal += ".0";
        }

        return $"{literal}f";
    }

    private static string FormatDoubleLiteral(double value)
    {
        if (double.IsNaN(value))
        {
            return "double.NaN";
        }

        if (double.IsPositiveInfinity(value))
        {
            return "double.PositiveInfinity";
        }

        if (double.IsNegativeInfinity(value))
        {
            return "double.NegativeInfinity";
        }

        var literal = value.ToString("R", CultureInfo.InvariantCulture);
        return literal.Contains('.', StringComparison.Ordinal) ||
               literal.Contains('E', StringComparison.Ordinal)
            ? literal
            : $"{literal}.0";
    }

    private static CallInfo? ResolveCall(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        int token,
        MemberReferenceCallerContext callerContext)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
                var methodHandle = (MethodDefinitionHandle)handle;
                var method = metadata.GetMethodDefinition(methodHandle);
                var methodDeclaringType = method.GetDeclaringType();
                var methodContext = TryCreateMemberReferenceCallerContext(
                    metadata,
                    methodDeclaringType,
                    methodHandle);
                if (!methodContext.IsAvailable)
                {
                    return null;
                }

                var methodSignature = method.DecodeSignature(
                    SignatureTypeNameProvider.Instance,
                    methodContext.SignatureContext);
                if (methodSignature.GenericParameterCount != method.GetGenericParameters().Count ||
                    methodSignature.Header.CallingConvention !=
                        SignatureCallingConvention.Default ||
                    methodSignature.Header.HasExplicitThis ||
                    methodSignature.RequiredParameterCount !=
                        methodSignature.ParameterTypes.Length ||
                    HasUnrepresentableMemberReferenceType(methodSignature.ReturnType) ||
                    methodSignature.ParameterTypes.Any(HasUnrepresentableMemberReferenceType) ||
                    methodSignature.Header.IsInstance == method.Attributes.HasFlag(MethodAttributes.Static))
                {
                    return null;
                }

                CliType methodDeclaringCliType;
                if (methodContext.TypeParameterCount > 0)
                {
                    if (!TryCreateCurrentGenericOwnerCliType(
                            metadata,
                            enumTypes,
                            methodDeclaringType,
                            methodContext.TypeParameterCount,
                            callerContext,
                            out methodDeclaringCliType))
                    {
                        return null;
                    }
                }
                else
                {
                    methodDeclaringCliType = CreateNominalCliType(
                        metadata,
                        enumTypes,
                        methodDeclaringType);
                }

                if (methodDeclaringCliType.Text.Length == 0)
                {
                    return null;
                }

                return new CallInfo(
                    methodDeclaringCliType.Text,
                    methodDeclaringCliType,
                    methodDeclaringType,
                    metadata.GetString(method.Name),
                    methodSignature.ParameterTypes.Length,
                    methodSignature.Header.IsInstance,
                    CreateCliType(methodSignature.ReturnType, enumTypes),
                    methodSignature.ReturnType.PrimitiveType == PrimitiveTypeCode.Void,
                    methodSignature.ParameterTypes.Select(type => CreateCliType(type, enumTypes)).ToArray(),
                    [],
                    methodSignature.GenericParameterCount,
                    method.Attributes);

            case HandleKind.MemberReference:
                if (!MemberReferenceSignatureValidator.TryValidateMethod(
                        metadata,
                        (MemberReferenceHandle)handle,
                        callerContext,
                        out var member,
                        out var parentContext))
                {
                    return null;
                }

                var memberSignature = member.DecodeMethodSignature(
                    SignatureTypeNameProvider.Instance,
                    parentContext.SignatureContext);
                if (memberSignature.Header.CallingConvention !=
                        SignatureCallingConvention.Default ||
                    memberSignature.Header.HasExplicitThis ||
                    memberSignature.RequiredParameterCount !=
                        memberSignature.ParameterTypes.Length ||
                    HasUnrepresentableMemberReferenceType(memberSignature.ReturnType) ||
                    memberSignature.ParameterTypes.Any(HasUnrepresentableMemberReferenceType))
                {
                    return null;
                }

                var memberName = metadata.GetString(member.Name);
                ArrayPseudoMemberInfo? arrayPseudoMember = null;
                if (parentContext.IsArray &&
                    !TryClassifyArrayPseudoMember(
                        memberName,
                        memberSignature,
                        parentContext,
                        out arrayPseudoMember))
                {
                    return null;
                }

                CliType declaringCliType;
                if (member.Parent.Kind == HandleKind.TypeDefinition &&
                    parentContext.TypeParameterLimit > 0)
                {
                    if (!TryCreateCurrentGenericOwnerCliType(
                            metadata,
                            enumTypes,
                            (TypeDefinitionHandle)member.Parent,
                            parentContext.TypeParameterLimit,
                            callerContext,
                            out declaringCliType))
                    {
                        return null;
                    }
                }
                else
                {
                    var decodedName = GetTypeName(metadata, member.Parent) ?? string.Empty;
                    declaringCliType = parentContext.DecodedType is { } decodedParent
                        ? CreateCliType(decodedParent, enumTypes) with { Text = decodedName }
                        : CreateNominalCliType(metadata, enumTypes, member.Parent);
                }

                var declaringTypeName = declaringCliType.Text;
                if (declaringTypeName.Length == 0)
                {
                    return null;
                }

                return new CallInfo(
                    declaringTypeName,
                    declaringCliType,
                    member.Parent,
                    memberName,
                    memberSignature.ParameterTypes.Length,
                    memberSignature.Header.IsInstance,
                    CreateCliType(memberSignature.ReturnType, enumTypes),
                    memberSignature.ReturnType.PrimitiveType == PrimitiveTypeCode.Void,
                    memberSignature.ParameterTypes.Select(type => CreateCliType(type, enumTypes)).ToArray(),
                    [],
                    memberSignature.GenericParameterCount,
                    DefinitionAttributes: null,
                    arrayPseudoMember);

            case HandleKind.MethodSpecification:
                if (!MemberReferenceSignatureValidator.TryValidateMethodSpecification(
                        metadata,
                        (MethodSpecificationHandle)handle,
                        callerContext,
                        out var spec))
                {
                    return null;
                }

                var resolved = ResolveCall(
                    metadata,
                    enumTypes,
                    MetadataTokens.GetToken(spec.Method),
                    callerContext);
                if (resolved is null)
                {
                    return null;
                }

                var decodedGenericArguments = spec.DecodeSignature(
                    SignatureTypeNameProvider.Instance,
                    callerContext.SignatureContext);
                if (resolved.GenericParameterCount <= 0 ||
                    decodedGenericArguments.Length != resolved.GenericParameterCount ||
                    decodedGenericArguments.Length > MaxGenericParametersPerOwner ||
                    decodedGenericArguments.Any(IsInvalidMethodSpecificationArgument))
                {
                    return null;
                }

                var remainingRenderedCharacters =
                    MaxInstantiatedMethodSignatureCharacters;
                if (!TryReserveMethodSpecificationGenericArgumentCharacters(
                        decodedGenericArguments,
                        ref remainingRenderedCharacters) ||
                    !TryInstantiateMethodSignatureCliType(
                        resolved.ReturnType,
                        decodedGenericArguments,
                        enumTypes,
                        ref remainingRenderedCharacters,
                        out var instantiatedReturnType))
                {
                    return null;
                }

                var instantiatedParameterTypes = new CliType[resolved.ParameterTypes.Count];
                for (var index = 0; index < instantiatedParameterTypes.Length; index++)
                {
                    if (!TryInstantiateMethodSignatureCliType(
                            resolved.ParameterTypes[index],
                            decodedGenericArguments,
                            enumTypes,
                            ref remainingRenderedCharacters,
                            out instantiatedParameterTypes[index]))
                    {
                        return null;
                    }
                }

                var genericArguments = decodedGenericArguments.Select(type => type.Text).ToArray();
                return resolved with
                {
                    ReturnType = instantiatedReturnType,
                    ParameterTypes = instantiatedParameterTypes,
                    GenericArguments = genericArguments
                };

            default:
                return null;
        }
    }

    private static bool IsInvalidMethodSpecificationArgument(SignatureTypeName type) =>
        HasUnrepresentableSignatureNode(type) ||
        type.OuterCustomModifiers.Length != 0 ||
        type.HasNestedCustomModifiers ||
        type.IsRestrictedGenericArgument ||
        type.HasPinnedQualifier ||
        type.PrimitiveType is PrimitiveTypeCode.Void or PrimitiveTypeCode.TypedReference ||
        (type.Text == "nint" && type.PrimitiveType is null);

    private static bool TryReserveMethodSpecificationGenericArgumentCharacters(
        ImmutableArray<SignatureTypeName> genericArguments,
        ref int remainingRenderedCharacters)
    {
        long requiredCharacters = 2;
        if (genericArguments.Length > 1)
        {
            requiredCharacters += (genericArguments.Length - 1L) * 2L;
        }

        foreach (var argument in genericArguments)
        {
            requiredCharacters += argument.Text.Length;
            if (requiredCharacters > remainingRenderedCharacters)
            {
                return false;
            }
        }

        return TryReserveRenderedCharacters(
            (int)requiredCharacters,
            ref remainingRenderedCharacters);
    }

    private static bool TryInstantiateMethodSignatureCliType(
        CliType type,
        ImmutableArray<SignatureTypeName> genericArguments,
        EnumTypeCatalog enumTypes,
        ref int remainingRenderedCharacters,
        out CliType instantiated)
    {
        instantiated = type;
        var argumentNames = genericArguments.Select(argument => argument.Text).ToArray();
        if (type.StructuralSignature is not { } structuralType)
        {
            if (!TryInstantiateMethodSignatureText(
                    type.Text,
                    argumentNames,
                    ref remainingRenderedCharacters,
                    out var fallbackText))
            {
                return false;
            }

            instantiated = fallbackText == type.Text
                ? type
                : new CliType(
                    fallbackText,
                    IsByReference: type.IsByReference,
                    HasPinnedQualifier: type.HasPinnedQualifier);
            return !ContainsUninstantiatedMethodGenericParameter(instantiated.Text);
        }

        var remainingNodes = 512;
        if (!TryInstantiateMethodSignatureTypeName(
                structuralType,
                genericArguments,
                argumentNames,
                depth: 0,
                ref remainingNodes,
                ref remainingRenderedCharacters,
                out var instantiatedSignature))
        {
            return false;
        }

        instantiated = CreateCliType(instantiatedSignature, enumTypes) with
        {
            IsByReference = type.IsByReference,
            HasPinnedQualifier = type.HasPinnedQualifier
        };
        return true;
    }

    private static bool TryInstantiateMethodSignatureTypeName(
        SignatureTypeName type,
        ImmutableArray<SignatureTypeName> genericArguments,
        IReadOnlyList<string> argumentNames,
        int depth,
        ref int remainingNodes,
        ref int remainingRenderedCharacters,
        out SignatureTypeName instantiated)
    {
        instantiated = type;
        if (depth > MaxStructureDepth || remainingNodes-- <= 0)
        {
            return false;
        }

        if (TryReadExactMethodGenericParameter(type, out var parameterIndex))
        {
            if (parameterIndex < 0 || parameterIndex >= genericArguments.Length)
            {
                return false;
            }

            if (!TryReserveRenderedCharacters(
                    genericArguments[parameterIndex].Text.Length,
                    ref remainingRenderedCharacters))
            {
                return false;
            }

            instantiated = genericArguments[parameterIndex];
            return true;
        }

        if (!TryInstantiateMethodSignatureText(
                type.Text,
                argumentNames,
                ref remainingRenderedCharacters,
                out var text))
        {
            return false;
        }

        if (type.ArrayElementType is { } arrayElement)
        {
            if (!TryInstantiateMethodSignatureTypeName(
                    arrayElement,
                    genericArguments,
                    argumentNames,
                    depth + 1,
                    ref remainingNodes,
                    ref remainingRenderedCharacters,
                    out var instantiatedElement))
            {
                return false;
            }

            instantiated = type with
            {
                Text = text,
                ArrayElementType = instantiatedElement,
                HasPinnedQualifier = instantiatedElement.HasPinnedQualifier,
                IsUnsupported = instantiatedElement.IsUnsupported
            };
            return true;
        }

        if (type.SzArrayElementType is { } szArrayElement)
        {
            if (!TryInstantiateMethodSignatureTypeName(
                    szArrayElement,
                    genericArguments,
                    argumentNames,
                    depth + 1,
                    ref remainingNodes,
                    ref remainingRenderedCharacters,
                    out var instantiatedElement))
            {
                return false;
            }

            instantiated = type with
            {
                Text = text,
                SzArrayElementType = instantiatedElement,
                HasPinnedQualifier = instantiatedElement.HasPinnedQualifier,
                IsUnsupported = instantiatedElement.IsUnsupported
            };
            return true;
        }

        if (type.ByReferenceElementType is { } byReferenceElement)
        {
            if (!TryInstantiateMethodSignatureTypeName(
                    byReferenceElement,
                    genericArguments,
                    argumentNames,
                    depth + 1,
                    ref remainingNodes,
                    ref remainingRenderedCharacters,
                    out var instantiatedElement))
            {
                return false;
            }

            instantiated = type with
            {
                Text = text,
                ByReferenceElementType = instantiatedElement,
                HasPinnedQualifier = instantiatedElement.HasPinnedQualifier,
                IsUnsupported = instantiatedElement.IsUnsupported
            };
            return true;
        }

        if (type.PointerElementType is { } pointerElement)
        {
            if (!TryInstantiateMethodSignatureTypeName(
                    pointerElement,
                    genericArguments,
                    argumentNames,
                    depth + 1,
                    ref remainingNodes,
                    ref remainingRenderedCharacters,
                    out var instantiatedElement))
            {
                return false;
            }

            instantiated = type with
            {
                Text = text,
                PointerElementType = instantiatedElement,
                HasPinnedQualifier = instantiatedElement.HasPinnedQualifier,
                IsUnsupported = instantiatedElement.IsUnsupported
            };
            return true;
        }

        if (type.FunctionPointerSignature is { } functionPointer)
        {
            if (!TryInstantiateMethodSignatureTypeName(
                    functionPointer.ReturnType,
                    genericArguments,
                    argumentNames,
                    depth + 1,
                    ref remainingNodes,
                    ref remainingRenderedCharacters,
                    out var instantiatedReturnType))
            {
                return false;
            }

            var parameterTypes = ImmutableArray.CreateBuilder<SignatureTypeName>(
                functionPointer.ParameterTypes.Length);
            foreach (var parameterType in functionPointer.ParameterTypes)
            {
                if (!TryInstantiateMethodSignatureTypeName(
                        parameterType,
                        genericArguments,
                        argumentNames,
                        depth + 1,
                        ref remainingNodes,
                        ref remainingRenderedCharacters,
                        out var instantiatedParameterType))
                {
                    return false;
                }

                parameterTypes.Add(instantiatedParameterType);
            }

            var instantiatedParameterTypes = parameterTypes.MoveToImmutable();
            instantiated = type with
            {
                Text = text,
                FunctionPointerSignature = functionPointer with
                {
                    ReturnType = instantiatedReturnType,
                    ParameterTypes = instantiatedParameterTypes
                },
                HasPinnedQualifier = instantiatedReturnType.HasPinnedQualifier ||
                                     instantiatedParameterTypes.Any(parameter =>
                                         parameter.HasPinnedQualifier),
                IsUnsupported = type.IsUnsupported ||
                                instantiatedReturnType.IsUnsupported ||
                                instantiatedParameterTypes.Any(parameter =>
                                    parameter.IsUnsupported)
            };
            return true;
        }

        if (!type.GenericArguments.IsDefaultOrEmpty)
        {
            var arguments = ImmutableArray.CreateBuilder<SignatureTypeName>(
                type.GenericArguments.Length);
            foreach (var argument in type.GenericArguments)
            {
                if (!TryInstantiateMethodSignatureTypeName(
                        argument,
                        genericArguments,
                        argumentNames,
                        depth + 1,
                        ref remainingNodes,
                        ref remainingRenderedCharacters,
                        out var instantiatedArgument))
                {
                    return false;
                }

                arguments.Add(instantiatedArgument);
            }

            var instantiatedArguments = arguments.MoveToImmutable();
            instantiated = type with
            {
                Text = text,
                GenericArguments = instantiatedArguments,
                HasPinnedQualifier = instantiatedArguments.Any(argument =>
                    argument.HasPinnedQualifier),
                IsUnsupported = type.IsUnsupported ||
                                instantiatedArguments.Any(argument => argument.IsUnsupported)
            };
            return true;
        }

        instantiated = type with { Text = text };
        return type.MethodParameterSlot is not null ||
               !ContainsUninstantiatedMethodGenericParameter(text);
    }

    private static bool TryReadExactMethodGenericParameter(
        SignatureTypeName type,
        out int index)
    {
        index = -1;
        if (type.TypeParameterSlot is not null ||
            type.PrimitiveType is not null ||
            !type.NominalHandle.IsNil ||
            !type.GenericArguments.IsDefaultOrEmpty ||
            type.ArrayElementType is not null ||
            type.SzArrayElementType is not null ||
            type.ByReferenceElementType is not null ||
            type.PointerElementType is not null ||
            type.FunctionPointerSignature is not null ||
            type.IsByReference ||
            type.HasPinnedQualifier ||
            !type.OuterCustomModifiers.IsEmpty ||
            type.HasNestedCustomModifiers ||
            !type.Text.StartsWith("!!", StringComparison.Ordinal) ||
            !int.TryParse(
                type.Text.AsSpan(2),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out index))
        {
            return false;
        }

        return type.MethodParameterSlot is not { } slot || slot.Index == index;
    }

    private static bool HasUnrepresentableMemberReferenceType(SignatureTypeName type) =>
        HasUnrepresentableSignatureNode(type) ||
        type.HasPinnedQualifier ||
        type.IsByReference ||
        type.HasNestedCustomModifiers ||
        !type.OuterCustomModifiers.IsEmpty ||
        type.PrimitiveType == PrimitiveTypeCode.TypedReference ||
        (type.Text == "nint" && type.PrimitiveType is null);

    private static bool HasUnrepresentableSignatureNode(SignatureTypeName type)
    {
        var remainingNodes = 1_024;
        return HasUnrepresentableSignatureNode(type, depth: 0, ref remainingNodes);
    }

    private static bool HasUnrepresentableSignatureNode(
        SignatureTypeName type,
        int depth,
        ref int remainingNodes)
    {
        if (depth > MaxStructureDepth ||
            remainingNodes-- <= 0 ||
            type.IsUnsupported ||
            type.ArrayElementType is not null && type.ArrayRank == 1 ||
            type.IsExactNamedType && IsPrimitiveAliasName(type.Text) ||
            type.IsCanonicalGenericInstantiation &&
            type.GenericDefinitionText is { } genericDefinition &&
            HasPrimitiveAliasGenericDefinitionSegment(genericDefinition))
        {
            return true;
        }

        foreach (var argument in type.GenericArguments.IsDefault
                     ? ImmutableArray<SignatureTypeName>.Empty
                     : type.GenericArguments)
        {
            if (HasUnrepresentableSignatureNode(
                    argument,
                    depth + 1,
                    ref remainingNodes))
            {
                return true;
            }
        }

        if (type.FunctionPointerSignature is { } functionPointer)
        {
            if (HasUnrepresentableSignatureNode(
                    functionPointer.ReturnType,
                    depth + 1,
                    ref remainingNodes))
            {
                return true;
            }

            foreach (var parameter in functionPointer.ParameterTypes)
            {
                if (HasUnrepresentableSignatureNode(
                        parameter,
                        depth + 1,
                        ref remainingNodes))
                {
                    return true;
                }
            }
        }

        return type.ArrayElementType is { } arrayElement &&
                   HasUnrepresentableSignatureNode(
                       arrayElement,
                       depth + 1,
                       ref remainingNodes) ||
               type.SzArrayElementType is { } szArrayElement &&
                   HasUnrepresentableSignatureNode(
                       szArrayElement,
                       depth + 1,
                       ref remainingNodes) ||
               type.ByReferenceElementType is { } byReferenceElement &&
                   HasUnrepresentableSignatureNode(
                       byReferenceElement,
                       depth + 1,
                       ref remainingNodes) ||
               type.PointerElementType is { } pointerElement &&
                   HasUnrepresentableSignatureNode(
                       pointerElement,
                       depth + 1,
                       ref remainingNodes);
    }

    private static bool TryClassifyArrayPseudoMember(
        string memberName,
        MethodSignature<SignatureTypeName> signature,
        MemberReferenceSignatureValidator.ParentContext parentContext,
        out ArrayPseudoMemberInfo? pseudoMember)
    {
        pseudoMember = null;
        if (!parentContext.IsArray ||
            parentContext.DecodedType is not { } arrayType ||
            parentContext.ArrayElementType is not { } elementType ||
            parentContext.ArrayRank is <= 1 or > 32 ||
            signature.Header.CallingConvention != SignatureCallingConvention.Default ||
            !signature.Header.IsInstance ||
            signature.Header.IsGeneric ||
            signature.Header.HasExplicitThis ||
            signature.GenericParameterCount != 0 ||
            signature.RequiredParameterCount != signature.ParameterTypes.Length ||
            !arrayType.ArraySizes.IsDefaultOrEmpty ||
            arrayType.ArrayLowerBounds.Any(bound => bound != 0))
        {
            return false;
        }

        var rank = parentContext.ArrayRank;
        var parameters = signature.ParameterTypes;
        var indexCount = memberName == "Set" ? parameters.Length - 1 : parameters.Length;
        if (indexCount != rank ||
            parameters.Take(rank).Any(type =>
                type.PrimitiveType != PrimitiveTypeCode.Int32 ||
                type.IsByReference ||
                type.IsUnsupported ||
                type.HasNestedCustomModifiers ||
                !type.OuterCustomModifiers.IsEmpty))
        {
            return false;
        }

        switch (memberName)
        {
            case "Get" when parameters.Length == rank &&
                            AreSameConstructorSignature(signature.ReturnType, elementType):
                pseudoMember = new ArrayPseudoMemberInfo(
                    ArrayPseudoMemberKind.Get,
                    elementType.Text,
                    rank);
                return true;

            case "Set" when parameters.Length == rank + 1 &&
                            signature.ReturnType.PrimitiveType == PrimitiveTypeCode.Void &&
                            AreSameConstructorSignature(parameters[^1], elementType):
                pseudoMember = new ArrayPseudoMemberInfo(
                    ArrayPseudoMemberKind.Set,
                    elementType.Text,
                    rank);
                return true;

            case ".ctor" when arrayType.ArrayElementType is not null &&
                              parameters.Length == rank &&
                              signature.ReturnType.PrimitiveType == PrimitiveTypeCode.Void:
                pseudoMember = new ArrayPseudoMemberInfo(
                    ArrayPseudoMemberKind.Constructor,
                    elementType.Text,
                    rank);
                return true;

            default:
                return false;
        }
    }

    private static CliType CreateNominalCliType(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        EntityHandle handle)
    {
        var type = handle.Kind switch
        {
            HandleKind.TypeDefinition => SignatureTypeNameProvider.Instance.GetTypeFromDefinition(
                metadata,
                (TypeDefinitionHandle)handle,
                rawTypeKind: 0),
            HandleKind.TypeReference => SignatureTypeNameProvider.Instance.GetTypeFromReference(
                metadata,
                (TypeReferenceHandle)handle,
                rawTypeKind: 0),
            HandleKind.TypeSpecification => TryReadSignatureTypeSpecification(
                metadata,
                (TypeSpecificationHandle)handle) ?? new SignatureTypeName(string.Empty),
            _ => new SignatureTypeName(string.Empty)
        };
        var text = GetTypeName(metadata, handle) ?? type.Text;
        return CreateCliType(type, enumTypes) with { Text = text };
    }

    private static CliType CreateCurrentInstanceCliType(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        TypeDefinitionHandle declaringType,
        MemberReferenceCallerContext callerContext)
    {
        if (callerContext.TypeParameterCount > 0 &&
            TryCreateCurrentGenericOwnerCliType(
                metadata,
                enumTypes,
                declaringType,
                callerContext.TypeParameterCount,
                callerContext,
                out var currentGenericType))
        {
            return currentGenericType;
        }

        return CreateNominalCliType(metadata, enumTypes, declaringType);
    }

    private static bool TryCreateCurrentGenericOwnerCliType(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        TypeDefinitionHandle handle,
        int genericArity,
        MemberReferenceCallerContext callerContext,
        out CliType type)
    {
        type = new CliType(string.Empty);
        if (genericArity <= 0 ||
            !callerContext.IsAvailable ||
            callerContext.TypeParameterOwner != handle ||
            callerContext.TypeParameterCount != genericArity)
        {
            return false;
        }

        var provider = SignatureTypeNameProvider.Instance;
        var genericType = provider.GetTypeFromDefinition(
            metadata,
            handle,
            rawTypeKind: 0);
        var ownerContext = SignatureGenericContext.ForOwner(handle, genericArity);
        var arguments = ImmutableArray.CreateBuilder<SignatureTypeName>(genericArity);
        for (var index = 0; index < genericArity; index++)
        {
            arguments.Add(provider.GetGenericTypeParameter(ownerContext, index));
        }

        var instantiated = provider.GetGenericInstantiation(
            genericType,
            arguments.MoveToImmutable());
        if (!instantiated.IsCanonicalGenericInstantiation ||
            instantiated.IsUnsupported ||
            instantiated.Text.Length == 0 ||
            instantiated.Text.Contains('`'))
        {
            return false;
        }

        type = CreateCliType(instantiated, enumTypes);
        return true;
    }

    private static bool TryCreateInstructionCliType(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        EntityHandle handle,
        MemberReferenceCallerContext callerContext,
        out CliType type)
    {
        type = new CliType(string.Empty);
        if (!MemberReferenceSignatureValidator.TryValidateTypeOperand(
                metadata,
                handle,
                callerContext,
                out var signature) ||
            HasUnrepresentableSignatureNode(signature) ||
            signature.HasPinnedQualifier ||
            signature.Text.Length == 0)
        {
            return false;
        }

        type = CreateCliType(signature, enumTypes);
        return true;
    }

    private static SignatureTypeName? TryReadSignatureTypeSpecification(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        object? genericContext = null)
    {
        try
        {
            return SignatureTypeNameProvider.Instance.GetTypeFromSpecification(
                metadata,
                genericContext,
                handle,
                rawTypeKind: 0);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private sealed class MemberReferenceSignatureValidator
    {
        private const int MaxSignatureBytes = 4 * 1_024;
        private const int MaxTypeSpecificationBytes = 256;
        private const int MaxAggregateTypeSpecificationBytes = 4 * 1_024;
        private const int MaxSignatureNodes = 1_024;
        private const int MaxSignatureDepth = 64;
        private const int MaxParameters = 256;
        private const int MaxGenericArguments = 64;
        private const int MaxArrayRank = 32;
        private const int MaxCustomModifiers = 64;
        private const int MaxNominalNameDepth = 64;
        private const int MaxNameSegmentBytes = 4 * 1_024;
        private const int MaxNominalNameBytes = 256 * 1_024;

        private readonly MetadataReader _metadata;
        private readonly MemberReferenceCallerContext _callerContext;
        private readonly HashSet<TypeSpecificationHandle> _activeTypeSpecifications = [];
        private int _typeSpecificationBytes;
        private int _signatureNodes;
        private int _customModifiers;
        private int _nominalNameBytes;

        internal readonly record struct ParentContext(
            object? SignatureContext,
            int TypeParameterLimit,
            int ContextualMethodParameterLimit,
            SignatureTypeName? DecodedType,
            SignatureTypeName? ArrayElementType,
            int ArrayRank)
        {
            public bool IsArray => ArrayElementType is not null && ArrayRank > 0;
        }

        private MemberReferenceSignatureValidator(
            MetadataReader metadata,
            MemberReferenceCallerContext callerContext)
        {
            _metadata = metadata;
            _callerContext = callerContext;
        }

        public static bool TryValidateMethod(
            MetadataReader metadata,
            MemberReferenceHandle handle,
            MemberReferenceCallerContext callerContext,
            out MemberReference member,
            out ParentContext parentContext)
        {
            member = default;
            parentContext = default;
            try
            {
                var validator = new MemberReferenceSignatureValidator(metadata, callerContext);
                if (!validator.IsValidRow(handle, TableIndex.MemberRef))
                {
                    return false;
                }

                member = metadata.GetMemberReference(handle);
                if (!validator.TryReserveMemberName(member.Name))
                {
                    return false;
                }

                if (!validator.TryValidateParent(member.Parent, out parentContext))
                {
                    return false;
                }

                var reader = metadata.GetBlobReader(member.Signature);
                return reader.Length is > 0 and <= MaxSignatureBytes &&
                       validator.TryValidateMethodSignature(
                           ref reader,
                           parentContext.TypeParameterLimit,
                           parentContext.ContextualMethodParameterLimit,
                           memberReference: true,
                           requireEnd: true,
                           typeDepth: 0);
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or ArgumentException or InvalidOperationException)
            {
                member = default;
                parentContext = default;
                return false;
            }
        }

        public static bool TryValidateField(
            MetadataReader metadata,
            MemberReferenceHandle handle,
            MemberReferenceCallerContext callerContext,
            out MemberReference member,
            out ParentContext parentContext)
        {
            member = default;
            parentContext = default;
            try
            {
                var validator = new MemberReferenceSignatureValidator(metadata, callerContext);
                if (!validator.IsValidRow(handle, TableIndex.MemberRef))
                {
                    return false;
                }

                member = metadata.GetMemberReference(handle);
                if (!validator.TryReserveMemberName(member.Name))
                {
                    return false;
                }

                if (!validator.TryValidateParent(member.Parent, out parentContext) ||
                    parentContext.IsArray)
                {
                    return false;
                }

                var reader = metadata.GetBlobReader(member.Signature);
                return reader.Length is > 1 and <= MaxSignatureBytes &&
                       reader.ReadByte() == 0x06 &&
                       validator.TryValidateFieldType(
                           ref reader,
                           parentContext.TypeParameterLimit,
                           methodParameterLimit: 0,
                           depth: 0) &&
                       reader.RemainingBytes == 0;
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or ArgumentException or InvalidOperationException)
            {
                member = default;
                parentContext = default;
                return false;
            }
        }

        public static bool TryValidateMethodSpecification(
            MetadataReader metadata,
            MethodSpecificationHandle handle,
            MemberReferenceCallerContext callerContext,
            out MethodSpecification specification)
        {
            specification = default;
            try
            {
                var validator = new MemberReferenceSignatureValidator(metadata, callerContext);
                if (!validator.IsValidRow(handle, TableIndex.MethodSpec))
                {
                    return false;
                }

                specification = metadata.GetMethodSpecification(handle);
                if (specification.Method.Kind == HandleKind.MethodDefinition)
                {
                    if (!validator.IsValidRow(specification.Method, TableIndex.MethodDef))
                    {
                        return false;
                    }
                }
                else if (specification.Method.Kind == HandleKind.MemberReference)
                {
                    if (!validator.IsValidRow(specification.Method, TableIndex.MemberRef))
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }

                var reader = metadata.GetBlobReader(specification.Signature);
                if (reader.Length is <= 2 or > MaxSignatureBytes ||
                    reader.ReadByte() != 0x0A ||
                    !TryReadCanonicalCompressedInteger(
                        ref reader,
                        out var genericArgumentCount) ||
                    genericArgumentCount is <= 0 or > MaxGenericArguments)
                {
                    return false;
                }

                for (var index = 0; index < genericArgumentCount; index++)
                {
                    if (!validator.TryValidateCoreType(
                            ref reader,
                            callerContext.IsAvailable
                                ? callerContext.TypeParameterCount
                                : 0,
                            callerContext.IsAvailable
                                ? callerContext.MethodParameterCount
                                : 0,
                            depth: 0))
                    {
                        return false;
                    }
                }

                return reader.RemainingBytes == 0;
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or ArgumentException or InvalidOperationException)
            {
                specification = default;
                return false;
            }
        }

        public static bool TryValidateTypeOperand(
            MetadataReader metadata,
            EntityHandle handle,
            MemberReferenceCallerContext callerContext,
            out SignatureTypeName type)
        {
            type = new SignatureTypeName(string.Empty) with { IsUnsupported = true };
            try
            {
                var validator = new MemberReferenceSignatureValidator(metadata, callerContext);
                if (!validator.TryValidateParent(handle, out var parentContext))
                {
                    return false;
                }

                if (handle.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference)
                {
                    if (parentContext.TypeParameterLimit != 0)
                    {
                        return false;
                    }

                    type = handle.Kind == HandleKind.TypeDefinition
                        ? SignatureTypeNameProvider.Instance.GetTypeFromDefinition(
                            metadata,
                            (TypeDefinitionHandle)handle,
                            rawTypeKind: 0)
                        : SignatureTypeNameProvider.Instance.GetTypeFromReference(
                            metadata,
                            (TypeReferenceHandle)handle,
                            rawTypeKind: 0);
                }
                else if (parentContext.DecodedType is { } decodedType)
                {
                    type = decodedType;
                }
                else
                {
                    return false;
                }

                return type.IsExactNamedType ||
                       type.IsCanonicalGenericInstantiation ||
                       type.ArrayElementType is not null ||
                       type.SzArrayElementType is not null;
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or ArgumentException or InvalidOperationException)
            {
                type = new SignatureTypeName(string.Empty) with { IsUnsupported = true };
                return false;
            }
        }

        private bool TryValidateParent(
            EntityHandle parent,
            out ParentContext context)
        {
            context = default;
            switch (parent.Kind)
            {
                case HandleKind.TypeDefinition:
                    var definitionHandle = (TypeDefinitionHandle)parent;
                    if (!TryGetCanonicalTypeDefinitionParameterCount(
                            definitionHandle,
                            out var definitionParameterCount) ||
                        definitionParameterCount > 0 &&
                        (!_callerContext.IsAvailable ||
                         _callerContext.TypeParameterOwner != definitionHandle))
                    {
                        return false;
                    }

                    context = new ParentContext(
                        SignatureGenericContext.ForOwner(
                            definitionHandle,
                            definitionParameterCount),
                        definitionParameterCount,
                        ContextualMethodParameterLimit: 0,
                        DecodedType: null,
                        ArrayElementType: null,
                        ArrayRank: 0);
                    return true;

                case HandleKind.TypeReference:
                    if (!TryGetCanonicalTypeReferenceParameterCount(
                            (TypeReferenceHandle)parent,
                            out var referenceParameterCount) ||
                        referenceParameterCount > 0)
                    {
                        return false;
                    }

                    context = new ParentContext(
                        SignatureContext: null,
                        TypeParameterLimit: 0,
                        ContextualMethodParameterLimit: 0,
                        DecodedType: null,
                        ArrayElementType: null,
                        ArrayRank: 0);
                    return true;

                case HandleKind.TypeSpecification:
                    var specificationHandle = (TypeSpecificationHandle)parent;
                    if (!TryValidateTypeSpecification(
                            specificationHandle,
                            depth: 0,
                            _callerContext.IsAvailable
                                ? _callerContext.TypeParameterCount
                                : 0,
                            _callerContext.IsAvailable
                                ? _callerContext.MethodParameterCount
                                : 0,
                            out var rootTypeCode,
                            out _) ||
                        rootTypeCode is not (0x14 or 0x15 or 0x1D) ||
                        TryReadSignatureTypeSpecification(
                            _metadata,
                            specificationHandle,
                            _callerContext.SignatureContext) is not { } declaringType ||
                        HasUnrepresentableSignatureNode(declaringType) ||
                        declaringType.HasPinnedQualifier ||
                        declaringType.IsRestrictedGenericArgument ||
                        declaringType.HasNestedCustomModifiers ||
                        !declaringType.OuterCustomModifiers.IsEmpty ||
                        declaringType.PrimitiveType is not null ||
                        declaringType.Text == "nint")
                    {
                        return false;
                    }

                    if (rootTypeCode == 0x15 &&
                        !declaringType.IsCanonicalGenericInstantiation)
                    {
                        return false;
                    }

                    if (declaringType.IsCanonicalGenericInstantiation)
                    {
                        if (declaringType.GenericArguments.IsDefaultOrEmpty ||
                            declaringType.GenericArguments.Length > MaxGenericArguments)
                        {
                            return false;
                        }

                        context = new ParentContext(
                            SignatureGenericContext.ForSubstitution(
                                declaringType.GenericArguments),
                            declaringType.GenericArguments.Length,
                            ContextualMethodParameterLimit: 0,
                            declaringType,
                            ArrayElementType: null,
                            ArrayRank: 0);
                        return true;
                    }

                    var arrayElementType = rootTypeCode == 0x14
                        ? declaringType.ArrayElementType
                        : declaringType.SzArrayElementType;
                    var arrayRank = rootTypeCode == 0x14 ? declaringType.ArrayRank : 1;
                    if (arrayElementType is null ||
                        rootTypeCode == 0x14 && arrayRank == 1 ||
                        arrayRank is <= 0 or > MaxArrayRank)
                    {
                        return false;
                    }

                    context = new ParentContext(
                        _callerContext.SignatureContext,
                        _callerContext.IsAvailable ? _callerContext.TypeParameterCount : 0,
                        _callerContext.IsAvailable ? _callerContext.MethodParameterCount : 0,
                        declaringType,
                        arrayElementType,
                        arrayRank);
                    return true;

                default:
                    return false;
            }
        }

        private bool TryValidateMethodSignature(
            ref BlobReader reader,
            int typeParameterLimit,
            int contextualMethodParameterLimit,
            bool memberReference,
            bool requireEnd,
            int typeDepth)
        {
            if (reader.RemainingBytes == 0)
            {
                return false;
            }

            var header = reader.ReadByte();
            if ((header & 0x80) != 0)
            {
                return false;
            }

            var callingConvention = header & 0x0F;
            var allowsSentinel = callingConvention == 0x05 ||
                                 (!memberReference && callingConvention == 0x01);
            if (memberReference
                    ? callingConvention is not (0x00 or 0x05)
                    : callingConvention > 0x05 && callingConvention != 0x09)
            {
                return false;
            }

            var hasThis = (header & 0x20) != 0;
            var hasExplicitThis = (header & 0x40) != 0;
            if (hasExplicitThis && !hasThis)
            {
                return false;
            }

            var methodParameterLimit = 0;
            if ((header & 0x10) != 0)
            {
                if (!TryReadCanonicalCompressedInteger(
                        ref reader,
                        out methodParameterLimit) ||
                    methodParameterLimit is <= 0 or > MaxParameters)
                {
                    return false;
                }
            }
            else
            {
                methodParameterLimit = contextualMethodParameterLimit;
            }

            if (!TryReadCanonicalCompressedInteger(ref reader, out var parameterCount) ||
                parameterCount is < 0 or > MaxParameters ||
                !TryValidateReturnType(
                    ref reader,
                    typeParameterLimit,
                    methodParameterLimit,
                    depth: typeDepth))
            {
                return false;
            }

            var sawSentinel = false;
            for (var parameterIndex = 0; parameterIndex < parameterCount; parameterIndex++)
            {
                if (reader.RemainingBytes > 0 && PeekByte(reader) == 0x41)
                {
                    if (!allowsSentinel || sawSentinel)
                    {
                        return false;
                    }

                    reader.ReadByte();
                    sawSentinel = true;
                }

                if (!TryValidateParameterType(
                        ref reader,
                        typeParameterLimit,
                        methodParameterLimit,
                        depth: typeDepth))
                {
                    return false;
                }
            }

            return (!requireEnd || reader.RemainingBytes == 0) &&
                   (allowsSentinel || !sawSentinel);
        }

        private bool TryValidateFieldType(
            ref BlobReader reader,
            int typeParameterLimit,
            int methodParameterLimit,
            int depth) =>
            TryValidateCustomModifiers(ref reader, depth, out var typeDepth) &&
            TryValidateCoreType(
                ref reader,
                typeParameterLimit,
                methodParameterLimit,
                typeDepth);

        private bool TryValidateParameterType(
            ref BlobReader reader,
            int typeParameterLimit,
            int methodParameterLimit,
            int depth)
        {
            if (!TryValidateCustomModifiers(ref reader, depth, out var typeDepth))
            {
                return false;
            }

            if (reader.RemainingBytes > 0 && PeekByte(reader) == 0x16) // TYPEDBYREF
            {
                return TryConsumeTerminalType(ref reader, 0x16, typeDepth);
            }

            if (reader.RemainingBytes > 0 && PeekByte(reader) == 0x10 &&
                !TryConsumeTypePrefix(ref reader, 0x10, ref typeDepth)) // BYREF
            {
                return false;
            }

            return TryValidateCoreType(
                ref reader,
                typeParameterLimit,
                methodParameterLimit,
                typeDepth);
        }

        private bool TryValidateReturnType(
            ref BlobReader reader,
            int typeParameterLimit,
            int methodParameterLimit,
            int depth)
        {
            if (!TryValidateCustomModifiers(ref reader, depth, out var typeDepth))
            {
                return false;
            }

            if (reader.RemainingBytes > 0 && PeekByte(reader) is 0x01 or 0x16)
            {
                return TryConsumeTerminalType(ref reader, PeekByte(reader), typeDepth);
            }

            if (reader.RemainingBytes > 0 && PeekByte(reader) == 0x10 &&
                !TryConsumeTypePrefix(ref reader, 0x10, ref typeDepth)) // BYREF
            {
                return false;
            }

            return TryValidateCoreType(
                ref reader,
                typeParameterLimit,
                methodParameterLimit,
                typeDepth);
        }

        private bool TryValidateCoreType(
            ref BlobReader reader,
            int typeParameterLimit,
            int methodParameterLimit,
            int depth)
        {
            if (depth >= MaxSignatureDepth ||
                ++_signatureNodes > MaxSignatureNodes ||
                reader.RemainingBytes == 0)
            {
                return false;
            }

            var typeCode = reader.ReadByte();
            switch (typeCode)
            {
                case >= 0x02 and <= 0x0E: // primitive and STRING
                case 0x18: // native int
                case 0x19: // native uint
                case 0x1C: // OBJECT
                    return true;

                case 0x0F: // PTR
                    if (!TryValidateCustomModifiers(
                            ref reader,
                            depth + 1,
                            out var pointedTypeDepth))
                    {
                        return false;
                    }

                    return reader.RemainingBytes > 0 && PeekByte(reader) == 0x01
                        ? TryConsumeTerminalType(ref reader, 0x01, pointedTypeDepth)
                        : TryValidateCoreType(
                            ref reader,
                            typeParameterLimit,
                            methodParameterLimit,
                            pointedTypeDepth);

                case 0x1D: // SZARRAY
                    return TryValidateCustomModifiers(
                               ref reader,
                               depth + 1,
                               out var elementTypeDepth) &&
                           TryValidateCoreType(
                        ref reader,
                        typeParameterLimit,
                        methodParameterLimit,
                        elementTypeDepth);

                case 0x11: // VALUETYPE
                case 0x12: // CLASS
                    return TryValidateClassOrValueType(
                        ref reader,
                        typeCode,
                        typeParameterLimit,
                        methodParameterLimit,
                        depth);

                case 0x13: // VAR
                    return TryReadCanonicalCompressedInteger(ref reader, out var typeParameter) &&
                           typeParameter >= 0 &&
                           typeParameter < typeParameterLimit;

                case 0x14: // ARRAY
                    if (!TryValidateCoreType(
                            ref reader,
                            typeParameterLimit,
                            methodParameterLimit,
                            depth + 1) ||
                        !TryReadCanonicalCompressedInteger(ref reader, out var rank) ||
                        rank is <= 0 or > MaxArrayRank ||
                        !TryReadCanonicalCompressedInteger(ref reader, out var sizeCount) ||
                        sizeCount < 0 ||
                        sizeCount > rank)
                    {
                        return false;
                    }

                    for (var index = 0; index < sizeCount; index++)
                    {
                        if (!TryReadCanonicalCompressedInteger(ref reader, out _))
                        {
                            return false;
                        }
                    }

                    if (!TryReadCanonicalCompressedInteger(
                            ref reader,
                            out var lowerBoundCount) ||
                        lowerBoundCount < 0 ||
                        lowerBoundCount > rank)
                    {
                        return false;
                    }

                    for (var index = 0; index < lowerBoundCount; index++)
                    {
                        if (!TryReadCanonicalCompressedSignedInteger(ref reader, out _))
                        {
                            return false;
                        }
                    }

                    return true;

                case 0x15: // GENERICINST
                    var genericRawTypeKind = reader.RemainingBytes == 0
                        ? (byte)0
                        : reader.ReadByte();
                    if (genericRawTypeKind is not (0x11 or 0x12) ||
                        !TryReadNominalTypeHandle(
                            ref reader,
                            out var genericDefinition) ||
                        !TryReadCanonicalCompressedInteger(
                            ref reader,
                            out var genericArgumentCount) ||
                        genericArgumentCount is <= 0 or > MaxGenericArguments ||
                        !HasCanonicalGenericArity(
                            genericDefinition,
                            genericArgumentCount) ||
                        !HasMatchingLocalSignatureKind(
                            genericDefinition,
                            genericRawTypeKind))
                    {
                        return false;
                    }

                    for (var index = 0; index < genericArgumentCount; index++)
                    {
                        if (!TryValidateCoreType(
                                ref reader,
                                typeParameterLimit,
                                methodParameterLimit,
                                depth + 1))
                        {
                            return false;
                        }
                    }

                    return true;

                case 0x1B: // FNPTR
                    return TryValidateMethodSignature(
                        ref reader,
                        typeParameterLimit,
                        contextualMethodParameterLimit: methodParameterLimit,
                        memberReference: false,
                        requireEnd: false,
                        typeDepth: depth + 1);

                case 0x1E: // MVAR
                    return TryReadCanonicalCompressedInteger(ref reader, out var methodParameter) &&
                           methodParameter >= 0 &&
                           methodParameter < methodParameterLimit;

                default:
                    return false;
            }
        }

        private bool TryValidateCustomModifiers(
            ref BlobReader reader,
            int depth,
            out int typeDepth)
        {
            typeDepth = depth;
            while (reader.RemainingBytes > 0 && PeekByte(reader) is 0x1F or 0x20)
            {
                if (!TryConsumeTypePrefix(
                        ref reader,
                        PeekByte(reader),
                        ref typeDepth) ||
                    ++_customModifiers > MaxCustomModifiers ||
                    !TryReadNominalTypeHandle(
                        ref reader,
                        out var modifierType) ||
                    !HasCanonicalNonGenericNominalArity(modifierType))
                {
                    return false;
                }
            }

            return true;
        }

        private bool TryConsumeTypePrefix(
            ref BlobReader reader,
            byte expectedCode,
            ref int depth)
        {
            if (depth >= MaxSignatureDepth ||
                ++_signatureNodes > MaxSignatureNodes ||
                reader.RemainingBytes == 0 ||
                reader.ReadByte() != expectedCode)
            {
                return false;
            }

            depth++;
            return true;
        }

        private bool TryConsumeTerminalType(
            ref BlobReader reader,
            byte expectedCode,
            int depth) =>
            depth < MaxSignatureDepth &&
            ++_signatureNodes <= MaxSignatureNodes &&
            reader.RemainingBytes > 0 &&
            reader.ReadByte() == expectedCode;

        private bool TryReadNominalTypeHandle(
            ref BlobReader reader,
            out EntityHandle handle)
        {
            handle = default;
            if (!TryReadCanonicalTypeHandle(ref reader, out handle) || handle.IsNil)
            {
                return false;
            }

            return handle.Kind switch
            {
                HandleKind.TypeDefinition =>
                    TryValidateTypeDefinitionName((TypeDefinitionHandle)handle),
                HandleKind.TypeReference =>
                    TryValidateTypeReferenceName((TypeReferenceHandle)handle),
                _ => false
            };
        }

        private bool TryValidateClassOrValueType(
            ref BlobReader reader,
            byte rawTypeKind,
            int typeParameterLimit,
            int methodParameterLimit,
            int depth)
        {
            if (!TryReadCanonicalTypeHandle(ref reader, out var handle) || handle.IsNil)
            {
                return false;
            }

            if (handle.Kind is HandleKind.TypeDefinition or HandleKind.TypeReference)
            {
                return (handle.Kind == HandleKind.TypeDefinition
                            ? TryValidateTypeDefinitionName((TypeDefinitionHandle)handle)
                            : TryValidateTypeReferenceName((TypeReferenceHandle)handle)) &&
                       HasCanonicalNonGenericNominalArity(handle) &&
                       HasMatchingLocalSignatureKind(handle, rawTypeKind);
            }

            return handle.Kind == HandleKind.TypeSpecification &&
                   TryValidateTypeSpecification(
                       (TypeSpecificationHandle)handle,
                       depth + 1,
                       typeParameterLimit,
                       methodParameterLimit,
                       out _,
                       out var specificationKind) &&
                   specificationKind == (rawTypeKind == 0x11
                       ? SignatureTypeKind.ValueType
                       : SignatureTypeKind.Class);
        }

        private bool TryValidateTypeSpecification(
            TypeSpecificationHandle handle,
            int depth,
            int typeParameterLimit,
            int methodParameterLimit,
            out byte rootTypeCode,
            out SignatureTypeKind signatureKind)
        {
            rootTypeCode = 0;
            signatureKind = SignatureTypeKind.Unknown;
            if (!IsValidRow(handle, TableIndex.TypeSpec))
            {
                return false;
            }

            if (depth >= MaxSignatureDepth ||
                _activeTypeSpecifications.Count >= MaxSignatureDepth ||
                !_activeTypeSpecifications.Add(handle))
            {
                return false;
            }

            try
            {
                var specification = _metadata.GetTypeSpecification(handle);
                var reader = _metadata.GetBlobReader(specification.Signature);
                if (reader.Length is <= 0 or > MaxTypeSpecificationBytes ||
                    _typeSpecificationBytes > MaxAggregateTypeSpecificationBytes - reader.Length)
                {
                    return false;
                }

                _typeSpecificationBytes += reader.Length;
                rootTypeCode = PeekByte(reader);
                signatureKind = GetTypeSpecificationSignatureKind(reader);
                if (signatureKind == SignatureTypeKind.Unknown)
                {
                    return false;
                }

                if (!TryValidateCoreType(
                        ref reader,
                        typeParameterLimit,
                        methodParameterLimit,
                        depth) ||
                    reader.RemainingBytes != 0)
                {
                    return false;
                }

                return true;
            }
            finally
            {
                _activeTypeSpecifications.Remove(handle);
            }
        }

        private static SignatureTypeKind GetTypeSpecificationSignatureKind(BlobReader reader)
        {
            if (reader.RemainingBytes == 0)
            {
                return SignatureTypeKind.Unknown;
            }

            return reader.ReadByte() switch
            {
                0x11 => SignatureTypeKind.ValueType,
                0x12 or 0x14 or 0x1D => SignatureTypeKind.Class,
                0x15 when reader.RemainingBytes > 0 => reader.ReadByte() switch
                {
                    0x11 => SignatureTypeKind.ValueType,
                    0x12 => SignatureTypeKind.Class,
                    _ => SignatureTypeKind.Unknown
                },
                _ => SignatureTypeKind.Unknown
            };
        }

        private bool HasCanonicalGenericArity(
            EntityHandle handle,
            int argumentCount)
        {
            if (handle.Kind == HandleKind.TypeReference)
            {
                return TryGetCanonicalTypeReferenceParameterCount(
                           (TypeReferenceHandle)handle,
                           out var parameterCount) &&
                       parameterCount == argumentCount;
            }

            return TryGetCanonicalTypeDefinitionParameterCount(
                       (TypeDefinitionHandle)handle,
                       out var definitionParameterCount) &&
                   definitionParameterCount == argumentCount;
        }

        private bool HasCanonicalNonGenericNominalArity(EntityHandle handle) =>
            HasCanonicalGenericArity(handle, argumentCount: 0);

        private bool HasMatchingLocalSignatureKind(
            EntityHandle handle,
            byte rawTypeKind)
        {
            if (handle.Kind != HandleKind.TypeDefinition)
            {
                return true;
            }

            var definition = _metadata.GetTypeDefinition((TypeDefinitionHandle)handle);
            if (!TryClassifyTrustedValueTypeBase(definition.BaseType, out var isValueType))
            {
                return false;
            }

            return rawTypeKind switch
            {
                0x11 => isValueType,
                0x12 => !isValueType,
                _ => false
            };
        }

        private bool TryClassifyTrustedValueTypeBase(
            EntityHandle baseType,
            out bool isValueType)
        {
            isValueType = false;
            if (baseType.IsNil)
            {
                return true;
            }

            switch (baseType.Kind)
            {
                case HandleKind.TypeSpecification:
                    return IsValidRow(baseType, TableIndex.TypeSpec);

                case HandleKind.TypeDefinition:
                    var definitionHandle = (TypeDefinitionHandle)baseType;
                    if (!TryValidateTypeDefinitionName(definitionHandle))
                    {
                        return false;
                    }

                    var definition = _metadata.GetTypeDefinition(definitionHandle);
                    if (!definition.GetDeclaringType().IsNil ||
                        _metadata.GetString(definition.Namespace) != "System" ||
                        _metadata.GetString(definition.Name) is not ("ValueType" or "Enum"))
                    {
                        return true;
                    }

                    if (!_metadata.IsAssembly)
                    {
                        return false;
                    }

                    var assemblyDefinition = _metadata.GetAssemblyDefinition();
                    isValueType = IsTrustedFrameworkAssembly(
                        _metadata,
                        _metadata.GetString(assemblyDefinition.Name),
                        assemblyDefinition.PublicKey,
                        assemblyDefinition.Culture,
                        assemblyDefinition.Flags);
                    return isValueType;

                case HandleKind.TypeReference:
                    var referenceHandle = (TypeReferenceHandle)baseType;
                    if (!TryValidateTypeReferenceName(referenceHandle))
                    {
                        return false;
                    }

                    var reference = _metadata.GetTypeReference(referenceHandle);
                    if (reference.ResolutionScope.Kind != HandleKind.AssemblyReference ||
                        _metadata.GetString(reference.Namespace) != "System" ||
                        _metadata.GetString(reference.Name) is not ("ValueType" or "Enum"))
                    {
                        return true;
                    }

                    var assembly = _metadata.GetAssemblyReference(
                        (AssemblyReferenceHandle)reference.ResolutionScope);
                    isValueType = IsTrustedFrameworkAssembly(
                        _metadata,
                        _metadata.GetString(assembly.Name),
                        assembly.PublicKeyOrToken,
                        assembly.Culture,
                        assembly.Flags);
                    return isValueType;

                default:
                    return false;
            }
        }

        private bool TryGetCanonicalTypeDefinitionParameterCount(
            TypeDefinitionHandle handle,
            out int parameterCount)
        {
            parameterCount = 0;
            if (!TryValidateTypeDefinitionName(handle))
            {
                return false;
            }

            var chain = new List<TypeDefinitionHandle>();
            var current = handle;
            while (!current.IsNil)
            {
                if (chain.Count >= MaxNominalNameDepth)
                {
                    return false;
                }

                chain.Add(current);
                current = _metadata.GetTypeDefinition(current).GetDeclaringType();
            }

            var cumulativeArity = 0;
            for (var index = chain.Count - 1; index >= 0; index--)
            {
                var definitionHandle = chain[index];
                var definition = _metadata.GetTypeDefinition(definitionHandle);
                if (!TryReadDeclaredGenericArity(definition.Name, out var declaredArity) ||
                    declaredArity > MaxParameters - cumulativeArity)
                {
                    return false;
                }

                cumulativeArity += declaredArity;
                var parameters = definition.GetGenericParameters();
                if (parameters.Count != cumulativeArity ||
                    !HasCanonicalGenericParameterDomain(
                        definitionHandle,
                        parameters,
                        cumulativeArity))
                {
                    return false;
                }
            }

            parameterCount = cumulativeArity;
            return true;
        }

        private bool TryGetCanonicalTypeReferenceParameterCount(
            TypeReferenceHandle handle,
            out int parameterCount)
        {
            parameterCount = 0;
            if (!TryValidateTypeReferenceName(handle))
            {
                return false;
            }

            var current = handle;
            while (!current.IsNil)
            {
                var reference = _metadata.GetTypeReference(current);
                if (!TryReadDeclaredGenericArity(reference.Name, out var declaredArity) ||
                    declaredArity > MaxParameters - parameterCount)
                {
                    return false;
                }

                parameterCount += declaredArity;
                current = reference.ResolutionScope.Kind == HandleKind.TypeReference
                    ? (TypeReferenceHandle)reference.ResolutionScope
                    : default;
            }

            return true;
        }

        private bool HasCanonicalGenericParameterDomain(
            TypeDefinitionHandle owner,
            GenericParameterHandleCollection parameters,
            int parameterCount)
        {
            var positions = new bool[parameterCount];
            foreach (var parameterHandle in parameters)
            {
                var parameter = _metadata.GetGenericParameter(parameterHandle);
                if (parameter.Parent != owner ||
                    parameter.Index < 0 ||
                    parameter.Index >= positions.Length ||
                    positions[parameter.Index])
                {
                    return false;
                }

                positions[parameter.Index] = true;
            }

            return true;
        }

        private bool TryReadDeclaredGenericArity(
            StringHandle nameHandle,
            out int arity)
        {
            arity = 0;
            var name = _metadata.GetString(nameHandle);
            var backtick = name.IndexOf('`', StringComparison.Ordinal);
            if (backtick < 0)
            {
                return true;
            }

            if (backtick == 0 ||
                name.LastIndexOf('`') != backtick ||
                backtick == name.Length - 1 ||
                name[backtick + 1] == '0' ||
                !int.TryParse(
                    name.AsSpan(backtick + 1),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out arity) ||
                arity is <= 0 or > MaxParameters)
            {
                arity = 0;
                return false;
            }

            return true;
        }

        private bool TryValidateTypeDefinitionName(TypeDefinitionHandle handle)
        {
            var seen = new HashSet<TypeDefinitionHandle>();
            var current = handle;
            while (!current.IsNil)
            {
                if (seen.Count >= MaxNominalNameDepth ||
                    !seen.Add(current) ||
                    !IsValidRow(current, TableIndex.TypeDef))
                {
                    return false;
                }

                var definition = _metadata.GetTypeDefinition(current);
                if (!TryReserveNominalName(
                        definition.Name,
                        definition.Namespace))
                {
                    return false;
                }

                current = definition.GetDeclaringType();
            }

            return true;
        }

        private bool TryValidateTypeReferenceName(TypeReferenceHandle handle)
        {
            var seen = new HashSet<TypeReferenceHandle>();
            var current = handle;
            while (!current.IsNil)
            {
                if (seen.Count >= MaxNominalNameDepth ||
                    !seen.Add(current) ||
                    !IsValidRow(current, TableIndex.TypeRef))
                {
                    return false;
                }

                var reference = _metadata.GetTypeReference(current);
                if (!TryReserveNominalName(
                        reference.Name,
                        reference.Namespace))
                {
                    return false;
                }

                var scope = reference.ResolutionScope;
                if (scope.IsNil)
                {
                    return true;
                }

                if (scope.Kind == HandleKind.TypeReference)
                {
                    current = (TypeReferenceHandle)scope;
                    continue;
                }

                return IsValidResolutionScope(scope);
            }

            return true;
        }

        private bool TryReserveNominalName(
            StringHandle name,
            StringHandle @namespace)
        {
            var nameBytes = _metadata.GetBlobReader(name).Length;
            var namespaceBytes = _metadata.GetBlobReader(@namespace).Length;
            if (nameBytes is <= 0 or > MaxNameSegmentBytes ||
                namespaceBytes > MaxNameSegmentBytes)
            {
                return false;
            }

            var bytes = nameBytes + namespaceBytes;
            if (bytes < 0 || _nominalNameBytes > MaxNominalNameBytes - bytes)
            {
                return false;
            }

            _nominalNameBytes += bytes;
            return true;
        }

        private bool TryReserveMemberName(StringHandle name)
        {
            var bytes = _metadata.GetBlobReader(name).Length;
            if (bytes is <= 0 or > MaxNameSegmentBytes ||
                _nominalNameBytes > MaxNominalNameBytes - bytes)
            {
                return false;
            }

            _nominalNameBytes += bytes;
            return true;
        }

        private bool IsValidResolutionScope(EntityHandle handle) => handle.Kind switch
        {
            HandleKind.ModuleDefinition => IsValidRow(handle, TableIndex.Module),
            HandleKind.ModuleReference => IsValidRow(handle, TableIndex.ModuleRef),
            HandleKind.AssemblyReference => IsValidRow(handle, TableIndex.AssemblyRef),
            _ => false
        };

        private bool IsValidRow(EntityHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private bool IsValidRow(MemberReferenceHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private bool IsValidRow(TypeDefinitionHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private bool IsValidRow(TypeReferenceHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private bool IsValidRow(TypeSpecificationHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private bool IsValidRow(MethodSpecificationHandle handle, TableIndex table) =>
            !handle.IsNil &&
            MetadataTokens.GetRowNumber(handle) is var row &&
            row > 0 &&
            row <= _metadata.GetTableRowCount(table);

        private static bool TryReadCanonicalCompressedSignedInteger(
            ref BlobReader reader,
            out int value)
        {
            var start = reader.Offset;
            if (!reader.TryReadCompressedSignedInteger(out value))
            {
                return false;
            }

            var expectedBytes = value switch
            {
                >= -64 and <= 63 => 1,
                >= -8_192 and <= 8_191 => 2,
                _ => 4
            };
            return reader.Offset - start == expectedBytes;
        }

        private static byte PeekByte(BlobReader reader) => reader.ReadByte();
    }

    private static bool TryRenderStaticFieldTarget(
        FieldInfo field,
        MemberReferenceCallerContext callerContext,
        out string target)
    {
        target = string.Empty;
        if (field.DeclaringType.Length == 0)
        {
            return false;
        }

        if (field.DeclaringGenericArity > 0 &&
            (field.DeclaringHandle.Kind != HandleKind.TypeDefinition ||
             !callerContext.IsAvailable ||
             callerContext.TypeParameterCount != field.DeclaringGenericArity ||
             callerContext.TypeParameterOwner !=
                 (TypeDefinitionHandle)field.DeclaringHandle))
        {
            return false;
        }

        target = $"{field.DeclaringType}.";
        return true;
    }

    private static bool IsWritableFieldDefinition(
        ReconContext context,
        FieldInfo field,
        bool staticStore)
    {
        if (field.DefinitionAttributes is not { } attributes)
        {
            return true;
        }

        if (attributes.HasFlag(FieldAttributes.Literal))
        {
            return false;
        }

        if (!attributes.HasFlag(FieldAttributes.InitOnly))
        {
            return true;
        }

        var caller = context.MemberReferenceCallerContext;
        if (!caller.IsAvailable ||
            caller.MethodParameterOwner.IsNil ||
            field.DeclaringHandle.Kind != HandleKind.TypeDefinition ||
            caller.TypeParameterOwner != (TypeDefinitionHandle)field.DeclaringHandle)
        {
            return false;
        }

        var method = context.Metadata.GetMethodDefinition(caller.MethodParameterOwner);
        return method.Attributes.HasFlag(MethodAttributes.Static) == staticStore &&
               context.Metadata.GetString(method.Name) ==
                   (staticStore ? ".cctor" : ".ctor");
    }

    private static FieldInfo? ResolveField(
        MetadataReader metadata,
        EnumTypeCatalog enumTypes,
        int token,
        MemberReferenceCallerContext callerContext)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.FieldDefinition:
                var field = metadata.GetFieldDefinition((FieldDefinitionHandle)handle);
                var fieldDeclaringType = field.GetDeclaringType();
                if (!TryGetCanonicalTypeDefinitionSignatureParameterCount(
                        metadata,
                        fieldDeclaringType,
                        out var fieldTypeParameterCount) ||
                    fieldTypeParameterCount > 0 &&
                    (!callerContext.IsAvailable ||
                     callerContext.TypeParameterOwner != fieldDeclaringType ||
                     callerContext.TypeParameterCount != fieldTypeParameterCount))
                {
                    return null;
                }

                var fieldType = field.DecodeSignature(
                    SignatureTypeNameProvider.Instance,
                    SignatureGenericContext.ForOwner(
                        fieldDeclaringType,
                        fieldTypeParameterCount));
                if (fieldType.HasPinnedQualifier)
                {
                    return null;
                }

                CliType fieldDeclaringCliType;
                if (fieldTypeParameterCount > 0)
                {
                    if (!TryCreateCurrentGenericOwnerCliType(
                            metadata,
                            enumTypes,
                            fieldDeclaringType,
                            fieldTypeParameterCount,
                            callerContext,
                            out fieldDeclaringCliType))
                    {
                        return null;
                    }
                }
                else
                {
                    fieldDeclaringCliType = CreateNominalCliType(
                        metadata,
                        enumTypes,
                        fieldDeclaringType);
                }

                return new FieldInfo(
                    fieldDeclaringCliType.Text,
                    fieldDeclaringCliType,
                    fieldDeclaringType,
                    fieldTypeParameterCount,
                    NormalizeFieldName(metadata.GetString(field.Name)),
                    CreateCliType(fieldType, enumTypes),
                    field.Attributes);

            case HandleKind.MemberReference:
                if (!MemberReferenceSignatureValidator.TryValidateField(
                        metadata,
                        (MemberReferenceHandle)handle,
                        callerContext,
                        out var member,
                        out var parentContext))
                {
                    return null;
                }

                var memberType = member.DecodeFieldSignature(
                    SignatureTypeNameProvider.Instance,
                    parentContext.SignatureContext);
                if (HasUnrepresentableMemberReferenceType(memberType))
                {
                    return null;
                }

                CliType memberDeclaringCliType;
                if (member.Parent.Kind == HandleKind.TypeDefinition &&
                    parentContext.TypeParameterLimit > 0)
                {
                    if (!TryCreateCurrentGenericOwnerCliType(
                            metadata,
                            enumTypes,
                            (TypeDefinitionHandle)member.Parent,
                            parentContext.TypeParameterLimit,
                            callerContext,
                            out memberDeclaringCliType))
                    {
                        return null;
                    }
                }
                else
                {
                    var declaringName = GetTypeName(metadata, member.Parent) ?? string.Empty;
                    memberDeclaringCliType = parentContext.DecodedType is { } decodedParent
                        ? CreateCliType(decodedParent, enumTypes) with { Text = declaringName }
                        : CreateNominalCliType(metadata, enumTypes, member.Parent);
                }

                return new FieldInfo(
                    memberDeclaringCliType.Text,
                    memberDeclaringCliType,
                    member.Parent,
                    member.Parent.Kind == HandleKind.TypeDefinition
                        ? parentContext.TypeParameterLimit
                        : 0,
                    NormalizeFieldName(metadata.GetString(member.Name)),
                    CreateCliType(memberType, enumTypes),
                    DefinitionAttributes: null);

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

    private static string EscapeCSharpString(string value)
    {
        var escaped = new StringBuilder(value.Length + 2);
        escaped.Append('"');
        foreach (var character in value)
        {
            switch (character)
            {
                case '\\':
                    escaped.Append("\\\\");
                    break;
                case '"':
                    escaped.Append("\\\"");
                    break;
                case '\0':
                    escaped.Append("\\0");
                    break;
                case '\a':
                    escaped.Append("\\a");
                    break;
                case '\b':
                    escaped.Append("\\b");
                    break;
                case '\f':
                    escaped.Append("\\f");
                    break;
                case '\n':
                    escaped.Append("\\n");
                    break;
                case '\r':
                    escaped.Append("\\r");
                    break;
                case '\t':
                    escaped.Append("\\t");
                    break;
                case '\v':
                    escaped.Append("\\v");
                    break;
                default:
                    if (char.IsControl(character) ||
                        char.IsSurrogate(character) ||
                        char.GetUnicodeCategory(character) == UnicodeCategory.Format ||
                        character is '\u0085' or '\u2028' or '\u2029')
                    {
                        escaped.Append("\\u");
                        escaped.Append(((int)character).ToString("X4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        escaped.Append(character);
                    }

                    break;
            }
        }

        escaped.Append('"');
        return escaped.ToString();
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

    private static string? ResolveMemberName(
        MetadataReader metadata,
        int token,
        MemberReferenceCallerContext callerContext)
    {
        try
        {
            return TryResolveCallGraphMemberName(
                metadata,
                MetadataTokens.EntityHandle(token),
                callerContext)?.Text;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static CallGraphMemberName? TryResolveCallGraphMemberName(
        MetadataReader metadata,
        EntityHandle handle,
        MemberReferenceCallerContext callerContext)
    {
        switch (handle.Kind)
        {
            case HandleKind.MethodDefinition:
                var methodHandle = (MethodDefinitionHandle)handle;
                var method = metadata.GetMethodDefinition(methodHandle);
                var methodDeclaringType = method.GetDeclaringType();
                var methodContext = TryCreateMemberReferenceCallerContext(
                    metadata,
                    methodDeclaringType,
                    methodHandle);
                if (!methodContext.IsAvailable)
                {
                    return null;
                }

                var methodSignature = method.DecodeSignature(
                    SignatureTypeNameProvider.Instance,
                    methodContext.SignatureContext);
                if (methodSignature.Header.IsInstance ==
                        method.Attributes.HasFlag(MethodAttributes.Static))
                {
                    return null;
                }

                var declaringType = GetTypeDefinitionFullName(
                    metadata,
                    methodDeclaringType);
                var methodName = metadata.GetString(method.Name);
                return new CallGraphMemberName(
                    string.IsNullOrEmpty(declaringType)
                        ? methodName
                        : $"{declaringType}.{methodName}",
                    methodContext.MethodParameterCount);

            case HandleKind.MemberReference:
                if (!MemberReferenceSignatureValidator.TryValidateMethod(
                        metadata,
                        (MemberReferenceHandle)handle,
                        callerContext,
                        out var member,
                        out var parentContext))
                {
                    return null;
                }

                var signature = member.DecodeMethodSignature(
                    SignatureTypeNameProvider.Instance,
                    parentContext.SignatureContext);
                var memberName = metadata.GetString(member.Name);
                if (parentContext.IsArray &&
                    !TryClassifyArrayPseudoMember(
                        memberName,
                        signature,
                        parentContext,
                        out _) &&
                    !IsCanonicalArrayAddressPseudoMember(
                        memberName,
                        signature,
                        parentContext))
                {
                    return null;
                }

                var parent = GetTypeName(metadata, member.Parent);
                return new CallGraphMemberName(
                    string.IsNullOrEmpty(parent)
                        ? memberName
                        : $"{parent}.{memberName}",
                    signature.GenericParameterCount);

            case HandleKind.MethodSpecification:
                if (!MemberReferenceSignatureValidator.TryValidateMethodSpecification(
                        metadata,
                        (MethodSpecificationHandle)handle,
                        callerContext,
                        out var specification))
                {
                    return null;
                }

                var resolved = TryResolveCallGraphMemberName(
                    metadata,
                    specification.Method,
                    callerContext);
                if (resolved is not { GenericParameterCount: > 0 })
                {
                    return null;
                }

                var genericArguments = specification.DecodeSignature(
                    SignatureTypeNameProvider.Instance,
                    callerContext.SignatureContext);
                if (genericArguments.Length != resolved.Value.GenericParameterCount ||
                    genericArguments.Any(IsInvalidMethodSpecificationArgument) ||
                    !TryRenderMethodSpecificationCallGraphName(
                        resolved.Value.Text,
                        genericArguments,
                        out var renderedName))
                {
                    return null;
                }

                return new CallGraphMemberName(
                    renderedName,
                    GenericParameterCount: 0);

            default:
                return null;
        }
    }

    private static bool TryRenderMethodSpecificationCallGraphName(
        string methodName,
        ImmutableArray<SignatureTypeName> genericArguments,
        out string rendered)
    {
        rendered = string.Empty;
        long requiredCharacters = methodName.Length + 2L;
        if (genericArguments.Length > 1)
        {
            requiredCharacters += (genericArguments.Length - 1L) * 2L;
        }

        foreach (var argument in genericArguments)
        {
            requiredCharacters += argument.Text.Length;
            if (requiredCharacters > MaxInstantiatedMethodSignatureCharacters)
            {
                return false;
            }
        }

        rendered = $"{methodName}<{string.Join(", ", genericArguments)}>";
        return true;
    }

    private static bool IsCanonicalArrayAddressPseudoMember(
        string memberName,
        MethodSignature<SignatureTypeName> signature,
        MemberReferenceSignatureValidator.ParentContext parentContext)
    {
        if (memberName != "Address" ||
            parentContext.ArrayElementType is not { } elementType ||
            parentContext.ArrayRank is <= 1 or > 32 ||
            signature.Header.CallingConvention != SignatureCallingConvention.Default ||
            !signature.Header.IsInstance ||
            signature.Header.IsGeneric ||
            signature.Header.HasExplicitThis ||
            signature.GenericParameterCount != 0 ||
            signature.RequiredParameterCount != signature.ParameterTypes.Length ||
            signature.ParameterTypes.Length != parentContext.ArrayRank ||
            signature.ParameterTypes.Any(type =>
                type.PrimitiveType != PrimitiveTypeCode.Int32 ||
                type.IsByReference ||
                type.IsUnsupported ||
                type.HasNestedCustomModifiers ||
                !type.OuterCustomModifiers.IsEmpty) ||
            !signature.ReturnType.IsByReference ||
            signature.ReturnType.IsUnsupported ||
            signature.ReturnType.HasNestedCustomModifiers ||
            !signature.ReturnType.OuterCustomModifiers.IsEmpty)
        {
            return false;
        }

        return signature.ReturnType.ByReferenceElementType is { } returnElement &&
               AreSameConstructorSignature(returnElement, elementType);
    }

    private static bool TryInstantiateMethodSignatureText(
        string signatureType,
        IReadOnlyList<string> genericArguments,
        ref int remainingRenderedCharacters,
        out string instantiated)
    {
        instantiated = signatureType;
        long requiredCharacters = 0;
        for (var position = 0; position < signatureType.Length;)
        {
            if (signatureType[position] != '!' ||
                position + 2 >= signatureType.Length ||
                signatureType[position + 1] != '!' ||
                !char.IsAsciiDigit(signatureType[position + 2]))
            {
                requiredCharacters++;
                position++;
                continue;
            }

            var digitEnd = position + 2;
            var argumentIndex = 0;
            var overflow = false;
            while (digitEnd < signatureType.Length &&
                   char.IsAsciiDigit(signatureType[digitEnd]))
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
                !(char.IsLetterOrDigit(signatureType[digitEnd]) ||
                  signatureType[digitEnd] == '_');
            if (!overflow &&
                hasTokenBoundary &&
                argumentIndex < genericArguments.Count)
            {
                requiredCharacters += genericArguments[argumentIndex].Length;
            }
            else
            {
                requiredCharacters += digitEnd - position;
            }

            if (requiredCharacters > remainingRenderedCharacters)
            {
                return false;
            }

            position = digitEnd;
        }

        if (requiredCharacters > remainingRenderedCharacters)
        {
            return false;
        }

        instantiated = InstantiateMethodSignatureType(signatureType, genericArguments);
        remainingRenderedCharacters -= (int)requiredCharacters;
        return true;
    }

    private static bool TryReserveRenderedCharacters(
        int requiredCharacters,
        ref int remainingRenderedCharacters)
    {
        if (requiredCharacters < 0 ||
            requiredCharacters > remainingRenderedCharacters)
        {
            return false;
        }

        remainingRenderedCharacters -= requiredCharacters;
        return true;
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
        MethodDefinitionHandle entryPointHandle,
        GenericMetadataBudget genericMetadataBudget)
    {
        var returnType = "void";
        var parameters = new List<ParameterModel>();
        var signatureText = $"{methodName}(...)";
        var genericParameterHandles = method.GetGenericParameters();
        var genericParameterResult = ReadGenericParametersWithEvidence(
            metadata,
            genericParameterHandles,
            methodHandle,
            genericMetadataBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);
        var genericParameterDetails = genericParameterResult.Parameters;
        var genericParametersComplete =
            genericParameterDetails.Count == genericParameterHandles.Count &&
            genericParameterDetails.All(parameter => parameter.Complete);

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
            GenericParameters = genericParameterDetails.Select(parameter => parameter.Name).ToArray(),
            GenericParameterDetails = genericParameterDetails,
            GenericParametersComplete = genericParametersComplete,
            GenericParameterDomainComplete = genericParameterResult.DomainComplete,
            GenericParametersError = genericParametersComplete
                ? null
                : "泛型參數 metadata 不完整；請檢查 genericParameterDetails 與 code.truncated",
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

    internal sealed record TypeGenericParameterReadResult(
        IReadOnlyList<GenericParameterModel> Parameters,
        bool Complete,
        bool DomainComplete,
        int DeclaringTypeDepth);

    internal sealed class TypeGenericParameterResolver(
        MetadataReader metadata,
        GenericMetadataBudget sharedBudget)
    {
        private readonly Dictionary<TypeDefinitionHandle, TypeGenericParameterReadResult> _cache = [];

        public TypeGenericParameterReadResult Read(TypeDefinitionHandle handle)
        {
            if (_cache.TryGetValue(handle, out var cached))
            {
                return cached;
            }

            var path = new List<TypeDefinitionHandle>(MaxGenericDeclaringTypeDepth);
            var visited = new HashSet<TypeDefinitionHandle>();
            var current = handle;
            TypeGenericParameterReadResult? declaringResult = null;
            while (true)
            {
                if (_cache.TryGetValue(current, out declaringResult))
                {
                    break;
                }

                if (!visited.Add(current) || path.Count >= MaxGenericDeclaringTypeDepth)
                {
                    return ReadWithoutDeclaringContext(handle);
                }

                path.Add(current);
                var declaringType = metadata.GetTypeDefinition(current).GetDeclaringType();
                if (declaringType.IsNil)
                {
                    break;
                }

                current = declaringType;
            }

            for (var index = path.Count - 1; index >= 0; index--)
            {
                var owner = path[index];
                var definition = metadata.GetTypeDefinition(owner);
                var declaringType = definition.GetDeclaringType();
                var inheritedParameterCount = declaringType.IsNil
                    ? 0
                    : metadata.GetTypeDefinition(declaringType).GetGenericParameters().Count;
                var declaringTypeDepth = declaringType.IsNil
                    ? 0
                    : Math.Min(
                        MaxGenericDeclaringTypeDepth,
                        (declaringResult?.DeclaringTypeDepth ?? MaxGenericDeclaringTypeDepth) + 1);
                var declaringContextComplete = declaringType.IsNil ||
                                               declaringResult?.Complete == true;
                var declaringDomainComplete = declaringType.IsNil ||
                                              declaringResult?.DomainComplete == true;
                if (declaringTypeDepth >= MaxGenericDeclaringTypeDepth)
                {
                    sharedBudget.MarkTruncated();
                    declaringContextComplete = false;
                    declaringDomainComplete = false;
                }

                var handles = definition.GetGenericParameters();
                var parameterResult = ReadGenericParametersWithEvidence(
                    metadata,
                    handles,
                    owner,
                    sharedBudget,
                    inheritedParameterCount,
                    declaringContextComplete ? declaringResult?.Parameters : null,
                    declaringDomainComplete ? declaringResult?.Parameters : null);
                var parameters = parameterResult.Parameters;
                var result = new TypeGenericParameterReadResult(
                    parameters,
                    declaringContextComplete &&
                    parameters.Count == handles.Count &&
                    parameters.Count >= inheritedParameterCount &&
                    parameters.All(parameter => parameter.Complete),
                    declaringDomainComplete && parameterResult.DomainComplete,
                    declaringTypeDepth);
                _cache[owner] = result;
                declaringResult = result;
            }

            return _cache[handle];
        }

        private TypeGenericParameterReadResult ReadWithoutDeclaringContext(TypeDefinitionHandle handle)
        {
            sharedBudget.MarkTruncated();
            var definition = metadata.GetTypeDefinition(handle);
            var declaringType = definition.GetDeclaringType();
            var inheritedParameterCount = declaringType.IsNil
                ? 0
                : metadata.GetTypeDefinition(declaringType).GetGenericParameters().Count;
            var parameterResult = ReadGenericParametersWithEvidence(
                metadata,
                definition.GetGenericParameters(),
                handle,
                sharedBudget,
                inheritedParameterCount,
                inheritedParameters: null,
                inheritedDomainParameters: null);
            var result = new TypeGenericParameterReadResult(
                parameterResult.Parameters,
                Complete: false,
                DomainComplete: false,
                DeclaringTypeDepth: MaxGenericDeclaringTypeDepth);
            _cache[handle] = result;
            return result;
        }
    }

    internal sealed record GenericParameterOwnerReadResult(
        IReadOnlyList<GenericParameterModel> Parameters,
        bool DomainComplete);

    private readonly record struct GenericParameterReadEvidence(
        GenericParameterModel Parameter,
        bool DeclarationComplete);

    internal static IReadOnlyList<GenericParameterModel> ReadGenericParameters(
        MetadataReader metadata,
        GenericParameterHandleCollection handles,
        EntityHandle expectedOwner,
        GenericMetadataBudget sharedBudget,
        int inheritedParameterCount,
        IReadOnlyList<GenericParameterModel>? inheritedParameters) =>
        ReadGenericParametersWithEvidence(
            metadata,
            handles,
            expectedOwner,
            sharedBudget,
            inheritedParameterCount,
            inheritedParameters,
            inheritedParameters).Parameters;

    internal static GenericParameterOwnerReadResult ReadGenericParametersWithEvidence(
        MetadataReader metadata,
        GenericParameterHandleCollection handles,
        EntityHandle expectedOwner,
        GenericMetadataBudget sharedBudget,
        int inheritedParameterCount,
        IReadOnlyList<GenericParameterModel>? inheritedParameters,
        IReadOnlyList<GenericParameterModel>? inheritedDomainParameters)
    {
        var rawDomain = ReadGenericParameterDomain(metadata, handles, expectedOwner);
        var genericContext = CreateConstraintGenericContext(metadata, expectedOwner, handles);
        var budget = sharedBudget.BeginOwner();
        var entries = new List<GenericParameterReadEvidence>(Math.Min(handles.Count, MaxGenericParametersPerOwner));
        var domainComplete = rawDomain.Complete &&
                             inheritedParameterCount >= 0 &&
                             inheritedParameterCount <= handles.Count;
        var ordinal = 0;
        foreach (var handle in handles)
        {
            if (entries.Count >= MaxGenericParametersPerOwner)
            {
                domainComplete = false;
                break;
            }

            if (!budget.TryConsumeParameterRow())
            {
                domainComplete = false;
                if (entries.Count > 0)
                {
                    entries[^1] = entries[^1] with
                    {
                        Parameter = MarkGenericParameterIncomplete(
                            entries[^1].Parameter,
                            "泛型 metadata 的 assembly parameter row 預算已用盡")
                    };
                }

                break;
            }

            var entry = ReadGenericParameter(
                metadata,
                handle,
                expectedOwner,
                genericContext,
                budget,
                inheritedParameterCount,
                ordinal);
            entries.Add(entry);
            domainComplete &= entry.DeclarationComplete;
            ordinal++;
        }

        entries.Sort((left, right) => left.Parameter.Position.CompareTo(right.Parameter.Position));
        domainComplete &= entries.Count == handles.Count;
        for (var index = 0; index < entries.Count; index++)
        {
            if (entries[index].Parameter.Position != index)
            {
                domainComplete = false;
                entries[index] = entries[index] with
                {
                    Parameter = MarkGenericParameterIncomplete(
                        entries[index].Parameter,
                        "泛型參數 position 不連續或重複")
                };
            }
        }

        if (inheritedParameterCount > 0 &&
            (inheritedDomainParameters is null ||
             inheritedDomainParameters.Count != inheritedParameterCount ||
             entries.Count < inheritedParameterCount))
        {
            domainComplete = false;
        }

        for (var index = 0; index < entries.Count && index < inheritedParameterCount; index++)
        {
            var parameter = entries[index].Parameter;
            if (inheritedDomainParameters is null ||
                inheritedDomainParameters.Count != inheritedParameterCount ||
                index >= inheritedDomainParameters.Count ||
                !InheritedGenericParameterDeclarationsMatch(
                    parameter,
                    inheritedDomainParameters[index]))
            {
                domainComplete = false;
            }

            if (inheritedParameters is null ||
                inheritedParameters.Count != inheritedParameterCount ||
                index >= inheritedParameters.Count ||
                !InheritedGenericParametersMatch(parameter, inheritedParameters[index]))
            {
                entries[index] = entries[index] with
                {
                    Parameter = MarkGenericParameterIncomplete(
                        parameter,
                        "inherited 泛型參數與 declaring type 的完整 metadata 不一致或無法取得")
                };
            }
        }

        if (handles.Count > MaxGenericParametersPerOwner && entries.Count > 0)
        {
            budget.MarkTruncated();
            domainComplete = false;
            entries[^1] = entries[^1] with
            {
                Parameter = MarkGenericParameterIncomplete(
                    entries[^1].Parameter,
                    $"泛型參數超過每個 owner 的 {MaxGenericParametersPerOwner} 筆限制")
            };
        }

        return new GenericParameterOwnerReadResult(
            entries.Select(entry => entry.Parameter).ToArray(),
            domainComplete);
    }

    private static bool InheritedGenericParameterDeclarationsMatch(
        GenericParameterModel current,
        GenericParameterModel declaring) =>
        current.Position == declaring.Position &&
        current.Name == declaring.Name;

    private static bool InheritedGenericParametersMatch(
        GenericParameterModel current,
        GenericParameterModel declaring)
    {
        if (!current.Complete ||
            !declaring.Complete ||
            current.Position != declaring.Position ||
            current.Name != declaring.Name ||
            current.RawAttributes != declaring.RawAttributes ||
            current.Variance != declaring.Variance ||
            current.ReferenceTypeConstraint != declaring.ReferenceTypeConstraint ||
            current.NotNullableValueTypeConstraint != declaring.NotNullableValueTypeConstraint ||
            current.NotNullConstraint != declaring.NotNullConstraint ||
            current.DefaultConstructorConstraint != declaring.DefaultConstructorConstraint ||
            current.AllowsRefStruct != declaring.AllowsRefStruct ||
            current.Nullability != declaring.Nullability ||
            !current.NullableFlags.SequenceEqual(declaring.NullableFlags) ||
            current.HasUnmanagedAttribute != declaring.HasUnmanagedAttribute ||
            current.TypeConstraints.Count != declaring.TypeConstraints.Count)
        {
            return false;
        }

        for (var index = 0; index < current.TypeConstraints.Count; index++)
        {
            var left = current.TypeConstraints[index];
            var right = declaring.TypeConstraints[index];
            if (!left.Complete ||
                !right.Complete ||
                left.Type != right.Type ||
                left.Kind != right.Kind ||
                left.Nullability != right.Nullability ||
                !left.NullableFlags.SequenceEqual(right.NullableFlags) ||
                !left.RequiredModifiers.SequenceEqual(right.RequiredModifiers) ||
                !left.OptionalModifiers.SequenceEqual(right.OptionalModifiers))
            {
                return false;
            }
        }

        return true;
    }

    private static ConstraintGenericContext CreateConstraintGenericContext(
        MetadataReader metadata,
        EntityHandle owner,
        GenericParameterHandleCollection ownerHandles)
    {
        var ownerDomain = ReadGenericParameterDomain(metadata, ownerHandles, owner);
        if (owner.Kind == HandleKind.TypeDefinition)
        {
            return new ConstraintGenericContext(
                ownerDomain.Count,
                0,
                AllowsMethodParameters: false,
                TypeParameterPositions: ownerDomain.Positions,
                MethodParameterPositions: default,
                TypeParameterPositionsComplete: ownerDomain.Complete,
                MethodParameterPositionsComplete: true);
        }

        if (owner.Kind == HandleKind.MethodDefinition)
        {
            var method = metadata.GetMethodDefinition((MethodDefinitionHandle)owner);
            var declaringType = method.GetDeclaringType();
            var typeDomain = declaringType.IsNil
                ? new GenericParameterDomain(0, [], true)
                : ReadGenericParameterDomain(
                    metadata,
                    metadata.GetTypeDefinition(declaringType).GetGenericParameters(),
                    declaringType);
            return new ConstraintGenericContext(
                typeDomain.Count,
                ownerDomain.Count,
                AllowsMethodParameters: true,
                TypeParameterPositions: typeDomain.Positions,
                MethodParameterPositions: ownerDomain.Positions,
                TypeParameterPositionsComplete: typeDomain.Complete,
                MethodParameterPositionsComplete: ownerDomain.Complete);
        }

        return new ConstraintGenericContext(0, 0, AllowsMethodParameters: false);
    }

    private static GenericParameterDomain ReadGenericParameterDomain(
        MetadataReader metadata,
        GenericParameterHandleCollection handles,
        EntityHandle expectedOwner)
    {
        var count = Math.Min(handles.Count, MaxGenericParametersPerOwner);
        var positions = new List<int>(count);
        var complete = handles.Count <= MaxGenericParametersPerOwner;
        foreach (var handle in handles)
        {
            if (positions.Count >= MaxGenericParametersPerOwner)
            {
                break;
            }

            try
            {
                var parameter = metadata.GetGenericParameter(handle);
                complete &= parameter.Parent == expectedOwner;
                positions.Add(parameter.Index);
            }
            catch (Exception exception) when (
                exception is BadImageFormatException or ArgumentException or InvalidOperationException)
            {
                complete = false;
            }
        }

        positions.Sort();
        complete &= positions.Count == count;
        for (var index = 0; index < positions.Count; index++)
        {
            complete &= positions[index] == index;
        }

        return new GenericParameterDomain(count, [.. positions], complete);
    }

    private readonly record struct GenericParameterDomain(
        int Count,
        ImmutableArray<int> Positions,
        bool Complete);

    internal sealed class GenericMetadataBudget
    {
        private readonly int _ownerConstraintRows;
        private readonly long _ownerCharacters;
        private int _remainingParameterRows;
        private int _remainingConstraintRows;
        private long _remainingCharacters;

        public GenericMetadataBudget(
            int parameterRows = MaxGenericParameterRows,
            int constraintRows = MaxGenericConstraintRows,
            long characters = MaxGenericMetadataCharacters,
            int ownerConstraintRows = MaxGenericConstraintRowsPerOwner,
            long ownerCharacters = MaxGenericMetadataCharactersPerOwner)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(parameterRows);
            ArgumentOutOfRangeException.ThrowIfNegative(constraintRows);
            ArgumentOutOfRangeException.ThrowIfNegative(characters);
            ArgumentOutOfRangeException.ThrowIfNegative(ownerConstraintRows);
            ArgumentOutOfRangeException.ThrowIfNegative(ownerCharacters);
            _remainingParameterRows = parameterRows;
            _remainingConstraintRows = constraintRows;
            _remainingCharacters = characters;
            _ownerConstraintRows = ownerConstraintRows;
            _ownerCharacters = ownerCharacters;
        }

        public bool Truncated { get; private set; }

        public GenericMetadataOwnerBudget BeginOwner() =>
            new(this, _ownerConstraintRows, _ownerCharacters);

        public bool TryConsumeParameterRow()
        {
            if (_remainingParameterRows <= 0)
            {
                Truncated = true;
                return false;
            }

            _remainingParameterRows--;
            return true;
        }

        public bool TryConsumeConstraintRow()
        {
            if (_remainingConstraintRows <= 0)
            {
                Truncated = true;
                return false;
            }

            _remainingConstraintRows--;
            return true;
        }

        public bool TryRetainCharacters(long characters)
        {
            if (characters < 0 || characters > _remainingCharacters)
            {
                Truncated = true;
                return false;
            }

            _remainingCharacters -= characters;
            return true;
        }

        public void MarkTruncated() => Truncated = true;
    }

    internal sealed class GenericMetadataOwnerBudget(
        GenericMetadataBudget shared,
        int ownerConstraintRows,
        long ownerCharacters)
    {
        private int _remainingConstraintRows = ownerConstraintRows;
        private long _remainingCharacters = ownerCharacters;

        public bool TryConsumeParameterRow() => shared.TryConsumeParameterRow();

        public void MarkTruncated() => shared.MarkTruncated();

        public bool TryConsumeConstraintRow()
        {
            if (_remainingConstraintRows <= 0 || !shared.TryConsumeConstraintRow())
            {
                shared.MarkTruncated();
                return false;
            }

            _remainingConstraintRows--;
            return true;
        }

        public bool TryRetainCharacters(long characters)
        {
            if (characters < 0 ||
                characters > _remainingCharacters ||
                !shared.TryRetainCharacters(characters))
            {
                shared.MarkTruncated();
                return false;
            }

            _remainingCharacters -= characters;
            return true;
        }

        public bool TryRetainConstraint(GenericTypeConstraintModel constraint)
        {
            long characters = constraint.Type.Length +
                              constraint.Kind.Length +
                              constraint.Nullability.Length +
                              constraint.NullableFlags.Count +
                              (constraint.Error?.Length ?? 0);
            foreach (var modifier in constraint.RequiredModifiers)
            {
                characters += modifier.Length;
            }

            foreach (var modifier in constraint.OptionalModifiers)
            {
                characters += modifier.Length;
            }

            return TryRetainCharacters(characters);
        }
    }

    private static GenericParameterReadEvidence ReadGenericParameter(
        MetadataReader metadata,
        GenericParameterHandle handle,
        EntityHandle expectedOwner,
        ConstraintGenericContext genericContext,
        GenericMetadataOwnerBudget budget,
        int inheritedParameterCount,
        int fallbackPosition)
    {
        try
        {
            var parameter = metadata.GetGenericParameter(handle);
            var attributes = parameter.Attributes;
            var rawAttributes = (int)attributes;
            var errors = new List<string>();
            var nameComplete = TryReadBoundedGenericParameterName(metadata, parameter.Name, out var decodedName);
            var name = nameComplete
                ? decodedName
                : $"!invalid{fallbackPosition}";
            var declarationComplete = nameComplete && !string.IsNullOrEmpty(decodedName);
            if (!nameComplete)
            {
                budget.MarkTruncated();
                AddGenericMetadataError(errors, "泛型參數名稱超過長度限制");
            }
            else if (string.IsNullOrEmpty(name))
            {
                AddGenericMetadataError(errors, "泛型參數名稱不得為空");
            }
            else if (!budget.TryRetainCharacters((long)name.Length * 2))
            {
                name = $"!invalid{fallbackPosition}";
                declarationComplete = false;
                AddGenericMetadataError(errors, "泛型 metadata 的字元預算已用盡");
            }

            if (parameter.Parent != expectedOwner)
            {
                declarationComplete = false;
                AddGenericMetadataError(errors, "泛型參數 owner 與宣告不一致");
            }

            var isInheritedParameter = parameter.Index >= 0 && parameter.Index < inheritedParameterCount;

            var knownAttributes = GenericParameterAttributes.VarianceMask |
                                  GenericParameterAttributes.SpecialConstraintMask |
                                  GenericParameterAttributes.AllowByRefLike;
            var primaryFlagsComplete = (attributes & ~knownAttributes) == 0;
            if (!primaryFlagsComplete)
            {
                AddGenericMetadataError(errors, $"泛型參數含未知 flags 0x{rawAttributes:X}");
            }

            var variance = (attributes & GenericParameterAttributes.VarianceMask) switch
            {
                GenericParameterAttributes.None => "none",
                GenericParameterAttributes.Covariant => "out",
                GenericParameterAttributes.Contravariant => "in",
                _ => "invalid"
            };
            if (variance == "invalid")
            {
                primaryFlagsComplete = false;
                AddGenericMetadataError(errors, "泛型參數 variance flags 衝突");
            }

            if (expectedOwner.Kind == HandleKind.MethodDefinition && variance != "none")
            {
                primaryFlagsComplete = false;
                AddGenericMetadataError(errors, "方法泛型參數不可宣告 variance");
            }
            else if (!isInheritedParameter &&
                     expectedOwner.Kind == HandleKind.TypeDefinition &&
                     variance != "none")
            {
                var ownerDefinition = metadata.GetTypeDefinition((TypeDefinitionHandle)expectedOwner);
                var ownerBaseType = GetTypeName(metadata, ownerDefinition.BaseType);
                if (!ownerDefinition.Attributes.HasFlag(TypeAttributes.Interface) &&
                    ownerBaseType is not ("System.Delegate" or "System.MulticastDelegate"))
                {
                    primaryFlagsComplete = false;
                    AddGenericMetadataError(errors, "只有 interface 或 delegate 型別可宣告 variance");
                }
            }
            else if (expectedOwner.Kind is not (HandleKind.TypeDefinition or HandleKind.MethodDefinition))
            {
                primaryFlagsComplete = false;
            }

            var referenceTypeConstraint = attributes.HasFlag(GenericParameterAttributes.ReferenceTypeConstraint);
            var valueTypeConstraint = attributes.HasFlag(GenericParameterAttributes.NotNullableValueTypeConstraint);
            if (referenceTypeConstraint && valueTypeConstraint)
            {
                primaryFlagsComplete = false;
                AddGenericMetadataError(errors, "reference 與 value-type special constraints 衝突");
            }

            var nullable = ReadEffectiveNullableFlag(metadata, parameter.GetCustomAttributes(), expectedOwner);
            if (!nullable.Complete && nullable.Error is not null)
            {
                AddGenericMetadataError(errors, nullable.Error);
            }

            var unmanaged = ReadMarkerAttribute(
                metadata,
                parameter.GetCustomAttributes(),
                "System.Runtime.CompilerServices.IsUnmanagedAttribute");
            if (!unmanaged.Complete && unmanaged.Error is not null)
            {
                AddGenericMetadataError(errors, unmanaged.Error);
            }

            var constraintResult = ReadGenericTypeConstraints(
                metadata,
                handle,
                parameter,
                expectedOwner,
                genericContext,
                budget,
                errors);
            var constraints = constraintResult.Constraints;
            if (constraints.Any(constraint => !constraint.Complete))
            {
                AddGenericMetadataError(errors, "一或多個型別 constraint 不完整");
            }

            var unmanagedMarker = constraints.Any(constraint =>
                constraint.Kind == "value-type-marker" &&
                constraint.RequiredModifiers.Contains(
                    "System.Runtime.InteropServices.UnmanagedType",
                    StringComparer.Ordinal));
            var valueTypeMarker = constraints.Any(constraint => constraint.Kind == "value-type-marker");
            if (valueTypeMarker != valueTypeConstraint)
            {
                AddGenericMetadataError(errors, "ValueType marker 與 value-type special flag 不一致");
            }

            if (unmanaged.Found != unmanagedMarker ||
                (unmanaged.Found &&
                 (!valueTypeConstraint ||
                  !attributes.HasFlag(GenericParameterAttributes.DefaultConstructorConstraint))))
            {
                AddGenericMetadataError(errors, "unmanaged attribute、ValueType modreq 與 special flags 不一致");
            }

            var defaultConstructorConstraint = attributes.HasFlag(
                GenericParameterAttributes.DefaultConstructorConstraint);
            var allowsRefStruct = attributes.HasFlag(GenericParameterAttributes.AllowByRefLike);
            var notNullConstraint = !referenceTypeConstraint &&
                                    !valueTypeConstraint &&
                                    nullable.FromDirectAttribute &&
                                    nullable.Complete &&
                                    nullable.Flags.Count == 1 &&
                                    nullable.Flags[0] == 1;
            string? provenPrimaryConstraintKind = null;
            if (declarationComplete &&
                primaryFlagsComplete &&
                unmanaged.Complete &&
                constraintResult.PrimaryEvidenceComplete)
            {
                if (valueTypeConstraint &&
                    !referenceTypeConstraint &&
                    defaultConstructorConstraint &&
                    !unmanaged.Found &&
                    !allowsRefStruct &&
                    constraintResult.ValueTypeMarkerCount == 1 &&
                    constraintResult.AllValueTypeMarkersPlain)
                {
                    provenPrimaryConstraintKind = "struct";
                }
                else if (!valueTypeConstraint &&
                         !referenceTypeConstraint &&
                         !notNullConstraint &&
                         !unmanaged.Found &&
                         !allowsRefStruct &&
                         nullable.Complete &&
                         constraintResult.ValueTypeMarkerCount == 0 &&
                         constraints.Count == 0)
                {
                    provenPrimaryConstraintKind = "none";
                }
            }

            var model = new GenericParameterModel
            {
                Position = parameter.Index,
                Name = name,
                RawAttributes = rawAttributes,
                Variance = variance,
                ReferenceTypeConstraint = referenceTypeConstraint,
                NotNullableValueTypeConstraint = valueTypeConstraint,
                NotNullConstraint = !referenceTypeConstraint &&
                                    !valueTypeConstraint &&
                                    notNullConstraint,
                DefaultConstructorConstraint = defaultConstructorConstraint,
                AllowsRefStruct = allowsRefStruct,
                Nullability = nullable.Nullability,
                NullableFlags = nullable.Flags,
                HasUnmanagedAttribute = unmanaged.Found,
                TypeConstraints = constraints,
                ProvenPrimaryConstraintKind = provenPrimaryConstraintKind,
                Complete = errors.Count == 0 && constraints.All(constraint => constraint.Complete),
                Error = errors.Count == 0 ? null : string.Join("；", errors)
            };
            return new GenericParameterReadEvidence(model, declarationComplete);
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return new GenericParameterReadEvidence(
                new GenericParameterModel
                {
                    Position = fallbackPosition,
                    Name = $"!invalid{fallbackPosition}",
                    RawAttributes = 0,
                    Variance = "invalid",
                    Nullability = "invalid",
                    Complete = false,
                    Error = $"無法讀取泛型參數 metadata：{exception.GetType().Name}"
                },
                DeclarationComplete: false);
        }
    }

    private sealed record GenericTypeConstraintOwnerReadResult(
        IReadOnlyList<GenericTypeConstraintModel> Constraints,
        bool RowsComplete,
        bool PrimaryEvidenceComplete,
        int ValueTypeMarkerCount,
        bool AllValueTypeMarkersPlain);

    private readonly record struct GenericTypeConstraintReadEvidence(
        GenericTypeConstraintModel Constraint,
        bool PrimaryEvidenceComplete,
        bool IsValueTypeMarker,
        bool IsPlainValueTypeMarker);

    private static GenericTypeConstraintOwnerReadResult ReadGenericTypeConstraints(
        MetadataReader metadata,
        GenericParameterHandle parameterHandle,
        GenericParameter parameter,
        EntityHandle owner,
        ConstraintGenericContext genericContext,
        GenericMetadataOwnerBudget budget,
        List<string> parameterErrors)
    {
        var handles = parameter.GetConstraints();
        var constraints = new List<GenericTypeConstraintModel>(
            Math.Min(handles.Count, MaxGenericConstraintsPerParameter));
        var rowsComplete = handles.Count <= MaxGenericConstraintsPerParameter;
        var primaryEvidenceComplete = true;
        var valueTypeMarkerCount = 0;
        var allValueTypeMarkersPlain = true;
        foreach (var handle in handles)
        {
            if (constraints.Count >= MaxGenericConstraintsPerParameter)
            {
                budget.MarkTruncated();
                rowsComplete = false;
                AddGenericMetadataError(
                    parameterErrors,
                    $"型別 constraints 超過每個泛型參數的 {MaxGenericConstraintsPerParameter} 筆限制");
                break;
            }

            if (!budget.TryConsumeConstraintRow())
            {
                rowsComplete = false;
                AddGenericMetadataError(
                    parameterErrors,
                    "泛型 metadata 的 constraint row 預算已用盡");
                break;
            }

            var decoded = ReadGenericTypeConstraint(
                metadata,
                handle,
                parameterHandle,
                owner,
                genericContext);
            if (!budget.TryRetainConstraint(decoded.Constraint))
            {
                rowsComplete = false;
                AddGenericMetadataError(
                    parameterErrors,
                    "泛型 metadata 的 constraint 字元預算已用盡");
                break;
            }

            constraints.Add(decoded.Constraint);
            primaryEvidenceComplete &= decoded.PrimaryEvidenceComplete;
            if (decoded.IsValueTypeMarker)
            {
                valueTypeMarkerCount++;
                allValueTypeMarkersPlain &= decoded.IsPlainValueTypeMarker;
            }
        }

        rowsComplete &= constraints.Count == handles.Count;
        return new GenericTypeConstraintOwnerReadResult(
            constraints,
            rowsComplete,
            primaryEvidenceComplete && rowsComplete,
            valueTypeMarkerCount,
            allValueTypeMarkersPlain);
    }

    private static GenericTypeConstraintReadEvidence ReadGenericTypeConstraint(
        MetadataReader metadata,
        GenericParameterConstraintHandle handle,
        GenericParameterHandle expectedParameter,
        EntityHandle owner,
        ConstraintGenericContext genericContext)
    {
        try
        {
            var constraint = metadata.GetGenericParameterConstraint(handle);
            var decoded = ConstraintSignatureTypeProvider.Decode(
                metadata,
                constraint.Type,
                genericContext,
                MaxConstraintModifiers);
            var nullable = ReadEffectiveNullableFlag(metadata, constraint.GetCustomAttributes(), owner);
            var errors = new List<string>();
            if (constraint.Parameter != expectedParameter)
            {
                AddGenericMetadataError(errors, "constraint parent 與泛型參數不一致");
            }

            if (!decoded.Complete && decoded.Error is not null)
            {
                AddGenericMetadataError(errors, decoded.Error);
            }

            if (!nullable.Complete && nullable.Error is not null)
            {
                AddGenericMetadataError(errors, nullable.Error);
            }

            if (decoded.Kind is "unknown" or "unsupported")
            {
                AddGenericMetadataError(errors, "constraint kind 無法由目前 assembly metadata 證明");
            }

            var model = new GenericTypeConstraintModel
            {
                Type = decoded.Type,
                Kind = decoded.Kind,
                Nullability = nullable.Nullability,
                NullableFlags = nullable.Flags,
                RequiredModifiers = decoded.RequiredModifiers,
                OptionalModifiers = decoded.OptionalModifiers,
                Complete = errors.Count == 0,
                Error = errors.Count == 0 ? null : string.Join("；", errors)
            };
            var isValueTypeMarker = decoded.Kind == "value-type-marker";
            var hasNoModifiers = decoded.RequiredModifiers.IsEmpty &&
                                 decoded.OptionalModifiers.IsEmpty;
            var markerNullabilityComplete = !isValueTypeMarker ||
                                            nullable.Complete &&
                                            (nullable.Nullability is "oblivious" or "not-annotated") &&
                                            nullable.Flags.Count <= 1 &&
                                            nullable.Flags.All(flag => flag <= 2);
            var kindStructurallyUsable = decoded.Kind is
                "class" or "interface" or "type-parameter" or "value-type-marker" or "unknown";
            var disguisesValueTypeMarker = decoded.Type == "System.ValueType" &&
                                           decoded.Kind != "value-type-marker";
            var primaryEvidenceComplete =
                constraint.Parameter == expectedParameter &&
                decoded.Complete &&
                hasNoModifiers &&
                markerNullabilityComplete &&
                kindStructurallyUsable &&
                !disguisesValueTypeMarker;
            var isPlainValueTypeMarker =
                isValueTypeMarker &&
                decoded.Type == "System.ValueType" &&
                primaryEvidenceComplete;
            return new GenericTypeConstraintReadEvidence(
                model,
                primaryEvidenceComplete,
                isValueTypeMarker,
                isPlainValueTypeMarker);
        }
        catch (Exception exception) when (exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return new GenericTypeConstraintReadEvidence(
                new GenericTypeConstraintModel
                {
                    Type = "<invalid>",
                    Kind = "unsupported",
                    Nullability = "invalid",
                    Complete = false,
                    Error = $"無法讀取 constraint metadata：{exception.GetType().Name}"
                },
                PrimaryEvidenceComplete: false,
                IsValueTypeMarker: false,
                IsPlainValueTypeMarker: false);
        }
    }

    private static GenericParameterModel MarkGenericParameterIncomplete(
        GenericParameterModel parameter,
        string error) =>
        parameter with
        {
            Complete = false,
            Error = string.IsNullOrEmpty(parameter.Error) ? error : $"{parameter.Error}；{error}"
        };

    private static bool TryReadBoundedGenericParameterName(
        MetadataReader metadata,
        StringHandle handle,
        out string name)
    {
        if (handle.IsNil)
        {
            name = string.Empty;
            return true;
        }

        var bytes = metadata.GetBlobReader(handle);
        if (bytes.Length > MaxGenericParameterNameUtf8Bytes)
        {
            name = string.Empty;
            return false;
        }

        name = metadata.GetString(handle);
        return name.Length <= MaxGenericParameterNameCharacters;
    }

    private static void AddGenericMetadataError(List<string> errors, string error)
    {
        if (errors.Count < 8 && !errors.Contains(error, StringComparer.Ordinal))
        {
            errors.Add(error);
        }
    }

    private readonly record struct NullableMetadataResult(
        string Nullability,
        IReadOnlyList<byte> Flags,
        bool FromDirectAttribute,
        bool Complete,
        string? Error);

    internal readonly record struct AttributeByteResult(
        bool Found,
        IReadOnlyList<byte> Values,
        bool Complete,
        string? Error);

    private readonly record struct AttributeMarkerResult(
        bool Found,
        bool Complete,
        string? Error);

    internal static bool TryGetBoundedGenericAttributeTypeName(
        MetadataReader metadata,
        CustomAttribute attribute,
        out string? fullName,
        out string error)
    {
        EntityHandle typeHandle;
        switch (attribute.Constructor.Kind)
        {
            case HandleKind.MethodDefinition:
                typeHandle = metadata.GetMethodDefinition(
                    (MethodDefinitionHandle)attribute.Constructor).GetDeclaringType();
                break;
            case HandleKind.MemberReference:
                typeHandle = metadata.GetMemberReference(
                    (MemberReferenceHandle)attribute.Constructor).Parent;
                break;
            default:
                fullName = null;
                error = $"custom attribute constructor kind 不受支援：{attribute.Constructor.Kind}";
                return false;
        }

        return typeHandle.Kind switch
        {
            HandleKind.TypeDefinition => TryGetBoundedGenericAttributeTypeDefinitionName(
                metadata,
                (TypeDefinitionHandle)typeHandle,
                out fullName,
                out error),
            HandleKind.TypeReference => TryGetBoundedGenericAttributeTypeReferenceName(
                metadata,
                (TypeReferenceHandle)typeHandle,
                out fullName,
                out error),
            HandleKind.TypeSpecification => TryGetBoundedGenericAttributeTypeSpecificationName(
                metadata,
                (TypeSpecificationHandle)typeHandle,
                out fullName,
                out error),
            _ => FailGenericAttributeTypeName(
                $"custom attribute type handle kind 不受支援：{typeHandle.Kind}",
                out fullName,
                out error)
        };
    }

    private static bool TryGetBoundedGenericAttributeTypeSpecificationName(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        out string? fullName,
        out string error)
    {
        var decoded = ConstraintSignatureTypeProvider.Decode(
            metadata,
            handle,
            new ConstraintGenericContext(0, 0, AllowsMethodParameters: false),
            maxModifiers: MaxConstraintModifiers);
        if (!decoded.Complete)
        {
            return FailGenericAttributeTypeName(
                $"custom attribute TypeSpec 無法安全解析：{decoded.Error}",
                out fullName,
                out error);
        }

        fullName = decoded.Type;
        error = string.Empty;
        return true;
    }

    private static bool TryGetBoundedGenericAttributeTypeDefinitionName(
        MetadataReader metadata,
        TypeDefinitionHandle handle,
        out string? fullName,
        out string error)
    {
        var visited = new HashSet<TypeDefinitionHandle>();
        var segments = new List<string>();
        var current = handle;
        var namespaceName = string.Empty;
        var characters = 0;
        while (!current.IsNil)
        {
            if (MetadataTokens.GetRowNumber(current) > metadata.GetTableRowCount(TableIndex.TypeDef) ||
                !visited.Add(current) ||
                visited.Count > MaxGenericAttributeTypeNameDepth)
            {
                return FailGenericAttributeTypeName(
                    "custom attribute TypeDef 宣告鏈循環、過深或超出 metadata 範圍",
                    out fullName,
                    out error);
            }

            var definition = metadata.GetTypeDefinition(current);
            if (!TryReadBoundedGenericAttributeName(metadata, definition.Name, out var name) ||
                !TryReserveGenericAttributeTypeName(name, segments.Count > 0, ref characters))
            {
                return FailGenericAttributeTypeName(
                    "custom attribute TypeDef name 超過長度限制",
                    out fullName,
                    out error);
            }

            segments.Add(name);
            var declaringType = definition.GetDeclaringType();
            if (declaringType.IsNil)
            {
                if (!TryReadBoundedGenericAttributeName(metadata, definition.Namespace, out namespaceName) ||
                    (!string.IsNullOrEmpty(namespaceName) &&
                     !TryReserveGenericAttributeTypeName(namespaceName, true, ref characters)))
                {
                    return FailGenericAttributeTypeName(
                        "custom attribute TypeDef namespace 超過長度限制",
                        out fullName,
                        out error);
                }

                break;
            }

            current = declaringType;
        }

        segments.Reverse();
        var nestedName = string.Join('.', segments);
        fullName = string.IsNullOrEmpty(namespaceName) ? nestedName : $"{namespaceName}.{nestedName}";
        error = string.Empty;
        return true;
    }

    private static bool TryGetBoundedGenericAttributeTypeReferenceName(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        out string? fullName,
        out string error)
    {
        var visited = new HashSet<TypeReferenceHandle>();
        var segments = new List<string>();
        var current = handle;
        var namespaceName = string.Empty;
        var characters = 0;
        while (!current.IsNil)
        {
            if (MetadataTokens.GetRowNumber(current) > metadata.GetTableRowCount(TableIndex.TypeRef) ||
                !visited.Add(current) ||
                visited.Count > MaxGenericAttributeTypeNameDepth)
            {
                return FailGenericAttributeTypeName(
                    "custom attribute TypeRef scope 鏈循環、過深或超出 metadata 範圍",
                    out fullName,
                    out error);
            }

            var reference = metadata.GetTypeReference(current);
            if (!TryReadBoundedGenericAttributeName(metadata, reference.Name, out var name) ||
                !TryReserveGenericAttributeTypeName(name, segments.Count > 0, ref characters))
            {
                return FailGenericAttributeTypeName(
                    "custom attribute TypeRef name 超過長度限制",
                    out fullName,
                    out error);
            }

            segments.Add(name);
            if (reference.ResolutionScope.Kind != HandleKind.TypeReference)
            {
                if (!TryReadBoundedGenericAttributeName(metadata, reference.Namespace, out namespaceName) ||
                    (!string.IsNullOrEmpty(namespaceName) &&
                     !TryReserveGenericAttributeTypeName(namespaceName, true, ref characters)))
                {
                    return FailGenericAttributeTypeName(
                        "custom attribute TypeRef namespace 超過長度限制",
                        out fullName,
                        out error);
                }

                break;
            }

            current = (TypeReferenceHandle)reference.ResolutionScope;
        }

        segments.Reverse();
        var nestedName = string.Join('.', segments);
        fullName = string.IsNullOrEmpty(namespaceName) ? nestedName : $"{namespaceName}.{nestedName}";
        error = string.Empty;
        return true;
    }

    private static bool TryReadBoundedGenericAttributeName(
        MetadataReader metadata,
        StringHandle handle,
        out string name)
    {
        if (handle.IsNil)
        {
            name = string.Empty;
            return true;
        }

        if (metadata.GetBlobReader(handle).Length > MaxGenericAttributeTypeNameUtf8Bytes)
        {
            name = string.Empty;
            return false;
        }

        name = metadata.GetString(handle);
        return name.Length <= MaxGenericAttributeTypeNameCharacters;
    }

    private static bool TryReserveGenericAttributeTypeName(
        string segment,
        bool needsSeparator,
        ref int characters)
    {
        var required = (long)segment.Length + (needsSeparator ? 1 : 0);
        if (required > MaxGenericAttributeTypeNameCharacters - characters)
        {
            return false;
        }

        characters += (int)required;
        return true;
    }

    private static bool FailGenericAttributeTypeName(
        string failure,
        out string? fullName,
        out string error)
    {
        fullName = null;
        error = failure;
        return false;
    }

    private static NullableMetadataResult ReadEffectiveNullableFlag(
        MetadataReader metadata,
        CustomAttributeHandleCollection directAttributes,
        EntityHandle owner)
    {
        var direct = ReadNullableAttributeFlag(metadata, directAttributes);
        if (direct.Found)
        {
            return ToNullableMetadataResult(direct, fromDirectAttribute: true);
        }

        if (!direct.Complete)
        {
            return new NullableMetadataResult("invalid", direct.Values, true, false, direct.Error);
        }

        var context = ReadGenericNullableContext(metadata, owner);
        return context.Found
            ? ToNullableMetadataResult(context)
            : context.Complete
                ? new NullableMetadataResult("oblivious", [], false, true, null)
                : new NullableMetadataResult("invalid", context.Values, false, false, context.Error);
    }

    private static NullableMetadataResult ToNullableMetadataResult(
        AttributeByteResult result,
        bool fromDirectAttribute = false)
    {
        if (!result.Complete || result.Values.Count == 0 || result.Values.Any(value => value > 2))
        {
            return new NullableMetadataResult(
                "invalid",
                result.Values,
                fromDirectAttribute,
                false,
                result.Error ?? "nullable flag 不在 0、1、2 範圍內");
        }

        var nullability = result.Values[0] switch
        {
            0 => "oblivious",
            1 => "not-annotated",
            2 => "annotated",
            _ => "invalid"
        };
        return new NullableMetadataResult(
            nullability,
            result.Values,
            fromDirectAttribute,
            true,
            null);
    }

    private static AttributeByteResult ReadGenericNullableContext(
        MetadataReader metadata,
        EntityHandle owner)
    {
        if (owner.Kind == HandleKind.MethodDefinition)
        {
            var method = metadata.GetMethodDefinition((MethodDefinitionHandle)owner);
            var methodContext = ReadSingleByteAttributeStrict(
                metadata,
                method.GetCustomAttributes(),
                "System.Runtime.CompilerServices.NullableContextAttribute");
            if (methodContext.Found || !methodContext.Complete)
            {
                return methodContext;
            }

            owner = method.GetDeclaringType();
        }

        var visited = new HashSet<TypeDefinitionHandle>();
        while (owner.Kind == HandleKind.TypeDefinition && !((TypeDefinitionHandle)owner).IsNil)
        {
            var typeHandle = (TypeDefinitionHandle)owner;
            if (!visited.Add(typeHandle) || visited.Count > 64)
            {
                return new AttributeByteResult(
                    false,
                    [],
                    false,
                    "nullable context 的 outer type 鏈結循環或過深");
            }

            var definition = metadata.GetTypeDefinition(typeHandle);
            var typeContext = ReadSingleByteAttributeStrict(
                metadata,
                definition.GetCustomAttributes(),
                "System.Runtime.CompilerServices.NullableContextAttribute");
            if (typeContext.Found || !typeContext.Complete)
            {
                return typeContext;
            }

            owner = definition.GetDeclaringType();
        }

        return new AttributeByteResult(false, [], true, null);
    }

    internal static AttributeByteResult ReadNullableAttributeFlag(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes)
    {
        if (attributes.Count > MaxGenericCustomAttributesPerTarget)
        {
            return new AttributeByteResult(
                false,
                [],
                false,
                $"custom attributes 超過 {MaxGenericCustomAttributesPerTarget} 筆限制");
        }

        AttributeByteResult? result = null;
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                if (!TryGetBoundedGenericAttributeTypeName(
                        metadata,
                        attribute,
                        out var attributeType,
                        out var typeError))
                {
                    return new AttributeByteResult(
                        result?.Found ?? false,
                        result?.Values ?? [],
                        false,
                        typeError);
                }

                if (attributeType != "System.Runtime.CompilerServices.NullableAttribute")
                {
                    continue;
                }

                if (result.HasValue)
                {
                    return new AttributeByteResult(
                        true,
                        result.Value.Values,
                        false,
                        "NullableAttribute 重複");
                }

                var reader = metadata.GetBlobReader(attribute.Value);
                if (reader.ReadUInt16() != 1)
                {
                    return new AttributeByteResult(true, [], false, "NullableAttribute prolog 無效");
                }

                IReadOnlyList<byte> values;
                if (reader.RemainingBytes == 3)
                {
                    values = [reader.ReadByte()];
                }
                else
                {
                    if (reader.RemainingBytes < 6)
                    {
                        return new AttributeByteResult(true, [], false, "NullableAttribute payload 過短");
                    }

                    var count = reader.ReadInt32();
                    if (count <= 0 || count > 256 || reader.RemainingBytes != count + 2)
                    {
                        return new AttributeByteResult(true, [], false, "NullableAttribute flags 長度無效或超過限制");
                    }

                    values = reader.ReadBytes(count);
                }

                result = reader.ReadUInt16() == 0 && reader.RemainingBytes == 0
                    ? new AttributeByteResult(true, values, true, null)
                    : new AttributeByteResult(true, values, false, "NullableAttribute named arguments 無效");
                if (!result.Value.Complete)
                {
                    return result.Value;
                }
            }
            catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
            {
                return new AttributeByteResult(
                    result?.Found ?? false,
                    result?.Values ?? [],
                    false,
                    $"NullableAttribute 無法解碼：{exception.GetType().Name}");
            }
        }

        return result ?? new AttributeByteResult(false, [], true, null);
    }

    private static AttributeByteResult ReadSingleByteAttributeStrict(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes,
        string fullName)
    {
        if (attributes.Count > MaxGenericCustomAttributesPerTarget)
        {
            return new AttributeByteResult(
                false,
                [],
                false,
                $"custom attributes 超過 {MaxGenericCustomAttributesPerTarget} 筆限制");
        }

        AttributeByteResult? result = null;
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                if (!TryGetBoundedGenericAttributeTypeName(
                        metadata,
                        attribute,
                        out var attributeType,
                        out var typeError))
                {
                    return new AttributeByteResult(
                        result?.Found ?? false,
                        result?.Values ?? [],
                        false,
                        typeError);
                }

                if (attributeType != fullName)
                {
                    continue;
                }

                if (result.HasValue)
                {
                    return new AttributeByteResult(
                        true,
                        result.Value.Values,
                        false,
                        $"{fullName} 重複");
                }

                var reader = metadata.GetBlobReader(attribute.Value);
                if (reader.ReadUInt16() != 1 || reader.RemainingBytes != 3)
                {
                    return new AttributeByteResult(true, [], false, $"{fullName} payload 無效");
                }

                var value = reader.ReadByte();
                result = reader.ReadUInt16() == 0 && reader.RemainingBytes == 0
                    ? new AttributeByteResult(true, [value], true, null)
                    : new AttributeByteResult(true, [value], false, $"{fullName} named arguments 無效");
                if (!result.Value.Complete)
                {
                    return result.Value;
                }
            }
            catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
            {
                return new AttributeByteResult(
                    result?.Found ?? false,
                    result?.Values ?? [],
                    false,
                    $"{fullName} 無法解碼：{exception.GetType().Name}");
            }
        }

        return result ?? new AttributeByteResult(false, [], true, null);
    }

    private static AttributeMarkerResult ReadMarkerAttribute(
        MetadataReader metadata,
        CustomAttributeHandleCollection attributes,
        string fullName)
    {
        if (attributes.Count > MaxGenericCustomAttributesPerTarget)
        {
            return new AttributeMarkerResult(
                false,
                false,
                $"custom attributes 超過 {MaxGenericCustomAttributesPerTarget} 筆限制");
        }

        AttributeMarkerResult? result = null;
        foreach (var handle in attributes)
        {
            try
            {
                var attribute = metadata.GetCustomAttribute(handle);
                if (!TryGetBoundedGenericAttributeTypeName(
                        metadata,
                        attribute,
                        out var attributeType,
                        out var typeError))
                {
                    return new AttributeMarkerResult(result?.Found ?? false, false, typeError);
                }

                if (attributeType != fullName)
                {
                    continue;
                }

                if (result.HasValue)
                {
                    return new AttributeMarkerResult(true, false, $"{fullName} 重複");
                }

                var reader = metadata.GetBlobReader(attribute.Value);
                result = reader.ReadUInt16() == 1 && reader.ReadUInt16() == 0 && reader.RemainingBytes == 0
                    ? new AttributeMarkerResult(true, true, null)
                    : new AttributeMarkerResult(true, false, $"{fullName} payload 無效");
                if (!result.Value.Complete)
                {
                    return result.Value;
                }
            }
            catch (Exception exception) when (exception is BadImageFormatException or ArgumentException)
            {
                return new AttributeMarkerResult(
                    result?.Found ?? false,
                    false,
                    $"{fullName} 無法解碼：{exception.GetType().Name}");
            }
        }

        return result ?? new AttributeMarkerResult(false, true, null);
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
                    signature.ParameterTypes.Select(type => type.Text).ToArray());
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

internal readonly record struct SignatureCustomModifier(
    string Type,
    bool IsRequired,
    EntityHandle NominalHandle,
    bool IsTrustedFunctionPointerCallingConvention);

internal readonly record struct SignatureTypeParameterSlot(
    TypeDefinitionHandle Owner,
    int Index);

internal readonly record struct SignatureMethodParameterSlot(
    MethodDefinitionHandle Owner,
    int Index);

internal sealed record SignatureFunctionPointer(
    SignatureHeader Header,
    int RequiredParameterCount,
    int GenericParameterCount,
    SignatureTypeName ReturnType,
    ImmutableArray<SignatureTypeName> ParameterTypes);

internal readonly record struct SignatureGenericContext(
    ImmutableArray<SignatureTypeName> TypeArguments,
    TypeDefinitionHandle TypeParameterOwner,
    int TypeParameterCount,
    MethodDefinitionHandle MethodParameterOwner,
    int MethodParameterCount)
{
    public static SignatureGenericContext ForSubstitution(
        ImmutableArray<SignatureTypeName> typeArguments) =>
        new(typeArguments, default, 0, default, 0);

    public static SignatureGenericContext ForOwner(
        TypeDefinitionHandle owner,
        int typeParameterCount) =>
        new(default, owner, typeParameterCount, default, 0);

    public static SignatureGenericContext ForCaller(
        TypeDefinitionHandle typeParameterOwner,
        int typeParameterCount,
        MethodDefinitionHandle methodParameterOwner,
        int methodParameterCount) =>
        new(
            default,
            typeParameterOwner,
            typeParameterCount,
            methodParameterOwner,
            methodParameterCount);
}

internal sealed record SignatureTypeName(
    string Text,
    ImmutableArray<SignatureCustomModifier> OuterCustomModifiers,
    bool HasNestedCustomModifiers,
    bool IsRestrictedGenericArgument,
    EntityHandle NominalHandle = default,
    byte RawTypeKind = 0,
    SignatureTypeKind SignatureKind = SignatureTypeKind.Unknown,
    bool IsExactNamedType = false,
    PrimitiveTypeCode? PrimitiveType = null,
    bool IsByReference = false,
    ImmutableArray<SignatureTypeName> GenericArguments = default,
    bool IsCanonicalGenericInstantiation = false,
    EntityHandle GenericDefinitionHandle = default,
    byte GenericDefinitionRawTypeKind = 0,
    SignatureTypeKind GenericDefinitionSignatureKind = SignatureTypeKind.Unknown,
    string? GenericDefinitionText = null,
    SignatureTypeParameterSlot? TypeParameterSlot = null,
    SignatureMethodParameterSlot? MethodParameterSlot = null,
    SignatureTypeName? ArrayElementType = null,
    int ArrayRank = 0,
    ImmutableArray<int> ArraySizes = default,
    ImmutableArray<int> ArrayLowerBounds = default,
    SignatureTypeName? SzArrayElementType = null,
    SignatureTypeName? ByReferenceElementType = null,
    SignatureTypeName? PointerElementType = null,
    SignatureFunctionPointer? FunctionPointerSignature = null,
    bool HasPinnedQualifier = false,
    bool IsUnsupported = false,
    bool IsTrustedFunctionPointerCallingConvention = false)
{
    public SignatureTypeName(string text)
        : this(text, [], false, false)
    {
    }

    public static implicit operator string(SignatureTypeName value) => value.Text;

    public static implicit operator SignatureTypeName(string value) => new(value);

    public override string ToString() => Text;
}

internal sealed class SignatureTypeNameProvider : ISignatureTypeProvider<SignatureTypeName, object?>
{
    private static readonly IReadOnlySet<string> SupportedFunctionPointerCallingConventions =
        new HashSet<string>(StringComparer.Ordinal)
        {
            "Cdecl",
            "Fastcall",
            "MemberFunction",
            "Stdcall",
            "SuppressGCTransition",
            "Swift",
            "Thiscall"
        };

    public static readonly SignatureTypeNameProvider Instance = new();

    public SignatureTypeName GetArrayType(SignatureTypeName elementType, ArrayShape shape) =>
        Wrap(
            $"{elementType.Text}[{new string(',', Math.Max(shape.Rank - 1, 0))}]",
            elementType,
            isRestrictedGenericArgument: false) with
        {
            ArrayElementType = elementType,
            ArrayRank = shape.Rank,
            ArraySizes = shape.Sizes,
            ArrayLowerBounds = shape.LowerBounds,
            // ELEMENT_TYPE_ARRAY rank 1 denotes CLR T[*], which C# cannot name.
            // SZARRAY is represented separately by GetSZArrayType and remains T[].
            IsUnsupported = elementType.IsUnsupported || shape.Rank == 1
        };

    public SignatureTypeName GetByReferenceType(SignatureTypeName elementType) =>
        Wrap($"ref {elementType.Text}", elementType, isRestrictedGenericArgument: true) with
        {
            IsByReference = true,
            ByReferenceElementType = elementType
        };

    public SignatureTypeName GetFunctionPointerType(MethodSignature<SignatureTypeName> signature)
    {
        var hasPinnedQualifier = signature.ReturnType.HasPinnedQualifier ||
                                 signature.ParameterTypes.Any(
                                     parameter => parameter.HasPinnedQualifier);
        if (signature.Header.Kind != SignatureKind.Method ||
            signature.Header.IsGeneric ||
            signature.Header.IsInstance ||
            signature.Header.HasExplicitThis ||
            signature.GenericParameterCount != 0 ||
            signature.RequiredParameterCount != signature.ParameterTypes.Length ||
            signature.ReturnType.IsUnsupported ||
            signature.ReturnType.Text is "ref void" or "TypedReference" or "ref TypedReference" ||
            signature.ReturnType.HasNestedCustomModifiers ||
            signature.ParameterTypes.Any(parameter =>
                parameter.IsUnsupported ||
                parameter.Text is "void" or "ref void" ||
                parameter.HasNestedCustomModifiers ||
                parameter.OuterCustomModifiers.Length > 0))
        {
            return Unsupported();
        }

        var conventions = new List<string>();
        var prefix = signature.Header.CallingConvention switch
        {
            SignatureCallingConvention.Default => " managed",
            SignatureCallingConvention.Unmanaged => " unmanaged",
            SignatureCallingConvention.CDecl => AddConvention("Cdecl"),
            SignatureCallingConvention.StdCall => AddConvention("Stdcall"),
            SignatureCallingConvention.ThisCall => AddConvention("Thiscall"),
            SignatureCallingConvention.FastCall => AddConvention("Fastcall"),
            _ => string.Empty
        };
        if (prefix.Length == 0)
        {
            return Unsupported();
        }

        const string callConventionPrefix = "System.Runtime.CompilerServices.CallConv";
        // Metadata stores the outermost modifier first, which is the reverse of
        // the source-level unmanaged[...] convention order.
        foreach (var modifier in signature.ReturnType.OuterCustomModifiers.Reverse())
        {
            if (modifier.IsRequired ||
                !modifier.IsTrustedFunctionPointerCallingConvention ||
                modifier.NominalHandle.Kind != HandleKind.TypeReference ||
                !modifier.Type.StartsWith(callConventionPrefix, StringComparison.Ordinal))
            {
                return Unsupported();
            }

            var convention = modifier.Type[callConventionPrefix.Length..];
            if (!SupportedFunctionPointerCallingConventions.Contains(convention))
            {
                return Unsupported();
            }

            conventions.Add(convention);
        }

        if (prefix == " managed" && conventions.Count > 0)
        {
            return Unsupported();
        }

        if (prefix == " unmanaged" && conventions.Count > 0)
        {
            prefix += $"[{string.Join(", ", conventions)}]";
        }

        return new SignatureTypeName(
            $"delegate*{prefix}<" +
            string.Join(", ", signature.ParameterTypes.Select(parameter => parameter.Text).Append(signature.ReturnType.Text)) +
            ">",
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: true,
            FunctionPointerSignature: new SignatureFunctionPointer(
                signature.Header,
                signature.RequiredParameterCount,
                signature.GenericParameterCount,
                signature.ReturnType,
                signature.ParameterTypes),
            HasPinnedQualifier: hasPinnedQualifier);

        SignatureTypeName Unsupported() =>
            new SignatureTypeName("nint") with
            {
                HasPinnedQualifier = hasPinnedQualifier,
                IsUnsupported = true
            };

        string AddConvention(string convention)
        {
            conventions.Add(convention);
            return " unmanaged";
        }
    }

    public SignatureTypeName GetGenericInstantiation(
        SignatureTypeName genericType,
        ImmutableArray<SignatureTypeName> typeArguments)
    {
        var hasPinnedQualifier = genericType.HasPinnedQualifier ||
                                 typeArguments.Any(type => type.HasPinnedQualifier);
        if (genericType.IsRestrictedGenericArgument ||
            genericType.IsUnsupported ||
            typeArguments.Any(type =>
                type.IsRestrictedGenericArgument || type.IsUnsupported))
        {
            return new SignatureTypeName("nint") with
            {
                HasPinnedQualifier = hasPinnedQualifier,
                IsUnsupported = true
            };
        }

        var segments = genericType.Text.Split('.');
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
                $"{segment[..backtick]}<{string.Join(", ", typeArguments.Skip(argumentIndex).Take(arity).Select(type => type.Text))}>";
            argumentIndex += arity;
        }

        return foundArity && argumentIndex == typeArguments.Length
            ? CreateGenericInstantiation(
                string.Join('.', rendered),
                genericType,
                typeArguments,
                isCanonical: true)
            : FormatLegacyGenericInstantiation(genericType, typeArguments);
    }

    public SignatureTypeName GetGenericMethodParameter(object? genericContext, int index)
    {
        if (genericContext is SignatureGenericContext context &&
            !context.MethodParameterOwner.IsNil &&
            index >= 0 &&
            index < context.MethodParameterCount)
        {
            return new SignatureTypeName(
                $"!!{index}",
                [],
                HasNestedCustomModifiers: false,
                IsRestrictedGenericArgument: false,
                MethodParameterSlot: new SignatureMethodParameterSlot(
                    context.MethodParameterOwner,
                    index));
        }

        return new SignatureTypeName($"!!{index}");
    }

    public SignatureTypeName GetGenericTypeParameter(object? genericContext, int index)
    {
        if (genericContext is SignatureGenericContext context)
        {
            if (!context.TypeArguments.IsDefault &&
                index >= 0 &&
                index < context.TypeArguments.Length)
            {
                return context.TypeArguments[index];
            }

            if (context.TypeArguments.IsDefault &&
                !context.TypeParameterOwner.IsNil &&
                index >= 0 &&
                index < context.TypeParameterCount)
            {
                return new SignatureTypeName(
                    $"!{index}",
                    [],
                    HasNestedCustomModifiers: false,
                    IsRestrictedGenericArgument: false,
                    TypeParameterSlot: new SignatureTypeParameterSlot(
                        context.TypeParameterOwner,
                        index));
            }
        }

        return new SignatureTypeName($"!{index}");
    }

    public SignatureTypeName GetModifiedType(
        SignatureTypeName modifier,
        SignatureTypeName unmodifiedType,
        bool isRequired) =>
        unmodifiedType with
        {
            OuterCustomModifiers = unmodifiedType.OuterCustomModifiers.Add(
                new SignatureCustomModifier(
                    modifier.Text,
                    isRequired,
                    modifier.NominalHandle,
                    modifier.IsTrustedFunctionPointerCallingConvention)),
            NominalHandle = default,
            RawTypeKind = 0,
            SignatureKind = SignatureTypeKind.Unknown,
            IsExactNamedType = false
        };

    public SignatureTypeName GetPinnedType(SignatureTypeName elementType) =>
        elementType with { HasPinnedQualifier = true };

    public SignatureTypeName GetPointerType(SignatureTypeName elementType) =>
        Wrap($"{elementType.Text}*", elementType, isRestrictedGenericArgument: true) with
        {
            PointerElementType = elementType
        };

    public SignatureTypeName GetPrimitiveType(PrimitiveTypeCode typeCode)
    {
        var text = typeCode switch
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
        return new SignatureTypeName(
            text,
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: typeCode == PrimitiveTypeCode.TypedReference,
            PrimitiveType: typeCode);
    }

    public SignatureTypeName GetSZArrayType(SignatureTypeName elementType) =>
        Wrap($"{elementType.Text}[]", elementType, isRestrictedGenericArgument: false) with
        {
            SzArrayElementType = elementType
        };

    public SignatureTypeName GetTypeFromDefinition(
        MetadataReader reader,
        TypeDefinitionHandle handle,
        byte rawTypeKind)
    {
        var definition = reader.GetTypeDefinition(handle);
        var name = reader.GetString(definition.Name);
        var declaringType = definition.GetDeclaringType();
        var namespaceName = reader.GetString(definition.Namespace);
        var text = !declaringType.IsNil
            ? $"{GetTypeFromDefinition(reader, declaringType, rawTypeKind).Text}.{name}"
            : string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";
        return new SignatureTypeName(
            text,
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: false,
            handle,
            rawTypeKind,
            reader.ResolveSignatureTypeKind(handle, rawTypeKind),
            IsExactNamedType: true);
    }

    private static bool IsTrustedFunctionPointerCallingConvention(
        MetadataReader reader,
        TypeReference reference,
        string name,
        string namespaceName)
    {
        if (namespaceName != "System.Runtime.CompilerServices" ||
            !name.StartsWith("CallConv", StringComparison.Ordinal) ||
            reference.ResolutionScope.Kind != HandleKind.AssemblyReference)
        {
            return false;
        }

        var assembly = reader.GetAssemblyReference(
            (AssemblyReferenceHandle)reference.ResolutionScope);
        return ManagedSymbolReader.IsTrustedFrameworkAssembly(
            reader,
            reader.GetString(assembly.Name),
            assembly.PublicKeyOrToken,
            assembly.Culture,
            assembly.Flags);
    }

    public SignatureTypeName GetTypeFromReference(
        MetadataReader reader,
        TypeReferenceHandle handle,
        byte rawTypeKind)
    {
        var reference = reader.GetTypeReference(handle);
        var name = reader.GetString(reference.Name);
        var namespaceName = reader.GetString(reference.Namespace);
        var text = reference.ResolutionScope.Kind == HandleKind.TypeReference
            ? $"{GetTypeFromReference(reader, (TypeReferenceHandle)reference.ResolutionScope, rawTypeKind).Text}.{name}"
            : string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";
        return new SignatureTypeName(
            text,
            [],
            HasNestedCustomModifiers: false,
            IsRestrictedGenericArgument: false,
            handle,
            rawTypeKind,
            reader.ResolveSignatureTypeKind(handle, rawTypeKind),
            IsExactNamedType: true,
            IsTrustedFunctionPointerCallingConvention:
                IsTrustedFunctionPointerCallingConvention(reader, reference, name, namespaceName));
    }

    private static SignatureTypeName FormatLegacyGenericInstantiation(
        SignatureTypeName genericType,
        ImmutableArray<SignatureTypeName> typeArguments) =>
        CreateGenericInstantiation(
            $"{StripQualifiedArity(genericType.Text)}<{string.Join(", ", typeArguments.Select(type => type.Text))}>",
            genericType,
            typeArguments,
            isCanonical: false);

    private static SignatureTypeName CreateGenericInstantiation(
        string text,
        SignatureTypeName genericType,
        ImmutableArray<SignatureTypeName> typeArguments,
        bool isCanonical)
    {
        var hasExactDefinition = isCanonical &&
                                 genericType.IsExactNamedType &&
                                 genericType.NominalHandle.Kind is
                                     HandleKind.TypeDefinition or HandleKind.TypeReference;
        return new SignatureTypeName(
            text,
            [],
            HasAnyCustomModifiers(genericType) || typeArguments.Any(HasAnyCustomModifiers),
            IsRestrictedGenericArgument: false,
            GenericArguments: typeArguments,
            IsCanonicalGenericInstantiation: isCanonical,
            GenericDefinitionHandle: hasExactDefinition ? genericType.NominalHandle : default,
            GenericDefinitionRawTypeKind: hasExactDefinition ? genericType.RawTypeKind : (byte)0,
            GenericDefinitionSignatureKind: hasExactDefinition
                ? genericType.SignatureKind
                : SignatureTypeKind.Unknown,
            GenericDefinitionText: hasExactDefinition ? genericType.Text : null,
            HasPinnedQualifier: genericType.HasPinnedQualifier ||
                                typeArguments.Any(type => type.HasPinnedQualifier),
            IsUnsupported: genericType.IsUnsupported ||
                           typeArguments.Any(type => type.IsUnsupported));
    }

    private static SignatureTypeName Wrap(
        string text,
        SignatureTypeName elementType,
        bool isRestrictedGenericArgument) =>
        new(
            text,
            [],
            HasAnyCustomModifiers(elementType),
            isRestrictedGenericArgument,
            HasPinnedQualifier: elementType.HasPinnedQualifier,
            IsUnsupported: elementType.IsUnsupported);

    private static bool HasAnyCustomModifiers(SignatureTypeName type) =>
        type.HasNestedCustomModifiers || type.OuterCustomModifiers.Length > 0;

    private static string StripQualifiedArity(string name) =>
        string.Join('.', name.Split('.').Select(StripArity));

    private static string StripArity(string name)
    {
        var backtick = name.IndexOf('`', StringComparison.Ordinal);
        return backtick < 0 ? name : name[..backtick];
    }

    public SignatureTypeName GetTypeFromSpecification(
        MetadataReader reader,
        object? genericContext,
        TypeSpecificationHandle handle,
        byte rawTypeKind)
    {
        var decoded = reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
        return decoded with
        {
            NominalHandle = default,
            RawTypeKind = 0,
            SignatureKind = SignatureTypeKind.Unknown,
            IsExactNamedType = false,
            PrimitiveType = null
        };
    }
}

internal sealed record ConstraintSignatureType(
    string Type,
    string Kind,
    ImmutableArray<string> RequiredModifiers,
    ImmutableArray<string> OptionalModifiers,
    bool Complete,
    string? Error);

internal readonly record struct ConstraintGenericContext(
    int TypeParameterCount,
    int MethodParameterCount,
    bool AllowsMethodParameters,
    ImmutableArray<int> TypeParameterPositions = default,
    ImmutableArray<int> MethodParameterPositions = default,
    bool TypeParameterPositionsComplete = true,
    bool MethodParameterPositionsComplete = true)
{
    public bool ContainsTypeParameter(int index) =>
        TypeParameterPositionsComplete &&
        index >= 0 &&
        index < TypeParameterCount &&
        (TypeParameterPositions.IsDefault || TypeParameterPositions.Contains(index));

    public bool ContainsMethodParameter(int index) =>
        AllowsMethodParameters &&
        MethodParameterPositionsComplete &&
        index >= 0 &&
        index < MethodParameterCount &&
        (MethodParameterPositions.IsDefault || MethodParameterPositions.Contains(index));
}

// GenericParamConstraint 的 TypeSpec 需保留 modreq/modopt；一般 signature rendering 仍維持原樣。
internal sealed class ConstraintSignatureTypeProvider : ISignatureTypeProvider<ConstraintSignatureType, object?>
{
    private const int MaxSignatureBytes = 256;
    private const int MaxSignatureNodes = 256;
    private const int MaxSignatureDepth = 64;
    private const int MaxGenericTypeArguments = 64;
    private const int MaxArrayRank = 32;
    private const int MaxAggregateSignatureBytes = 4_096;
    private const int MaxRenderedTypeCharacters = 8_192;
    private const int MaxMetadataNameUtf8Bytes = MaxRenderedTypeCharacters * 4;
    private const int MaxQualifiedNameDepth = 64;
    private const int MaxRetainedModifierCharacters = 32_768;
    private const int MaxRetainedModifierUtf8Bytes = 32_768;

    private readonly int _maxModifiers;
    private readonly HashSet<TypeSpecificationHandle> _activeTypeSpecifications = [];
    private readonly HashSet<TypeSpecificationHandle> _validatedTypeSpecifications = [];
    private int _nodes;
    private int _validatedNodes;
    private int _signatureBytes;
    private int _retainedModifierCharacters;
    private int _validatedModifierUtf8Bytes;

    internal ConstraintSignatureTypeProvider(int maxModifiers)
    {
        _maxModifiers = maxModifiers;
    }

    public static ConstraintSignatureType Decode(
        MetadataReader metadata,
        EntityHandle handle,
        ConstraintGenericContext genericContext,
        int maxModifiers)
    {
        var provider = new ConstraintSignatureTypeProvider(maxModifiers);
        return handle.Kind switch
        {
            HandleKind.TypeDefinition => provider.GetTypeFromDefinition(
                metadata,
                (TypeDefinitionHandle)handle,
                0),
            HandleKind.TypeReference => provider.GetTypeFromReference(
                metadata,
                (TypeReferenceHandle)handle,
                0),
            HandleKind.TypeSpecification => provider.DecodeTypeSpecification(
                metadata,
                (TypeSpecificationHandle)handle,
                genericContext),
            _ => provider.Track(Invalid(
                "<unsupported>",
                "unsupported",
                $"不支援的 constraint handle kind：{handle.Kind}"))
        };
    }

    private ConstraintSignatureType DecodeTypeSpecification(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        ConstraintGenericContext genericContext)
    {
        if (!IsValidTypeSpecificationHandle(metadata, handle))
        {
            return Track(Invalid(
                "<unsupported>",
                "unsupported",
                "constraint TypeSpec handle 超出 metadata 範圍"));
        }

        if (!_activeTypeSpecifications.Add(handle))
        {
            return Track(Invalid("<unsupported>", "unsupported", "constraint TypeSpec 參照循環或過深"));
        }

        try
        {
            if (_activeTypeSpecifications.Count > MaxSignatureDepth)
            {
                return Track(Invalid(
                    "<unsupported>",
                    "unsupported",
                    "constraint TypeSpec 參照循環或過深"));
            }

            if (!_validatedTypeSpecifications.Contains(handle) &&
                !TryValidateTypeSpecificationBody(metadata, handle, genericContext, out var validationError))
            {
                return Track(Invalid("<unsupported>", "unsupported", validationError));
            }

            _validatedTypeSpecifications.Add(handle);
            var specification = metadata.GetTypeSpecification(handle);
            return specification.DecodeSignature(this, genericContext);
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            return Track(Invalid(
                "<unsupported>",
                "unsupported",
                $"constraint TypeSpec signature 無法解碼：{exception.GetType().Name}"));
        }
        finally
        {
            _activeTypeSpecifications.Remove(handle);
        }
    }

    private bool TryValidateReferencedTypeSpecification(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        ConstraintGenericContext genericContext,
        out string error)
    {
        if (!IsValidTypeSpecificationHandle(metadata, handle))
        {
            error = "constraint TypeSpec handle 超出 metadata 範圍";
            return false;
        }

        if (_activeTypeSpecifications.Contains(handle))
        {
            error = "constraint TypeSpec 參照循環或過深";
            return false;
        }

        if (_validatedTypeSpecifications.Contains(handle))
        {
            error = string.Empty;
            return true;
        }

        if (_activeTypeSpecifications.Count >= MaxSignatureDepth ||
            !_activeTypeSpecifications.Add(handle))
        {
            error = "constraint TypeSpec 參照循環或過深";
            return false;
        }

        try
        {
            if (!TryValidateTypeSpecificationBody(metadata, handle, genericContext, out error))
            {
                return false;
            }

            _validatedTypeSpecifications.Add(handle);
            return true;
        }
        finally
        {
            _activeTypeSpecifications.Remove(handle);
        }
    }

    private bool TryValidateTypeSpecificationBody(
        MetadataReader metadata,
        TypeSpecificationHandle handle,
        ConstraintGenericContext genericContext,
        out string error)
    {
        var specification = metadata.GetTypeSpecification(handle);
        var signature = metadata.GetBlobReader(specification.Signature);
        if (signature.Length is <= 0 or > MaxSignatureBytes)
        {
            error = $"constraint TypeSpec signature 長度必須介於 1 與 {MaxSignatureBytes} bytes";
            return false;
        }

        if (_signatureBytes > MaxAggregateSignatureBytes - signature.Length)
        {
            error = $"constraint TypeSpec signature 累計超過 {MaxAggregateSignatureBytes} bytes 限制";
            return false;
        }

        _signatureBytes += signature.Length;
        return TryValidateTypeSignature(
            metadata,
            signature,
            genericContext,
            _activeTypeSpecifications.Count - 1,
            out error);
    }

    private bool TryValidateTypeSignature(
        MetadataReader metadata,
        BlobReader reader,
        ConstraintGenericContext genericContext,
        int depth,
        out string error)
    {
        try
        {
            if (!TryValidateTypeSignatureNode(
                    metadata,
                    ref reader,
                    genericContext,
                    depth,
                    out error))
            {
                return false;
            }

            if (reader.RemainingBytes != 0)
            {
                error = "constraint TypeSpec signature 含 trailing bytes";
                return false;
            }

            error = string.Empty;
            return true;
        }
        catch (Exception exception) when (
            exception is BadImageFormatException or ArgumentException or InvalidOperationException)
        {
            error = $"constraint TypeSpec signature 格式損壞：{exception.GetType().Name}";
            return false;
        }
    }

    private bool TryValidateTypeSignatureNode(
        MetadataReader metadata,
        ref BlobReader reader,
        ConstraintGenericContext genericContext,
        int depth,
        out string error)
    {
        error = string.Empty;
        if (depth >= MaxSignatureDepth || ++_validatedNodes > MaxSignatureNodes)
        {
            error = "constraint TypeSpec signature 深度或節點數超過限制";
            return false;
        }

        if (reader.RemainingBytes == 0)
        {
            error = "constraint TypeSpec signature 提前結束";
            return false;
        }

        var typeCode = reader.ReadByte();
        switch (typeCode)
        {
            // Primitive、void、TypedReference 與 object；是否合法作為 C# constraint 由 provider 分類。
            case >= 0x01 and <= 0x0E:
            case 0x16:
            case 0x18:
            case 0x19:
            case 0x1C:
                error = string.Empty;
                return true;

            // Pointer、by-ref、SZArray 與 pinned 都包住另一個 type node。
            case 0x0F:
            case 0x10:
            case 0x1D:
            case 0x45:
                return TryValidateTypeSignatureNode(
                    metadata,
                    ref reader,
                    genericContext,
                    depth + 1,
                    out error);

            // ValueType／Class + TypeDefOrRefEncoded。
            case 0x11:
            case 0x12:
                return TryReadConstraintTypeHandle(
                    metadata,
                    ref reader,
                    genericContext,
                    depth + 1,
                    isModifier: false,
                    out error);

            // Generic type/method parameter index。
            case 0x13:
                if (!reader.TryReadCompressedInteger(out var typeParameterIndex) ||
                    !genericContext.ContainsTypeParameter(typeParameterIndex))
                {
                    error = "constraint type generic parameter index 超出 owner context";
                    return false;
                }

                return true;

            case 0x1E:
                if (!reader.TryReadCompressedInteger(out var methodParameterIndex) ||
                    !genericContext.ContainsMethodParameter(methodParameterIndex))
                {
                    error = "constraint method generic parameter index 超出 owner context";
                    return false;
                }

                return true;

            // Multi-dimensional array shape。
            case 0x14:
                if (!TryValidateTypeSignatureNode(
                        metadata,
                        ref reader,
                        genericContext,
                        depth + 1,
                        out error) ||
                    !reader.TryReadCompressedInteger(out var rank) ||
                    rank is <= 0 or > MaxArrayRank ||
                    !reader.TryReadCompressedInteger(out var sizeCount) ||
                    sizeCount < 0 ||
                    sizeCount > rank)
                {
                    error = string.IsNullOrEmpty(error)
                        ? "constraint array rank 或 sizes 數量無效"
                        : error;
                    return false;
                }

                for (var index = 0; index < sizeCount; index++)
                {
                    if (!reader.TryReadCompressedInteger(out _))
                    {
                        error = "constraint array size 無效";
                        return false;
                    }
                }

                if (!reader.TryReadCompressedInteger(out var lowerBoundCount) ||
                    lowerBoundCount < 0 ||
                    lowerBoundCount > rank)
                {
                    error = "constraint array lower-bound 數量無效";
                    return false;
                }

                for (var index = 0; index < lowerBoundCount; index++)
                {
                    if (!reader.TryReadCompressedSignedInteger(out _))
                    {
                        error = "constraint array lower bound 無效";
                        return false;
                    }
                }

                return true;

            // GenericInst + class/value marker + TypeDefOrRefEncoded + bounded arguments。
            case 0x15:
                if (reader.RemainingBytes == 0 || reader.ReadByte() is not (0x11 or 0x12))
                {
                    error = "constraint generic instantiation header 無效";
                    return false;
                }

                var genericTypeHandleReader = reader;
                if (
                    !TryReadConstraintTypeHandle(
                        metadata,
                        ref reader,
                        genericContext,
                        depth + 1,
                        isModifier: false,
                        out error) ||
                    !reader.TryReadCompressedInteger(out var argumentCount) ||
                    argumentCount is <= 0 or > MaxGenericTypeArguments)
                {
                    error = string.IsNullOrEmpty(error)
                        ? "constraint generic instantiation header 或 argument count 無效"
                        : error;
                    return false;
                }

                var genericTypeHandle = genericTypeHandleReader.ReadTypeHandle();
                if (!TryValidateLocalGenericTypeArity(
                        metadata,
                        genericTypeHandle,
                        argumentCount,
                        out error))
                {
                    return false;
                }

                for (var index = 0; index < argumentCount; index++)
                {
                    if (!TryValidateTypeSignatureNode(
                            metadata,
                            ref reader,
                            genericContext,
                            depth + 1,
                            out error))
                    {
                        return false;
                    }
                }

                return true;

            // modreq/modopt + modifier TypeDefOrRefEncoded + wrapped type。
            case 0x1F:
            case 0x20:
                return TryReadConstraintTypeHandle(
                           metadata,
                           ref reader,
                           genericContext,
                           depth + 1,
                           isModifier: true,
                           out error) &&
                       TryValidateTypeSignatureNode(
                           metadata,
                           ref reader,
                           genericContext,
                           depth + 1,
                           out error);

            // Function pointer/type sentinel/internal runtime encodings are not legal C# constraints and
            // can declare large child counts before provider callbacks, so reject them before decoding。
            default:
                error = $"constraint TypeSpec 含不支援的 type code 0x{typeCode:X2}";
                return false;
        }
    }

    private static bool TryValidateLocalGenericTypeArity(
        MetadataReader metadata,
        EntityHandle handle,
        int argumentCount,
        out string error)
    {
        if (handle.Kind != HandleKind.TypeDefinition)
        {
            if (handle.Kind == HandleKind.TypeReference)
            {
                error = string.Empty;
                return true;
            }

            error = "constraint generic type 必須是 TypeDef 或 TypeRef";
            return false;
        }

        var definitionHandle = (TypeDefinitionHandle)handle;
        var handles = metadata.GetTypeDefinition(definitionHandle).GetGenericParameters();
        if (handles.Count != argumentCount || handles.Count > MaxGenericTypeArguments)
        {
            error = "constraint local generic TypeDef 的 GenericParam row count 與 arity 不一致";
            return false;
        }

        var positions = new bool[handles.Count];
        foreach (var parameterHandle in handles)
        {
            var parameter = metadata.GetGenericParameter(parameterHandle);
            if (parameter.Parent != definitionHandle ||
                parameter.Index < 0 ||
                parameter.Index >= positions.Length ||
                positions[parameter.Index])
            {
                error = "constraint local generic TypeDef 的 GenericParam domain 無效";
                return false;
            }

            positions[parameter.Index] = true;
        }

        error = string.Empty;
        return true;
    }

    private bool TryReadConstraintTypeHandle(
        MetadataReader metadata,
        ref BlobReader reader,
        ConstraintGenericContext genericContext,
        int depth,
        bool isModifier,
        out string error)
    {
        var handle = reader.ReadTypeHandle();
        if (handle.IsNil)
        {
            error = "constraint TypeDefOrRefEncoded token 無效";
            return false;
        }

        switch (handle.Kind)
        {
            case HandleKind.TypeDefinition:
                if (!IsValidTypeDefinitionHandle(metadata, (TypeDefinitionHandle)handle))
                {
                    error = "constraint TypeDef handle 超出 metadata 範圍";
                    return false;
                }

                if (isModifier &&
                    !TryReserveModifierNameBytes(metadata, (TypeDefinitionHandle)handle, out error))
                {
                    return false;
                }

                break;
            case HandleKind.TypeReference:
                if (!IsValidTypeReferenceHandle(metadata, (TypeReferenceHandle)handle))
                {
                    error = "constraint TypeRef handle 超出 metadata 範圍";
                    return false;
                }

                if (isModifier &&
                    !TryReserveModifierNameBytes(metadata, (TypeReferenceHandle)handle, out error))
                {
                    return false;
                }

                break;
            case HandleKind.TypeSpecification:
                if (depth >= MaxSignatureDepth)
                {
                    error = "constraint TypeSpec 參照深度超過限制";
                    return false;
                }

                if (!TryValidateReferencedTypeSpecification(
                        metadata,
                        (TypeSpecificationHandle)handle,
                        genericContext,
                        out error))
                {
                    return false;
                }

                if (isModifier)
                {
                    error = "constraint modifier TypeSpec 無法安全保留名稱與位置";
                    return false;
                }

                break;
            default:
                error = $"constraint type handle kind 不受支援：{handle.Kind}";
                return false;
        }

        error = string.Empty;
        return true;
    }

    private bool TryReserveModifierNameBytes(
        MetadataReader metadata,
        TypeDefinitionHandle handle,
        out string error)
    {
        var visited = new HashSet<TypeDefinitionHandle>();
        var current = handle;
        long bytes = 0;
        while (!current.IsNil)
        {
            if (!IsValidTypeDefinitionHandle(metadata, current) ||
                !visited.Add(current) ||
                visited.Count > MaxQualifiedNameDepth)
            {
                error = "constraint modifier TypeDef 宣告鏈循環、過深或超出範圍";
                return false;
            }

            var definition = metadata.GetTypeDefinition(current);
            bytes += metadata.GetBlobReader(definition.Name).Length + (visited.Count > 1 ? 1 : 0);
            var declaringType = definition.GetDeclaringType();
            if (declaringType.IsNil)
            {
                if (!definition.Namespace.IsNil)
                {
                    bytes += metadata.GetBlobReader(definition.Namespace).Length + 1;
                }

                break;
            }

            current = declaringType;
        }

        return TryReserveModifierNameBytes(bytes, out error);
    }

    private bool TryReserveModifierNameBytes(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        out string error)
    {
        var visited = new HashSet<TypeReferenceHandle>();
        var current = handle;
        long bytes = 0;
        while (!current.IsNil)
        {
            if (!IsValidTypeReferenceHandle(metadata, current) ||
                !visited.Add(current) ||
                visited.Count > MaxQualifiedNameDepth)
            {
                error = "constraint modifier TypeRef scope 鏈循環、過深或超出範圍";
                return false;
            }

            var reference = metadata.GetTypeReference(current);
            bytes += metadata.GetBlobReader(reference.Name).Length + (visited.Count > 1 ? 1 : 0);
            if (reference.ResolutionScope.Kind != HandleKind.TypeReference)
            {
                if (!reference.Namespace.IsNil)
                {
                    bytes += metadata.GetBlobReader(reference.Namespace).Length + 1;
                }

                break;
            }

            current = (TypeReferenceHandle)reference.ResolutionScope;
        }

        return TryReserveModifierNameBytes(bytes, out error);
    }

    private bool TryReserveModifierNameBytes(long bytes, out string error)
    {
        if (bytes < 0 || bytes > MaxRetainedModifierUtf8Bytes - _validatedModifierUtf8Bytes)
        {
            error = $"constraint modifier UTF-8 bytes 累計超過 {MaxRetainedModifierUtf8Bytes} bytes 限制";
            return false;
        }

        _validatedModifierUtf8Bytes += (int)bytes;
        error = string.Empty;
        return true;
    }

    private static bool IsValidTypeDefinitionHandle(MetadataReader metadata, TypeDefinitionHandle handle) =>
        !handle.IsNil &&
        MetadataTokens.GetRowNumber(handle) <= metadata.GetTableRowCount(TableIndex.TypeDef);

    private static bool IsValidTypeReferenceHandle(MetadataReader metadata, TypeReferenceHandle handle) =>
        !handle.IsNil &&
        MetadataTokens.GetRowNumber(handle) <= metadata.GetTableRowCount(TableIndex.TypeRef);

    private static bool IsValidTypeSpecificationHandle(MetadataReader metadata, TypeSpecificationHandle handle) =>
        !handle.IsNil &&
        MetadataTokens.GetRowNumber(handle) <= metadata.GetTableRowCount(TableIndex.TypeSpec);

    public ConstraintSignatureType GetArrayType(ConstraintSignatureType elementType, ArrayShape shape) =>
        Merge(
            shape.Rank is > 0 and <= 32
                ? $"{elementType.Type}[{new string(',', shape.Rank - 1)}]"
                : $"{elementType.Type}[...]",
            "unsupported",
            [elementType],
            complete: shape.Rank is > 0 and <= 32,
            error: shape.Rank is > 0 and <= 32 ? null : "array rank 無效或超過 32 維限制");

    public ConstraintSignatureType GetByReferenceType(ConstraintSignatureType elementType) =>
        WithShape(elementType, $"ref {elementType.Type}", "by-ref constraint 不受支援");

    public ConstraintSignatureType GetFunctionPointerType(MethodSignature<ConstraintSignatureType> signature)
    {
        var parts = signature.ParameterTypes.Prepend(signature.ReturnType);
        return Merge("method*", "unsupported", parts, false, "function-pointer constraint 不受支援");
    }

    public ConstraintSignatureType GetGenericInstantiation(
        ConstraintSignatureType genericType,
        ImmutableArray<ConstraintSignatureType> typeArguments)
    {
        var complete = genericType.Complete;
        var error = genericType.Error;
        if (!genericType.RequiredModifiers.IsEmpty || !genericType.OptionalModifiers.IsEmpty)
        {
            complete = false;
            error = CombineErrors(
                error,
                "constructed type name 的巢狀 modreq/modopt 無法以頂層 modifier 清單無損表示");
        }

        foreach (var argument in typeArguments)
        {
            complete &= argument.Complete;
            error = CombineErrors(error, argument.Error);
            if (!argument.RequiredModifiers.IsEmpty || !argument.OptionalModifiers.IsEmpty)
            {
                complete = false;
                error = CombineErrors(
                    error,
                    "巢狀 type argument 的 modreq/modopt 無法以頂層 modifier 清單無損表示");
            }
        }

        if (!TryRenderGenericInstantiation(genericType.Type, typeArguments, out var rendered))
        {
            rendered = "<unsupported>";
            complete = false;
            error = CombineErrors(error, "constraint constructed type arity 無效或輸出超過長度限制");
        }

        // generic argument 裡的 modifier 有自己的位置，不能攤平成 constraint 的頂層 modifier。
        return Track(new ConstraintSignatureType(
            rendered,
            genericType.Kind,
            [],
            [],
            complete,
            error));
    }

    public ConstraintSignatureType GetGenericMethodParameter(object? genericContext, int index)
    {
        if (genericContext is not ConstraintGenericContext context ||
            !context.ContainsMethodParameter(index))
        {
            return Track(Invalid(
                $"!!{index}",
                "type-parameter",
                "method generic parameter index 超出 owner context"));
        }

        return Simple($"!!{index}", "type-parameter");
    }

    public ConstraintSignatureType GetGenericTypeParameter(object? genericContext, int index)
    {
        if (genericContext is not ConstraintGenericContext context ||
            !context.ContainsTypeParameter(index))
        {
            return Track(Invalid(
                $"!{index}",
                "type-parameter",
                "type generic parameter index 超出 owner context"));
        }

        return Simple($"!{index}", "type-parameter");
    }

    public ConstraintSignatureType GetModifiedType(
        ConstraintSignatureType modifier,
        ConstraintSignatureType unmodifiedType,
        bool isRequired)
    {
        var required = unmodifiedType.RequiredModifiers.ToList();
        var optional = unmodifiedType.OptionalModifiers.ToList();
        var target = isRequired ? required : optional;
        var complete = modifier.Complete && unmodifiedType.Complete;
        var error = CombineErrors(modifier.Error, unmodifiedType.Error);
        if (!modifier.RequiredModifiers.IsEmpty || !modifier.OptionalModifiers.IsEmpty)
        {
            complete = false;
            error = CombineErrors(
                error,
                "modifier type 的巢狀 modreq/modopt 無法以頂層 modifier 清單無損表示");
        }

        if (target.Count >= _maxModifiers)
        {
            complete = false;
            error = CombineErrors(error, $"constraint modifiers 超過 {_maxModifiers} 筆限制");
        }
        else if (modifier.Type.Length > MaxRetainedModifierCharacters - _retainedModifierCharacters)
        {
            complete = false;
            error = CombineErrors(
                error,
                $"constraint modifier 字元累計超過 {MaxRetainedModifierCharacters} 字元限制");
        }
        else
        {
            target.Add(modifier.Type);
            _retainedModifierCharacters += modifier.Type.Length;
        }

        return Track(new ConstraintSignatureType(
            unmodifiedType.Type,
            unmodifiedType.Kind,
            [.. required],
            [.. optional],
            complete,
            error));
    }

    public ConstraintSignatureType GetPinnedType(ConstraintSignatureType elementType) =>
        WithShape(elementType, elementType.Type, "pinned constraint 不受支援");

    public ConstraintSignatureType GetPointerType(ConstraintSignatureType elementType) =>
        WithShape(elementType, $"{elementType.Type}*", "pointer constraint 不受支援");

    public ConstraintSignatureType GetPrimitiveType(PrimitiveTypeCode typeCode)
    {
        var type = SignatureTypeNameProvider.Instance.GetPrimitiveType(typeCode);
        // primitive 作為頂層 constraint 仍由 caller 以 unsupported fail closed；
        // 作為 constructed type 的型別參數時不應污染整個 TypeSpec 的解碼完整性。
        return Simple(type, "unsupported");
    }

    public ConstraintSignatureType GetSZArrayType(ConstraintSignatureType elementType) =>
        Merge($"{elementType.Type}[]", "unsupported", [elementType]);

    public ConstraintSignatureType GetTypeFromDefinition(
        MetadataReader reader,
        TypeDefinitionHandle handle,
        byte rawTypeKind)
    {
        var definition = reader.GetTypeDefinition(handle);
        var isSealed = definition.Attributes.HasFlag(TypeAttributes.Sealed);
        if (!TryGetTypeDefinitionName(reader, handle, out var type, out var error))
        {
            return Track(Invalid("<unsupported>", "unsupported", error));
        }

        if (type is "System.Object" or "System.Array")
        {
            // 頂層時由 caller 以 unsupported fail closed；嵌套於 constructed type 內仍是合法 type argument。
            return Simple(type, "unsupported");
        }

        if (type == "System.ValueType")
        {
            return Simple(type, "value-type-marker");
        }

        if (definition.Attributes.HasFlag(TypeAttributes.Interface))
        {
            return Simple(type, "interface");
        }

        if (isSealed)
        {
            // TypeSpec 內的 constructed type／custom attribute 仍可能合法使用 sealed type；
            // 保留完整名稱，但以 unsupported 阻止 caller 把它當頂層 base constraint。
            return Simple(type, "unsupported");
        }

        if (!TryGetDirectBaseTypeName(reader, definition.BaseType, out var baseType) ||
            baseType is "System.ValueType" or "System.Enum")
        {
            return Simple(type, "unsupported");
        }

        return Simple(type, "class");
    }

    private bool TryGetDirectBaseTypeName(
        MetadataReader reader,
        EntityHandle handle,
        out string type)
    {
        type = string.Empty;
        if (handle.IsNil)
        {
            return false;
        }

        if (handle.Kind == HandleKind.TypeSpecification)
        {
            // 合法 class 可繼承 constructed generic base；value type／enum 的直接 base 則不是 TypeSpec。
            type = "<type-spec>";
            return true;
        }

        return handle.Kind switch
        {
            HandleKind.TypeDefinition => TryGetTypeDefinitionName(
                reader,
                (TypeDefinitionHandle)handle,
                out type,
                out _),
            HandleKind.TypeReference => TryGetTypeReferenceName(
                reader,
                (TypeReferenceHandle)handle,
                out type,
                out _),
            _ => false
        };
    }

    public ConstraintSignatureType GetTypeFromReference(
        MetadataReader reader,
        TypeReferenceHandle handle,
        byte rawTypeKind)
    {
        if (!TryGetTypeReferenceName(reader, handle, out var type, out var error))
        {
            return Track(Invalid("<unsupported>", "unsupported", error));
        }

        if (type is "System.Object" or "System.Array")
        {
            return Simple(type, "unsupported");
        }

        var kind = type switch
        {
            "System.ValueType" => "value-type-marker",
            "System.Enum" or "System.Delegate" or "System.MulticastDelegate" => "class",
            _ => "unknown"
        };
        return Simple(type, kind);
    }

    public ConstraintSignatureType GetTypeFromSpecification(
        MetadataReader reader,
        object? genericContext,
        TypeSpecificationHandle handle,
        byte rawTypeKind)
    {
        if (genericContext is not ConstraintGenericContext context)
        {
            return Track(Invalid(
                "<unsupported>",
                "unsupported",
                "constraint TypeSpec 缺少 owner generic context"));
        }

        return DecodeTypeSpecification(reader, handle, context);
    }

    private ConstraintSignatureType WithShape(
        ConstraintSignatureType elementType,
        string rendered,
        string error) =>
        Track(new ConstraintSignatureType(
            rendered,
            "unsupported",
            [],
            [],
            false,
            CombineErrors(
                elementType.Error,
                !elementType.RequiredModifiers.IsEmpty || !elementType.OptionalModifiers.IsEmpty
                    ? $"{error}；巢狀 element type modifier 無法以頂層 modifier 清單無損表示"
                    : error)));

    private ConstraintSignatureType Merge(
        string type,
        string kind,
        IEnumerable<ConstraintSignatureType> parts,
        bool complete = true,
        string? error = null)
    {
        foreach (var part in parts)
        {
            complete &= part.Complete;
            error = CombineErrors(error, part.Error);
            if (!part.RequiredModifiers.IsEmpty || !part.OptionalModifiers.IsEmpty)
            {
                complete = false;
                error = CombineErrors(
                    error,
                    "巢狀 component modifier 無法以頂層 modifier 清單無損表示");
            }
        }

        return Track(new ConstraintSignatureType(
            type,
            kind,
            [],
            [],
            complete,
            error));
    }

    private ConstraintSignatureType Simple(string type, string kind) =>
        Track(new ConstraintSignatureType(type, kind, [], [], true, null));

    private static ConstraintSignatureType Invalid(string type, string kind, string error) =>
        new(type, kind, [], [], false, error);

    private ConstraintSignatureType Track(ConstraintSignatureType value)
    {
        var complete = value.Complete;
        var error = value.Error;
        if (++_nodes > MaxSignatureNodes)
        {
            complete = false;
            error = CombineErrors(error, $"constraint decoded nodes 超過 {MaxSignatureNodes} 筆限制");
        }

        var type = value.Type;
        if (type.Length > MaxRenderedTypeCharacters)
        {
            type = string.Concat(type.AsSpan(0, MaxRenderedTypeCharacters - 1), "…");
            complete = false;
            error = CombineErrors(
                error,
                $"constraint rendered type 超過 {MaxRenderedTypeCharacters} 字元限制");
        }

        return value with { Type = type, Complete = complete, Error = error };
    }

    private static bool TryGetTypeDefinitionName(
        MetadataReader metadata,
        TypeDefinitionHandle handle,
        out string type,
        out string error)
    {
        var visited = new HashSet<TypeDefinitionHandle>();
        var segments = new List<string>();
        var current = handle;
        var namespaceName = string.Empty;
        var characters = 0;
        while (!current.IsNil)
        {
            if (!IsValidTypeDefinitionHandle(metadata, current) ||
                !visited.Add(current) ||
                visited.Count > MaxQualifiedNameDepth)
            {
                type = "<unsupported>";
                error = "constraint TypeDef 宣告鏈循環、過深或超出 metadata 範圍";
                return false;
            }

            var definition = metadata.GetTypeDefinition(current);
            if (!TryReadBoundedMetadataName(metadata, definition.Name, out var name))
            {
                type = "<unsupported>";
                error = "constraint TypeDef name 超過 UTF-8 bytes 限制";
                return false;
            }

            if (!TryReserveQualifiedNameCharacters(name, segments.Count > 0, ref characters))
            {
                type = "<unsupported>";
                error = "constraint TypeDef qualified name 超過長度限制";
                return false;
            }

            segments.Add(name);
            var declaringType = definition.GetDeclaringType();
            if (declaringType.IsNil)
            {
                if (!TryReadBoundedMetadataName(metadata, definition.Namespace, out namespaceName))
                {
                    type = "<unsupported>";
                    error = "constraint TypeDef namespace 超過 UTF-8 bytes 限制";
                    return false;
                }

                break;
            }

            current = declaringType;
        }

        if (!string.IsNullOrEmpty(namespaceName) &&
            !TryReserveQualifiedNameCharacters(namespaceName, segments.Count > 0, ref characters))
        {
            type = "<unsupported>";
            error = "constraint TypeDef qualified name 超過長度限制";
            return false;
        }

        segments.Reverse();
        var nestedName = string.Join('.', segments);
        type = string.IsNullOrEmpty(namespaceName) ? nestedName : $"{namespaceName}.{nestedName}";
        error = string.Empty;
        return true;
    }

    private static bool TryGetTypeReferenceName(
        MetadataReader metadata,
        TypeReferenceHandle handle,
        out string type,
        out string error)
    {
        var visited = new HashSet<TypeReferenceHandle>();
        var segments = new List<string>();
        var current = handle;
        var namespaceName = string.Empty;
        var characters = 0;
        while (!current.IsNil)
        {
            if (!IsValidTypeReferenceHandle(metadata, current) ||
                !visited.Add(current) ||
                visited.Count > MaxQualifiedNameDepth)
            {
                type = "<unsupported>";
                error = "constraint TypeRef scope 鏈循環、過深或超出 metadata 範圍";
                return false;
            }

            var reference = metadata.GetTypeReference(current);
            if (!TryReadBoundedMetadataName(metadata, reference.Name, out var name))
            {
                type = "<unsupported>";
                error = "constraint TypeRef name 超過 UTF-8 bytes 限制";
                return false;
            }

            if (!TryReserveQualifiedNameCharacters(name, segments.Count > 0, ref characters))
            {
                type = "<unsupported>";
                error = "constraint TypeRef qualified name 超過長度限制";
                return false;
            }

            segments.Add(name);
            if (reference.ResolutionScope.Kind != HandleKind.TypeReference)
            {
                if (!TryReadBoundedMetadataName(metadata, reference.Namespace, out namespaceName))
                {
                    type = "<unsupported>";
                    error = "constraint TypeRef namespace 超過 UTF-8 bytes 限制";
                    return false;
                }

                break;
            }

            current = (TypeReferenceHandle)reference.ResolutionScope;
        }

        if (!string.IsNullOrEmpty(namespaceName) &&
            !TryReserveQualifiedNameCharacters(namespaceName, segments.Count > 0, ref characters))
        {
            type = "<unsupported>";
            error = "constraint TypeRef qualified name 超過長度限制";
            return false;
        }

        segments.Reverse();
        var nestedName = string.Join('.', segments);
        type = string.IsNullOrEmpty(namespaceName) ? nestedName : $"{namespaceName}.{nestedName}";
        error = string.Empty;
        return true;
    }

    private static bool TryReadBoundedMetadataName(
        MetadataReader metadata,
        StringHandle handle,
        out string value)
    {
        if (handle.IsNil)
        {
            value = string.Empty;
            return true;
        }

        var bytes = metadata.GetBlobReader(handle);
        if (bytes.Length > MaxMetadataNameUtf8Bytes)
        {
            value = string.Empty;
            return false;
        }

        value = metadata.GetString(handle);
        return value.Length <= MaxRenderedTypeCharacters;
    }

    private static bool TryReserveQualifiedNameCharacters(
        string segment,
        bool needsSeparator,
        ref int characters)
    {
        var required = (long)segment.Length + (needsSeparator ? 1 : 0);
        if (required > MaxRenderedTypeCharacters - characters)
        {
            return false;
        }

        characters += (int)required;
        return true;
    }

    private static bool TryRenderGenericInstantiation(
        string genericType,
        ImmutableArray<ConstraintSignatureType> typeArguments,
        out string rendered)
    {
        var segments = genericType.Split('.');
        var builder = new StringBuilder(Math.Min(genericType.Length + 16, MaxRenderedTypeCharacters));
        var argumentIndex = 0;
        var foundArity = false;
        for (var index = 0; index < segments.Length; index++)
        {
            if (index > 0 && !TryAppendBounded(builder, "."))
            {
                rendered = string.Empty;
                return false;
            }

            var segment = segments[index];
            var backtick = segment.LastIndexOf('`');
            if (backtick < 0)
            {
                if (!TryAppendBounded(builder, segment))
                {
                    rendered = string.Empty;
                    return false;
                }

                continue;
            }

            foundArity = true;
            if (!int.TryParse(
                    segment.AsSpan(backtick + 1),
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var arity) ||
                arity <= 0 ||
                arity > typeArguments.Length - argumentIndex)
            {
                rendered = string.Empty;
                return false;
            }

            if (!TryAppendBounded(builder, segment.AsSpan(0, backtick)) ||
                !TryAppendBounded(builder, "<"))
            {
                rendered = string.Empty;
                return false;
            }

            for (var argument = 0; argument < arity; argument++)
            {
                if ((argument > 0 && !TryAppendBounded(builder, ", ")) ||
                    !TryAppendBounded(builder, typeArguments[argumentIndex++].Type))
                {
                    rendered = string.Empty;
                    return false;
                }
            }

            if (!TryAppendBounded(builder, ">"))
            {
                rendered = string.Empty;
                return false;
            }
        }

        if (!foundArity || argumentIndex != typeArguments.Length)
        {
            rendered = string.Empty;
            return false;
        }

        rendered = builder.ToString();
        return true;
    }

    private static bool TryAppendBounded(StringBuilder builder, string value) =>
        TryAppendBounded(builder, value.AsSpan());

    private static bool TryAppendBounded(StringBuilder builder, ReadOnlySpan<char> value)
    {
        if (value.Length > MaxRenderedTypeCharacters - builder.Length)
        {
            return false;
        }

        builder.Append(value);
        return true;
    }

    private static string? CombineErrors(string? left, string? right)
    {
        if (string.IsNullOrEmpty(left))
        {
            return right;
        }

        if (string.IsNullOrEmpty(right) || left.Contains(right, StringComparison.Ordinal))
        {
            return left;
        }

        return $"{left}；{right}";
    }
}
