using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
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
            var namespaceName = metadata.GetString(definition.Namespace);
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
            var baseTypeName = GetTypeName(metadata, definition.BaseType);
            var methods = new List<MethodModel>();

            foreach (var methodHandle in definition.GetMethods())
            {
                var method = metadata.GetMethodDefinition(methodHandle);
                var methodName = metadata.GetString(method.Name);
                var hasBody = method.RelativeVirtualAddress != 0;
                var declaringName = BuildTypeFullName(namespaceName, name);
                var il = hasBody ? TryReadIl(peReader, method) : null;

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
                            model.ReturnType);
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
                FullName = BuildTypeFullName(namespaceName, name),
                Namespace = namespaceName,
                Name = name,
                Kind = kind,
                Accessibility = GetTypeAccessibility(attributes),
                IsStatic = kind == "class" && isAbstract && isSealed,
                IsAbstract = isAbstract,
                IsSealed = isSealed,
                IsNested = !definition.GetDeclaringType().IsNil,
                BaseType = baseTypeName,
                Interfaces = ReadInterfaces(metadata, definition),
                GenericParameters = ReadTypeGenericParameters(metadata, definition),
                Fields = ReadFields(metadata, definition),
                Properties = ReadProperties(metadata, definition),
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
            CallGraph = edges
        };
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
        var declaringType = metadata.GetTypeDefinition(method.GetDeclaringType());
        var fullName = BuildTypeFullName(
            metadata.GetString(declaringType.Namespace),
            metadata.GetString(declaringType.Name));
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
                var total = 4 + (count * 4);
                yield return new IlInstruction(offset, opValue, position, total);
                position += total;
                continue;
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
                return $" ({(instruction.OperandSize - 4) / 4} targets)";
            default:
                return string.Empty;
        }
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

    private sealed record CallInfo(string DeclaringType, string Name, int ParamCount, bool HasThis, bool ReturnsVoid);

    private const int MaxStructureDepth = 32;

    private readonly record struct Instr(int Offset, string Name, int OperandOffset, bool IsBranch, int Target);

    private sealed record ReconContext(
        MetadataReader Metadata,
        byte[] Il,
        Dictionary<int, string> ParameterNames,
        bool IsInstance,
        string ReturnType);

    // 把方法的 IL 還原成 C#。先解碼成指令陣列，再用區間遞迴結構化還原 if／if-else（可巢狀）。
    // 採全有或全無：遇到迴圈（回跳）、switch、例外處理或任何無法結構化的跳轉就整個方法放棄，
    // 退回 IL 註解，寧可不還原也不要產出語意錯誤的程式碼。輸出的 C# 不保證能編譯，但語意貼近原程式。
    private static IReadOnlyList<string>? TryReconstructLinearBody(
        MetadataReader metadata,
        byte[] il,
        bool isInstance,
        Dictionary<int, string> parameterNames,
        string returnType)
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
            if (operandType == OperandType.InlineSwitch)
            {
                return null;
            }

            var target = -1;
            if (operandType == OperandType.ShortInlineBrTarget)
            {
                target = instruction.OperandOffset + 1 + (sbyte)il[instruction.OperandOffset];
            }
            else if (operandType == OperandType.InlineBrTarget)
            {
                target = instruction.OperandOffset + 4 + BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(instruction.OperandOffset, 4));
            }

            offsetToIndex[instruction.Offset] = instructions.Count;
            instructions.Add(new Instr(instruction.Offset, opCode.Name!, instruction.OperandOffset, target >= 0, target));
        }

        offsetToIndex[il.Length] = instructions.Count;
        var context = new ReconContext(metadata, il, parameterNames, isInstance, returnType);
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
                // 只允許往前跳到本區間結尾（等同順順落下）；其餘無條件跳轉無法結構化。
                if (offsetToIndex.TryGetValue(instr.Target, out var branchIndex) && branchIndex == end)
                {
                    index++;
                    continue;
                }

                return null;
            }

            // 條件分支：往前跳才可能是 if。回跳代表迴圈，直接放棄。
            if (instr.Target <= instr.Offset ||
                !offsetToIndex.TryGetValue(instr.Target, out var targetIndex) ||
                targetIndex > end ||
                targetIndex <= index)
            {
                return null;
            }

            if (!TryBuildCondition(instr.Name, stack, out var condition) || stack.Count != 0)
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

    // 依分支指令算出「順順落下（fall-through）」時的 C# 條件，也就是不跳轉時該執行 then 區塊的條件。
    private static bool TryBuildCondition(string name, Stack<string> stack, out string condition)
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

                condition = $"!({truthy})";
                return true;
            case "brfalse":
            case "brfalse.s":
                if (!TryPop(stack, out var falsy))
                {
                    return false;
                }

                condition = falsy;
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
                stack.Push(ArgName(context, 0));
                return true;
            case "ldarg.1":
                stack.Push(ArgName(context, 1));
                return true;
            case "ldarg.2":
                stack.Push(ArgName(context, 2));
                return true;
            case "ldarg.3":
                stack.Push(ArgName(context, 3));
                return true;
            case "ldarg.s":
                stack.Push(ArgName(context, il[offset]));
                return true;
            case "ldarg":
                stack.Push(ArgName(context, BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2))));
                return true;
            case "starg.s":
                if (!TryPop(stack, out var stargValue))
                {
                    return false;
                }

                statements.Add($"{ArgName(context, il[offset])} = {stargValue};");
                return true;

            case "ldnull":
                stack.Push("null");
                return true;
            case "ldstr":
                stack.Push(EscapeCSharpString(ReadUserString(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))));
                return true;
            case "ldc.i4.m1":
                stack.Push("-1");
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
                stack.Push(name["ldc.i4.".Length..]);
                return true;
            case "ldc.i4.s":
                stack.Push(((sbyte)il[offset]).ToString());
                return true;
            case "ldc.i4":
                stack.Push(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)).ToString());
                return true;
            case "ldc.i8":
                stack.Push($"{BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8))}L");
                return true;
            case "ldc.r4":
                stack.Push($"{BitConverter.Int32BitsToSingle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)))}f");
                return true;
            case "ldc.r8":
                stack.Push($"{BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(il.AsSpan(offset, 8)))}");
                return true;

            case "ldloc.0":
            case "ldloc.1":
            case "ldloc.2":
            case "ldloc.3":
                stack.Push($"v{name["ldloc.".Length..]}");
                return true;
            case "ldloc.s":
                stack.Push($"v{il[offset]}");
                return true;
            case "ldloc":
                stack.Push($"v{BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2))}");
                return true;
            case "stloc.0":
            case "stloc.1":
            case "stloc.2":
            case "stloc.3":
                return TryStoreLocal(stack, statements, declaredLocals, int.Parse(name["stloc.".Length..]));
            case "stloc.s":
                return TryStoreLocal(stack, statements, declaredLocals, il[offset]);
            case "stloc":
                return TryStoreLocal(stack, statements, declaredLocals, BinaryPrimitives.ReadUInt16LittleEndian(il.AsSpan(offset, 2)));

            case "ldsfld":
                var loadStatic = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (loadStatic is null || IsGeneratedName(loadStatic.Value.DeclaringType) || IsGeneratedName(loadStatic.Value.Name))
                {
                    return false;
                }

                stack.Push($"{loadStatic.Value.DeclaringType}.{loadStatic.Value.Name}");
                return true;
            case "ldfld":
                var loadField = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (loadField is null || IsGeneratedName(loadField.Value.Name) || !TryPop(stack, out var fieldTarget))
                {
                    return false;
                }

                stack.Push($"{fieldTarget}.{loadField.Value.Name}");
                return true;
            case "stsfld":
                var storeStatic = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (storeStatic is null || IsGeneratedName(storeStatic.Value.DeclaringType) || IsGeneratedName(storeStatic.Value.Name) || !TryPop(stack, out var storeStaticValue))
                {
                    return false;
                }

                statements.Add($"{storeStatic.Value.DeclaringType}.{storeStatic.Value.Name} = {storeStaticValue};");
                return true;
            case "stfld":
                var storeField = ResolveField(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)));
                if (storeField is null || IsGeneratedName(storeField.Value.Name) || !TryPop(stack, out var storeFieldValue) || !TryPop(stack, out var storeFieldTarget))
                {
                    return false;
                }

                statements.Add($"{storeFieldTarget}.{storeField.Value.Name} = {storeFieldValue};");
                return true;

            case "add":
            case "sub":
            case "mul":
            case "div":
            case "div.un":
            case "rem":
            case "rem.un":
            case "and":
            case "or":
            case "xor":
            case "shl":
            case "shr":
            case "shr.un":
                return TryBinary(stack, BinaryOperator(name));
            case "ceq":
                return TryBinary(stack, "==");
            case "cgt":
            case "cgt.un":
                return TryBinary(stack, ">");
            case "clt":
            case "clt.un":
                return TryBinary(stack, "<");
            case "neg":
                return TryUnary(stack, "-");
            case "not":
                return TryUnary(stack, "~");

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
                return TryUnaryCast(stack, ConversionType(name));

            case "castclass":
                var castType = GetTypeName(metadata, MetadataTokens.EntityHandle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4))));
                if (castType is null || IsGeneratedName(castType) || !TryPop(stack, out var castValue))
                {
                    return false;
                }

                stack.Push($"(({castType}){castValue})");
                return true;
            case "isinst":
                var instType = GetTypeName(metadata, MetadataTokens.EntityHandle(BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4))));
                if (instType is null || IsGeneratedName(instType) || !TryPop(stack, out var instValue))
                {
                    return false;
                }

                stack.Push($"({instValue} as {instType})");
                return true;

            case "call":
            case "callvirt":
                return TryEmitCall(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)), stack, statements);
            case "newobj":
                return TryEmitNewObject(metadata, BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset, 4)), stack);

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

    private static bool TryBinary(Stack<string> stack, string op)
    {
        if (stack.Count < 2)
        {
            return false;
        }

        var right = stack.Pop();
        var left = stack.Pop();
        stack.Push($"({left} {op} {right})");
        return true;
    }

    private static bool TryUnary(Stack<string> stack, string op)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        stack.Push($"({op}{value})");
        return true;
    }

    private static bool TryUnaryCast(Stack<string> stack, string type)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        stack.Push($"({type})({value})");
        return true;
    }

    private static bool TryStoreLocal(Stack<string> stack, List<string> statements, HashSet<int> declaredLocals, int index)
    {
        if (!TryPop(stack, out var value))
        {
            return false;
        }

        statements.Add(declaredLocals.Add(index) ? $"var v{index} = {value};" : $"v{index} = {value};");
        return true;
    }

    // 編譯器產生的名稱（狀態機、lambda、匿名型別）沒辦法在 C# 直接寫出來，碰到就放棄整個方法。
    private static bool IsGeneratedName(string name) =>
        name.StartsWith('<') || name.Contains(".<", StringComparison.Ordinal) || name.Contains("<>", StringComparison.Ordinal);

    private static bool TryEmitCall(MetadataReader metadata, int token, Stack<string> stack, List<string> statements)
    {
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

            args[index] = argument;
        }

        string? receiver = null;
        if (info.HasThis && !TryPop(stack, out receiver))
        {
            return false;
        }

        if (info.Name.StartsWith("op_", StringComparison.Ordinal))
        {
            return TryEmitOperator(info, args, stack);
        }

        var target = info.HasThis ? receiver! : info.DeclaringType;

        if (info.Name.StartsWith("get_", StringComparison.Ordinal) && info.ParamCount == 0)
        {
            stack.Push($"{target}.{info.Name["get_".Length..]}");
            return true;
        }

        if (info.Name.StartsWith("set_", StringComparison.Ordinal) && info.ParamCount == 1 && info.ReturnsVoid)
        {
            statements.Add($"{target}.{info.Name["set_".Length..]} = {args[0]};");
            return true;
        }

        var call = $"{target}.{info.Name}({string.Join(", ", args)})";
        if (info.ReturnsVoid)
        {
            statements.Add($"{call};");
        }
        else
        {
            stack.Push(call);
        }

        return true;
    }

    // 把運算子方法（op_Equality 等）還原成運算子語法，避免產生 Type.op_Equality(a, b) 這種非法 C#。
    // 對應不到的運算子就放棄整個方法，退回 IL 註解。
    private static bool TryEmitOperator(CallInfo info, string[] args, Stack<string> stack)
    {
        if (info.ParamCount == 2 && BinaryOperators.TryGetValue(info.Name, out var binary))
        {
            stack.Push($"({args[0]} {binary} {args[1]})");
            return true;
        }

        if (info.ParamCount == 1 && UnaryOperators.TryGetValue(info.Name, out var unary))
        {
            stack.Push($"({unary}{args[0]})");
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

    private static bool TryEmitNewObject(MetadataReader metadata, int token, Stack<string> stack)
    {
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

            args[index] = argument;
        }

        stack.Push($"new {info.DeclaringType}({string.Join(", ", args)})");
        return true;
    }

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
                    methodSignature.ReturnType == "void");

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
                    memberSignature.ReturnType == "void");

            case HandleKind.MethodSpecification:
                var spec = metadata.GetMethodSpecification((MethodSpecificationHandle)handle);
                return ResolveCall(metadata, MetadataTokens.GetToken(spec.Method));

            default:
                return null;
        }
    }

    private static (string DeclaringType, string Name)? ResolveField(MetadataReader metadata, int token)
    {
        var handle = MetadataTokens.EntityHandle(token);
        switch (handle.Kind)
        {
            case HandleKind.FieldDefinition:
                var field = metadata.GetFieldDefinition((FieldDefinitionHandle)handle);
                return (GetTypeName(metadata, field.GetDeclaringType()) ?? string.Empty, NormalizeFieldName(metadata.GetString(field.Name)));

            case HandleKind.MemberReference:
                var member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                if (member.GetKind() != MemberReferenceKind.Field)
                {
                    return null;
                }

                return (GetTypeName(metadata, member.Parent) ?? string.Empty, NormalizeFieldName(metadata.GetString(member.Name)));

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
        "div" or "div.un" => "/",
        "rem" or "rem.un" => "%",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        "shl" => "<<",
        "shr" or "shr.un" => ">>",
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
                var declaringType = metadata.GetTypeDefinition(method.GetDeclaringType());
                var typeName = BuildTypeFullName(
                    metadata.GetString(declaringType.Namespace),
                    StripArity(metadata.GetString(declaringType.Name)));
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
                return ResolveMemberName(metadata, MetadataTokens.GetToken(spec.Method));

            default:
                return null;
        }
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
                var definition = metadata.GetTypeDefinition((TypeDefinitionHandle)handle);
                return BuildTypeFullName(
                    metadata.GetString(definition.Namespace),
                    StripArity(metadata.GetString(definition.Name)));

            case HandleKind.TypeReference:
                var reference = metadata.GetTypeReference((TypeReferenceHandle)handle);
                return BuildTypeFullName(
                    metadata.GetString(reference.Namespace),
                    StripArity(metadata.GetString(reference.Name)));

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

    private static string StripArity(string name)
    {
        var backtick = name.IndexOf('`', StringComparison.Ordinal);
        return backtick < 0 ? name : name[..backtick];
    }

    private static string BuildTypeFullName(string namespaceName, string name) =>
        string.IsNullOrEmpty(namespaceName) ? name : $"{namespaceName}.{name}";

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
            returnType = signature.ReturnType;
            var parameterNames = ReadParameterNames(metadata, method);
            for (var index = 0; index < signature.ParameterTypes.Length; index++)
            {
                var name = parameterNames.TryGetValue(index + 1, out var value) && !string.IsNullOrEmpty(value)
                    ? value
                    : $"arg{index}";
                parameters.Add(new ParameterModel { Name = name, Type = signature.ParameterTypes[index] });
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
            IsConstructor = methodName is ".ctor" or ".cctor",
            IsEntryPoint = methodHandle == entryPointHandle,
            HasBody = hasBody,
            GenericParameters = ReadMethodGenericParameters(metadata, method),
            Parameters = parameters
        };
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
                IsConstant = field.Attributes.HasFlag(FieldAttributes.Literal)
            });
        }

        return fields;
    }

    private static IReadOnlyList<PropertyModel> ReadProperties(MetadataReader metadata, TypeDefinition definition)
    {
        var properties = new List<PropertyModel>();
        foreach (var handle in definition.GetProperties())
        {
            var property = metadata.GetPropertyDefinition(handle);
            string propertyType;
            try
            {
                propertyType = property.DecodeSignature(SignatureTypeNameProvider.Instance, null).ReturnType;
            }
            catch (BadImageFormatException)
            {
                propertyType = "object";
            }

            var accessors = property.GetAccessors();
            properties.Add(new PropertyModel
            {
                Name = metadata.GetString(property.Name),
                Type = propertyType,
                HasGetter = !accessors.Getter.IsNil,
                HasSetter = !accessors.Setter.IsNil
            });
        }

        return properties;
    }

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

    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) =>
        $"{genericType}<{string.Join(", ", typeArguments)}>";

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
        return StripArity(reader.GetString(definition.Name));
    }

    public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind)
    {
        var reference = reader.GetTypeReference(handle);
        return StripArity(reader.GetString(reference.Name));
    }

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
