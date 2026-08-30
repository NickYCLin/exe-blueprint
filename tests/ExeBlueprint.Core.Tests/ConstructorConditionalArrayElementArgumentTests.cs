using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorConditionalArrayElementArgumentTests
{
    [Theory]
    [InlineData(BranchEncoding.Short)]
    [InlineData(BranchEncoding.Long)]
    public void AcceptsExactConsecutiveInt32ArrayDiamondsForDirectBase(
        BranchEncoding branchEncoding)
    {
        using var fixture = CreateFixture(Mutation.None, branchEncoding);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal(
            [
                "text",
                "capcount != 0 ? caps[(capcount - 1) * 2] : 0",
                "capcount != 0 ? caps[capcount * 2 - 1] : 0"
            ],
            result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.WrongConditionBranch)]
    [InlineData(Mutation.ConditionLeave)]
    [InlineData(Mutation.ConditionSwitch)]
    [InlineData(Mutation.FirstFalseTargetBackward)]
    [InlineData(Mutation.FirstFalseTargetIntoOperand)]
    [InlineData(Mutation.FirstFalseTargetAcrossDiamond)]
    [InlineData(Mutation.FirstJoinTargetBackward)]
    [InlineData(Mutation.FirstJoinTargetAcrossDiamond)]
    [InlineData(Mutation.SecondJoinTargetIntoCallOperand)]
    [InlineData(Mutation.SecondJoinTargetPastEnd)]
    [InlineData(Mutation.MissingFirstJoinBranch)]
    [InlineData(Mutation.WrongSecondJoinBranch)]
    [InlineData(Mutation.FirstFalseValueOne)]
    [InlineData(Mutation.SecondFalseValueOne)]
    [InlineData(Mutation.FirstTrueArmSideEffect)]
    [InlineData(Mutation.ConditionOtherSlot)]
    [InlineData(Mutation.IndexOtherSlot)]
    [InlineData(Mutation.FirstIndexAdd)]
    [InlineData(Mutation.SecondIndexDivide)]
    [InlineData(Mutation.FirstIndexConversion)]
    [InlineData(Mutation.FirstIndexLocal)]
    [InlineData(Mutation.SecondIndexField)]
    [InlineData(Mutation.FirstIndexCall)]
    [InlineData(Mutation.FirstLdelemUInt32)]
    [InlineData(Mutation.SecondLdelemReference)]
    [InlineData(Mutation.FirstLdelema)]
    [InlineData(Mutation.ConditionUInt32)]
    [InlineData(Mutation.ConditionBoolean)]
    [InlineData(Mutation.ArrayUInt32)]
    [InlineData(Mutation.ArrayMultidimensional)]
    [InlineData(Mutation.ArrayJagged)]
    [InlineData(Mutation.ArrayOuterOptionalModifier)]
    [InlineData(Mutation.ArrayOuterRequiredModifier)]
    [InlineData(Mutation.ArrayElementModifier)]
    [InlineData(Mutation.ArrayByReference)]
    [InlineData(Mutation.TargetUInt32)]
    [InlineData(Mutation.ThisConstructor)]
    [InlineData(Mutation.TailBranchIntoDiamond)]
    public void RejectsUnprovenConditionalArrayElementArgument(Mutation mutation)
    {
        using var fixture = CreateFixture(mutation, BranchEncoding.Short);

        Assert.Null(Reconstruct(fixture));
    }

    [Fact]
    public void PreservesAnotherCanonicalArrayParameterIdentity()
    {
        using var fixture = CreateFixture(Mutation.ArrayOtherSlot, BranchEncoding.Short);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal(
            [
                "text",
                "capcount != 0 ? otherCaps[(capcount - 1) * 2] : 0",
                "capcount != 0 ? otherCaps[capcount * 2 - 1] : 0"
            ],
            result.Initializer.Arguments);
    }

    [Fact]
    public void RejectsLongBranchTargetInsideOperand()
    {
        using var fixture = CreateFixture(
            Mutation.SecondJoinTargetIntoCallOperand,
            BranchEncoding.Long);

        Assert.Null(Reconstruct(fixture));
    }

    [Fact]
    public void RejectsExceptionRegionCoveringConditionalPrefix()
    {
        using var fixture = CreateFixture(Mutation.None, BranchEncoding.Short);

        var result = ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Reader,
            fixture.Il,
            fixture.CurrentConstructor,
            [
                new ManagedSymbolReader.ExceptionRegionInfo(
                    ExceptionRegionKind.Finally,
                    TryOffset: 0,
                    TryLength: fixture.CallEndOffset,
                    HandlerOffset: fixture.CallEndOffset,
                    HandlerLength: 1)
            ],
            requireBaseInitializer: false);

        Assert.Null(result);
    }

    private static ManagedSymbolReader.ConstructorReconstructionTestResult? Reconstruct(
        MetadataFixture fixture) =>
        ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Reader,
            fixture.Il,
            fixture.CurrentConstructor,
            requireBaseInitializer: false);

    private static MetadataFixture CreateFixture(
        Mutation mutation,
        BranchEncoding branchEncoding)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString(
                "ConstructorConditionalArrayElementArgumentTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("989677b9-a5af-4b53-9b47-09286f1a22d0")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorConditionalArrayElementArgumentTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var runtime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: metadata.GetOrAddBlob(
                ImmutableArray.Create<byte>(
                    0xB0,
                    0x3F,
                    0x5F,
                    0x7F,
                    0x11,
                    0xD5,
                    0x0A,
                    0x3A)),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            runtime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var modifierType = metadata.AddTypeReference(
            runtime,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("IsConst"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var baseType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Capture"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var targetSignature = new BlobBuilder();
        targetSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        targetSignature.WriteByte(0x03);
        targetSignature.WriteByte(0x01); // VOID
        targetSignature.WriteByte(0x0E); // STRING
        targetSignature.WriteByte(
            mutation == Mutation.TargetUInt32
                ? (byte)0x09 // U4
                : (byte)0x08); // I4
        targetSignature.WriteByte(0x08); // I4
        var targetSignatureHandle = metadata.GetOrAddBlob(targetSignature);
        var baseConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            targetSignatureHandle,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        AddParameters(metadata, "text", "index", "length");

        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Group"),
            baseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(2));
        var thisConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            targetSignatureHandle,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(4));
        AddParameters(metadata, "text", "index", "length");

        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteByte(0x05);
        currentSignature.WriteByte(0x01); // VOID
        currentSignature.WriteByte(0x0E); // STRING
        WriteArraySignature(currentSignature, mutation, modifierType);
        currentSignature.WriteByte(mutation switch
        {
            Mutation.ConditionUInt32 => (byte)0x09, // U4
            Mutation.ConditionBoolean => (byte)0x02, // BOOLEAN
            _ => (byte)0x08 // I4
        });
        currentSignature.WriteByte(0x08); // otherCount: I4
        currentSignature.WriteByte(0x1D); // otherCaps: SZARRAY
        currentSignature.WriteByte(0x08); // I4
        var currentConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(currentSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(7));
        AddParameters(metadata, "text", "caps", "capcount", "otherCount", "otherCaps");

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(
            metadataImage.ToImmutableArray());
        var il = BuildIl(
            mutation,
            branchEncoding,
            MetadataTokens.GetToken(
                mutation == Mutation.ThisConstructor
                    ? thisConstructor
                    : baseConstructor),
            MetadataTokens.GetToken(objectType));
        return new MetadataFixture(
            provider,
            currentConstructor,
            il.Bytes,
            il.CallEndOffset);
    }

    private static void AddParameters(MetadataBuilder metadata, params string[] names)
    {
        for (var index = 0; index < names.Length; index++)
        {
            metadata.AddParameter(
                ParameterAttributes.None,
                metadata.GetOrAddString(names[index]),
                index + 1);
        }
    }

    private static void WriteArraySignature(
        BlobBuilder signature,
        Mutation mutation,
        TypeReferenceHandle modifierType)
    {
        if (mutation is
            Mutation.ArrayOuterOptionalModifier or
            Mutation.ArrayOuterRequiredModifier)
        {
            signature.WriteByte(
                mutation == Mutation.ArrayOuterRequiredModifier
                    ? (byte)0x1F // CMOD_REQD
                    : (byte)0x20); // CMOD_OPT
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
        }

        if (mutation == Mutation.ArrayByReference)
        {
            signature.WriteByte(0x10); // BYREF
        }

        if (mutation == Mutation.ArrayMultidimensional)
        {
            signature.WriteByte(0x14); // ARRAY
            signature.WriteByte(0x08); // I4
            signature.WriteByte(0x01); // rank
            signature.WriteByte(0x00); // no sizes
            signature.WriteByte(0x00); // no lower bounds
            return;
        }

        signature.WriteByte(0x1D); // SZARRAY
        if (mutation == Mutation.ArrayJagged)
        {
            signature.WriteByte(0x1D); // SZARRAY
        }

        if (mutation == Mutation.ArrayElementModifier)
        {
            signature.WriteByte(0x20); // CMOD_OPT
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
        }

        signature.WriteByte(
            mutation == Mutation.ArrayUInt32
                ? (byte)0x09 // U4
                : (byte)0x08); // I4
    }

    private static IlBuildResult BuildIl(
        Mutation mutation,
        BranchEncoding branchEncoding,
        int constructorToken,
        int elementTypeToken)
    {
        var bytes = new List<byte>();
        var labels = new Dictionary<string, int>(StringComparer.Ordinal);
        var fixups = new List<BranchFixup>();

        Mark("method");
        EmitLdarg(0);
        EmitLdarg(1);
        EmitDiamond(1, subtractBeforeMultiply: true);
        EmitDiamond(2, subtractBeforeMultiply: false);
        Mark("call");
        bytes.Add(0x28); // call
        AppendInt32(bytes, constructorToken);
        var callEndOffset = bytes.Count;
        if (mutation == Mutation.TailBranchIntoDiamond)
        {
            EmitBranch(0x2B, 0x38, "diamond1"); // br.s / br
        }

        bytes.Add(0x2A); // ret
        labels["outside"] = bytes.Count + 16;
        labels["conditionOperand1"] = labels["conditionBranch1"] + 1;
        labels["callOperand"] = labels["call"] + 1;
        foreach (var fixup in fixups)
        {
            var delta = checked(labels[fixup.Target] - fixup.BaseOffset);
            if (fixup.Size == 1)
            {
                Assert.InRange(delta, sbyte.MinValue, sbyte.MaxValue);
                bytes[fixup.Offset] = unchecked((byte)(sbyte)delta);
            }
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(
                    CollectionsMarshal.AsSpan(bytes).Slice(fixup.Offset, 4),
                    delta);
            }
        }

        return new IlBuildResult([.. bytes], callEndOffset);

        void EmitDiamond(int number, bool subtractBeforeMultiply)
        {
            Mark($"diamond{number}");
            EmitLdarg(
                mutation == Mutation.ConditionOtherSlot
                    ? 4
                    : 3);
            Mark($"conditionBranch{number}");
            var falseTarget = number == 1
                ? mutation switch
                {
                    Mutation.FirstFalseTargetBackward => "method",
                    Mutation.FirstFalseTargetIntoOperand => "conditionOperand1",
                    Mutation.FirstFalseTargetAcrossDiamond => "false2",
                    _ => "false1"
                }
                : "false2";
            if (number == 1 && mutation == Mutation.ConditionSwitch)
            {
                bytes.Add(0x45); // switch
                AppendInt32(bytes, 1);
                var deltaOffset = bytes.Count;
                AppendInt32(bytes, 0);
                fixups.Add(new BranchFixup(
                    deltaOffset,
                    4,
                    falseTarget,
                    bytes.Count));
            }
            else
            {
                var shortOpcode = number == 1
                    ? mutation switch
                    {
                        Mutation.WrongConditionBranch => (byte)0x2D, // brtrue.s
                        Mutation.ConditionLeave => (byte)0xDE, // leave.s
                        _ => (byte)0x2C // brfalse.s
                    }
                    : (byte)0x2C;
                var longOpcode = number == 1
                    ? mutation switch
                    {
                        Mutation.WrongConditionBranch => (byte)0x3A, // brtrue
                        Mutation.ConditionLeave => (byte)0xDD, // leave
                        _ => (byte)0x39 // brfalse
                    }
                    : (byte)0x39;
                EmitBranch(shortOpcode, longOpcode, falseTarget);
            }

            EmitLdarg(
                mutation == Mutation.ArrayOtherSlot
                    ? 5
                    : 2);
            if (number == 1 && mutation == Mutation.FirstTrueArmSideEffect)
            {
                bytes.Add(0x25); // dup
            }

            if (number == 1 && mutation == Mutation.FirstIndexLocal)
            {
                bytes.Add(0x06); // ldloc.0
            }
            else if (number == 2 && mutation == Mutation.SecondIndexField)
            {
                bytes.Add(0x7E); // ldsfld
                AppendInt32(bytes, elementTypeToken);
            }
            else if (number == 1 && mutation == Mutation.FirstIndexCall)
            {
                bytes.Add(0x28); // call
                AppendInt32(bytes, constructorToken);
            }
            else
            {
                EmitLdarg(
                    mutation == Mutation.IndexOtherSlot
                        ? 4
                        : 3);
            }

            if (subtractBeforeMultiply)
            {
                bytes.Add(0x17); // ldc.i4.1
                bytes.Add(
                    number == 1 && mutation == Mutation.FirstIndexAdd
                        ? (byte)0x58 // add
                        : (byte)0x59); // sub
                bytes.Add(0x18); // ldc.i4.2
                bytes.Add(0x5A); // mul
            }
            else
            {
                bytes.Add(0x18); // ldc.i4.2
                bytes.Add(0x5A); // mul
                bytes.Add(0x17); // ldc.i4.1
                bytes.Add(
                    number == 2 && mutation == Mutation.SecondIndexDivide
                        ? (byte)0x5B // div
                        : (byte)0x59); // sub
            }

            if (number == 1 && mutation == Mutation.FirstIndexConversion)
            {
                bytes.Add(0x69); // conv.i4
            }

            if (number == 1 && mutation == Mutation.FirstLdelema)
            {
                bytes.Add(0x8F); // ldelema
                AppendInt32(bytes, elementTypeToken);
            }
            else
            {
                bytes.Add(number switch
                {
                    1 when mutation == Mutation.FirstLdelemUInt32 => (byte)0x95,
                    2 when mutation == Mutation.SecondLdelemReference => (byte)0x9A,
                    _ => (byte)0x94 // ldelem.i4
                });
            }

            Mark($"joinBranch{number}");
            var joinTarget = number == 1
                ? mutation switch
                {
                    Mutation.FirstJoinTargetBackward => "method",
                    Mutation.FirstJoinTargetAcrossDiamond => "false2",
                    _ => "diamond2"
                }
                : mutation switch
                {
                    Mutation.SecondJoinTargetIntoCallOperand => "callOperand",
                    Mutation.SecondJoinTargetPastEnd => "outside",
                    _ => "call"
                };
            if (number == 1 && mutation == Mutation.MissingFirstJoinBranch)
            {
                bytes.Add(0x00); // nop
            }
            else
            {
                EmitBranch(
                    number == 2 && mutation == Mutation.WrongSecondJoinBranch
                        ? (byte)0xDE // leave.s
                        : (byte)0x2B, // br.s
                    number == 2 && mutation == Mutation.WrongSecondJoinBranch
                        ? (byte)0xDD // leave
                        : (byte)0x38, // br
                    joinTarget);
            }

            Mark($"false{number}");
            bytes.Add(number switch
            {
                1 when mutation == Mutation.FirstFalseValueOne => (byte)0x17,
                2 when mutation == Mutation.SecondFalseValueOne => (byte)0x17,
                _ => (byte)0x16 // ldc.i4.0
            });
        }

        void EmitLdarg(int slot)
        {
            switch (slot)
            {
                case 0:
                case 1:
                case 2:
                case 3:
                    bytes.Add((byte)(0x02 + slot));
                    break;
                default:
                    bytes.Add(0x0E); // ldarg.s
                    bytes.Add(checked((byte)slot));
                    break;
            }
        }

        void EmitBranch(byte shortOpcode, byte longOpcode, string target)
        {
            if (branchEncoding == BranchEncoding.Short)
            {
                bytes.Add(shortOpcode);
                var operandOffset = bytes.Count;
                bytes.Add(0);
                fixups.Add(new BranchFixup(
                    operandOffset,
                    1,
                    target,
                    bytes.Count));
            }
            else
            {
                bytes.Add(longOpcode);
                var operandOffset = bytes.Count;
                AppendInt32(bytes, 0);
                fixups.Add(new BranchFixup(
                    operandOffset,
                    4,
                    target,
                    bytes.Count));
            }
        }

        void Mark(string label) => labels.Add(label, bytes.Count);
    }

    private static void AppendInt32(List<byte> bytes, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    public enum BranchEncoding
    {
        Short,
        Long
    }

    public enum Mutation
    {
        None,
        WrongConditionBranch,
        ConditionLeave,
        ConditionSwitch,
        FirstFalseTargetBackward,
        FirstFalseTargetIntoOperand,
        FirstFalseTargetAcrossDiamond,
        FirstJoinTargetBackward,
        FirstJoinTargetAcrossDiamond,
        SecondJoinTargetIntoCallOperand,
        SecondJoinTargetPastEnd,
        MissingFirstJoinBranch,
        WrongSecondJoinBranch,
        FirstFalseValueOne,
        SecondFalseValueOne,
        FirstTrueArmSideEffect,
        ConditionOtherSlot,
        ArrayOtherSlot,
        IndexOtherSlot,
        FirstIndexAdd,
        SecondIndexDivide,
        FirstIndexConversion,
        FirstIndexLocal,
        SecondIndexField,
        FirstIndexCall,
        FirstLdelemUInt32,
        SecondLdelemReference,
        FirstLdelema,
        ConditionUInt32,
        ConditionBoolean,
        ArrayUInt32,
        ArrayMultidimensional,
        ArrayJagged,
        ArrayOuterOptionalModifier,
        ArrayOuterRequiredModifier,
        ArrayElementModifier,
        ArrayByReference,
        TargetUInt32,
        ThisConstructor,
        TailBranchIntoDiamond
    }

    private readonly record struct BranchFixup(
        int Offset,
        int Size,
        string Target,
        int BaseOffset);

    private readonly record struct IlBuildResult(byte[] Bytes, int CallEndOffset);

    private sealed class MetadataFixture(
        MetadataReaderProvider provider,
        MethodDefinitionHandle currentConstructor,
        byte[] il,
        int callEndOffset) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MethodDefinitionHandle CurrentConstructor { get; } = currentConstructor;

        public byte[] Il { get; } = il;

        public int CallEndOffset { get; } = callEndOffset;

        public void Dispose() => provider.Dispose();
    }
}
