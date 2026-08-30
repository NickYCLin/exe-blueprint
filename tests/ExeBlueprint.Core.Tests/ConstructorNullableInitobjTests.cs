using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorNullableInitobjTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AcceptsCanonicalNullableDefaultLocalConstructorArgument(bool useWideLocals)
    {
        using var fixture = CreateFixture(Mutation.None, useWideLocals);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal(
            ["default(System.Nullable<Tests.Option>)"],
            result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.MissingLocalSignature)]
    [InlineData(Mutation.WrongLocalHeader)]
    [InlineData(Mutation.ZeroLocalCount)]
    [InlineData(Mutation.TwoLocalCount)]
    [InlineData(Mutation.NonCanonicalLocalCount)]
    [InlineData(Mutation.PinnedLocal)]
    [InlineData(Mutation.ByRefLocal)]
    [InlineData(Mutation.ModifiedLocal)]
    [InlineData(Mutation.TrailingLocalSignatureData)]
    [InlineData(Mutation.OversizedLocalSignature)]
    [InlineData(Mutation.LocalTypeMismatch)]
    [InlineData(Mutation.InitobjNonTypeSpecification)]
    [InlineData(Mutation.InitobjTypeMismatch)]
    [InlineData(Mutation.AddressSlotOne)]
    [InlineData(Mutation.LoadSlotMismatch)]
    [InlineData(Mutation.InterposedNop)]
    [InlineData(Mutation.TargetTypeMismatch)]
    [InlineData(Mutation.ThisConstructor)]
    public void RejectsUnprovenNullableDefaultLocalConstructorArgument(Mutation mutation)
    {
        using var fixture = CreateFixture(mutation);

        Assert.Null(Reconstruct(fixture));
    }

    [Theory]
    [InlineData(Mutation.TailLdlocCompact)]
    [InlineData(Mutation.TailLdlocShort)]
    [InlineData(Mutation.TailLdlocWide)]
    [InlineData(Mutation.TailStlocCompact)]
    [InlineData(Mutation.TailStlocShort)]
    [InlineData(Mutation.TailStlocWide)]
    [InlineData(Mutation.TailLdlocaShort)]
    [InlineData(Mutation.TailLdlocaWide)]
    [InlineData(Mutation.TailLdlocShortSlotOne)]
    [InlineData(Mutation.TailStlocShortSlotOne)]
    [InlineData(Mutation.TailLdlocaShortSlotOne)]
    [InlineData(Mutation.UnreachableTailLdloc)]
    public void RejectsAnyTailReuseOfFoldedNullableLocal(Mutation mutation)
    {
        using var fixture = CreateFixture(mutation);

        Assert.Null(Reconstruct(fixture));
    }

    private static ManagedSymbolReader.ConstructorReconstructionTestResult? Reconstruct(
        MetadataFixture fixture) =>
        ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Reader,
            fixture.Il,
            fixture.CurrentConstructor,
            localSignature: fixture.LocalSignature,
            requireBaseInitializer: false);

    private static MetadataFixture CreateFixture(
        Mutation mutation,
        bool useWideLocals = false)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstructorNullableInitobjTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("6581f734-16ee-40a1-bdf0-f7bf81789846")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorNullableInitobjTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var systemRuntime = metadata.AddAssemblyReference(
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
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var valueType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("ValueType"));
        var nullableType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Nullable`1"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var optionType = metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Option"),
            valueType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var otherOptionType = metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.SequentialLayout,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("OtherOption"),
            valueType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var baseType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Base"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var derivedType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Derived"),
            baseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var nullableOption = AddNullableTypeSpecification(optionType);
        var nullableOtherOption = AddNullableTypeSpecification(otherOptionType);
        var targetNullableType = mutation == Mutation.TargetTypeMismatch
            ? otherOptionType
            : optionType;
        var baseConstructorSignature = new BlobBuilder();
        baseConstructorSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        baseConstructorSignature.WriteCompressedInteger(1);
        baseConstructorSignature.WriteByte(0x01); // VOID
        WriteNullableType(baseConstructorSignature, targetNullableType);
        var baseConstructor = metadata.AddMemberReference(
            baseType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(baseConstructorSignature));
        var thisConstructor = metadata.AddMethodDefinition(
            MethodAttributes.Public |
            MethodAttributes.HideBySig |
            MethodAttributes.SpecialName |
            MethodAttributes.RTSpecialName,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(baseConstructorSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteCompressedInteger(0);
        currentSignature.WriteByte(0x01); // VOID
        var currentConstructor = metadata.AddMethodDefinition(
            MethodAttributes.Public |
            MethodAttributes.HideBySig |
            MethodAttributes.SpecialName |
            MethodAttributes.RTSpecialName,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(currentSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        StandaloneSignatureHandle localSignature = default;
        if (mutation != Mutation.MissingLocalSignature)
        {
            var signature = new BlobBuilder();
            signature.WriteByte(
                mutation == Mutation.WrongLocalHeader
                    ? (byte)0x06
                    : (byte)0x07); // LOCAL_SIG
            if (mutation == Mutation.NonCanonicalLocalCount)
            {
                signature.WriteByte(0x80);
                signature.WriteByte(0x01);
            }
            else
            {
                signature.WriteByte(mutation switch
                {
                    Mutation.ZeroLocalCount => 0x00,
                    Mutation.TwoLocalCount => 0x02,
                    _ => 0x01
                });
            }
            if (mutation == Mutation.PinnedLocal)
            {
                signature.WriteByte(0x45); // PINNED
            }
            else if (mutation == Mutation.ByRefLocal)
            {
                signature.WriteByte(0x10); // BYREF
            }
            else if (mutation == Mutation.ModifiedLocal)
            {
                signature.WriteByte(0x20); // CMOD_OPT
                signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(valueType));
            }

            WriteNullableType(
                signature,
                mutation == Mutation.LocalTypeMismatch
                    ? otherOptionType
                    : optionType);
            if (mutation == Mutation.TrailingLocalSignatureData)
            {
                signature.WriteByte(0x00);
            }
            else if (mutation == Mutation.OversizedLocalSignature)
            {
                for (var index = 0; index < 70; index++)
                {
                    signature.WriteByte(0x00);
                }
            }

            localSignature = metadata.AddStandaloneSignature(
                metadata.GetOrAddBlob(signature));
        }

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(
            metadataImage.ToImmutableArray());
        var initobjType = mutation switch
        {
            Mutation.InitobjNonTypeSpecification => (EntityHandle)optionType,
            Mutation.InitobjTypeMismatch => nullableOtherOption,
            _ => nullableOption
        };
        return new MetadataFixture(
            provider,
            currentConstructor,
            localSignature,
            BuildIl(
                mutation,
                useWideLocals,
                MetadataTokens.GetToken(initobjType),
                MetadataTokens.GetToken(
                    mutation == Mutation.ThisConstructor
                        ? thisConstructor
                        : baseConstructor)));

        TypeSpecificationHandle AddNullableTypeSpecification(EntityHandle elementType)
        {
            var signature = new BlobBuilder();
            WriteNullableType(signature, elementType);
            return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
        }

        void WriteNullableType(BlobBuilder signature, EntityHandle elementType)
        {
            signature.WriteByte(0x15); // GENERICINST
            signature.WriteByte(0x11); // VALUETYPE
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(nullableType));
            signature.WriteCompressedInteger(1);
            signature.WriteByte(0x11); // VALUETYPE
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(elementType));
        }
    }

    private static byte[] BuildIl(
        Mutation mutation,
        bool useWideLocals,
        int initobjToken,
        int constructorToken)
    {
        var il = new List<byte> { 0x02 }; // ldarg.0
        var addressSlot = mutation == Mutation.AddressSlotOne ? 1 : 0;
        var loadSlot = mutation == Mutation.LoadSlotMismatch ? 1 : addressSlot;
        WriteLocalAddress(addressSlot);
        if (mutation == Mutation.InterposedNop)
        {
            il.Add(0x00); // nop
        }

        il.Add(0xFE);
        il.Add(0x15); // initobj
        WriteToken(initobjToken);
        WriteLocalLoad(loadSlot);
        il.Add(0x28); // call
        WriteToken(constructorToken);
        WriteTailLocalAccess();
        il.Add(0x2A); // ret
        return [.. il];

        void WriteLocalAddress(int slot)
        {
            if (useWideLocals)
            {
                il.Add(0xFE);
                il.Add(0x0D); // ldloca
                WriteUInt16(slot);
            }
            else
            {
                il.Add(0x12); // ldloca.s
                il.Add((byte)slot);
            }
        }

        void WriteLocalLoad(int slot)
        {
            if (useWideLocals)
            {
                il.Add(0xFE);
                il.Add(0x0C); // ldloc
                WriteUInt16(slot);
            }
            else if (slot == 0)
            {
                il.Add(0x06); // ldloc.0
            }
            else
            {
                il.Add(0x11); // ldloc.s
                il.Add((byte)slot);
            }
        }

        void WriteTailLocalAccess()
        {
            switch (mutation)
            {
                case Mutation.TailLdlocCompact:
                    il.Add(0x06); // ldloc.0
                    break;
                case Mutation.TailLdlocShort:
                    il.Add(0x11); // ldloc.s
                    il.Add(0x00);
                    break;
                case Mutation.TailLdlocWide:
                    il.Add(0xFE);
                    il.Add(0x0C); // ldloc
                    WriteUInt16(0);
                    break;
                case Mutation.TailStlocCompact:
                    il.Add(0x0A); // stloc.0
                    break;
                case Mutation.TailStlocShort:
                    il.Add(0x13); // stloc.s
                    il.Add(0x00);
                    break;
                case Mutation.TailStlocWide:
                    il.Add(0xFE);
                    il.Add(0x0E); // stloc
                    WriteUInt16(0);
                    break;
                case Mutation.TailLdlocaShort:
                    il.Add(0x12); // ldloca.s
                    il.Add(0x00);
                    break;
                case Mutation.TailLdlocaWide:
                    il.Add(0xFE);
                    il.Add(0x0D); // ldloca
                    WriteUInt16(0);
                    break;
                case Mutation.TailLdlocShortSlotOne:
                    il.Add(0x11); // ldloc.s
                    il.Add(0x01);
                    break;
                case Mutation.TailStlocShortSlotOne:
                    il.Add(0x13); // stloc.s
                    il.Add(0x01);
                    break;
                case Mutation.TailLdlocaShortSlotOne:
                    il.Add(0x12); // ldloca.s
                    il.Add(0x01);
                    break;
                case Mutation.UnreachableTailLdloc:
                    il.Add(0x2B); // br.s
                    il.Add(0x01);
                    il.Add(0x06); // ldloc.0
                    break;
            }
        }

        void WriteToken(int token)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(bytes, token);
            foreach (var value in bytes)
            {
                il.Add(value);
            }
        }

        void WriteUInt16(int value)
        {
            Span<byte> bytes = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(bytes, checked((ushort)value));
            foreach (var item in bytes)
            {
                il.Add(item);
            }
        }
    }

    public enum Mutation
    {
        None,
        MissingLocalSignature,
        WrongLocalHeader,
        ZeroLocalCount,
        TwoLocalCount,
        NonCanonicalLocalCount,
        PinnedLocal,
        ByRefLocal,
        ModifiedLocal,
        TrailingLocalSignatureData,
        OversizedLocalSignature,
        LocalTypeMismatch,
        InitobjNonTypeSpecification,
        InitobjTypeMismatch,
        AddressSlotOne,
        LoadSlotMismatch,
        InterposedNop,
        TargetTypeMismatch,
        ThisConstructor,
        TailLdlocCompact,
        TailLdlocShort,
        TailLdlocWide,
        TailStlocCompact,
        TailStlocShort,
        TailStlocWide,
        TailLdlocaShort,
        TailLdlocaWide,
        TailLdlocShortSlotOne,
        TailStlocShortSlotOne,
        TailLdlocaShortSlotOne,
        UnreachableTailLdloc
    }

    private sealed class MetadataFixture(
        MetadataReaderProvider provider,
        MethodDefinitionHandle currentConstructor,
        StandaloneSignatureHandle localSignature,
        byte[] il) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MethodDefinitionHandle CurrentConstructor { get; } = currentConstructor;

        public StandaloneSignatureHandle LocalSignature { get; } = localSignature;

        public byte[] Il { get; } = il;

        public void Dispose() => provider.Dispose();
    }
}
