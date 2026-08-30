using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorTrustedGenericInterfaceUpcastTests
{
    [Fact]
    public void AcceptsTrustedIListToIEnumerableThroughBaseTypeSubstitution()
    {
        using var fixture = CreateFixture(Mutation.None);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal(
            ["(System.Collections.Generic.IEnumerable<Tests.Argument>)arg0"],
            result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.DifferentAssemblyReference)]
    [InlineData(Mutation.ShadowRuntimeAssembly)]
    [InlineData(Mutation.WrongAssemblyToken)]
    [InlineData(Mutation.EmptyAssemblyToken)]
    [InlineData(Mutation.AssemblyCulture)]
    [InlineData(Mutation.RetargetableAssembly)]
    [InlineData(Mutation.WindowsRuntimeAssembly)]
    [InlineData(Mutation.PublicKeyFlagWithToken)]
    [InlineData(Mutation.WrongSourceNamespace)]
    [InlineData(Mutation.WrongTargetNamespace)]
    [InlineData(Mutation.WrongSourceName)]
    [InlineData(Mutation.WrongTargetName)]
    [InlineData(Mutation.SourceTwoArguments)]
    [InlineData(Mutation.NestedSourceReference)]
    [InlineData(Mutation.NestedTargetReference)]
    [InlineData(Mutation.SourceLocalDefinition)]
    [InlineData(Mutation.TargetLocalDefinition)]
    [InlineData(Mutation.SourceValueTypeMarker)]
    [InlineData(Mutation.TargetValueTypeMarker)]
    [InlineData(Mutation.DifferentArgumentHandle)]
    [InlineData(Mutation.SourceArgumentValueTypeMarker)]
    [InlineData(Mutation.ModifiedSource)]
    [InlineData(Mutation.ModifiedTarget)]
    [InlineData(Mutation.ModifiedSourceArgument)]
    [InlineData(Mutation.ByRefSource)]
    [InlineData(Mutation.OpenSourceDefinition)]
    [InlineData(Mutation.SwappedInterfacePair)]
    [InlineData(Mutation.TargetCollectionInterface)]
    [InlineData(Mutation.ThisConstructor)]
    [InlineData(Mutation.LocalSourceShadow)]
    [InlineData(Mutation.LocalTargetShadow)]
    [InlineData(Mutation.NestedLocalSourceShadow)]
    [InlineData(Mutation.NestedLocalTargetShadow)]
    [InlineData(Mutation.OverlongShadowAncestor)]
    [InlineData(Mutation.OverlongShadowNamespace)]
    [InlineData(Mutation.DuplicateBaseTypeSpecificationParent)]
    [InlineData(Mutation.OpenBaseTypeArgument)]
    [InlineData(Mutation.TargetOutOfRangeBaseSlot)]
    [InlineData(Mutation.OwnerSlotArgument)]
    public void RejectsUnprovenGenericInterfaceUpcast(Mutation mutation)
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
            requireBaseInitializer: false);

    private static MetadataFixture CreateFixture(Mutation mutation)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString(
                "ConstructorTrustedGenericInterfaceUpcastTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("cfd0482f-1a38-41bc-8955-f2de0aa2ad4a")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorTrustedGenericInterfaceUpcastTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var trustedToken = ImmutableArray.Create<byte>(
            0xB0,
            0x3F,
            0x5F,
            0x7F,
            0x11,
            0xD5,
            0x0A,
            0x3A);
        var primaryRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString(
                mutation == Mutation.ShadowRuntimeAssembly
                    ? "Shadow.Runtime"
                    : "System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: mutation == Mutation.AssemblyCulture
                ? metadata.GetOrAddString("en-US")
                : default,
            publicKeyOrToken: mutation switch
            {
                Mutation.EmptyAssemblyToken => default,
                Mutation.WrongAssemblyToken => metadata.GetOrAddBlob(
                    ImmutableArray.Create<byte>(0, 0, 0, 0, 0, 0, 0, 0)),
                _ => metadata.GetOrAddBlob(trustedToken)
            },
            flags: mutation switch
            {
                Mutation.RetargetableAssembly => AssemblyFlags.Retargetable,
                Mutation.WindowsRuntimeAssembly => AssemblyFlags.WindowsRuntime,
                Mutation.PublicKeyFlagWithToken => AssemblyFlags.PublicKey,
                _ => (AssemblyFlags)0
            },
            hashValue: default);
        var secondRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: metadata.GetOrAddBlob(trustedToken),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            secondRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var modifierType = metadata.AddTypeReference(
            secondRuntime,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("IsConst"));
        var nestedSourceScope = metadata.AddTypeReference(
            primaryRuntime,
            metadata.GetOrAddString("System.Collections"),
            metadata.GetOrAddString("Generic"));
        var nestedTargetScope = metadata.AddTypeReference(
            mutation == Mutation.DifferentAssemblyReference
                ? secondRuntime
                : primaryRuntime,
            metadata.GetOrAddString("System.Collections"),
            metadata.GetOrAddString("Generic"));
        var sourceReference = metadata.AddTypeReference(
            mutation == Mutation.NestedSourceReference
                ? nestedSourceScope
                : primaryRuntime,
            metadata.GetOrAddString(
                mutation == Mutation.WrongSourceNamespace
                    ? "Shadow.Collections.Generic"
                    : mutation == Mutation.NestedSourceReference
                        ? string.Empty
                        : "System.Collections.Generic"),
            metadata.GetOrAddString(mutation switch
            {
                Mutation.WrongSourceName => "ICollection`1",
                Mutation.SwappedInterfacePair => "IEnumerable`1",
                _ => "IList`1"
            }));
        var targetReference = metadata.AddTypeReference(
            mutation == Mutation.NestedTargetReference
                ? nestedTargetScope
                : mutation == Mutation.DifferentAssemblyReference
                    ? secondRuntime
                    : primaryRuntime,
            metadata.GetOrAddString(
                mutation == Mutation.WrongTargetNamespace
                    ? "Shadow.Collections.Generic"
                    : mutation == Mutation.NestedTargetReference
                        ? string.Empty
                        : "System.Collections.Generic"),
            metadata.GetOrAddString(mutation switch
            {
                Mutation.WrongTargetName => "IReadOnlyCollection`1",
                Mutation.TargetCollectionInterface => "ICollection`1",
                Mutation.SwappedInterfacePair => "IList`1",
                _ => "IEnumerable`1"
            }));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var argumentType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Argument"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var duplicateArgumentType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString(
                mutation == Mutation.DifferentArgumentHandle
                    ? "Argument"
                    : "OtherArgument"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var localSourceDefinition = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("LocalList`1"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var localTargetDefinition = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("LocalEnumerable`1"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var genericBase = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericBase`1"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        metadata.AddGenericParameter(
            localSourceDefinition,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TSource"),
            index: 0);
        metadata.AddGenericParameter(
            localTargetDefinition,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TTarget"),
            index: 0);
        metadata.AddGenericParameter(
            genericBase,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TBase"),
            index: 0);

        if (mutation is Mutation.LocalSourceShadow or Mutation.LocalTargetShadow)
        {
            var shadow = metadata.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract,
                metadata.GetOrAddString("System.Collections.Generic"),
                metadata.GetOrAddString(
                    mutation == Mutation.LocalSourceShadow
                        ? "IList`1"
                        : "IEnumerable`1"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            metadata.AddGenericParameter(
                shadow,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TShadow"),
                index: 0);
        }

        if (mutation is Mutation.NestedLocalSourceShadow or Mutation.NestedLocalTargetShadow)
        {
            var shadowParent = metadata.AddTypeDefinition(
                TypeAttributes.Public,
                metadata.GetOrAddString("System.Collections"),
                metadata.GetOrAddString("Generic"),
                objectType,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            var nestedShadow = metadata.AddTypeDefinition(
                TypeAttributes.NestedPublic | TypeAttributes.Interface | TypeAttributes.Abstract,
                @namespace: default,
                metadata.GetOrAddString(
                    mutation == Mutation.NestedLocalSourceShadow
                        ? "IList`1"
                        : "IEnumerable`1"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            metadata.AddNestedType(nestedShadow, shadowParent);
            metadata.AddGenericParameter(
                nestedShadow,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TNestedShadow"),
                index: 0);
        }

        if (mutation == Mutation.OverlongShadowAncestor)
        {
            var shadowParent = metadata.AddTypeDefinition(
                TypeAttributes.Public,
                metadata.GetOrAddString("System.Collections"),
                metadata.GetOrAddString(new string('A', 1_025)),
                objectType,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            var nestedShadow = metadata.AddTypeDefinition(
                TypeAttributes.NestedPublic | TypeAttributes.Interface | TypeAttributes.Abstract,
                @namespace: default,
                metadata.GetOrAddString("IList`1"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            metadata.AddNestedType(nestedShadow, shadowParent);
            metadata.AddGenericParameter(
                nestedShadow,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TOverlongAncestor"),
                index: 0);
        }

        if (mutation == Mutation.OverlongShadowNamespace)
        {
            var shadow = metadata.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Interface | TypeAttributes.Abstract,
                metadata.GetOrAddString(new string('N', 1_025)),
                metadata.GetOrAddString("IList`1"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
            metadata.AddGenericParameter(
                shadow,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TOverlongNamespace"),
                index: 0);
        }

        var baseTypeSignature = new BlobBuilder();
        baseTypeSignature.WriteByte(0x15); // GENERICINST
        baseTypeSignature.WriteByte(0x12); // CLASS
        baseTypeSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericBase));
        baseTypeSignature.WriteByte(0x01);
        if (mutation == Mutation.OpenBaseTypeArgument)
        {
            baseTypeSignature.WriteByte(0x13); // VAR
            baseTypeSignature.WriteByte(0x00);
        }
        else
        {
            baseTypeSignature.WriteByte(0x12); // CLASS
            baseTypeSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(
                mutation == Mutation.DifferentArgumentHandle
                    ? duplicateArgumentType
                    : argumentType));
        }

        var baseType = metadata.AddTypeSpecification(
            metadata.GetOrAddBlob(baseTypeSignature));
        var duplicateBaseType = mutation == Mutation.DuplicateBaseTypeSpecificationParent
            ? metadata.AddTypeSpecification(metadata.GetOrAddBlob(baseTypeSignature))
            : default;
        var ownerType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString(
                mutation == Mutation.OwnerSlotArgument
                    ? "Owner`1"
                    : "Owner"),
            baseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        if (mutation == Mutation.OwnerSlotArgument)
        {
            metadata.AddGenericParameter(
                ownerType,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TOwner"),
                index: 0);
        }

        var selectedSourceDefinition = mutation == Mutation.SourceLocalDefinition
            ? (EntityHandle)localSourceDefinition
            : sourceReference;
        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteByte(0x01);
        currentSignature.WriteByte(0x01); // VOID
        if (mutation == Mutation.ModifiedSource)
        {
            currentSignature.WriteByte(0x20); // CMOD_OPT
            currentSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
        }
        else if (mutation == Mutation.ByRefSource)
        {
            currentSignature.WriteByte(0x10); // BYREF
        }

        if (mutation == Mutation.OpenSourceDefinition)
        {
            currentSignature.WriteByte(0x12); // CLASS
            currentSignature.WriteCompressedInteger(
                CodedIndex.TypeDefOrRef(selectedSourceDefinition));
        }
        else
        {
            currentSignature.WriteByte(0x15); // GENERICINST
            currentSignature.WriteByte(
                mutation == Mutation.SourceValueTypeMarker
                    ? (byte)0x11 // VALUETYPE
                    : (byte)0x12); // CLASS
            currentSignature.WriteCompressedInteger(
                CodedIndex.TypeDefOrRef(selectedSourceDefinition));
            currentSignature.WriteByte(
                mutation == Mutation.SourceTwoArguments
                    ? (byte)0x02
                    : (byte)0x01);
            WriteSourceArgument();
            if (mutation == Mutation.SourceTwoArguments)
            {
                currentSignature.WriteByte(0x12); // CLASS
                currentSignature.WriteCompressedInteger(
                    CodedIndex.TypeDefOrRef(argumentType));
            }
        }

        var targetSignature = new BlobBuilder();
        targetSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        targetSignature.WriteByte(0x01);
        targetSignature.WriteByte(0x01); // VOID
        if (mutation == Mutation.ModifiedTarget)
        {
            targetSignature.WriteByte(0x20); // CMOD_OPT
            targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
        }

        targetSignature.WriteByte(0x15); // GENERICINST
        targetSignature.WriteByte(
            mutation == Mutation.TargetValueTypeMarker
                ? (byte)0x11 // VALUETYPE
                : (byte)0x12); // CLASS
        targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(
            mutation == Mutation.TargetLocalDefinition
                ? localTargetDefinition
                : targetReference));
        targetSignature.WriteByte(0x01);
        targetSignature.WriteByte(0x13); // VAR
        targetSignature.WriteByte(
            mutation == Mutation.TargetOutOfRangeBaseSlot
                ? (byte)0x01
                : (byte)0x00);
        var baseConstructor = metadata.AddMemberReference(
            mutation == Mutation.DuplicateBaseTypeSpecificationParent
                ? duplicateBaseType
                : baseType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(targetSignature));

        var thisSignature = new BlobBuilder();
        thisSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        thisSignature.WriteByte(0x01);
        thisSignature.WriteByte(0x01); // VOID
        thisSignature.WriteByte(0x15); // GENERICINST
        thisSignature.WriteByte(0x12); // CLASS
        thisSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(targetReference));
        thisSignature.WriteByte(0x01);
        thisSignature.WriteByte(0x12); // CLASS
        thisSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(argumentType));
        var thisConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(thisSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var currentConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(currentSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(
            metadataImage.ToImmutableArray());
        return new MetadataFixture(
            provider,
            currentConstructor,
            BuildIl(MetadataTokens.GetToken(
                mutation == Mutation.ThisConstructor
                    ? thisConstructor
                    : baseConstructor)));

        void WriteSourceArgument()
        {
            if (mutation == Mutation.ModifiedSourceArgument)
            {
                currentSignature.WriteByte(0x20); // CMOD_OPT
                currentSignature.WriteCompressedInteger(
                    CodedIndex.TypeDefOrRef(modifierType));
            }

            if (mutation == Mutation.OwnerSlotArgument)
            {
                currentSignature.WriteByte(0x13); // VAR
                currentSignature.WriteByte(0x00);
                return;
            }

            currentSignature.WriteByte(
                mutation == Mutation.SourceArgumentValueTypeMarker
                    ? (byte)0x11 // VALUETYPE
                    : (byte)0x12); // CLASS
            currentSignature.WriteCompressedInteger(
                CodedIndex.TypeDefOrRef(argumentType));
        }
    }

    private static byte[] BuildIl(int constructorToken)
    {
        var il = new byte[8];
        il[0] = 0x02; // ldarg.0
        il[1] = 0x03; // ldarg.1
        il[2] = 0x28; // call
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(3, 4), constructorToken);
        il[7] = 0x2A; // ret
        return il;
    }

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    public enum Mutation
    {
        None,
        DifferentAssemblyReference,
        ShadowRuntimeAssembly,
        WrongAssemblyToken,
        EmptyAssemblyToken,
        AssemblyCulture,
        RetargetableAssembly,
        WindowsRuntimeAssembly,
        PublicKeyFlagWithToken,
        WrongSourceNamespace,
        WrongTargetNamespace,
        WrongSourceName,
        WrongTargetName,
        SourceTwoArguments,
        NestedSourceReference,
        NestedTargetReference,
        SourceLocalDefinition,
        TargetLocalDefinition,
        SourceValueTypeMarker,
        TargetValueTypeMarker,
        DifferentArgumentHandle,
        SourceArgumentValueTypeMarker,
        ModifiedSource,
        ModifiedTarget,
        ModifiedSourceArgument,
        ByRefSource,
        OpenSourceDefinition,
        SwappedInterfacePair,
        TargetCollectionInterface,
        ThisConstructor,
        LocalSourceShadow,
        LocalTargetShadow,
        NestedLocalSourceShadow,
        NestedLocalTargetShadow,
        OverlongShadowAncestor,
        OverlongShadowNamespace,
        DuplicateBaseTypeSpecificationParent,
        OpenBaseTypeArgument,
        TargetOutOfRangeBaseSlot,
        OwnerSlotArgument
    }

    private sealed class MetadataFixture(
        MetadataReaderProvider provider,
        MethodDefinitionHandle currentConstructor,
        byte[] il) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MethodDefinitionHandle CurrentConstructor { get; } = currentConstructor;

        public byte[] Il { get; } = il;

        public void Dispose() => provider.Dispose();
    }
}
