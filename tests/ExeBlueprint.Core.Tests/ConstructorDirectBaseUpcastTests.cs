using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorDirectBaseUpcastTests
{
    [Fact]
    public void AcceptsCanonicalLocalGenericClassDirectBaseUpcast()
    {
        using var fixture = CreateFixture(Mutation.None);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal(["arg0"], result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.UnrelatedBase)]
    [InlineData(Mutation.IndirectBase)]
    [InlineData(Mutation.InterfaceImplementation)]
    [InlineData(Mutation.SourceInterface)]
    [InlineData(Mutation.SealedTarget)]
    [InlineData(Mutation.GenericTarget)]
    [InlineData(Mutation.ExternalSourceDefinition)]
    [InlineData(Mutation.ExternalTarget)]
    [InlineData(Mutation.SourceValueTypeMarker)]
    [InlineData(Mutation.TargetValueTypeMarker)]
    [InlineData(Mutation.SameNameWrongTargetHandle)]
    [InlineData(Mutation.TypeSpecificationBase)]
    [InlineData(Mutation.NonCanonicalSourceArity)]
    [InlineData(Mutation.PrimitiveAliasSourceDefinition)]
    [InlineData(Mutation.WrongSourceParameterPosition)]
    [InlineData(Mutation.SourceParameterConstraint)]
    [InlineData(Mutation.SourceParameterAttributes)]
    [InlineData(Mutation.ModifiedSource)]
    [InlineData(Mutation.ByRefSource)]
    [InlineData(Mutation.ModifiedTarget)]
    [InlineData(Mutation.SourceImport)]
    [InlineData(Mutation.SourceWindowsRuntime)]
    [InlineData(Mutation.TargetImport)]
    [InlineData(Mutation.TargetWindowsRuntime)]
    [InlineData(Mutation.ThisConstructor)]
    [InlineData(Mutation.SelfTypeDefinitionBase)]
    [InlineData(Mutation.GenericSelfTypeSpecificationBase)]
    public void RejectsUnprovenLocalGenericClassUpcast(Mutation mutation)
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
            moduleName: metadata.GetOrAddString("ConstructorDirectBaseUpcastTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("32280e2f-c147-4184-9d21-22fa0a286807")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorDirectBaseUpcastTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var expectedOwnerType = MetadataTokens.TypeDefinitionHandle(7);

        var systemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: default,
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var externalSource = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ArgumentDerived`1"));
        var externalTarget = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ArgumentBase"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var targetType = metadata.AddTypeDefinition(
            TypeAttributes.Public |
            (mutation == Mutation.InterfaceImplementation
                ? TypeAttributes.Interface | TypeAttributes.Abstract
                : (TypeAttributes)0) |
            (mutation == Mutation.SealedTarget ? TypeAttributes.Sealed : (TypeAttributes)0) |
            (mutation == Mutation.TargetImport ? TypeAttributes.Import : (TypeAttributes)0) |
            (mutation == Mutation.TargetWindowsRuntime
                ? TypeAttributes.WindowsRuntime
                : (TypeAttributes)0),
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ArgumentBase"),
            mutation == Mutation.InterfaceImplementation ? default : objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var duplicateTarget = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ArgumentBase"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var intermediateType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ArgumentIntermediate"),
            targetType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var sourceBaseSpecification = new BlobBuilder();
        sourceBaseSpecification.WriteByte(0x12); // CLASS
        sourceBaseSpecification.WriteCompressedInteger(CodedIndex.TypeDefOrRef(targetType));
        var sourceBaseType = mutation switch
        {
            Mutation.UnrelatedBase => (EntityHandle)objectType,
            Mutation.IndirectBase => intermediateType,
            Mutation.TypeSpecificationBase => metadata.AddTypeSpecification(
                metadata.GetOrAddBlob(sourceBaseSpecification)),
            _ => targetType
        };
        var sourceType = metadata.AddTypeDefinition(
            TypeAttributes.Public |
            (mutation == Mutation.SourceInterface
                ? TypeAttributes.Interface | TypeAttributes.Abstract
                : (TypeAttributes)0) |
            (mutation == Mutation.SourceImport ? TypeAttributes.Import : (TypeAttributes)0) |
            (mutation == Mutation.SourceWindowsRuntime
                ? TypeAttributes.WindowsRuntime
                : (TypeAttributes)0),
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString(mutation switch
            {
                Mutation.NonCanonicalSourceArity => "ArgumentDerived`2",
                Mutation.PrimitiveAliasSourceDefinition => "int`1",
                _ => "ArgumentDerived`1"
            }),
            sourceBaseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        if (mutation == Mutation.InterfaceImplementation)
        {
            metadata.AddInterfaceImplementation(sourceType, targetType);
        }

        var constructorBase = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ConstructorBase"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var genericSelfBaseSignature = new BlobBuilder();
        genericSelfBaseSignature.WriteByte(0x15); // GENERICINST
        genericSelfBaseSignature.WriteByte(0x12); // CLASS
        genericSelfBaseSignature.WriteCompressedInteger(
            CodedIndex.TypeDefOrRef(expectedOwnerType));
        genericSelfBaseSignature.WriteByte(0x01);
        genericSelfBaseSignature.WriteByte(0x13); // VAR
        genericSelfBaseSignature.WriteByte(0x00);
        var genericSelfBase = mutation == Mutation.GenericSelfTypeSpecificationBase
            ? metadata.AddTypeSpecification(metadata.GetOrAddBlob(genericSelfBaseSignature))
            : default;
        var ownerBaseType = mutation switch
        {
            Mutation.SelfTypeDefinitionBase => (EntityHandle)expectedOwnerType,
            Mutation.GenericSelfTypeSpecificationBase => genericSelfBase,
            _ => constructorBase
        };
        var ownerType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Owner`1"),
            ownerBaseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        Assert.Equal(expectedOwnerType, ownerType);

        if (mutation == Mutation.GenericTarget)
        {
            metadata.AddGenericParameter(
                targetType,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("TTarget"),
                index: 0);
        }

        var sourceParameter = metadata.AddGenericParameter(
            sourceType,
            mutation == Mutation.SourceParameterAttributes
                ? GenericParameterAttributes.ReferenceTypeConstraint
                : GenericParameterAttributes.None,
            metadata.GetOrAddString("TSource"),
            index: mutation == Mutation.WrongSourceParameterPosition ? 1 : 0);
        if (mutation == Mutation.SourceParameterConstraint)
        {
            metadata.AddGenericParameterConstraint(sourceParameter, objectType);
        }

        metadata.AddGenericParameter(
            ownerType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);

        var targetSignature = new BlobBuilder();
        targetSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        targetSignature.WriteByte(0x01);
        targetSignature.WriteByte(0x01); // VOID
        if (mutation == Mutation.ModifiedTarget)
        {
            targetSignature.WriteByte(0x20); // CMOD_OPT
            targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(objectType));
        }

        targetSignature.WriteByte(
            mutation == Mutation.TargetValueTypeMarker
                ? (byte)0x11 // VALUETYPE
                : (byte)0x12); // CLASS
        var selectedTarget = mutation switch
        {
            Mutation.ExternalTarget => (EntityHandle)externalTarget,
            Mutation.SameNameWrongTargetHandle => duplicateTarget,
            _ => targetType
        };
        targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(selectedTarget));
        var baseConstructor = metadata.AddMemberReference(
            mutation == Mutation.GenericSelfTypeSpecificationBase
                ? genericSelfBase
                : constructorBase,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(targetSignature));
        var thisConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(targetSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteByte(0x01);
        currentSignature.WriteByte(0x01); // VOID
        if (mutation == Mutation.ModifiedSource)
        {
            currentSignature.WriteByte(0x20); // CMOD_OPT
            currentSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(objectType));
        }
        else if (mutation == Mutation.ByRefSource)
        {
            currentSignature.WriteByte(0x10); // BYREF
        }

        currentSignature.WriteByte(0x15); // GENERICINST
        currentSignature.WriteByte(
            mutation == Mutation.SourceValueTypeMarker
                ? (byte)0x11 // VALUETYPE
                : (byte)0x12); // CLASS
        currentSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(
            mutation == Mutation.ExternalSourceDefinition
                ? externalSource
                : sourceType));
        currentSignature.WriteByte(0x01);
        currentSignature.WriteByte(0x13); // VAR
        currentSignature.WriteByte(0x00);
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
                mutation is Mutation.ThisConstructor or Mutation.SelfTypeDefinitionBase
                    ? thisConstructor
                    : baseConstructor)));
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
        UnrelatedBase,
        IndirectBase,
        InterfaceImplementation,
        SourceInterface,
        SealedTarget,
        GenericTarget,
        ExternalSourceDefinition,
        ExternalTarget,
        SourceValueTypeMarker,
        TargetValueTypeMarker,
        SameNameWrongTargetHandle,
        TypeSpecificationBase,
        NonCanonicalSourceArity,
        PrimitiveAliasSourceDefinition,
        WrongSourceParameterPosition,
        SourceParameterConstraint,
        SourceParameterAttributes,
        ModifiedSource,
        ByRefSource,
        ModifiedTarget,
        SourceImport,
        SourceWindowsRuntime,
        TargetImport,
        TargetWindowsRuntime,
        ThisConstructor,
        SelfTypeDefinitionBase,
        GenericSelfTypeSpecificationBase
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
