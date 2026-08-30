using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class NewObjectTargetSafetyTests
{
    [Fact]
    public void AcceptsCanonicalMethodDefinitionConstructorTarget()
    {
        using var fixture = CreateFixture();

        Assert.Equal(
            ["new Tests.Target();"],
            Reconstruct(fixture.Reader, fixture.CanonicalConstructor));
    }

    [Fact]
    public void RejectsMethodDefinitionTargetsWithoutConstructorSemantics()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(Reconstruct(fixture.Reader, fixture.MissingFlagsConstructor)),
            () => Assert.Null(Reconstruct(fixture.Reader, fixture.StaticConstructor)),
            () => Assert.Null(Reconstruct(fixture.Reader, fixture.NonVoidConstructor)),
            () => Assert.Null(Reconstruct(fixture.Reader, fixture.OrdinaryInstanceMethod)));
    }

    private static IReadOnlyList<string>? Reconstruct(
        MetadataReader metadata,
        MethodDefinitionHandle target) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildNewObjectIl(MetadataTokens.GetToken(target)),
            isInstance: false,
            returnType: "void");

    private static MetadataFixture CreateFixture()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("NewObjectTargetSafety.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("f9b502b0-f112-49aa-b412-08f4502909b0")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("NewObjectTargetSafety"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var runtime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: default,
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            runtime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Target"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var instanceVoidSignature = AddMethodSignature(metadata, isInstance: true, returnType: 0x01);
        var staticVoidSignature = AddMethodSignature(metadata, isInstance: false, returnType: 0x01);
        var instanceInt32Signature = AddMethodSignature(metadata, isInstance: true, returnType: 0x08);
        var canonicalConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            instanceVoidSignature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var missingFlagsConstructor = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            instanceVoidSignature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var staticConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            staticVoidSignature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var nonVoidConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            instanceInt32Signature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var ordinaryInstanceMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("Create"),
            instanceVoidSignature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        return new MetadataFixture(
            provider,
            canonicalConstructor,
            missingFlagsConstructor,
            staticConstructor,
            nonVoidConstructor,
            ordinaryInstanceMethod);
    }

    private static BlobHandle AddMethodSignature(
        MetadataBuilder metadata,
        bool isInstance,
        byte returnType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(isInstance ? (byte)0x20 : (byte)0x00); // HASTHIS | DEFAULT / DEFAULT
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(returnType);
        return metadata.GetOrAddBlob(signature);
    }

    private static byte[] BuildNewObjectIl(int token)
    {
        var il = new byte[7];
        il[0] = 0x73; // newobj
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(1, 4), token);
        il[5] = 0x26; // pop
        il[6] = 0x2A; // ret
        return il;
    }

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    private sealed class MetadataFixture(
        MetadataReaderProvider provider,
        MethodDefinitionHandle canonicalConstructor,
        MethodDefinitionHandle missingFlagsConstructor,
        MethodDefinitionHandle staticConstructor,
        MethodDefinitionHandle nonVoidConstructor,
        MethodDefinitionHandle ordinaryInstanceMethod) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MethodDefinitionHandle CanonicalConstructor { get; } = canonicalConstructor;

        public MethodDefinitionHandle MissingFlagsConstructor { get; } = missingFlagsConstructor;

        public MethodDefinitionHandle StaticConstructor { get; } = staticConstructor;

        public MethodDefinitionHandle NonVoidConstructor { get; } = nonVoidConstructor;

        public MethodDefinitionHandle OrdinaryInstanceMethod { get; } = ordinaryInstanceMethod;

        public void Dispose() => provider.Dispose();
    }
}
