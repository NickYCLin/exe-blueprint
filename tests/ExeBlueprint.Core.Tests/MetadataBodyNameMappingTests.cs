using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class MetadataBodyNameMappingTests
{
    [Theory]
    [InlineData("class", "@class")]
    [InlineData("bad;\nname", "bad__name")]
    [InlineData("zero\u200bwidth", "zero_width")]
    [InlineData("rtl\u202ename", "rtl_name")]
    public void MapsParameterNamesBeforeBodyEmission(string name, string expected)
    {
        using var fixture = CreateFixture(name, "arg1", "Target", "Type", "Namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(), [0x02, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal([$"return {expected};"], body);
    }

    [Fact]
    public void ParameterCollisionsUseSameSuffixAsDeclarations()
    {
        using var fixture = CreateFixture("bad-name", "bad_name", "Target", "Type", "Namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(), [0x03, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal(["return bad_name_2;"], body);
    }

    [Fact]
    public void MapsMethodAndDeclaringTypeWithoutChangingRawMetadata()
    {
        using var fixture = CreateFixture("arg0", "arg1", "bad;name", "bad;type", "bad;namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(),
            [0x28, 0x01, 0x00, 0x00, 0x06, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal(["return bad_namespace.bad_type.bad_name();"], body);
        var reader = fixture.GetMetadataReader();
        Assert.Equal("bad;name", reader.GetString(reader.GetMethodDefinition(MetadataTokens.MethodDefinitionHandle(1)).Name));
    }

    [Fact]
    public void PreservesLiteralContentsInsteadOfSanitizingBodyText()
    {
        using var stream = File.OpenRead(typeof(MetadataBodyNameMappingTests).Assembly.Location);
        using var executable = new PEReader(stream);
        var metadata = executable.GetMetadataReader();
        var handle = metadata.MethodDefinitions.Single(candidate =>
            metadata.GetString(metadata.GetMethodDefinition(candidate).Name) == nameof(LiteralFixture));
        var il = executable.GetMethodBody(metadata.GetMethodDefinition(handle).RelativeVirtualAddress).GetILBytes()!;
        var body = ManagedSymbolReader.ReconstructMethodForTest(metadata, il, handle, executable);
        Assert.Equal(["return \"bad;name and class\";"], body);
    }

    private static string LiteralFixture() => "bad;name and class";

    [Fact]
    public void KeepsRawTypeIdentityWhileRenderingStructuredTypes()
    {
        using var fixture = CreateFixture("arg0", "arg1", "Target", "bad;type`1", "bad;namespace");
        var provider = SignatureTypeNameProvider.Instance;
        var nominal = provider.GetTypeFromDefinition(fixture.GetMetadataReader(), MetadataTokens.TypeDefinitionHandle(2), 0x12);
        Assert.Equal("bad;namespace.bad;type`1", nominal.Text);
        var generic = provider.GetGenericInstantiation(nominal, [new SignatureTypeName("int")]);
        Assert.Equal("bad;namespace.bad;type<int>", generic.Text);
        Assert.Equal("bad_namespace.bad_type<int>", generic.BodyText);
        Assert.Equal("bad_namespace.bad_type<int>[]", provider.GetSZArrayType(generic).BodyText);
    }

    [Fact]
    public void MapsExternalMemberReferences()
    {
        using var fixture = CreateFixture("arg0", "arg1", "Target", "Type", "Namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(),
            [0x28, 0x01, 0x00, 0x00, 0x0a, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal(["return external_namespace.external_type.external_method();"], body);
    }

    [Fact]
    public void MapsGetterPropertyNames()
    {
        using var fixture = CreateFixture("arg0", "arg1", "get_bad;name", "Type", "Namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(),
            [0x28, 0x01, 0x00, 0x00, 0x06, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal(["return Namespace.Type.bad_name;"], body);
    }

    [Fact]
    public void MapsFieldNamesBeforeBodyEmission()
    {
        using var fixture = CreateFixture("arg0", "arg1", "Target", "Type", "Namespace");
        var body = ManagedSymbolReader.ReconstructMethodForTest(fixture.GetMetadataReader(),
            [0x7e, 0x01, 0x00, 0x00, 0x04, 0x2a], MetadataTokens.MethodDefinitionHandle(2));
        Assert.Equal(["return Namespace.Type.bad_field;"], body);
    }

    private static MetadataReaderProvider CreateFixture(string first, string second, string target, string type, string space)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(0, metadata.GetOrAddString("fixture"), metadata.GetOrAddGuid(Guid.NewGuid()), default, default);
        metadata.AddAssembly(metadata.GetOrAddString("fixture"), new Version(1, 0), default, default, default, default);
        var assembly = metadata.AddAssemblyReference(metadata.GetOrAddString("external"), new Version(1, 0), default, default, default, default);
        var external = metadata.AddTypeReference(assembly, metadata.GetOrAddString("external;namespace"), metadata.GetOrAddString("external;type"));
        metadata.AddMemberReference(external, metadata.GetOrAddString("external;method"),
            metadata.GetOrAddBlob(ImmutableArray.Create<byte>(0x00, 0x00, 0x08)));
        metadata.AddTypeDefinition(TypeAttributes.NotPublic, default, metadata.GetOrAddString("<Module>"), default,
            MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddTypeDefinition(TypeAttributes.Public, metadata.GetOrAddString(space), metadata.GetOrAddString(type), default,
            MetadataTokens.FieldDefinitionHandle(1), MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddFieldDefinition(FieldAttributes.Public | FieldAttributes.Static, metadata.GetOrAddString("bad;field"),
            metadata.GetOrAddBlob(ImmutableArray.Create<byte>(0x06, 0x08)));
        metadata.AddMethodDefinition(MethodAttributes.Public | MethodAttributes.Static, MethodImplAttributes.IL,
            metadata.GetOrAddString(target), metadata.GetOrAddBlob(ImmutableArray.Create<byte>(0x00, 0x00, 0x08)),
            0, MetadataTokens.ParameterHandle(1));
        metadata.AddMethodDefinition(MethodAttributes.Public | MethodAttributes.Static, MethodImplAttributes.IL,
            metadata.GetOrAddString("Caller"), metadata.GetOrAddBlob(ImmutableArray.Create<byte>(0x00, 0x02, 0x08, 0x08, 0x08)),
            0, MetadataTokens.ParameterHandle(1));
        metadata.AddParameter(default, metadata.GetOrAddString(first), 1);
        metadata.AddParameter(default, metadata.GetOrAddString(second), 2);
        var image = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(image, 0, 0);
        return MetadataReaderProvider.FromMetadataImage(image.ToImmutableArray());
    }
}
