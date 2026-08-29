using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstraintSignatureTypeProviderTests
{
    [Fact]
    public void ValidatesGenericParameterIndicesAgainstOwnerContext()
    {
        var typeOwnerProvider = new ConstraintSignatureTypeProvider(maxModifiers: 8);
        var typeOwner = new ConstraintGenericContext(
            TypeParameterCount: 2,
            MethodParameterCount: 0,
            AllowsMethodParameters: false);

        var validTypeParameter = typeOwnerProvider.GetGenericTypeParameter(typeOwner, 1);
        Assert.True(validTypeParameter.Complete);
        Assert.Equal("!1", validTypeParameter.Type);

        var outOfRangeTypeParameter = typeOwnerProvider.GetGenericTypeParameter(typeOwner, 2);
        Assert.False(outOfRangeTypeParameter.Complete);
        Assert.Contains("type generic parameter index", outOfRangeTypeParameter.Error, StringComparison.Ordinal);

        var methodParameterOnTypeOwner = typeOwnerProvider.GetGenericMethodParameter(typeOwner, 0);
        Assert.False(methodParameterOnTypeOwner.Complete);
        Assert.Contains("method generic parameter index", methodParameterOnTypeOwner.Error, StringComparison.Ordinal);

        var methodOwnerProvider = new ConstraintSignatureTypeProvider(maxModifiers: 8);
        var methodOwner = new ConstraintGenericContext(
            TypeParameterCount: 2,
            MethodParameterCount: 1,
            AllowsMethodParameters: true);

        Assert.True(methodOwnerProvider.GetGenericTypeParameter(methodOwner, 1).Complete);
        Assert.True(methodOwnerProvider.GetGenericMethodParameter(methodOwner, 0).Complete);
        Assert.False(methodOwnerProvider.GetGenericTypeParameter(methodOwner, 2).Complete);
        Assert.False(methodOwnerProvider.GetGenericMethodParameter(methodOwner, 1).Complete);

        var sparseOwner = new ConstraintGenericContext(
            TypeParameterCount: 3,
            MethodParameterCount: 0,
            AllowsMethodParameters: false,
            TypeParameterPositions: [0, 2]);
        var sparseProvider = new ConstraintSignatureTypeProvider(maxModifiers: 8);
        Assert.True(sparseProvider.GetGenericTypeParameter(sparseOwner, 2).Complete);
        Assert.False(sparseProvider.GetGenericTypeParameter(sparseOwner, 1).Complete);

        var malformedOwner = sparseOwner with { TypeParameterPositionsComplete = false };
        Assert.False(new ConstraintSignatureTypeProvider(maxModifiers: 8)
            .GetGenericTypeParameter(malformedOwner, 0)
            .Complete);
    }

    [Fact]
    public void DoesNotFlattenNestedGenericArgumentModifiers()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var box = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Box`1"));
            var modifier = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Marker"));

            var type = new BlobEncoder(signature).TypeSpecificationSignature();
            var argument = type.GenericInstantiation(box, genericArgumentCount: 1, isValueType: false)
                .AddArgument();
            argument.CustomModifiers().AddModifier(modifier, isOptional: false);
            argument.GenericTypeParameter(0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.Equal("Tests.Box<!0>", result.Type);
        Assert.Empty(result.RequiredModifiers);
        Assert.Empty(result.OptionalModifiers);
        Assert.False(result.Complete);
        Assert.Contains("巢狀 type argument", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void PreservesTopLevelRequiredModifier()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var modifier = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Marker"));

            signature.WriteByte(0x1F); // CMOD_REQD
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifier));
            WriteGenericTypeParameter(signature, 0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.True(result.Complete);
        Assert.Equal("!0", result.Type);
        Assert.Collection(
            result.RequiredModifiers,
            modifier => Assert.Equal("Tests.Marker", modifier));
        Assert.Empty(result.OptionalModifiers);
    }

    [Fact]
    public void DoesNotPromoteArrayElementModifier()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var modifier = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Marker"));

            signature.WriteByte(0x1D); // SZARRAY
            signature.WriteByte(0x1F); // CMOD_REQD on the element type
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifier));
            WriteGenericTypeParameter(signature, 0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Empty(result.RequiredModifiers);
        Assert.Empty(result.OptionalModifiers);
        Assert.Contains("巢狀 component modifier", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsTrailingTypeSpecificationBytes()
    {
        using var fixture = CreateTypeSpecification((_, _, signature) =>
        {
            WriteGenericTypeParameter(signature, 0);
            WriteGenericTypeParameter(signature, 0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Contains("trailing bytes", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsCyclicTypeSpecificationTokens()
    {
        using var fixture = CreateTypeSpecification((_, _, signature) =>
        {
            signature.WriteByte(0x1F); // CMOD_REQD
            signature.WriteCompressedInteger(
                CodedIndex.TypeDefOrRefOrSpec(MetadataTokens.TypeSpecificationHandle(1)));
            WriteGenericTypeParameter(signature, 0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Contains("循環", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsOversizedGenericArgumentCountsBeforeDecodingArguments()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var box = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Box`65"));

            signature.WriteByte(0x15); // GENERICINST
            signature.WriteByte(0x12); // CLASS
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(box));
            signature.WriteCompressedInteger(65);
            // No arguments are needed: the bounded preflight must reject the declared count first.
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Contains("argument count", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsGenericInstantiationArityMismatch()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var pair = metadata.AddTypeReference(
                module,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Pair`2"));

            var type = new BlobEncoder(signature).TypeSpecificationSignature();
            type.GenericInstantiation(pair, genericArgumentCount: 1, isValueType: false)
                .AddArgument()
                .GenericTypeParameter(0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Equal("<unsupported>", result.Type);
        Assert.Contains("arity", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsLocalGenericTypeNameWithoutMatchingParameterRows()
    {
        using var fixture = CreateTypeSpecification((metadata, _, signature) =>
        {
            var pair = metadata.AddTypeDefinition(
                TypeAttributes.NotPublic,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("Pair`2"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));

            var type = new BlobEncoder(signature).TypeSpecificationSignature();
            var arguments = type.GenericInstantiation(pair, genericArgumentCount: 2, isValueType: false);
            arguments.AddArgument().GenericTypeParameter(0);
            arguments.AddArgument().GenericTypeParameter(1);
        });

        var result = Decode(fixture, new ConstraintGenericContext(2, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.Contains("GenericParam row count", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void BoundsModifierOutputBudget()
    {
        using var fixture = CreateTypeSpecification((metadata, module, signature) =>
        {
            var modifier = metadata.AddTypeReference(
                module,
                @namespace: default,
                metadata.GetOrAddString(new string('M', 8_192)));

            for (var index = 0; index < 5; index++)
            {
                signature.WriteByte(0x1F); // CMOD_REQD
                signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifier));
            }

            WriteGenericTypeParameter(signature, 0);
        });

        var result = Decode(fixture, new ConstraintGenericContext(1, 0, AllowsMethodParameters: false));

        Assert.False(result.Complete);
        Assert.True(result.RequiredModifiers.Length <= 4);
        Assert.Contains("modifier UTF-8 bytes 累計", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsCyclicTypeReferenceScopesWithoutRecursion()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstraintSignatureTests"),
            mvid: metadata.GetOrAddGuid(new Guid("9c09e934-ed3b-4877-a2e8-c5eb80d1820a")),
            encId: default,
            encBaseId: default);
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var selfReference = metadata.AddTypeReference(
            MetadataTokens.TypeReferenceHandle(1),
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Cyclic"));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(metadataImage, methodBodyStreamRva: 0, mappedFieldDataStreamRva: 0);
        using var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        var result = ConstraintSignatureTypeProvider.Decode(
            provider.GetMetadataReader(),
            selfReference,
            new ConstraintGenericContext(0, 0, AllowsMethodParameters: false),
            maxModifiers: 8);

        Assert.False(result.Complete);
        Assert.Contains("TypeRef scope 鏈循環", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsLocalSealedAndValueTypeBaseConstraints()
    {
        var metadata = new MetadataBuilder();
        var module = metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstraintKindTests"),
            mvid: metadata.GetOrAddGuid(new Guid("7601fc3c-c48d-4022-9e3c-8e70ad05cf09")),
            encId: default,
            encBaseId: default);
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var objectType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var valueType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("ValueType"));
        var enumType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Enum"));
        var openClass = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("OpenClass"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var sealedClass = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic | TypeAttributes.Sealed,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("SealedClass"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var spoofedSystemEnum = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic | TypeAttributes.Sealed,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Enum"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var structType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic | TypeAttributes.Sealed | TypeAttributes.SequentialLayout,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Value"),
            valueType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var localEnum = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic | TypeAttributes.Sealed,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("State"),
            enumType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var interfaceType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic | TypeAttributes.Interface | TypeAttributes.Abstract,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("IMarker"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(metadataImage, methodBodyStreamRva: 0, mappedFieldDataStreamRva: 0);
        using var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        var reader = provider.GetMetadataReader();
        var context = new ConstraintGenericContext(0, 0, AllowsMethodParameters: false);
        Assert.True(reader.GetTypeDefinition(spoofedSystemEnum).Attributes.HasFlag(TypeAttributes.Sealed));

        var openResult = ConstraintSignatureTypeProvider.Decode(reader, openClass, context, maxModifiers: 8);
        Assert.True(openResult.Complete);
        Assert.Equal("class", openResult.Kind);
        var interfaceResult = ConstraintSignatureTypeProvider.Decode(reader, interfaceType, context, maxModifiers: 8);
        Assert.True(interfaceResult.Complete);
        Assert.Equal("interface", interfaceResult.Kind);
        foreach (var (handle, name) in new[]
                 {
                     (sealedClass, "sealed class"),
                     (spoofedSystemEnum, "spoofed System.Enum"),
                     (structType, "struct"),
                     (localEnum, "enum")
                 })
        {
            var result = ConstraintSignatureTypeProvider.Decode(reader, handle, context, maxModifiers: 8);
            Assert.True(result.Complete);
            Assert.True(result.Kind == "unsupported", $"{name}: {result.Type} ({result.Kind})");
        }
    }

    private static ConstraintSignatureType Decode(
        TypeSpecificationFixture fixture,
        ConstraintGenericContext context) =>
        ConstraintSignatureTypeProvider.Decode(
            fixture.Reader,
            fixture.Specification,
            context,
            maxModifiers: 8);

    private static void WriteGenericTypeParameter(BlobBuilder signature, int index)
    {
        signature.WriteByte(0x13); // VAR
        signature.WriteCompressedInteger(index);
    }

    private static TypeSpecificationFixture CreateTypeSpecification(
        Action<MetadataBuilder, ModuleDefinitionHandle, BlobBuilder> writeSignature)
    {
        var metadata = new MetadataBuilder();
        var module = metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstraintSignatureTests"),
            mvid: metadata.GetOrAddGuid(new Guid("a67b91d4-68fb-4836-a151-7148df7e4749")),
            encId: default,
            encBaseId: default);
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var signature = new BlobBuilder();
        writeSignature(metadata, module, signature);
        var specification = metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(metadataImage, methodBodyStreamRva: 0, mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        return new TypeSpecificationFixture(provider, specification);
    }

    private sealed class TypeSpecificationFixture : IDisposable
    {
        private readonly MetadataReaderProvider _provider;

        public TypeSpecificationFixture(
            MetadataReaderProvider provider,
            TypeSpecificationHandle specification)
        {
            _provider = provider;
            Reader = provider.GetMetadataReader();
            Specification = specification;
        }

        public MetadataReader Reader { get; }

        public TypeSpecificationHandle Specification { get; }

        public void Dispose() => _provider.Dispose();
    }
}
