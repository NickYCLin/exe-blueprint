using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class GenericAttributeMetadataTests
{
    [Fact]
    public void RejectsCyclicCustomAttributeTypeReferenceScopes()
    {
        var metadata = CreateMetadata(out var module);
        var cyclicType = metadata.AddTypeReference(
            MetadataTokens.TypeReferenceHandle(1),
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("CyclicAttribute"));
        var constructor = metadata.AddMemberReference(
            cyclicType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(Array.Empty<byte>()));
        var attributeHandle = metadata.AddCustomAttribute(
            MetadataTokens.TypeDefinitionHandle(1),
            constructor,
            metadata.GetOrAddBlob(Array.Empty<byte>()));

        using var fixture = Serialize(metadata);
        var attribute = fixture.Reader.GetCustomAttribute(attributeHandle);

        Assert.False(ManagedSymbolReader.TryGetBoundedGenericAttributeTypeName(
            fixture.Reader,
            attribute,
            out _,
            out var error));
        Assert.Contains("TypeRef scope 鏈循環", error, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsDuplicateNullableAttributes()
    {
        var metadata = CreateMetadata(out var module);
        var fixtureType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericFixture`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var parameter = metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        var nullableType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("NullableAttribute"));
        var constructor = metadata.AddMemberReference(
            nullableType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(Array.Empty<byte>()));
        var value = new BlobBuilder();
        value.WriteUInt16(1);
        value.WriteByte(1);
        value.WriteUInt16(0);
        var valueHandle = metadata.GetOrAddBlob(value);
        metadata.AddCustomAttribute(parameter, constructor, valueHandle);
        metadata.AddCustomAttribute(parameter, constructor, valueHandle);

        using var fixture = Serialize(metadata);
        var attributes = fixture.Reader.GetGenericParameter(parameter).GetCustomAttributes();
        var result = ManagedSymbolReader.ReadNullableAttributeFlag(fixture.Reader, attributes);

        Assert.True(result.Found);
        Assert.False(result.Complete);
        Assert.Contains("重複", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void MarksMidOwnerParameterBudgetExhaustionAndEmptyNewOwnerAsTruncated()
    {
        var metadata = CreateMetadata(out _);
        var fixtureType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("BudgetFixture`2"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TFirst"),
            index: 0);
        metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TSecond"),
            index: 1);

        using var fixture = Serialize(metadata);
        var handles = fixture.Reader.GetTypeDefinition(fixtureType).GetGenericParameters();
        var midOwnerBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 1,
            constraintRows: 8,
            characters: 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var partial = ManagedSymbolReader.ReadGenericParameters(
            fixture.Reader,
            handles,
            fixtureType,
            midOwnerBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null);

        var retained = Assert.Single(partial);
        Assert.False(retained.Complete);
        Assert.Contains("parameter row 預算", retained.Error, StringComparison.Ordinal);
        Assert.True(midOwnerBudget.Truncated);

        var emptyOwnerBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 0,
            constraintRows: 8,
            characters: 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var empty = ManagedSymbolReader.ReadGenericParameters(
            fixture.Reader,
            handles,
            fixtureType,
            emptyOwnerBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null);

        Assert.Empty(empty);
        Assert.True(emptyOwnerBudget.Truncated);
        Assert.NotEqual(handles.Count, empty.Count);

        var characterBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 2,
            constraintRows: 8,
            characters: 1,
            ownerConstraintRows: 8,
            ownerCharacters: 1);
        var characterLimited = ManagedSymbolReader.ReadGenericParameters(
            fixture.Reader,
            handles,
            fixtureType,
            characterBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null);

        Assert.Equal(2, characterLimited.Count);
        Assert.All(characterLimited, parameter => Assert.False(parameter.Complete));
        Assert.Contains(
            characterLimited,
            parameter => parameter.Error?.Contains("字元預算", StringComparison.Ordinal) == true);
        Assert.True(characterBudget.Truncated);
    }

    [Fact]
    public void MarksConstraintRowBudgetExhaustionOnRetainedParameter()
    {
        var metadata = CreateMetadata(out _);
        var fixtureType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("ConstraintBudgetFixture`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var baseType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Base"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var parameter = metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameterConstraint(parameter, baseType);
        metadata.AddGenericParameterConstraint(parameter, baseType);

        using var fixture = Serialize(metadata);
        var handles = fixture.Reader.GetTypeDefinition(fixtureType).GetGenericParameters();
        var budget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 4,
            constraintRows: 1,
            characters: 1_024,
            ownerConstraintRows: 1,
            ownerCharacters: 1_024);
        var result = ManagedSymbolReader.ReadGenericParameters(
            fixture.Reader,
            handles,
            fixtureType,
            budget,
            inheritedParameterCount: 0,
            inheritedParameters: null);

        var retained = Assert.Single(result);
        Assert.Single(retained.TypeConstraints);
        Assert.False(retained.Complete);
        Assert.Contains("constraint row 預算", retained.Error, StringComparison.Ordinal);
        Assert.True(budget.Truncated);
    }

    [Fact]
    public void ResolvesInheritedParametersWhenNestedTypePrecedesDeclaringType()
    {
        var metadata = CreateMetadata(out _);
        var nestedType = metadata.AddTypeDefinition(
            TypeAttributes.NestedPrivate,
            @namespace: default,
            metadata.GetOrAddString("Inner`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var declaringType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Outer`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddNestedType(nestedType, declaringType);
        metadata.AddGenericParameter(
            nestedType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameter(
            declaringType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);

        using var fixture = Serialize(metadata);
        Assert.Equal(
            declaringType,
            fixture.Reader.GetTypeDefinition(nestedType).GetDeclaringType());
        var budget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 2,
            constraintRows: 8,
            characters: 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var resolver = new ManagedSymbolReader.TypeGenericParameterResolver(fixture.Reader, budget);

        var nestedResult = resolver.Read(nestedType);
        var declaringResult = resolver.Read(declaringType);

        Assert.True(nestedResult.Complete);
        Assert.True(declaringResult.Complete);
        Assert.True(Assert.Single(nestedResult.Parameters).Complete);
        Assert.True(Assert.Single(declaringResult.Parameters).Complete);
        Assert.False(budget.Truncated);
    }

    [Fact]
    public void PropagatesIncompleteDeclaringOwnerThroughNestedChain()
    {
        var metadata = CreateMetadata(out _);
        var outerType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Outer`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var middleType = metadata.AddTypeDefinition(
            TypeAttributes.NestedPrivate,
            @namespace: default,
            metadata.GetOrAddString("Middle"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var childType = metadata.AddTypeDefinition(
            TypeAttributes.NestedPrivate,
            @namespace: default,
            metadata.GetOrAddString("Child`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddNestedType(middleType, outerType);
        metadata.AddNestedType(childType, middleType);
        metadata.AddGenericParameter(
            outerType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameter(
            childType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("U"),
            index: 0);

        using var fixture = Serialize(metadata);
        var budget = new ManagedSymbolReader.GenericMetadataBudget();
        var resolver = new ManagedSymbolReader.TypeGenericParameterResolver(fixture.Reader, budget);

        var outerResult = resolver.Read(outerType);
        var middleResult = resolver.Read(middleType);
        var childResult = resolver.Read(childType);

        Assert.True(outerResult.Complete);
        Assert.False(middleResult.Complete);
        Assert.Empty(middleResult.Parameters);
        Assert.False(childResult.Complete);
        Assert.True(Assert.Single(childResult.Parameters).Complete);
        Assert.False(budget.Truncated);
    }

    [Fact]
    public void EnforcesDeclaringDepthWhenEveryParentIsAlreadyCached()
    {
        var metadata = CreateMetadata(out var module);
        var types = new List<TypeDefinitionHandle>();
        for (var index = 0; index <= 64; index++)
        {
            types.Add(metadata.AddTypeDefinition(
                index == 0 ? TypeAttributes.NotPublic : TypeAttributes.NestedPrivate,
                index == 0 ? metadata.GetOrAddString("Tests") : default,
                metadata.GetOrAddString(index == 0 ? "Root`1" : $"Nested{index}`1"),
                baseType: default,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1)));
        }

        for (var index = 1; index < types.Count; index++)
        {
            metadata.AddNestedType(types[index], types[index - 1]);
        }

        var nullableType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("NullableAttribute"));
        var nullableConstructor = metadata.AddMemberReference(
            nullableType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(Array.Empty<byte>()));
        var nullableValue = new BlobBuilder();
        nullableValue.WriteUInt16(1);
        nullableValue.WriteByte(1);
        nullableValue.WriteUInt16(0);
        var nullableValueHandle = metadata.GetOrAddBlob(nullableValue);
        foreach (var type in types)
        {
            var parameter = metadata.AddGenericParameter(
                type,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("T"),
                index: 0);
            metadata.AddCustomAttribute(parameter, nullableConstructor, nullableValueHandle);
        }

        using var fixture = Serialize(metadata);
        var budget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: types.Count,
            constraintRows: 8,
            characters: 64 * 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var resolver = new ManagedSymbolReader.TypeGenericParameterResolver(fixture.Reader, budget);

        for (var index = 0; index < 64; index++)
        {
            var result = resolver.Read(types[index]);
            Assert.True(result.Complete);
            Assert.Equal(index, result.DeclaringTypeDepth);
        }

        var overflow = resolver.Read(types[64]);

        Assert.False(overflow.Complete);
        Assert.Equal(64, overflow.DeclaringTypeDepth);
        Assert.True(budget.Truncated);

        var reverseBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: types.Count,
            constraintRows: 8,
            characters: 64 * 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var reverseResolver = new ManagedSymbolReader.TypeGenericParameterResolver(
            fixture.Reader,
            reverseBudget);

        var reverseOverflow = reverseResolver.Read(types[64]);
        Assert.False(reverseOverflow.Complete);
        for (var index = 0; index < 64; index++)
        {
            var result = reverseResolver.Read(types[index]);
            Assert.True(result.Complete);
            Assert.Equal(index, result.DeclaringTypeDepth);
        }

        Assert.True(reverseBudget.Truncated);
    }

    private static MetadataBuilder CreateMetadata(out ModuleDefinitionHandle module)
    {
        var metadata = new MetadataBuilder();
        module = metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("GenericAttributeTests"),
            mvid: metadata.GetOrAddGuid(new Guid("4b706414-a0e0-4c83-a0de-7e3bbdc0b5e9")),
            encId: default,
            encBaseId: default);
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        return metadata;
    }

    private static MetadataFixture Serialize(MetadataBuilder metadata)
    {
        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(metadataImage, methodBodyStreamRva: 0, mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        return new MetadataFixture(provider);
    }

    private sealed class MetadataFixture : IDisposable
    {
        private readonly MetadataReaderProvider _provider;

        public MetadataFixture(MetadataReaderProvider provider)
        {
            _provider = provider;
            Reader = provider.GetMetadataReader();
        }

        public MetadataReader Reader { get; }

        public void Dispose() => _provider.Dispose();
    }
}
