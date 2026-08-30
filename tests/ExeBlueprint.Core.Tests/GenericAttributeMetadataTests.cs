using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text.Json;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

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
    public void LegacyJsonDefaultsNewGenericEvidenceToUnknown()
    {
        var type = JsonSerializer.Deserialize<TypeModel>(
            """
            {
              "FullName": "Tests.Legacy",
              "Namespace": "Tests",
              "Name": "Legacy",
              "Kind": "class",
              "Accessibility": "internal",
              "GenericParameterDetails": [
                {
                  "Position": 0,
                  "Name": "T",
                  "Variance": "none",
                  "Nullability": "oblivious"
                }
              ]
            }
            """);
        var method = JsonSerializer.Deserialize<MethodModel>(
            """
            {
              "Name": "Method",
              "Signature": "void Method<T>()",
              "ReturnType": "void",
              "Accessibility": "internal"
            }
            """);

        Assert.NotNull(type);
        Assert.False(type.GenericParameterDomainComplete);
        Assert.Null(Assert.Single(type.GenericParameterDetails).ProvenPrimaryConstraintKind);
        Assert.NotNull(method);
        Assert.False(method.GenericParameterDomainComplete);
    }

    [Fact]
    public void ProvesOnlyPlainStructPrimaryFromCompleteRawEvidence()
    {
        var metadata = CreateMetadata(out var module);
        var fixtureType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("EvidenceFixture`7"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var valueType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("ValueType"));
        var unknownInterface = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("IExternal`1"));
        var requiredModifier = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("RequiredModifier"));
        var unmanagedModifier = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System.Runtime.InteropServices"),
            metadata.GetOrAddString("UnmanagedType"));
        var unmanagedAttribute = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("IsUnmanagedAttribute"));
        var unmanagedConstructor = metadata.AddMemberReference(
            unmanagedAttribute,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(Array.Empty<byte>()));
        var unmanagedAttributeValue = new BlobBuilder();
        unmanagedAttributeValue.WriteUInt16(1);
        unmanagedAttributeValue.WriteUInt16(0);

        const GenericParameterAttributes structAttributes =
            GenericParameterAttributes.NotNullableValueTypeConstraint |
            GenericParameterAttributes.DefaultConstructorConstraint;
        var plain = metadata.AddGenericParameter(
            fixtureType,
            structAttributes,
            metadata.GetOrAddString("TPlain"),
            index: 0);
        metadata.AddGenericParameterConstraint(plain, valueType);
        metadata.AddGenericParameterConstraint(
            plain,
            AddGenericConstraintSpecification(metadata, unknownInterface, genericParameterIndex: 0));

        var unmanaged = metadata.AddGenericParameter(
            fixtureType,
            structAttributes,
            metadata.GetOrAddString("TUnmanaged"),
            index: 1);
        metadata.AddGenericParameterConstraint(
            unmanaged,
            AddModifiedConstraintSpecification(metadata, unmanagedModifier, valueType));
        metadata.AddCustomAttribute(
            unmanaged,
            unmanagedConstructor,
            metadata.GetOrAddBlob(unmanagedAttributeValue));

        var allowsRefStruct = metadata.AddGenericParameter(
            fixtureType,
            structAttributes | GenericParameterAttributes.AllowByRefLike,
            metadata.GetOrAddString("TAllowsRefStruct"),
            index: 2);
        metadata.AddGenericParameterConstraint(allowsRefStruct, valueType);

        var duplicateMarker = metadata.AddGenericParameter(
            fixtureType,
            structAttributes,
            metadata.GetOrAddString("TDuplicateMarker"),
            index: 3);
        metadata.AddGenericParameterConstraint(duplicateMarker, valueType);
        metadata.AddGenericParameterConstraint(duplicateMarker, valueType);

        var modifiedMarker = metadata.AddGenericParameter(
            fixtureType,
            structAttributes,
            metadata.GetOrAddString("TModifiedMarker"),
            index: 4);
        metadata.AddGenericParameterConstraint(
            modifiedMarker,
            AddModifiedConstraintSpecification(metadata, requiredModifier, valueType));

        metadata.AddGenericParameter(
            fixtureType,
            structAttributes,
            metadata.GetOrAddString("TMissingMarker"),
            index: 5);
        metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TNone"),
            index: 6);

        using var fixture = Serialize(metadata);
        var result = ManagedSymbolReader.ReadGenericParametersWithEvidence(
            fixture.Reader,
            fixture.Reader.GetTypeDefinition(fixtureType).GetGenericParameters(),
            fixtureType,
            new ManagedSymbolReader.GenericMetadataBudget(),
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);
        var parameters = result.Parameters.ToDictionary(parameter => parameter.Name);

        Assert.True(result.DomainComplete);
        Assert.False(parameters["TPlain"].Complete);
        Assert.Equal("struct", parameters["TPlain"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TUnmanaged"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TAllowsRefStruct"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TDuplicateMarker"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TModifiedMarker"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TMissingMarker"].ProvenPrimaryConstraintKind);
        Assert.Equal("none", parameters["TNone"].ProvenPrimaryConstraintKind);
    }

    [Fact]
    public void KeepsDomainAndPrimaryProofFailClosedAcrossIndependentTruncation()
    {
        var metadata = CreateMetadata(out var module);
        var fixtureType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("TruncatedEvidenceFixture`2"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var valueType = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("ValueType"));
        var unknownInterface = metadata.AddTypeReference(
            module,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("IExternal`1"));
        var constrained = metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.NotNullableValueTypeConstraint |
            GenericParameterAttributes.DefaultConstructorConstraint,
            metadata.GetOrAddString("TStruct"),
            index: 0);
        metadata.AddGenericParameterConstraint(constrained, valueType);
        metadata.AddGenericParameterConstraint(
            constrained,
            AddGenericConstraintSpecification(metadata, unknownInterface, genericParameterIndex: 0));
        metadata.AddGenericParameter(
            fixtureType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TPeer"),
            index: 1);

        var gappedPositionType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GappedPosition`2"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddGenericParameter(
            gappedPositionType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TFirst"),
            index: 0);
        metadata.AddGenericParameter(
            gappedPositionType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TSecond"),
            index: 2);

        var emptyNameType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("EmptyName`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddGenericParameter(
            emptyNameType,
            GenericParameterAttributes.None,
            name: default,
            index: 0);

        using var fixture = Serialize(metadata);
        var handles = fixture.Reader.GetTypeDefinition(fixtureType).GetGenericParameters();
        var parameterBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 1,
            constraintRows: 8,
            characters: 1_024,
            ownerConstraintRows: 8,
            ownerCharacters: 1_024);
        var truncatedDomain = ManagedSymbolReader.ReadGenericParametersWithEvidence(
            fixture.Reader,
            handles,
            fixtureType,
            parameterBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);

        Assert.False(truncatedDomain.DomainComplete);
        Assert.Equal("struct", Assert.Single(truncatedDomain.Parameters).ProvenPrimaryConstraintKind);
        Assert.True(parameterBudget.Truncated);

        var constraintBudget = new ManagedSymbolReader.GenericMetadataBudget(
            parameterRows: 2,
            constraintRows: 1,
            characters: 1_024,
            ownerConstraintRows: 1,
            ownerCharacters: 1_024);
        var truncatedPrimary = ManagedSymbolReader.ReadGenericParametersWithEvidence(
            fixture.Reader,
            handles,
            fixtureType,
            constraintBudget,
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);

        Assert.True(truncatedPrimary.DomainComplete);
        Assert.Null(truncatedPrimary.Parameters[0].ProvenPrimaryConstraintKind);
        Assert.True(constraintBudget.Truncated);

        var gappedDomain = ManagedSymbolReader.ReadGenericParametersWithEvidence(
            fixture.Reader,
            fixture.Reader.GetTypeDefinition(gappedPositionType).GetGenericParameters(),
            gappedPositionType,
            new ManagedSymbolReader.GenericMetadataBudget(),
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);
        Assert.False(gappedDomain.DomainComplete);

        var emptyNameDomain = ManagedSymbolReader.ReadGenericParametersWithEvidence(
            fixture.Reader,
            fixture.Reader.GetTypeDefinition(emptyNameType).GetGenericParameters(),
            emptyNameType,
            new ManagedSymbolReader.GenericMetadataBudget(),
            inheritedParameterCount: 0,
            inheritedParameters: null,
            inheritedDomainParameters: null);
        Assert.False(emptyNameDomain.DomainComplete);
        Assert.Null(Assert.Single(emptyNameDomain.Parameters).ProvenPrimaryConstraintKind);
    }

    [Fact]
    public async Task PublishesDomainEvidenceWithoutDowngradingUnmanagedOrRefStruct()
    {
        var assemblyPath = typeof(GenericConstraintFixture<,,,,,>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var types = document.Files[0].Code!.Types;
        var constrainedType = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericConstraintFixture");
        var parameters = constrainedType.GenericParameterDetails.ToDictionary(parameter => parameter.Name);

        Assert.True(constrainedType.GenericParameterDomainComplete);
        Assert.Equal("struct", parameters["TStruct"].ProvenPrimaryConstraintKind);
        Assert.Null(parameters["TUnmanaged"].ProvenPrimaryConstraintKind);
        Assert.True(Assert.Single(
            constrainedType.Methods,
            method => method.Name == "Method").GenericParameterDomainComplete);
        Assert.True(Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericConstraintFixture.Nested")
            .GenericParameterDomainComplete);

        var allowsRefStruct = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.IAllowsRefStructFixture");
        Assert.True(allowsRefStruct.GenericParameterDomainComplete);
        Assert.Null(Assert.Single(allowsRefStruct.GenericParameterDetails).ProvenPrimaryConstraintKind);

        var incompleteSecondary = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NullableTypeConstraintFixture");
        Assert.False(incompleteSecondary.GenericParametersComplete);
        Assert.True(incompleteSecondary.GenericParameterDomainComplete);
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
        Assert.True(nestedResult.DomainComplete);
        Assert.True(declaringResult.DomainComplete);
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
        Assert.True(outerResult.DomainComplete);
        Assert.False(middleResult.Complete);
        Assert.False(middleResult.DomainComplete);
        Assert.Empty(middleResult.Parameters);
        Assert.False(childResult.Complete);
        Assert.False(childResult.DomainComplete);
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
        Assert.False(overflow.DomainComplete);
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
        Assert.False(reverseOverflow.DomainComplete);
        for (var index = 0; index < 64; index++)
        {
            var result = reverseResolver.Read(types[index]);
            Assert.True(result.Complete);
            Assert.Equal(index, result.DeclaringTypeDepth);
        }

        Assert.True(reverseBudget.Truncated);
    }

    private static TypeSpecificationHandle AddGenericConstraintSpecification(
        MetadataBuilder metadata,
        EntityHandle genericType,
        int genericParameterIndex)
    {
        var signature = new BlobBuilder();
        var type = new BlobEncoder(signature).TypeSpecificationSignature();
        type.GenericInstantiation(genericType, genericArgumentCount: 1, isValueType: false)
            .AddArgument()
            .GenericTypeParameter(genericParameterIndex);
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static TypeSpecificationHandle AddModifiedConstraintSpecification(
        MetadataBuilder metadata,
        EntityHandle modifier,
        EntityHandle unmodifiedType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x1F); // ELEMENT_TYPE_CMOD_REQD
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifier));
        signature.WriteByte(0x12); // ELEMENT_TYPE_CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(unmodifiedType));
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
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
