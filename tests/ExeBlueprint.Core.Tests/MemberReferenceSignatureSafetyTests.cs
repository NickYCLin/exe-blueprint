using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class MemberReferenceSignatureSafetyTests
{
    [Fact]
    public void AcceptsCanonicalPlainMethodAndFieldSignatures()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["return Tests.Target.Echo(arg0);"],
                ReconstructCall(fixture.Reader, fixture.CanonicalMethod, "int", ["int"])),
            () => Assert.Equal(
                ["return Tests.Target.Value;"],
                ReconstructField(fixture.Reader, fixture.CanonicalField, "int")));
    }

    [Fact]
    public void RejectsMalformedOrUntrustedPlainMemberReferences()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.TrailingMethod,
                "int",
                ["int"])),
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.TruncatedMethod,
                "int",
                ["int"])),
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.NonCanonicalParameterCountMethod,
                "int",
                ["int"])),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.NonCanonicalTypeHandleMethod)),
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.NonTypeParentMethod,
                "int",
                ["int"])),
            () => Assert.Null(ReconstructField(
                fixture.Reader,
                fixture.TrailingField,
                "int")),
            () => Assert.Null(ReconstructField(
                fixture.Reader,
                fixture.TruncatedField,
                "int")),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.NonCanonicalTypeHandleField)),
            () => Assert.Null(ReconstructField(
                fixture.Reader,
                fixture.NonTypeParentField,
                "int")));
    }

    [Fact]
    public void SubstitutesClosedTypeSpecificationArgumentsForMethodsAndFields()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["return Tests.GenericBox<string>.Echo(arg0);"],
                ReconstructCall(
                    fixture.Reader,
                    fixture.ClosedGenericMethod,
                    "string",
                    ["string"])),
            () => Assert.Equal(
                ["return Tests.GenericBox<string>.Value;"],
                ReconstructField(
                    fixture.Reader,
                    fixture.ClosedGenericField,
                    "string")));
    }

    [Fact]
    public void RejectsMalformedClosedTypeSpecificationParents()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.TrailingTypeSpecificationMethod,
                "string",
                ["string"])),
            () => Assert.Null(ReconstructField(
                fixture.Reader,
                fixture.TrailingTypeSpecificationField,
                "string")),
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.NonCanonicalArgumentCountTypeSpecificationMethod,
                "string",
                ["string"])),
            () => Assert.Null(ReconstructField(
                fixture.Reader,
                fixture.NonCanonicalArgumentCountTypeSpecificationField,
                "string")));
    }

    [Fact]
    public void RejectsUnrepresentedCustomModifiersInMemberTypes()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.ModifiedReturnMethod)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.ModifiedField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.NestedModifiedField)));
    }

    [Fact]
    public void RejectsUninstantiatedAndMismatchedGenericMemberTypes()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.UninstantiatedGenericReturnMethod)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.UninstantiatedGenericField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.MismatchedGenericArityField)));
    }

    [Fact]
    public void RejectsInvalidParentsGenericDomainsAndNameBudgets()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.False(ManagedSymbolReader.ValidateMemberReferenceMethodForTest(
                fixture.Reader,
                fixture.CyclicTypeSpecificationMethod)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.PrimitiveTypeSpecificationField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.GappedGenericDomainField)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.OversizedNameMethod)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.DeepTypeReferenceMethod)));
    }

    [Fact]
    public void RejectsFunctionPointerSignaturesPastTheSharedDepthBudget()
    {
        using var fixture = CreateFixture();

        Assert.Null(ReconstructDiscardedCall(
            fixture.Reader,
            fixture.DeepFunctionPointerMethod));
    }

    [Fact]
    public void RejectsReusedTypeSpecificationsPastTheExpandedBudget()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.True(ManagedSymbolReader.ValidateMemberReferenceMethodForTest(
                fixture.Reader,
                fixture.WithinExpandedTypeSpecificationBudgetMethod)),
            () => Assert.False(ManagedSymbolReader.ValidateMemberReferenceMethodForTest(
                fixture.Reader,
                fixture.ExpandingTypeSpecificationMethod)));
    }

    [Fact]
    public void AppliesTheClosedParentDomainToNestedTypeSpecifications()
    {
        using var fixture = CreateFixture();

        var valid = ManagedSymbolReader.ValidateMemberReferenceMethodForTest(
            fixture.Reader,
            fixture.InRangeNestedTypeSpecificationMethod,
            fixture.TwoTypeGenericCallerMethod);
        var outOfRange = ManagedSymbolReader.ValidateMemberReferenceMethodForTest(
            fixture.Reader,
            fixture.OutOfRangeNestedTypeSpecificationMethod,
            fixture.TwoTypeGenericCallerMethod);

        Assert.Multiple(
            () => Assert.True(valid),
            () => Assert.False(outOfRange));
    }

    [Fact]
    public void RejectsTypeGrammarTokensOutsideTheirEcmaPositions()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.ByReferenceField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.TypedReferenceField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.ArrayOfByReferenceField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.GenericOfTypedReferenceField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.SzArrayOfVoidField)));
    }

    [Fact]
    public void RejectsUnsupportedFunctionPointersThroughTypeWrappers()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.ArrayOfUnsupportedFunctionPointerField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.GenericOfUnsupportedFunctionPointerField)),
            () => Assert.Null(ReconstructDiscardedField(
                fixture.Reader,
                fixture.UntrustedConventionFunctionPointerField)));
    }

    [Fact]
    public void RejectsMismatchedLocalTypeDefinitionKinds()
    {
        using var fixture = CreateFixture();

        Assert.Null(ReconstructDiscardedField(
            fixture.Reader,
            fixture.ClassEncodedAsValueTypeField));
    }

    [Fact]
    public void ValidatesOpenTypeSpecificationSlotsAgainstTheCallerDomain()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["box.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x6F, fixture.OpenTypeSlotInstanceMethod),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Equal(
                ["box.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x6F, fixture.OpenMethodSlotInstanceMethod),
                    fixture.MethodGenericCallerMethod)),
            () => Assert.Equal(
                ["box.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x6F, fixture.OpenTypeSlotInstanceMethod),
                    fixture.RenamedNestedTypeGenericCallerMethod)),
            () => Assert.Equal(
                ["Tests.Caller<!0>.Take(box);"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x28, fixture.SameOwnerGenericArgumentMethod),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x02], 0x28, fixture.DifferentOwnerGenericArgumentMethod),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x02], 0x28, fixture.UnownedTypeReferenceSlotMethod),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ReconstructVoidCall(
                fixture.Reader,
                fixture.OpenTypeSlotStaticMethod)),
            () => Assert.Null(ReconstructVoidCall(
                fixture.Reader,
                fixture.OpenMethodSlotStaticMethod)),
            () => Assert.Equal(
                ["Tests.GenericBox<!0>.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([], 0x28, fixture.OpenTypeSlotStaticMethod),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Equal(
                ["Tests.GenericBox<!!0>.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([], 0x28, fixture.OpenMethodSlotStaticMethod),
                    fixture.MethodGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([], 0x28, fixture.OutOfRangeTypeSlotStaticMethod),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([], 0x28, fixture.OutOfRangeMethodSlotStaticMethod),
                fixture.MethodGenericCallerMethod)));
    }

    [Fact]
    public void QualifiesGenericStaticFieldsWithTheProvenOwnerInstantiation()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["Tests.Caller<!0>.DefinitionValue = Tests.Caller<!0>.DefinitionValue;"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildStaticFieldRoundTrip(
                        fixture.SameOwnerFieldDefinition,
                        fixture.SameOwnerFieldDefinition),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Equal(
                ["Tests.Caller<!0>.ReferenceValue = Tests.Caller<!0>.ReferenceValue;"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildStaticFieldRoundTrip(
                        fixture.SameOwnerFieldReference,
                        fixture.SameOwnerFieldReference),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildStaticFieldRoundTrip(
                    fixture.DifferentOwnerFieldDefinition,
                    fixture.DifferentOwnerFieldDefinition),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildStaticFieldRoundTrip(
                    fixture.DifferentOwnerFieldReference,
                    fixture.DifferentOwnerFieldReference),
                fixture.TypeGenericCallerMethod)));
    }

    [Fact]
    public void ComparesSameTextArgumentTypesByTheirNominalIdentity()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["Tests.Target.TakeValue(value);"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x28, fixture.SameNominalIdentityMethod),
                    fixture.NominalCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x02], 0x28, fixture.DifferentNominalIdentityMethod),
                fixture.NominalCallerMethod)));
    }

    [Fact]
    public void QualifiesGenericMethodDefinitionsOnlyForTheCurrentOwner()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["Tests.Caller<!0>.InvokeType(box);"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl([0x02], 0x28, fixture.TypeGenericCallerMethod),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([], 0x28, fixture.TwoTypeGenericCallerMethod),
                fixture.TypeGenericCallerMethod)));
    }

    [Fact]
    public void ValidatesConstructedReceiversAndFieldOpcodeKinds()
    {
        using var fixture = CreateFixture();

        var matchingLoad = ManagedSymbolReader.ReconstructMethodForTest(
            fixture.Reader,
            BuildTokenIl(
                [0x02],
                0x7B,
                fixture.SameConstructedReceiverField),
            fixture.ConstructedFieldCallerMethod);

        Assert.Multiple(
            () => Assert.Equal(
                ["box.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl(
                        [0x02],
                        0x6F,
                        fixture.SameConstructedReceiverMethod),
                    fixture.ConstructedCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x6F,
                    fixture.DifferentConstructedReceiverMethod),
                fixture.ConstructedCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x6F,
                    fixture.SameTextDifferentConstructedReceiverMethod),
                fixture.ConstructedCallerMethod)),
            () => Assert.Equal(
                ["contract.Ping();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl(
                        [0x02],
                        0x6F,
                        fixture.SameConstructedInterfaceMethod),
                    fixture.InterfaceCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x6F,
                    fixture.DifferentConstructedInterfaceMethod),
                fixture.InterfaceCallerMethod)),
            () => Assert.Equal(["return box.Value;"], matchingLoad),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x7B,
                    fixture.SameConstructedReceiverField,
                    popResult: true),
                fixture.ConstructedCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x7B,
                    fixture.DifferentConstructedReceiverField),
                fixture.ConstructedFieldCallerMethod)),
            () => Assert.Equal(
                ["box.Value = 1;"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl(
                        [0x02, 0x17],
                        0x7D,
                        fixture.SameConstructedReceiverField),
                    fixture.ConstructedCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02, 0x17],
                    0x7D,
                    fixture.DifferentConstructedReceiverField),
                fixture.ConstructedCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [],
                    0x7E,
                    fixture.InstanceFieldDefinition),
                fixture.ConstructedFieldCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x17], 0x80, fixture.InstanceFieldDefinition),
                fixture.NominalCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02],
                    0x7B,
                    fixture.NominalStaticFieldDefinition),
                fixture.ConstructedFieldCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02, 0x17],
                    0x7D,
                    fixture.SameOwnerFieldDefinition),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x17], 0x80, fixture.LiteralFieldDefinition),
                fixture.NominalCallerMethod)));
    }

    [Fact]
    public void RejectsUnrepresentableCallingConventionsWithoutDroppingGraphIdentity()
    {
        using var fixture = CreateFixture();

        var varArgGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod, fixture.VarArgSentinelMethod));
        var explicitThisGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod, fixture.ExplicitThisMethod),
            fixture.ConstructedCallerMethod);

        Assert.Multiple(
            () => Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
                fixture.Reader,
                BuildTokenIl([0x16, 0x17], 0x28, fixture.VarArgSentinelMethod),
                isInstance: false,
                returnType: "void")),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl([0x02], 0x6F, fixture.ExplicitThisMethod),
                fixture.ConstructedCallerMethod)),
            () => Assert.True(varArgGraph.Complete),
            () => Assert.Equal(2, varArgGraph.EdgeCount),
            () => Assert.True(explicitThisGraph.Complete),
            () => Assert.Equal(2, explicitThisGraph.EdgeCount));
    }

    [Fact]
    public void RejectsRankOneMdArraysAndPreservesZeroLowerBounds()
    {
        using var fixture = CreateFixture();

        var rankOneGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod, fixture.RankOneArrayGetMethod),
            fixture.RankOneArrayCallerMethod);
        var rankOneSpecificationGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.RankOneArrayMethodSpecification));
        var zeroLowerBoundGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.ZeroLowerBoundArrayGetMethod));
        var nonzeroLowerBoundGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.NonzeroLowerBoundArrayGetMethod));

        Assert.Multiple(
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [0x02, 0x16],
                    0x28,
                    fixture.RankOneArrayGetMethod),
                fixture.RankOneArrayCallerMethod)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.RankOneArrayMethodSpecification)),
            () => Assert.False(rankOneGraph.Complete),
            () => Assert.Equal(0, rankOneGraph.EdgeCount),
            () => Assert.False(rankOneSpecificationGraph.Complete),
            () => Assert.Equal(0, rankOneSpecificationGraph.EdgeCount),
            () => Assert.True(zeroLowerBoundGraph.Complete),
            () => Assert.Equal(1, zeroLowerBoundGraph.EdgeCount),
            () => Assert.False(nonzeroLowerBoundGraph.Complete),
            () => Assert.Equal(0, nonzeroLowerBoundGraph.EdgeCount));
    }

    [Fact]
    public void RejectsNestedAliasSpoofingAndRenderedSignatureExpansion()
    {
        using var fixture = CreateFixture();

        var aliasGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod, fixture.NestedAliasMethod));
        var aliasSpecificationGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.NestedAliasMethodSpecification));
        var fakeParentGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.FakePrimitiveGenericParentMethod));
        var expansionGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.ExpandingRenderedMethodSpecification));
        var unusedExpansionGraph = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.UnusedExpandingRenderedMethodSpecification));

        Assert.Multiple(
            () => Assert.Null(ReconstructCall(
                fixture.Reader,
                fixture.NestedAliasMethod,
                "void",
                ["int[]"])),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.NestedAliasMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.ExpandingRenderedMethodSpecification)),
            () => Assert.Null(ReconstructVoidCall(
                fixture.Reader,
                fixture.UnusedExpandingRenderedMethodSpecification)),
            () => Assert.Null(ReconstructVoidCall(
                fixture.Reader,
                fixture.FakePrimitiveGenericParentMethod)),
            () => Assert.True(aliasGraph.Complete),
            () => Assert.Equal(2, aliasGraph.EdgeCount),
            () => Assert.False(aliasSpecificationGraph.Complete),
            () => Assert.Equal(0, aliasSpecificationGraph.EdgeCount),
            () => Assert.False(fakeParentGraph.Complete),
            () => Assert.Equal(0, fakeParentGraph.EdgeCount),
            () => Assert.False(expansionGraph.Complete),
            () => Assert.Equal(0, expansionGraph.EdgeCount),
            () => Assert.False(unusedExpansionGraph.Complete),
            () => Assert.Equal(0, unusedExpansionGraph.EdgeCount));
    }

    [Fact]
    public void ValidatesMethodSpecificationsBeforeDecodingOrInstantiation()
    {
        using var fixture = CreateFixture();

        Assert.Multiple(
            () => Assert.Equal(
                ["Tests.Target.Create<int>();"],
                ReconstructDiscardedCall(
                    fixture.Reader,
                    fixture.CanonicalMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.TrailingMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.NonCanonicalMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.UnsupportedWrappedFunctionPointerMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.RestrictedPointerMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.MismatchedArityMethodSpecification)),
            () => Assert.Null(ReconstructDiscardedCall(
                fixture.Reader,
                fixture.MalformedGenericDefinitionMethodSpecification)),
            () => Assert.Equal(
                ["Tests.Target.Create<!0>();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl(
                        [],
                        0x28,
                        fixture.OpenTypeSlotMethodSpecification,
                        popResult: true),
                    fixture.TypeGenericCallerMethod)),
            () => Assert.Equal(
                ["Tests.Target.Create<!!0>();"],
                ManagedSymbolReader.ReconstructMethodForTest(
                    fixture.Reader,
                    BuildTokenIl(
                        [],
                        0x28,
                        fixture.OpenMethodSlotMethodSpecification,
                        popResult: true),
                    fixture.MethodGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [],
                    0x28,
                    fixture.OutOfRangeTypeSlotMethodSpecification,
                    popResult: true),
                fixture.TypeGenericCallerMethod)),
            () => Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
                fixture.Reader,
                BuildTokenIl(
                    [],
                    0x28,
                    fixture.OutOfRangeMethodSlotMethodSpecification,
                    popResult: true),
                fixture.MethodGenericCallerMethod)));
    }

    [Fact]
    public void DiscardsTheWholeMethodCallBatchWhenAnEligibleTargetIsInvalid()
    {
        using var fixture = CreateFixture();

        var control = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod));
        var malformed = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethod, fixture.TrailingMethod));
        var canonicalSpecification = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(fixture.CanonicalMethodSpecification));
        var mismatchedSpecification = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.MismatchedArityMethodSpecification));
        var unsupportedSpecification = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.UnsupportedWrappedFunctionPointerMethodSpecification));
        var restrictedSpecification = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.RestrictedPointerMethodSpecification));
        var trailingSpecification = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethodSpecification,
                fixture.TrailingMethodSpecification));
        var crossGenericMethodDefinition = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.TwoTypeGenericCallerMethod),
            fixture.TypeGenericCallerMethod);
        var malformedGenericDefinition = ManagedSymbolReader.CollectCallsForTest(
            fixture.Reader,
            BuildCallSequence(
                fixture.CanonicalMethod,
                fixture.MalformedGenericDefinitionMethodSpecification));

        Assert.Multiple(
            () => Assert.True(control.Complete),
            () => Assert.Equal(1, control.EdgeCount),
            () => Assert.False(malformed.Complete),
            () => Assert.Equal(0, malformed.EdgeCount),
            () => Assert.True(canonicalSpecification.Complete),
            () => Assert.Equal(1, canonicalSpecification.EdgeCount),
            () => Assert.False(mismatchedSpecification.Complete),
            () => Assert.Equal(0, mismatchedSpecification.EdgeCount),
            () => Assert.False(unsupportedSpecification.Complete),
            () => Assert.Equal(0, unsupportedSpecification.EdgeCount),
            () => Assert.False(restrictedSpecification.Complete),
            () => Assert.Equal(0, restrictedSpecification.EdgeCount),
            () => Assert.False(trailingSpecification.Complete),
            () => Assert.Equal(0, trailingSpecification.EdgeCount),
            () => Assert.True(crossGenericMethodDefinition.Complete),
            () => Assert.Equal(2, crossGenericMethodDefinition.EdgeCount),
            () => Assert.False(malformedGenericDefinition.Complete),
            () => Assert.Equal(0, malformedGenericDefinition.EdgeCount));
    }

    private static IReadOnlyList<string>? ReconstructCall(
        MetadataReader metadata,
        MemberReferenceHandle target,
        string returnType,
        IReadOnlyList<string> parameterTypes) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildTokenIl([0x02], 0x28, target), // ldarg.0; call; ret
            isInstance: false,
            returnType,
            parameterTypes: parameterTypes);

    private static IReadOnlyList<string>? ReconstructField(
        MetadataReader metadata,
        MemberReferenceHandle target,
        string returnType) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildTokenIl([], 0x7E, target), // ldsfld; ret
            isInstance: false,
            returnType);

    private static IReadOnlyList<string>? ReconstructDiscardedCall(
        MetadataReader metadata,
        EntityHandle target) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildTokenIl([], 0x28, target, popResult: true), // call; pop; ret
            isInstance: false,
            returnType: "void");

    private static IReadOnlyList<string>? ReconstructVoidCall(
        MetadataReader metadata,
        EntityHandle target) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildTokenIl([], 0x28, target), // call; ret
            isInstance: false,
            returnType: "void");

    private static IReadOnlyList<string>? ReconstructDiscardedField(
        MetadataReader metadata,
        MemberReferenceHandle target) =>
        ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            BuildStaticFieldRoundTrip(target, target), // ldsfld; stsfld; ret
            isInstance: false,
            returnType: "void");

    private static MetadataFixture CreateFixture()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("MemberReferenceSignatureSafety.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("9941696e-0776-4f3f-969f-aee2ebd8db09")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("MemberReferenceSignatureSafety"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var gappedGenericType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GappedGeneric`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddGenericParameter(
            gappedGenericType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 1);
        var localClassType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("LocalClass"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var callerGenericType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Caller`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var outerGenericType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Outer`1"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(2),
            MetadataTokens.MethodDefinitionHandle(3));
        var renamedNestedGenericType = metadata.AddTypeDefinition(
            TypeAttributes.NestedPrivate,
            @namespace: default,
            metadata.GetOrAddString("Inner"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(2),
            MetadataTokens.MethodDefinitionHandle(3));
        metadata.AddNestedType(renamedNestedGenericType, outerGenericType);
        var twoTypeGenericCallerType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("CallerTwo`2"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(2),
            MetadataTokens.MethodDefinitionHandle(4));
        var nominalCallerType = metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("NominalCaller"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(3),
            MetadataTokens.MethodDefinitionHandle(5));

        var contracts = metadata.AddAssemblyReference(
            metadata.GetOrAddString("Fixture.Contracts"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKeyOrToken: default,
            flags: (AssemblyFlags)0,
            hashValue: default);
        var alternateContracts = metadata.AddAssemblyReference(
            metadata.GetOrAddString("Fixture.AlternateContracts"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKeyOrToken: default,
            flags: (AssemblyFlags)0,
            hashValue: default);
        var spoofedSystemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: AddBlob(metadata, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var targetType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Target"));
        var genericBoxType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericBox`1"));
        var alternateGenericBoxType = metadata.AddTypeReference(
            alternateContracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericBox`1"));
        var genericInterfaceType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("IGeneric`1"));
        var fakePrimitiveGenericType = metadata.AddTypeReference(
            contracts,
            @namespace: default,
            metadata.GetOrAddString("int`1"));
        var openGenericBoxFieldSignature = AddOpenGenericBoxFieldSignature(
            metadata,
            genericBoxType);
        var sameOwnerFieldDefinition = metadata.AddFieldDefinition(
            FieldAttributes.Public | FieldAttributes.Static,
            metadata.GetOrAddString("DefinitionValue"),
            openGenericBoxFieldSignature);
        var differentOwnerFieldDefinition = metadata.AddFieldDefinition(
            FieldAttributes.Public | FieldAttributes.Static,
            metadata.GetOrAddString("DifferentDefinitionValue"),
            openGenericBoxFieldSignature);
        var instanceFieldDefinition = metadata.AddFieldDefinition(
            FieldAttributes.Public,
            metadata.GetOrAddString("InstanceValue"),
            AddBlob(metadata, 0x06, 0x08));
        var literalFieldDefinition = metadata.AddFieldDefinition(
            FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal,
            metadata.GetOrAddString("LiteralValue"),
            AddBlob(metadata, 0x06, 0x08));
        var nominalStaticFieldDefinition = metadata.AddFieldDefinition(
            FieldAttributes.Public | FieldAttributes.Static,
            metadata.GetOrAddString("StaticValue"),
            AddBlob(metadata, 0x06, 0x08));
        var mismatchedGenericBoxType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericBox`2"));
        var modifierType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("IsVolatile"));
        var untrustedCallConventionType = metadata.AddTypeReference(
            spoofedSystemRuntime,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("CallConvCdecl"));
        var pairType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Pair`2"));
        var firstValueType = metadata.AddTypeReference(
            contracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Value"));
        var secondValueType = metadata.AddTypeReference(
            alternateContracts,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Value"));
        var fakeIntType = metadata.AddTypeReference(
            contracts,
            @namespace: default,
            metadata.GetOrAddString("int"));
        EntityHandle largeRenderedTypeReference = contracts;
        for (var depth = 0; depth < 64; depth++)
        {
            largeRenderedTypeReference = metadata.AddTypeReference(
                largeRenderedTypeReference,
                @namespace: default,
                metadata.GetOrAddString(new string('L', 1_024)));
        }

        EntityHandle deepTypeReference = contracts;
        for (var depth = 0; depth <= 64; depth++)
        {
            deepTypeReference = metadata.AddTypeReference(
                deepTypeReference,
                @namespace: default,
                metadata.GetOrAddString($"Nested{depth}"));
        }

        var nonTypeParent = metadata.AddModuleReference(
            metadata.GetOrAddString("Native.fixture"));

        var canonicalMethodSignature = AddBlob(metadata, 0x00, 0x01, 0x08, 0x08);
        var canonicalFieldSignature = AddBlob(metadata, 0x06, 0x08);
        var canonicalMethod = AddMember(
            metadata,
            targetType,
            "Echo",
            canonicalMethodSignature);
        var canonicalField = AddMember(
            metadata,
            targetType,
            "Value",
            canonicalFieldSignature);
        var varArgSentinelMethod = AddMember(
            metadata,
            targetType,
            "VarArg",
            AddBlob(metadata, 0x05, 0x02, 0x01, 0x08, 0x41, 0x08));
        var nestedAliasMethod = AddMember(
            metadata,
            targetType,
            "TakeAlias",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x01, 0x01, 0x1D, 0x12],
                fakeIntType));
        var sameOwnerFieldReference = AddMember(
            metadata,
            callerGenericType,
            "ReferenceValue",
            openGenericBoxFieldSignature);
        var differentOwnerFieldReference = AddMember(
            metadata,
            twoTypeGenericCallerType,
            "DifferentReferenceValue",
            openGenericBoxFieldSignature);
        var sameNominalIdentityMethod = AddMember(
            metadata,
            targetType,
            "TakeValue",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x01, 0x01, 0x12],
                firstValueType));
        var differentNominalIdentityMethod = AddMember(
            metadata,
            targetType,
            "TakeValue",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x01, 0x01, 0x12],
                secondValueType));

        var trailingMethod = AddMember(
            metadata,
            targetType,
            "Echo",
            AddBlob(metadata, 0x00, 0x01, 0x08, 0x08, 0x00));
        var truncatedMethod = AddMember(
            metadata,
            targetType,
            "Echo",
            AddBlob(metadata, 0x00, 0x01, 0x08));
        var nonCanonicalParameterCountMethod = AddMember(
            metadata,
            targetType,
            "Echo",
            AddBlob(metadata, 0x00, 0x80, 0x01, 0x08, 0x08));
        var nonCanonicalTypeHandleMethod = AddMember(
            metadata,
            targetType,
            "Create",
            AddSignatureWithNonCanonicalTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                targetType));
        var nonTypeParentMethod = AddMember(
            metadata,
            nonTypeParent,
            "Echo",
            canonicalMethodSignature);

        var trailingField = AddMember(
            metadata,
            targetType,
            "Value",
            AddBlob(metadata, 0x06, 0x08, 0x00));
        var truncatedField = AddMember(
            metadata,
            targetType,
            "Value",
            AddBlob(metadata, 0x06));
        var nonCanonicalTypeHandleField = AddMember(
            metadata,
            targetType,
            "Instance",
            AddSignatureWithNonCanonicalTypeHandle(
                metadata,
                [0x06, 0x12],
                targetType));
        var nonTypeParentField = AddMember(
            metadata,
            nonTypeParent,
            "Value",
            canonicalFieldSignature);
        var modifiedReturnMethod = AddMember(
            metadata,
            targetType,
            "ReadModified",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x1F],
                modifierType,
                0x08));
        var modifiedField = AddMember(
            metadata,
            targetType,
            "ModifiedValue",
            AddSignatureWithTypeHandle(
                metadata,
                [0x06, 0x20],
                modifierType,
                0x08));
        var nestedModifiedField = AddMember(
            metadata,
            targetType,
            "ModifiedValues",
            AddSignatureWithTypeHandle(
                metadata,
                [0x06, 0x1D, 0x1F],
                modifierType,
                0x08));
        var byReferenceField = AddMember(
            metadata,
            targetType,
            "ByReferenceValue",
            AddBlob(metadata, 0x06, 0x10, 0x08));
        var typedReferenceField = AddMember(
            metadata,
            targetType,
            "TypedReferenceValue",
            AddBlob(metadata, 0x06, 0x16));
        var arrayOfByReferenceField = AddMember(
            metadata,
            targetType,
            "ArrayOfByReference",
            AddBlob(metadata, 0x06, 0x14, 0x10, 0x08, 0x01, 0x00, 0x00));
        var genericOfTypedReferenceField = AddMember(
            metadata,
            targetType,
            "GenericOfTypedReference",
            AddGenericInstantiationFieldSignature(
                metadata,
                genericBoxType,
                genericArgumentCount: 1,
                genericArgumentTypeCode: 0x16));
        var szArrayOfVoidField = AddMember(
            metadata,
            targetType,
            "SzArrayOfVoid",
            AddBlob(metadata, 0x06, 0x1D, 0x01));
        var arrayOfUnsupportedFunctionPointerField = AddMember(
            metadata,
            targetType,
            "ArrayOfUnsupportedFunctionPointer",
            AddBlob(metadata, 0x06, 0x1D, 0x1B, 0x05, 0x00, 0x08));
        var genericOfUnsupportedFunctionPointerField = AddMember(
            metadata,
            targetType,
            "GenericOfUnsupportedFunctionPointer",
            AddGenericFunctionPointerFieldSignature(metadata, genericBoxType));
        var untrustedConventionFunctionPointerField = AddMember(
            metadata,
            targetType,
            "UntrustedConventionFunctionPointer",
            AddConventionFunctionPointerFieldSignature(
                metadata,
                untrustedCallConventionType));
        var uninstantiatedGenericReturnMethod = AddMember(
            metadata,
            targetType,
            "ReadOpenGeneric",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                genericBoxType));
        var uninstantiatedGenericField = AddMember(
            metadata,
            targetType,
            "OpenGenericValue",
            AddSignatureWithTypeHandle(
                metadata,
                [0x06, 0x12],
                genericBoxType));
        var mismatchedGenericArityField = AddMember(
            metadata,
            targetType,
            "MismatchedGenericValue",
            AddGenericInstantiationFieldSignature(
                metadata,
                mismatchedGenericBoxType,
                genericArgumentCount: 1));
        var gappedGenericDomainField = AddMember(
            metadata,
            gappedGenericType,
            "Value",
            AddBlob(metadata, 0x06, 0x13, 0x00));
        var classEncodedAsValueTypeField = AddMember(
            metadata,
            targetType,
            "WrongKindValue",
            AddSignatureWithTypeHandle(
                metadata,
                [0x06, 0x11],
                localClassType));
        var oversizedNameMethod = AddMember(
            metadata,
            targetType,
            new string('M', 4_097),
            canonicalMethodSignature);
        var deepTypeReferenceMethod = AddMember(
            metadata,
            deepTypeReference,
            "Read",
            AddBlob(metadata, 0x00, 0x00, 0x08));
        var deepFunctionPointerMethod = AddMember(
            metadata,
            targetType,
            "ReadFunctionPointer",
            AddNestedFunctionPointerMethodSignature(metadata, depth: 65));

        var closedType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            nonCanonicalArgumentCount: false,
            trailingData: false);
        var closedIntType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            nonCanonicalArgumentCount: false,
            trailingData: false,
            genericArgumentTypeCode: 0x08);
        var alternateClosedIntType = AddClosedGenericBoxTypeSpecification(
            metadata,
            alternateGenericBoxType,
            nonCanonicalArgumentCount: false,
            trailingData: false,
            genericArgumentTypeCode: 0x08);
        var closedIntInterfaceType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericInterfaceType,
            nonCanonicalArgumentCount: false,
            trailingData: false,
            genericArgumentTypeCode: 0x08);
        var closedStringInterfaceType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericInterfaceType,
            nonCanonicalArgumentCount: false,
            trailingData: false);
        var fakePrimitiveGenericSpecification = AddClosedGenericBoxTypeSpecification(
            metadata,
            fakePrimitiveGenericType,
            nonCanonicalArgumentCount: false,
            trailingData: false);
        var rankOneArrayType = metadata.AddTypeSpecification(
            AddBlob(metadata, 0x14, 0x08, 0x01, 0x00, 0x00));
        var zeroLowerBoundArrayType = metadata.AddTypeSpecification(
            AddBlob(metadata, 0x14, 0x08, 0x02, 0x00, 0x01, 0x00));
        var nonzeroLowerBoundArrayType = metadata.AddTypeSpecification(
            AddBlob(metadata, 0x14, 0x08, 0x02, 0x00, 0x01, 0x02));
        var trailingClosedType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            nonCanonicalArgumentCount: false,
            trailingData: true);
        var nonCanonicalArgumentCountClosedType = AddClosedGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            nonCanonicalArgumentCount: true,
            trailingData: false);
        var inRangeNestedTypeSpecification = AddOpenArrayTypeSpecification(
            metadata,
            genericParameterIndex: 0);
        var outOfRangeNestedTypeSpecification = AddOpenArrayTypeSpecification(
            metadata,
            genericParameterIndex: 1);
        var primitiveTypeSpecification = metadata.AddTypeSpecification(
            AddBlob(metadata, 0x08));
        var cyclicTypeSpecificationHandle = MetadataTokens.TypeSpecificationHandle(
            MetadataTokens.GetRowNumber(primitiveTypeSpecification) + 1);
        var cyclicTypeSpecification = metadata.AddTypeSpecification(
            AddSignatureWithTypeHandle(
                metadata,
                [0x1D, 0x12],
                cyclicTypeSpecificationHandle));
        Assert.Equal(cyclicTypeSpecificationHandle, cyclicTypeSpecification);
        var expandingTypeSpecification = AddLargeArrayTypeSpecification(metadata);
        for (var depth = 0; depth < 4; depth++)
        {
            expandingTypeSpecification = AddDuplicatingGenericTypeSpecification(
                metadata,
                pairType,
                expandingTypeSpecification);
        }
        var withinExpandedTypeSpecificationBudget = expandingTypeSpecification;
        expandingTypeSpecification = AddDuplicatingGenericTypeSpecification(
            metadata,
            pairType,
            expandingTypeSpecification);
        var genericMethodSignature = AddBlob(metadata, 0x00, 0x01, 0x13, 0x00, 0x13, 0x00);
        var genericFieldSignature = AddBlob(metadata, 0x06, 0x13, 0x00);
        var sameConstructedReceiverMethod = AddMember(
            metadata,
            closedIntType,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var differentConstructedReceiverMethod = AddMember(
            metadata,
            closedType,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var sameTextDifferentConstructedReceiverMethod = AddMember(
            metadata,
            alternateClosedIntType,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var sameConstructedInterfaceMethod = AddMember(
            metadata,
            closedIntInterfaceType,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var differentConstructedInterfaceMethod = AddMember(
            metadata,
            closedStringInterfaceType,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var fakePrimitiveGenericParentMethod = AddMember(
            metadata,
            fakePrimitiveGenericSpecification,
            "Ping",
            AddBlob(metadata, 0x00, 0x00, 0x01));
        var explicitThisMethod = AddMember(
            metadata,
            closedIntType,
            "Explicit",
            AddBlob(metadata, 0x60, 0x00, 0x01));
        var sameConstructedReceiverField = AddMember(
            metadata,
            closedIntType,
            "Value",
            canonicalFieldSignature);
        var differentConstructedReceiverField = AddMember(
            metadata,
            closedType,
            "Value",
            canonicalFieldSignature);
        var rankOneArrayGetMethod = AddMember(
            metadata,
            rankOneArrayType,
            "Get",
            AddBlob(metadata, 0x20, 0x01, 0x08, 0x08));
        var zeroLowerBoundArrayGetMethod = AddMember(
            metadata,
            zeroLowerBoundArrayType,
            "Get",
            AddBlob(metadata, 0x20, 0x02, 0x08, 0x08, 0x08));
        var nonzeroLowerBoundArrayGetMethod = AddMember(
            metadata,
            nonzeroLowerBoundArrayType,
            "Get",
            AddBlob(metadata, 0x20, 0x02, 0x08, 0x08, 0x08));
        var closedGenericMethod = AddMember(
            metadata,
            closedType,
            "Echo",
            genericMethodSignature);
        var closedGenericField = AddMember(
            metadata,
            closedType,
            "Value",
            genericFieldSignature);
        var trailingTypeSpecificationMethod = AddMember(
            metadata,
            trailingClosedType,
            "Echo",
            genericMethodSignature);
        var trailingTypeSpecificationField = AddMember(
            metadata,
            trailingClosedType,
            "Value",
            genericFieldSignature);
        var nonCanonicalArgumentCountTypeSpecificationMethod = AddMember(
            metadata,
            nonCanonicalArgumentCountClosedType,
            "Echo",
            genericMethodSignature);
        var nonCanonicalArgumentCountTypeSpecificationField = AddMember(
            metadata,
            nonCanonicalArgumentCountClosedType,
            "Value",
            genericFieldSignature);
        var inRangeNestedTypeSpecificationMethod = AddMember(
            metadata,
            closedType,
            "ReadNested",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                inRangeNestedTypeSpecification));
        var outOfRangeNestedTypeSpecificationMethod = AddMember(
            metadata,
            closedType,
            "ReadNestedOutOfRange",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                outOfRangeNestedTypeSpecification));
        var primitiveTypeSpecificationField = AddMember(
            metadata,
            primitiveTypeSpecification,
            "Value",
            canonicalFieldSignature);
        var cyclicTypeSpecificationMethod = AddMember(
            metadata,
            cyclicTypeSpecification,
            "Read",
            AddBlob(metadata, 0x00, 0x00, 0x08));
        var withinExpandedTypeSpecificationBudgetMethod = AddMember(
            metadata,
            targetType,
            "ReadWithinBudget",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                withinExpandedTypeSpecificationBudget));
        var expandingTypeSpecificationMethod = AddMember(
            metadata,
            targetType,
            "Read",
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x00, 0x12],
                expandingTypeSpecification));
        var openTypeSlot = AddOpenGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            genericParameterTypeCode: 0x13);
        var openMethodSlot = AddOpenGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            genericParameterTypeCode: 0x1E);
        var outOfRangeTypeSlot = AddOpenGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            genericParameterTypeCode: 0x13,
            genericParameterIndex: 1);
        var outOfRangeMethodSlot = AddOpenGenericBoxTypeSpecification(
            metadata,
            genericBoxType,
            genericParameterTypeCode: 0x1E,
            genericParameterIndex: 1);
        var openTypeSlotInstanceMethod = AddMember(
            metadata,
            openTypeSlot,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var openMethodSlotInstanceMethod = AddMember(
            metadata,
            openMethodSlot,
            "Ping",
            AddBlob(metadata, 0x20, 0x00, 0x01));
        var openTypeSlotStaticMethod = AddMember(
            metadata,
            openTypeSlot,
            "Ping",
            AddBlob(metadata, 0x00, 0x00, 0x01));
        var openMethodSlotStaticMethod = AddMember(
            metadata,
            openMethodSlot,
            "Ping",
            AddBlob(metadata, 0x00, 0x00, 0x01));
        var outOfRangeTypeSlotStaticMethod = AddMember(
            metadata,
            outOfRangeTypeSlot,
            "Ping",
            AddBlob(metadata, 0x00, 0x00, 0x01));
        var outOfRangeMethodSlotStaticMethod = AddMember(
            metadata,
            outOfRangeMethodSlot,
            "Ping",
            AddBlob(metadata, 0x00, 0x00, 0x01));
        var genericArgumentParameterSignature = AddOpenGenericCallerMethodSignature(
            metadata,
            genericBoxType,
            genericParameterTypeCode: 0x13,
            methodGeneric: false);
        var sameOwnerGenericArgumentMethod = AddMember(
            metadata,
            callerGenericType,
            "Take",
            genericArgumentParameterSignature);
        var differentOwnerGenericArgumentMethod = AddMember(
            metadata,
            genericBoxType,
            "Take",
            genericArgumentParameterSignature);
        var unownedTypeReferenceSlotMethod = AddMember(
            metadata,
            genericBoxType,
            "TakeUnowned",
            AddBlob(metadata, 0x00, 0x01, 0x01, 0x13, 0x00));
        var genericFactoryMethod = AddMember(
            metadata,
            targetType,
            "Create",
            AddBlob(metadata, 0x10, 0x01, 0x00, 0x1E, 0x00));
        var unusedGenericMethod = AddMember(
            metadata,
            targetType,
            "Unused",
            AddBlob(metadata, 0x10, 0x01, 0x00, 0x01));
        var canonicalMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x08));
        var rankOneArrayMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x14, 0x08, 0x01, 0x00, 0x00));
        var nestedAliasMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddSignatureWithTypeHandle(
                metadata,
                [0x0A, 0x01, 0x1D, 0x12],
                fakeIntType));
        var expandingRenderedMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddSignatureWithTypeHandle(
                metadata,
                [0x0A, 0x01, 0x12],
                largeRenderedTypeReference));
        var unusedExpandingRenderedMethodSpecification =
            metadata.AddMethodSpecification(
                unusedGenericMethod,
                AddSignatureWithTypeHandle(
                    metadata,
                    [0x0A, 0x01, 0x12],
                    largeRenderedTypeReference));
        var trailingMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x08, 0x00));
        var nonCanonicalMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x80, 0x01, 0x08));
        var unsupportedWrappedFunctionPointerMethodSpecification =
            metadata.AddMethodSpecification(
                genericFactoryMethod,
                AddBlob(metadata, 0x0A, 0x01, 0x1D, 0x1B, 0x05, 0x00, 0x08));
        var mismatchedArityMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x02, 0x08, 0x08));
        var restrictedPointerMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x0F, 0x08));
        var openTypeSlotMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x13, 0x00));
        var openMethodSlotMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x1E, 0x00));
        var outOfRangeTypeSlotMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x13, 0x01));
        var outOfRangeMethodSlotMethodSpecification = metadata.AddMethodSpecification(
            genericFactoryMethod,
            AddBlob(metadata, 0x0A, 0x01, 0x1E, 0x01));

        var typeCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("box"),
            sequenceNumber: 1);
        var methodCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("box"),
            sequenceNumber: 1);
        var nestedCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("box"),
            sequenceNumber: 1);
        var twoTypeCallerReturnParameter = metadata.AddParameter(
            ParameterAttributes.None,
            name: default,
            sequenceNumber: 0);
        var nominalCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("value"),
            sequenceNumber: 1);
        var constructedCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("box"),
            sequenceNumber: 1);
        var rankOneArrayCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("values"),
            sequenceNumber: 1);
        var constructedFieldCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("box"),
            sequenceNumber: 1);
        var interfaceCallerParameter = metadata.AddParameter(
            ParameterAttributes.None,
            metadata.GetOrAddString("contract"),
            sequenceNumber: 1);
        var typeGenericCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeType"),
            AddOpenGenericCallerMethodSignature(
                metadata,
                genericBoxType,
                genericParameterTypeCode: 0x13,
                methodGeneric: false),
            bodyOffset: 0,
            parameterList: typeCallerParameter);
        var methodGenericCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeMethod"),
            AddOpenGenericCallerMethodSignature(
                metadata,
                genericBoxType,
                genericParameterTypeCode: 0x1E,
                methodGeneric: true),
            bodyOffset: 0,
            parameterList: methodCallerParameter);
        var renamedNestedTypeGenericCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeNested"),
            AddOpenGenericCallerMethodSignature(
                metadata,
                genericBoxType,
                genericParameterTypeCode: 0x13,
                methodGeneric: false),
            bodyOffset: 0,
            parameterList: nestedCallerParameter);
        var twoTypeGenericCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeTwoTypeParameters"),
            AddBlob(metadata, 0x00, 0x00, 0x01),
            bodyOffset: 0,
            parameterList: twoTypeCallerReturnParameter);
        var nominalCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeNominal"),
            AddSignatureWithTypeHandle(
                metadata,
                [0x00, 0x01, 0x01, 0x12],
                firstValueType),
            bodyOffset: 0,
            parameterList: nominalCallerParameter);
        var constructedCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeConstructed"),
            AddClosedGenericBoxCallerMethodSignature(metadata, genericBoxType),
            bodyOffset: 0,
            parameterList: constructedCallerParameter);
        var rankOneArrayCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeRankOneArray"),
            AddBlob(metadata, 0x00, 0x01, 0x08, 0x14, 0x08, 0x01, 0x00, 0x00),
            bodyOffset: 0,
            parameterList: rankOneArrayCallerParameter);
        var constructedFieldCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("ReadConstructedField"),
            AddClosedGenericBoxCallerMethodSignature(
                metadata,
                genericBoxType,
                returnTypeCode: 0x08),
            bodyOffset: 0,
            parameterList: constructedFieldCallerParameter);
        var interfaceCallerMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("InvokeInterface"),
            AddClosedGenericBoxCallerMethodSignature(
                metadata,
                genericInterfaceType),
            bodyOffset: 0,
            parameterList: interfaceCallerParameter);
        var malformedGenericDefinitionMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("MalformedGeneric"),
            AddBlob(metadata, 0x00, 0x00, 0x08),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(10));
        var malformedGenericDefinitionMethodSpecification =
            metadata.AddMethodSpecification(
                malformedGenericDefinitionMethod,
                AddBlob(metadata, 0x0A, 0x01, 0x08));
        metadata.AddGenericParameter(
            methodGenericCallerMethod,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("U"),
            index: 0);
        metadata.AddGenericParameter(
            callerGenericType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameter(
            outerGenericType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameter(
            renamedNestedGenericType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("Q"),
            index: 0);
        metadata.AddGenericParameter(
            twoTypeGenericCallerType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TFirst"),
            index: 0);
        metadata.AddGenericParameter(
            twoTypeGenericCallerType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TSecond"),
            index: 1);
        metadata.AddGenericParameter(
            malformedGenericDefinitionMethod,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("TMalformed"),
            index: 0);

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        return new MetadataFixture(provider)
        {
            CanonicalMethod = canonicalMethod,
            CanonicalField = canonicalField,
            SameOwnerFieldDefinition = sameOwnerFieldDefinition,
            DifferentOwnerFieldDefinition = differentOwnerFieldDefinition,
            InstanceFieldDefinition = instanceFieldDefinition,
            LiteralFieldDefinition = literalFieldDefinition,
            NominalStaticFieldDefinition = nominalStaticFieldDefinition,
            SameOwnerFieldReference = sameOwnerFieldReference,
            DifferentOwnerFieldReference = differentOwnerFieldReference,
            SameNominalIdentityMethod = sameNominalIdentityMethod,
            DifferentNominalIdentityMethod = differentNominalIdentityMethod,
            TrailingMethod = trailingMethod,
            TruncatedMethod = truncatedMethod,
            NonCanonicalParameterCountMethod = nonCanonicalParameterCountMethod,
            NonCanonicalTypeHandleMethod = nonCanonicalTypeHandleMethod,
            NonTypeParentMethod = nonTypeParentMethod,
            TrailingField = trailingField,
            TruncatedField = truncatedField,
            NonCanonicalTypeHandleField = nonCanonicalTypeHandleField,
            NonTypeParentField = nonTypeParentField,
            ClosedGenericMethod = closedGenericMethod,
            ClosedGenericField = closedGenericField,
            TrailingTypeSpecificationMethod = trailingTypeSpecificationMethod,
            TrailingTypeSpecificationField = trailingTypeSpecificationField,
            NonCanonicalArgumentCountTypeSpecificationMethod =
                nonCanonicalArgumentCountTypeSpecificationMethod,
            NonCanonicalArgumentCountTypeSpecificationField =
                nonCanonicalArgumentCountTypeSpecificationField,
            InRangeNestedTypeSpecificationMethod =
                inRangeNestedTypeSpecificationMethod,
            OutOfRangeNestedTypeSpecificationMethod =
                outOfRangeNestedTypeSpecificationMethod,
            ModifiedReturnMethod = modifiedReturnMethod,
            ModifiedField = modifiedField,
            NestedModifiedField = nestedModifiedField,
            ByReferenceField = byReferenceField,
            TypedReferenceField = typedReferenceField,
            ArrayOfByReferenceField = arrayOfByReferenceField,
            GenericOfTypedReferenceField = genericOfTypedReferenceField,
            SzArrayOfVoidField = szArrayOfVoidField,
            ArrayOfUnsupportedFunctionPointerField =
                arrayOfUnsupportedFunctionPointerField,
            GenericOfUnsupportedFunctionPointerField =
                genericOfUnsupportedFunctionPointerField,
            UntrustedConventionFunctionPointerField =
                untrustedConventionFunctionPointerField,
            UninstantiatedGenericReturnMethod = uninstantiatedGenericReturnMethod,
            UninstantiatedGenericField = uninstantiatedGenericField,
            MismatchedGenericArityField = mismatchedGenericArityField,
            GappedGenericDomainField = gappedGenericDomainField,
            ClassEncodedAsValueTypeField = classEncodedAsValueTypeField,
            OversizedNameMethod = oversizedNameMethod,
            DeepTypeReferenceMethod = deepTypeReferenceMethod,
            DeepFunctionPointerMethod = deepFunctionPointerMethod,
            PrimitiveTypeSpecificationField = primitiveTypeSpecificationField,
            CyclicTypeSpecificationMethod = cyclicTypeSpecificationMethod,
            WithinExpandedTypeSpecificationBudgetMethod =
                withinExpandedTypeSpecificationBudgetMethod,
            ExpandingTypeSpecificationMethod = expandingTypeSpecificationMethod,
            OpenTypeSlotInstanceMethod = openTypeSlotInstanceMethod,
            OpenMethodSlotInstanceMethod = openMethodSlotInstanceMethod,
            OpenTypeSlotStaticMethod = openTypeSlotStaticMethod,
            OpenMethodSlotStaticMethod = openMethodSlotStaticMethod,
            OutOfRangeTypeSlotStaticMethod = outOfRangeTypeSlotStaticMethod,
            OutOfRangeMethodSlotStaticMethod = outOfRangeMethodSlotStaticMethod,
            SameOwnerGenericArgumentMethod = sameOwnerGenericArgumentMethod,
            DifferentOwnerGenericArgumentMethod = differentOwnerGenericArgumentMethod,
            UnownedTypeReferenceSlotMethod = unownedTypeReferenceSlotMethod,
            TypeGenericCallerMethod = typeGenericCallerMethod,
            MethodGenericCallerMethod = methodGenericCallerMethod,
            RenamedNestedTypeGenericCallerMethod = renamedNestedTypeGenericCallerMethod,
            TwoTypeGenericCallerMethod = twoTypeGenericCallerMethod,
            NominalCallerMethod = nominalCallerMethod,
            CanonicalMethodSpecification = canonicalMethodSpecification,
            RankOneArrayMethodSpecification = rankOneArrayMethodSpecification,
            NestedAliasMethodSpecification = nestedAliasMethodSpecification,
            ExpandingRenderedMethodSpecification =
                expandingRenderedMethodSpecification,
            UnusedExpandingRenderedMethodSpecification =
                unusedExpandingRenderedMethodSpecification,
            MalformedGenericDefinitionMethodSpecification =
                malformedGenericDefinitionMethodSpecification,
            TrailingMethodSpecification = trailingMethodSpecification,
            NonCanonicalMethodSpecification = nonCanonicalMethodSpecification,
            UnsupportedWrappedFunctionPointerMethodSpecification =
                unsupportedWrappedFunctionPointerMethodSpecification,
            MismatchedArityMethodSpecification = mismatchedArityMethodSpecification,
            RestrictedPointerMethodSpecification = restrictedPointerMethodSpecification,
            OpenTypeSlotMethodSpecification = openTypeSlotMethodSpecification,
            OpenMethodSlotMethodSpecification = openMethodSlotMethodSpecification,
            OutOfRangeTypeSlotMethodSpecification = outOfRangeTypeSlotMethodSpecification,
            OutOfRangeMethodSlotMethodSpecification = outOfRangeMethodSlotMethodSpecification,
            SameConstructedReceiverMethod = sameConstructedReceiverMethod,
            DifferentConstructedReceiverMethod = differentConstructedReceiverMethod,
            SameTextDifferentConstructedReceiverMethod =
                sameTextDifferentConstructedReceiverMethod,
            SameConstructedInterfaceMethod = sameConstructedInterfaceMethod,
            DifferentConstructedInterfaceMethod = differentConstructedInterfaceMethod,
            SameConstructedReceiverField = sameConstructedReceiverField,
            DifferentConstructedReceiverField = differentConstructedReceiverField,
            VarArgSentinelMethod = varArgSentinelMethod,
            ExplicitThisMethod = explicitThisMethod,
            RankOneArrayGetMethod = rankOneArrayGetMethod,
            ZeroLowerBoundArrayGetMethod = zeroLowerBoundArrayGetMethod,
            NonzeroLowerBoundArrayGetMethod = nonzeroLowerBoundArrayGetMethod,
            NestedAliasMethod = nestedAliasMethod,
            FakePrimitiveGenericParentMethod = fakePrimitiveGenericParentMethod,
            ConstructedCallerMethod = constructedCallerMethod,
            RankOneArrayCallerMethod = rankOneArrayCallerMethod,
            ConstructedFieldCallerMethod = constructedFieldCallerMethod,
            InterfaceCallerMethod = interfaceCallerMethod
        };
    }

    private static MemberReferenceHandle AddMember(
        MetadataBuilder metadata,
        EntityHandle parent,
        string name,
        BlobHandle signature) =>
        metadata.AddMemberReference(
            parent,
            metadata.GetOrAddString(name),
            signature);

    private static BlobHandle AddSignatureWithNonCanonicalTypeHandle(
        MetadataBuilder metadata,
        IReadOnlyList<byte> prefix,
        EntityHandle type)
    {
        var codedIndex = CodedIndex.TypeDefOrRef(type);
        Assert.InRange(codedIndex, 0, 0x7F);
        var signature = new BlobBuilder();
        foreach (var value in prefix)
        {
            signature.WriteByte(value);
        }

        signature.WriteByte(0x80);
        signature.WriteByte((byte)codedIndex);
        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddSignatureWithTypeHandle(
        MetadataBuilder metadata,
        IReadOnlyList<byte> prefix,
        EntityHandle type,
        params byte[] suffix)
    {
        var signature = new BlobBuilder();
        foreach (var value in prefix)
        {
            signature.WriteByte(value);
        }

        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRefOrSpec(type));
        foreach (var value in suffix)
        {
            signature.WriteByte(value);
        }

        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddGenericInstantiationFieldSignature(
        MetadataBuilder metadata,
        EntityHandle genericType,
        int genericArgumentCount,
        byte genericArgumentTypeCode = 0x0E)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x06); // FIELD
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericType));
        signature.WriteCompressedInteger(genericArgumentCount);
        for (var index = 0; index < genericArgumentCount; index++)
        {
            signature.WriteByte(genericArgumentTypeCode);
        }

        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddOpenGenericBoxFieldSignature(
        MetadataBuilder metadata,
        EntityHandle genericType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x06); // FIELD
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericType));
        signature.WriteByte(0x01);
        signature.WriteByte(0x13); // VAR
        signature.WriteByte(0x00);
        return metadata.GetOrAddBlob(signature);
    }

    private static TypeSpecificationHandle AddDuplicatingGenericTypeSpecification(
        MetadataBuilder metadata,
        EntityHandle genericType,
        TypeSpecificationHandle child)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericType));
        signature.WriteByte(0x02);
        for (var index = 0; index < 2; index++)
        {
            signature.WriteByte(0x12); // CLASS
            signature.WriteCompressedInteger(CodedIndex.TypeDefOrRefOrSpec(child));
        }

        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static TypeSpecificationHandle AddLargeArrayTypeSpecification(
        MetadataBuilder metadata)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x14); // ARRAY
        signature.WriteByte(0x08); // INT32 element
        signature.WriteCompressedInteger(32); // rank
        signature.WriteCompressedInteger(32); // sizes
        for (var index = 0; index < 32; index++)
        {
            signature.WriteCompressedInteger(0x4000 + index);
        }

        signature.WriteCompressedInteger(0); // no explicit lower bounds
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static BlobHandle AddGenericFunctionPointerFieldSignature(
        MetadataBuilder metadata,
        EntityHandle genericType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x06); // FIELD
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericType));
        signature.WriteByte(0x01);
        signature.WriteByte(0x1B); // FNPTR
        signature.WriteByte(0x05); // VARARG, not representable as a C# function pointer
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(0x08); // INT32 return type
        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddConventionFunctionPointerFieldSignature(
        MetadataBuilder metadata,
        EntityHandle conventionType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x06); // FIELD
        signature.WriteByte(0x1B); // FNPTR
        signature.WriteByte(0x09); // UNMANAGED
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(0x20); // CMOD_OPT on return type
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(conventionType));
        signature.WriteByte(0x01); // VOID return type
        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddNestedFunctionPointerMethodSignature(
        MetadataBuilder metadata,
        int depth)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x00); // DEFAULT
        signature.WriteByte(0x00); // zero parameters
        for (var index = 0; index < depth; index++)
        {
            signature.WriteByte(0x1B); // FNPTR
            signature.WriteByte(0x00); // DEFAULT
            signature.WriteByte(0x00); // zero parameters
        }

        signature.WriteByte(0x08); // INT32 leaf return type
        return metadata.GetOrAddBlob(signature);
    }

    private static TypeSpecificationHandle AddClosedGenericBoxTypeSpecification(
        MetadataBuilder metadata,
        EntityHandle genericBoxType,
        bool nonCanonicalArgumentCount,
        bool trailingData,
        byte genericArgumentTypeCode = 0x0E)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericBoxType));
        if (nonCanonicalArgumentCount)
        {
            signature.WriteByte(0x80);
            signature.WriteByte(0x01);
        }
        else
        {
            signature.WriteByte(0x01);
        }

        signature.WriteByte(genericArgumentTypeCode);
        if (trailingData)
        {
            signature.WriteByte(0x00);
        }

        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static TypeSpecificationHandle AddOpenGenericBoxTypeSpecification(
        MetadataBuilder metadata,
        EntityHandle genericBoxType,
        byte genericParameterTypeCode,
        int genericParameterIndex = 0)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x15); // GENERICINST
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericBoxType));
        signature.WriteByte(0x01);
        signature.WriteByte(genericParameterTypeCode); // VAR or MVAR
        signature.WriteCompressedInteger(genericParameterIndex);
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static TypeSpecificationHandle AddOpenArrayTypeSpecification(
        MetadataBuilder metadata,
        int genericParameterIndex)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x1D); // SZARRAY
        signature.WriteByte(0x13); // VAR
        signature.WriteCompressedInteger(genericParameterIndex);
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static BlobHandle AddOpenGenericCallerMethodSignature(
        MetadataBuilder metadata,
        EntityHandle genericBoxType,
        byte genericParameterTypeCode,
        bool methodGeneric)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(methodGeneric ? (byte)0x10 : (byte)0x00);
        if (methodGeneric)
        {
            signature.WriteByte(0x01);
        }

        signature.WriteByte(0x01); // one parameter
        signature.WriteByte(0x01); // VOID return type
        signature.WriteByte(0x15); // GENERICINST parameter
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericBoxType));
        signature.WriteByte(0x01);
        signature.WriteByte(genericParameterTypeCode); // VAR or MVAR
        signature.WriteByte(0x00);
        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddClosedGenericBoxCallerMethodSignature(
        MetadataBuilder metadata,
        EntityHandle genericBoxType,
        byte returnTypeCode = 0x01)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x00); // DEFAULT static method
        signature.WriteByte(0x01); // one parameter
        signature.WriteByte(returnTypeCode);
        signature.WriteByte(0x15); // GENERICINST parameter
        signature.WriteByte(0x12); // CLASS
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(genericBoxType));
        signature.WriteByte(0x01);
        signature.WriteByte(0x08); // INT32 argument
        return metadata.GetOrAddBlob(signature);
    }

    private static BlobHandle AddBlob(MetadataBuilder metadata, params byte[] bytes)
    {
        var blob = new BlobBuilder();
        foreach (var value in bytes)
        {
            blob.WriteByte(value);
        }

        return metadata.GetOrAddBlob(blob);
    }

    private static byte[] BuildTokenIl(
        IReadOnlyList<byte> prefix,
        byte opcode,
        EntityHandle target,
        bool popResult = false)
    {
        var il = new byte[prefix.Count + (popResult ? 7 : 6)];
        for (var index = 0; index < prefix.Count; index++)
        {
            il[index] = prefix[index];
        }

        il[prefix.Count] = opcode;
        BinaryPrimitives.WriteInt32LittleEndian(
            il.AsSpan(prefix.Count + 1, 4),
            MetadataTokens.GetToken(target));
        if (popResult)
        {
            il[^2] = 0x26; // pop
        }

        il[^1] = 0x2A; // ret
        return il;
    }

    private static byte[] BuildCallSequence(params EntityHandle[] targets)
    {
        var il = new byte[(targets.Length * 5) + 1];
        for (var index = 0; index < targets.Length; index++)
        {
            var offset = index * 5;
            il[offset] = 0x28; // call
            BinaryPrimitives.WriteInt32LittleEndian(
                il.AsSpan(offset + 1, 4),
                MetadataTokens.GetToken(targets[index]));
        }

        il[^1] = 0x2A; // ret
        return il;
    }

    private static byte[] BuildStaticFieldRoundTrip(
        EntityHandle loadTarget,
        EntityHandle storeTarget)
    {
        var il = new byte[11];
        il[0] = 0x7E; // ldsfld
        BinaryPrimitives.WriteInt32LittleEndian(
            il.AsSpan(1, 4),
            MetadataTokens.GetToken(loadTarget));
        il[5] = 0x80; // stsfld
        BinaryPrimitives.WriteInt32LittleEndian(
            il.AsSpan(6, 4),
            MetadataTokens.GetToken(storeTarget));
        il[10] = 0x2A; // ret
        return il;
    }

    private sealed class MetadataFixture(MetadataReaderProvider provider) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MemberReferenceHandle CanonicalMethod { get; init; }

        public MemberReferenceHandle CanonicalField { get; init; }

        public FieldDefinitionHandle SameOwnerFieldDefinition { get; init; }

        public FieldDefinitionHandle DifferentOwnerFieldDefinition { get; init; }

        public FieldDefinitionHandle InstanceFieldDefinition { get; init; }

        public FieldDefinitionHandle LiteralFieldDefinition { get; init; }

        public FieldDefinitionHandle NominalStaticFieldDefinition { get; init; }

        public MemberReferenceHandle SameOwnerFieldReference { get; init; }

        public MemberReferenceHandle DifferentOwnerFieldReference { get; init; }

        public MemberReferenceHandle SameNominalIdentityMethod { get; init; }

        public MemberReferenceHandle DifferentNominalIdentityMethod { get; init; }

        public MemberReferenceHandle TrailingMethod { get; init; }

        public MemberReferenceHandle TruncatedMethod { get; init; }

        public MemberReferenceHandle NonCanonicalParameterCountMethod { get; init; }

        public MemberReferenceHandle NonCanonicalTypeHandleMethod { get; init; }

        public MemberReferenceHandle NonTypeParentMethod { get; init; }

        public MemberReferenceHandle TrailingField { get; init; }

        public MemberReferenceHandle TruncatedField { get; init; }

        public MemberReferenceHandle NonCanonicalTypeHandleField { get; init; }

        public MemberReferenceHandle NonTypeParentField { get; init; }

        public MemberReferenceHandle ClosedGenericMethod { get; init; }

        public MemberReferenceHandle ClosedGenericField { get; init; }

        public MemberReferenceHandle TrailingTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle TrailingTypeSpecificationField { get; init; }

        public MemberReferenceHandle NonCanonicalArgumentCountTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle NonCanonicalArgumentCountTypeSpecificationField { get; init; }

        public MemberReferenceHandle InRangeNestedTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle OutOfRangeNestedTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle ModifiedReturnMethod { get; init; }

        public MemberReferenceHandle ModifiedField { get; init; }

        public MemberReferenceHandle NestedModifiedField { get; init; }

        public MemberReferenceHandle ByReferenceField { get; init; }

        public MemberReferenceHandle TypedReferenceField { get; init; }

        public MemberReferenceHandle ArrayOfByReferenceField { get; init; }

        public MemberReferenceHandle GenericOfTypedReferenceField { get; init; }

        public MemberReferenceHandle SzArrayOfVoidField { get; init; }

        public MemberReferenceHandle ArrayOfUnsupportedFunctionPointerField { get; init; }

        public MemberReferenceHandle GenericOfUnsupportedFunctionPointerField { get; init; }

        public MemberReferenceHandle UntrustedConventionFunctionPointerField { get; init; }

        public MemberReferenceHandle UninstantiatedGenericReturnMethod { get; init; }

        public MemberReferenceHandle UninstantiatedGenericField { get; init; }

        public MemberReferenceHandle MismatchedGenericArityField { get; init; }

        public MemberReferenceHandle GappedGenericDomainField { get; init; }

        public MemberReferenceHandle ClassEncodedAsValueTypeField { get; init; }

        public MemberReferenceHandle OversizedNameMethod { get; init; }

        public MemberReferenceHandle DeepTypeReferenceMethod { get; init; }

        public MemberReferenceHandle DeepFunctionPointerMethod { get; init; }

        public MemberReferenceHandle PrimitiveTypeSpecificationField { get; init; }

        public MemberReferenceHandle CyclicTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle WithinExpandedTypeSpecificationBudgetMethod { get; init; }

        public MemberReferenceHandle ExpandingTypeSpecificationMethod { get; init; }

        public MemberReferenceHandle OpenTypeSlotInstanceMethod { get; init; }

        public MemberReferenceHandle OpenMethodSlotInstanceMethod { get; init; }

        public MemberReferenceHandle OpenTypeSlotStaticMethod { get; init; }

        public MemberReferenceHandle OpenMethodSlotStaticMethod { get; init; }

        public MemberReferenceHandle OutOfRangeTypeSlotStaticMethod { get; init; }

        public MemberReferenceHandle OutOfRangeMethodSlotStaticMethod { get; init; }

        public MemberReferenceHandle SameOwnerGenericArgumentMethod { get; init; }

        public MemberReferenceHandle DifferentOwnerGenericArgumentMethod { get; init; }

        public MemberReferenceHandle UnownedTypeReferenceSlotMethod { get; init; }

        public MethodDefinitionHandle TypeGenericCallerMethod { get; init; }

        public MethodDefinitionHandle MethodGenericCallerMethod { get; init; }

        public MethodDefinitionHandle RenamedNestedTypeGenericCallerMethod { get; init; }

        public MethodDefinitionHandle TwoTypeGenericCallerMethod { get; init; }

        public MethodDefinitionHandle NominalCallerMethod { get; init; }

        public MethodSpecificationHandle CanonicalMethodSpecification { get; init; }

        public MethodSpecificationHandle TrailingMethodSpecification { get; init; }

        public MethodSpecificationHandle NonCanonicalMethodSpecification { get; init; }

        public MethodSpecificationHandle UnsupportedWrappedFunctionPointerMethodSpecification { get; init; }

        public MethodSpecificationHandle MismatchedArityMethodSpecification { get; init; }

        public MethodSpecificationHandle RestrictedPointerMethodSpecification { get; init; }

        public MethodSpecificationHandle OpenTypeSlotMethodSpecification { get; init; }

        public MethodSpecificationHandle OpenMethodSlotMethodSpecification { get; init; }

        public MethodSpecificationHandle OutOfRangeTypeSlotMethodSpecification { get; init; }

        public MethodSpecificationHandle OutOfRangeMethodSlotMethodSpecification { get; init; }

        public MethodSpecificationHandle RankOneArrayMethodSpecification { get; init; }

        public MethodSpecificationHandle NestedAliasMethodSpecification { get; init; }

        public MethodSpecificationHandle ExpandingRenderedMethodSpecification { get; init; }

        public MethodSpecificationHandle UnusedExpandingRenderedMethodSpecification { get; init; }

        public MethodSpecificationHandle MalformedGenericDefinitionMethodSpecification { get; init; }

        public MemberReferenceHandle SameConstructedReceiverMethod { get; init; }

        public MemberReferenceHandle DifferentConstructedReceiverMethod { get; init; }

        public MemberReferenceHandle SameTextDifferentConstructedReceiverMethod { get; init; }

        public MemberReferenceHandle SameConstructedInterfaceMethod { get; init; }

        public MemberReferenceHandle DifferentConstructedInterfaceMethod { get; init; }

        public MemberReferenceHandle SameConstructedReceiverField { get; init; }

        public MemberReferenceHandle DifferentConstructedReceiverField { get; init; }

        public MemberReferenceHandle VarArgSentinelMethod { get; init; }

        public MemberReferenceHandle ExplicitThisMethod { get; init; }

        public MemberReferenceHandle RankOneArrayGetMethod { get; init; }

        public MemberReferenceHandle ZeroLowerBoundArrayGetMethod { get; init; }

        public MemberReferenceHandle NonzeroLowerBoundArrayGetMethod { get; init; }

        public MemberReferenceHandle NestedAliasMethod { get; init; }

        public MemberReferenceHandle FakePrimitiveGenericParentMethod { get; init; }

        public MethodDefinitionHandle ConstructedCallerMethod { get; init; }

        public MethodDefinitionHandle RankOneArrayCallerMethod { get; init; }

        public MethodDefinitionHandle ConstructedFieldCallerMethod { get; init; }

        public MethodDefinitionHandle InterfaceCallerMethod { get; init; }

        public void Dispose() => provider.Dispose();
    }
}
