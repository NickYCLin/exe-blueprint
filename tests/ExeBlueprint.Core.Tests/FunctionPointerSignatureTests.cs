using System.Collections.Immutable;
using System.Reflection.Metadata;
using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;

namespace ExeBlueprint.Core.Tests;

public sealed class FunctionPointerSignatureTests
{
    private const string CallConvPrefix = "System.Runtime.CompilerServices.CallConv";

    [Fact]
    public void RendersRepresentableManagedAndUnmanagedSignatures()
    {
        var provider = SignatureTypeNameProvider.Instance;
        var managed = provider.GetFunctionPointerType(Signature(
            SignatureCallingConvention.Default,
            "bool",
            ["int", "ref string"]));

        Assert.Equal("delegate* managed<int, ref string, bool>", managed.Text);
        Assert.True(managed.IsRestrictedGenericArgument);
        Assert.Empty(managed.OuterCustomModifiers);
        Assert.False(managed.HasNestedCustomModifiers);

        var decoratedReturn = provider.GetModifiedType($"{CallConvPrefix}Cdecl", "void", isRequired: false);
        decoratedReturn = provider.GetModifiedType(
            $"{CallConvPrefix}SuppressGCTransition",
            decoratedReturn,
            isRequired: false);
        var decorated = provider.GetFunctionPointerType(Signature(
            SignatureCallingConvention.Unmanaged,
            decoratedReturn,
            ["nint"]));

        Assert.Equal(
            "delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void>",
            decorated.Text);
        Assert.Equal(
            "delegate* unmanaged[Cdecl]<void>",
            provider.GetFunctionPointerType(Signature(SignatureCallingConvention.CDecl, "void", [])).Text);

        var duplicateReturn = provider.GetModifiedType($"{CallConvPrefix}Cdecl", "void", isRequired: false);
        duplicateReturn = provider.GetModifiedType(
            $"{CallConvPrefix}Cdecl",
            duplicateReturn,
            isRequired: false);
        Assert.Equal(
            "delegate* unmanaged[Cdecl, Cdecl]<void>",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Unmanaged,
                duplicateReturn,
                [])).Text);
    }

    [Fact]
    public void FallsBackForUnrepresentableFunctionPointerMetadata()
    {
        var provider = SignatureTypeNameProvider.Instance;
        var unknownConvention = provider.GetModifiedType($"{CallConvPrefix}Blue", "void", isRequired: false);
        var requiredConvention = provider.GetModifiedType($"{CallConvPrefix}Cdecl", "void", isRequired: true);
        var modifiedParameter = provider.GetModifiedType("Example.OptionalModifier", "int", isRequired: false);
        var nestedModifier = provider.GetPointerType(modifiedParameter);

        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Unmanaged,
                unknownConvention,
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Unmanaged,
                requiredConvention,
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "void",
                [modifiedParameter])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                nestedModifier,
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.VarArgs,
                "void",
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "void",
                ["void"])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "void",
                ["ref void"])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "ref void",
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "TypedReference",
                [])).Text);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(Signature(
                SignatureCallingConvention.Default,
                "ref TypedReference",
                [])).Text);

        var genericHeader = new SignatureHeader(
            SignatureKind.Method,
            SignatureCallingConvention.Default,
            SignatureAttributes.Generic);
        Assert.Equal(
            "nint",
            provider.GetFunctionPointerType(new MethodSignature<SignatureTypeName>(
                genericHeader,
                "void",
                requiredParameterCount: 0,
                genericParameterCount: 1,
                [])).Text);
    }

    [Fact]
    public void KeepsRestrictedSignatureTypesOutOfGenericArguments()
    {
        var provider = SignatureTypeNameProvider.Instance;
        var functionPointer = provider.GetFunctionPointerType(Signature(
            SignatureCallingConvention.Default,
            "void",
            []));

        Assert.Equal(
            "nint",
            provider.GetGenericInstantiation(
                "System.Collections.Generic.List`1",
                [functionPointer]).Text);
        Assert.Equal(
            "nint",
            provider.GetGenericInstantiation(
                "System.Collections.Generic.List`1",
                [provider.GetByReferenceType("int")]).Text);
        Assert.Equal(
            "nint",
            provider.GetGenericInstantiation(
                "System.Collections.Generic.List`1",
                [provider.GetPrimitiveType(PrimitiveTypeCode.TypedReference)]).Text);

        var array = provider.GetSZArrayType(functionPointer);
        Assert.Equal("delegate* managed<void>[]", array.Text);
        Assert.False(array.IsRestrictedGenericArgument);
    }

    [Fact]
    public async Task ReadsAndGeneratesCompilerFunctionPointerSignatures()
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(typeof(FunctionPointerFixture).Assembly.Location);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.FunctionPointerFixture");

        AssertMethodSignature(
            fixture,
            nameof(FunctionPointerFixture.EchoManaged),
            "delegate* managed<int, ref string, bool>");
        AssertMethodSignature(
            fixture,
            nameof(FunctionPointerFixture.EchoNative),
            "delegate* unmanaged[Cdecl]<nint, void>");
        AssertMethodSignature(
            fixture,
            nameof(FunctionPointerFixture.EchoDecoratedNative),
            "delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void>");

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;
        Assert.Contains(
            "delegate* managed<int, ref string, bool> EchoManaged(delegate* managed<int, ref string, bool> value)",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "delegate* unmanaged[Cdecl]<nint, void> EchoNative(delegate* unmanaged[Cdecl]<nint, void> value)",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void> EchoDecoratedNative(" +
            "delegate* unmanaged[SuppressGCTransition, Cdecl]<nint, void> value)",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("method*", source, StringComparison.Ordinal);
    }

    private static MethodSignature<SignatureTypeName> Signature(
        SignatureCallingConvention callingConvention,
        SignatureTypeName returnType,
        ImmutableArray<SignatureTypeName> parameterTypes) =>
        new(
            new SignatureHeader(SignatureKind.Method, callingConvention, SignatureAttributes.None),
            returnType,
            parameterTypes.Length,
            genericParameterCount: 0,
            parameterTypes);

    private static void AssertMethodSignature(
        ExeBlueprint.Models.TypeModel fixture,
        string methodName,
        string expectedType)
    {
        var method = Assert.Single(fixture.Methods, method => method.Name == methodName);
        Assert.Equal(expectedType, method.ReturnType);
        Assert.Equal(expectedType, Assert.Single(method.Parameters).Type);
    }
}
