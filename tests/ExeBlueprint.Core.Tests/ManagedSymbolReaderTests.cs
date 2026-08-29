using ExeBlueprint.Analysis;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;
using System.Text.Json;

namespace ExeBlueprint.Core.Tests;

public sealed class ManagedSymbolReaderTests
{
    [Fact]
    public async Task AnalyzeManagedAssemblyExtractsTypesMethodsAndCallGraph()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var artifact = Assert.Single(document.Files);
        var code = artifact.Code;
        Assert.NotNull(code);
        Assert.Equal("managed", code!.Kind);
        Assert.True(code.TypeCount > 0);
        Assert.True(code.MethodCount > 0);

        var analyzerType = Assert.Single(
            code.Types,
            type => type.FullName == "ExeBlueprint.Analysis.BlueprintAnalyzer");
        Assert.Equal("class", analyzerType.Kind);
        Assert.Contains(analyzerType.Methods, method => method.Name == "AnalyzeAsync");

        Assert.True(code.CallEdgeCount > 0);
        Assert.All(code.CallGraph, edge => Assert.Contains(edge.Kind, new[] { "call", "callvirt", "newobj" }));
    }

    [Fact]
    public async Task DisassemblesMethodBodiesIntoReadableIl()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var code = document.Files[0].Code!;

        var methodsWithIl = code.Types
            .SelectMany(type => type.Methods)
            .Where(method => method.Il.Count > 0)
            .ToArray();

        Assert.NotEmpty(methodsWithIl);
        Assert.All(methodsWithIl, method =>
            Assert.All(method.Il, instruction => Assert.StartsWith("IL_", instruction, StringComparison.Ordinal)));
        Assert.Contains(methodsWithIl, method => method.Il[^1].EndsWith("ret", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsStraightLineMethodBodiesIntoCSharp()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var code = document.Files[0].Code!;

        // 只看會真的輸出的使用者型別與方法（排除編譯器產生的狀態機／lambda 型別）。
        var reconstructed = code.Types
            .Where(type => !type.FullName.Contains('<') && !type.FullName.Contains('>'))
            .SelectMany(type => type.Methods)
            .Where(method => method.BodyReconstructed && !method.Name.Contains('<') && !method.Name.Contains('>'))
            .ToArray();

        Assert.NotEmpty(reconstructed);

        // 每行不是陳述式（; 結尾）就是區塊符號（if/else/{ /}）。
        foreach (var method in reconstructed)
        {
            Assert.All(method.Body, statement =>
            {
                var trimmed = statement.Trim();
                Assert.True(
                    trimmed.EndsWith(';')
                    || trimmed is "{" or "}" or "else" or "do" or "try" or "finally" or "default:"
                    || trimmed.StartsWith("if (", StringComparison.Ordinal)
                    || trimmed.StartsWith("while (", StringComparison.Ordinal)
                    || trimmed.StartsWith("switch (", StringComparison.Ordinal)
                    || trimmed.StartsWith("catch", StringComparison.Ordinal)
                    || trimmed.StartsWith("case ", StringComparison.Ordinal),
                    $"未預期的重建輸出：{statement}");
            });
        }

        // record 產生的 Equals(object) 是典型直線方法，應被還原。
        Assert.Contains(reconstructed, method =>
            method.Name == "Equals"
            && method.Body.Any(statement => statement.Contains(" as ", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedUnsignedArithmetic()
    {
        var assemblyPath = typeof(UnsignedArithmeticFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.UnsignedArithmeticFixture");

        Assert.Equal(
            ["return (unchecked((uint)left) / unchecked((uint)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.Divide)).Body);
        Assert.Equal(
            ["return unchecked((int)(unchecked((uint)left) / unchecked((uint)right)));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.DivideSigned)).Body);
        Assert.Equal(
            [
                "ExeBlueprint.Core.Tests.UnsignedArithmeticFixture.Stored = unchecked((int)(unchecked((uint)left) % unchecked((uint)right)));",
                "return ExeBlueprint.Core.Tests.UnsignedArithmeticFixture.Stored;"
            ],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.StoreSignedField)).Body);
        Assert.Equal(
            ["return (unchecked((uint)left) > unchecked((uint)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.GreaterThanUInt32)).Body);
        Assert.Equal(
            ["return (unchecked((uint)left) < unchecked((uint)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.LessThanUInt32)).Body);
        Assert.Equal(
            ["return (unchecked((ulong)left) > unchecked((ulong)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.GreaterThanUInt64)).Body);
        Assert.Equal(
            ["return (unchecked((ulong)left) < unchecked((ulong)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.LessThanUInt64)).Body);
        Assert.Equal(
            ["return (unchecked((nuint)left) > unchecked((nuint)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.GreaterThanNativeUInt)).Body);
        Assert.Equal(
            ["return (unchecked((nuint)left) < unchecked((nuint)right));"],
            Assert.Single(fixture.Methods, method => method.Name == nameof(UnsignedArithmeticFixture.LessThanNativeUInt)).Body);
        var selectAtLeast = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(UnsignedArithmeticFixture.SelectAtLeastUInt32));
        Assert.Contains(
            selectAtLeast.Il,
            instruction => instruction.Contains("blt.un", StringComparison.Ordinal));
        Assert.Equal(
            [
                "if (unchecked((uint)left) >= unchecked((uint)right))",
                "{",
                "    return 1;",
                "}",
                "return 0;"
            ],
            selectAtLeast.Body);
        var selectGreater = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(UnsignedArithmeticFixture.SelectGreaterUInt64));
        Assert.Contains(
            selectGreater.Il,
            instruction => instruction.Contains("ble.un", StringComparison.Ordinal));
        Assert.Equal(
            [
                "if (unchecked((ulong)left) > unchecked((ulong)right))",
                "{",
                "    return 1;",
                "}",
                "return 0;"
            ],
            selectGreater.Body);
        var selectAtMost = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(UnsignedArithmeticFixture.SelectAtMostNativeUInt));
        Assert.Contains(
            selectAtMost.Il,
            instruction => instruction.Contains("bgt.un", StringComparison.Ordinal));
        Assert.Equal(
            [
                "if (unchecked((nuint)left) <= unchecked((nuint)right))",
                "{",
                "    return 1;",
                "}",
                "return 0;"
            ],
            selectAtMost.Body);
    }

    [Fact]
    public async Task ReadsTopLevelNullableMethodAnnotations()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var blueprintDocument = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Models.BlueprintDocument");

        var equalsObject = Assert.Single(
            blueprintDocument.Methods,
            method => method.Name == "Equals" && method.Parameters[0].Type == "object?");
        Assert.Equal("bool", equalsObject.ReturnType);

        Assert.Contains(
            blueprintDocument.Methods,
            method => method.Name == "Equals"
                && method.Parameters.Count == 1
                && method.Parameters[0].Type == "ExeBlueprint.Models.BlueprintDocument?");

        var recordStruct = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Analysis.ManagedSymbolReader.AccessorShape");
        Assert.Contains(
            recordStruct.Methods,
            method => method.Name == "Equals"
                && method.Parameters.Count == 1
                && method.Parameters[0].Type == "object?");

        var nativeAnalyzer = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Analysis.NativeAnalyzer");
        Assert.Equal(
            "string?",
            Assert.Single(nativeAnalyzer.Methods, method => method.Name == "LocateHeadless").ReturnType);

        var fixtureDocument = await new BlueprintAnalyzer().AnalyzeAsync(typeof(ReferenceConditionFixture).Assembly.Location);
        var referenceFixture = Assert.Single(
            fixtureDocument.Files[0].Code!.Types,
            type => type.FullName == typeof(ReferenceConditionFixture).FullName);
        Assert.Equal(
            "ExeBlueprint.Core.Tests.ReferenceConditionFixture?",
            Assert.Single(referenceFixture.Methods, method => method.Name == nameof(ReferenceConditionFixture.HasParameter))
                .Parameters[0]
                .Type);
    }

    [Fact]
    public async Task ReconstructsCharLiteralsAndTypedLocals()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var methods = document.Files[0].Code!.Types.SelectMany(type => type.Methods).ToArray();

        // char 參數的整數常值應還原成 char 常值。
        var fixtureDocument = await new BlueprintAnalyzer().AnalyzeAsync(typeof(ManagedSymbolReaderTests).Assembly.Location);
        var fixture = Assert.Single(
            fixtureDocument.Files[0].Code!.Types,
            type => type.FullName == typeof(TypedArgumentFixture).FullName);
        var startsWith = Assert.Single(fixture.Methods, method => method.Name == nameof(TypedArgumentFixture.StartsWithLessThan));
        Assert.Contains(
            startsWith.Body,
            line => line.Contains("StartsWith('<')", StringComparison.Ordinal));

        // 讀得到區域變數型別時，宣告應用實際型別而非 var。
        Assert.Contains(
            methods,
            method => method.Body.Any(line => line.TrimStart().StartsWith("System.Text.StringBuilder v", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task PreservesNullableSkeletonExpressions()
    {
        var coreDocument = await new BlueprintAnalyzer().AnalyzeAsync(typeof(BlueprintAnalyzer).Assembly.Location);
        var reader = Assert.Single(
            coreDocument.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Analysis.ManagedSymbolReader");
        var accessibility = Assert.Single(
            reader.Methods,
            method => method.Name == "GetFieldAccessibility");
        Assert.Contains("string v0 = default!;", accessibility.Body);

        var fixtureDocument = await new BlueprintAnalyzer().AnalyzeAsync(typeof(NullableHashFixture).Assembly.Location);
        var fixture = Assert.Single(
            fixtureDocument.Files[0].Code!.Types,
            type => type.FullName == typeof(NullableHashFixture).FullName);
        var getHashCode = Assert.Single(fixture.Methods, method => method.Name == nameof(GetHashCode));
        Assert.Contains(
            getHashCode.Body,
            statement => statement.Contains("GetHashCode(this.Value!)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsBooleanEnumAndNumericCallArguments()
    {
        var assemblyPath = typeof(ManagedSymbolReaderTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == typeof(TypedArgumentFixture).FullName);

        var startsWith = Assert.Single(fixture.Methods, method => method.Name == nameof(TypedArgumentFixture.StartsWithIgnoreCase));
        Assert.Contains(
            startsWith.Body,
            line => line.Contains("unchecked((System.StringComparison)5)", StringComparison.Ordinal));

        var delete = Assert.Single(fixture.Methods, method => method.Name == nameof(TypedArgumentFixture.DeleteRecursively));
        Assert.Contains(
            delete.Body,
            line => line.Contains("System.IO.Directory.Delete(path, true)", StringComparison.Ordinal));

        var deleteNonRecursively = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(TypedArgumentFixture.DeleteNonRecursively));
        Assert.Contains(
            deleteNonRecursively.Body,
            line => line.Contains("System.IO.Directory.Delete(path, false)", StringComparison.Ordinal));

        var numericFixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == typeof(NumericArgumentFixture).FullName);
        var log2 = Assert.Single(
            numericFixture.Methods,
            method => method.Name == nameof(NumericArgumentFixture.Log2));
        Assert.Contains(
            log2.Body,
            line => line.Contains(
                "System.Numerics.BitOperations.Log2(unchecked((uint)value))",
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsReferenceBranchesAsNullChecks()
    {
        var assemblyPath = typeof(ManagedSymbolReaderTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == typeof(ReferenceConditionFixture).FullName);

        var parameter = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ReferenceConditionFixture.HasParameter));
        Assert.Contains("if (value is null)", parameter.Body);

        var field = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ReferenceConditionFixture.HasField));
        Assert.Contains("if (this._value is null)", field.Body);
    }

    [Fact]
    public async Task ReconstructsIndexerAccessors()
    {
        var assemblyPath = typeof(ManagedSymbolReaderTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == typeof(TypedArgumentFixture).FullName);

        var getter = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(TypedArgumentFixture.ReadCharacter));
        Assert.Contains("return value[index];", getter.Body);

        var setter = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(TypedArgumentFixture.SetDictionaryValue));
        Assert.Contains("values[key] = value;", setter.Body);
    }

    [Fact]
    public async Task ReconstructsConditionalBranchesIntoIfStatements()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var code = document.Files[0].Code!;

        var withIf = code.Types
            .SelectMany(type => type.Methods)
            .Where(method => method.BodyReconstructed && method.Body.Any(line => line.TrimStart().StartsWith("if (", StringComparison.Ordinal)))
            .ToArray();

        Assert.NotEmpty(withIf);

        // if 區塊必須成對出現大括號，確保結構化輸出是完整的。
        foreach (var method in withIf)
        {
            var opens = method.Body.Count(line => line.Trim() == "{");
            var closes = method.Body.Count(line => line.Trim() == "}");
            Assert.Equal(opens, closes);
        }
    }

    [Fact]
    public async Task ExtractsEnumUnderlyingTypeAndConstantValues()
    {
        var assemblyPath = typeof(LongBackedTestEnum).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var enumType = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.LongBackedTestEnum");

        Assert.Equal("enum", enumType.Kind);
        Assert.Equal("long", Assert.Single(enumType.Fields, field => field.Name == "value__").Type);

        var negative = Assert.Single(enumType.Fields, field => field.Name == nameof(LongBackedTestEnum.Negative));
        Assert.True(negative.IsConstant);
        Assert.Equal("long", negative.ConstantValue?.Type);
        Assert.Equal("-4", negative.ConstantValue?.Value);

        var sparse = Assert.Single(enumType.Fields, field => field.Name == nameof(LongBackedTestEnum.Sparse));
        Assert.Equal("42", sparse.ConstantValue?.Value);
    }

    [Fact]
    public async Task ExtractsPropertyEventAndFieldModifiers()
    {
        var assemblyPath = typeof(MemberShapeFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.MemberShapeFixture");

        var label = Assert.Single(fixture.Fields, field => field.Name == nameof(MemberShapeFixture.Label));
        Assert.True(label.IsConstant);
        Assert.Equal("string", label.ConstantValue?.Type);
        Assert.Equal("blueprint", label.ConstantValue?.Value);

        var counter = Assert.Single(fixture.Fields, field => field.Name == "Counter");
        Assert.Equal("protected internal", counter.Accessibility);
        Assert.True(counter.IsStatic);
        Assert.True(counter.IsReadOnly);

        var name = Assert.Single(fixture.Properties, property => property.Name == nameof(MemberShapeFixture.Name));
        Assert.Equal("public", name.Accessibility);
        Assert.Equal("public", name.GetterAccessibility);
        Assert.Equal("protected", name.SetterAccessibility);
        Assert.True(name.IsVirtual);
        Assert.True(name.IsNewSlot);
        Assert.False(name.IsFinal);
        Assert.False(name.IsStatic);

        var builder = Assert.Single(fixture.Properties, property => property.Name == nameof(MemberShapeFixture.Builder));
        Assert.Equal("System.Text.StringBuilder", builder.Type);

        var changed = Assert.Single(fixture.Events, @event => @event.Name == "Changed");
        Assert.Equal("System.EventHandler", changed.Type);
        Assert.Equal("internal", changed.Accessibility);
        Assert.True(changed.IsStatic);

        var updated = Assert.Single(fixture.Events, @event => @event.Name == "Updated");
        Assert.Equal("protected", updated.Accessibility);
        Assert.True(updated.IsVirtual);
        Assert.True(updated.IsNewSlot);
        Assert.False(updated.IsFinal);
    }

    [Fact]
    public async Task ExtractsOverrideAndFinalDispatchFlags()
    {
        var assemblyPath = typeof(DispatchDerivedFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.DispatchDerivedFixture");

        var describe = Assert.Single(fixture.Methods, method => method.Name == nameof(DispatchDerivedFixture.Describe));
        Assert.True(describe.IsVirtual);
        Assert.False(describe.IsNewSlot);
        Assert.False(describe.IsFinal);

        var transform = Assert.Single(fixture.Methods, method => method.Name == nameof(DispatchDerivedFixture.Transform));
        Assert.True(transform.IsVirtual);
        Assert.False(transform.IsNewSlot);
        Assert.True(transform.IsFinal);

        var dispose = Assert.Single(fixture.Methods, method => method.Name == nameof(DispatchDerivedFixture.Dispose));
        Assert.True(dispose.IsVirtual);
        Assert.True(dispose.IsNewSlot);
        Assert.True(dispose.IsFinal);

        var value = Assert.Single(fixture.Properties, property => property.Name == nameof(DispatchDerivedFixture.Value));
        Assert.True(value.IsVirtual);
        Assert.False(value.IsNewSlot);
        Assert.False(value.IsFinal);

        var dispatched = Assert.Single(fixture.Events, @event => @event.Name == nameof(DispatchDerivedFixture.Dispatched));
        Assert.True(dispatched.IsVirtual);
        Assert.False(dispatched.IsNewSlot);
        Assert.True(dispatched.IsFinal);
    }

    [Fact]
    public async Task ExtractsNestedTypeOwnershipAndGenericContext()
    {
        var assemblyPath = typeof(NestedTypeFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var types = document.Files[0].Code!.Types;

        var outer = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NestedTypeFixture");
        Assert.False(outer.IsNested);
        Assert.Null(outer.DeclaringType);
        Assert.Equal(["T"], outer.GenericParameters);

        var child = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NestedTypeFixture.Child");
        Assert.True(child.IsNested);
        Assert.Equal(outer.FullName, child.DeclaringType);
        Assert.Equal(outer.Namespace, child.Namespace);
        Assert.Equal(["T", "U"], child.GenericParameters);
        Assert.Equal(1, child.InheritedGenericParameterCount);

        var state = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NestedTypeFixture.Child.State");
        Assert.Equal(child.FullName, state.DeclaringType);
        Assert.Equal(["T", "U"], state.GenericParameters);
        Assert.Equal(2, state.InheritedGenericParameterCount);
    }

    [Fact]
    public async Task ExtractsAndSerializesGenericParameterMetadataAndConstraints()
    {
        var assemblyPath = typeof(GenericConstraintFixture<,,,,,>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var types = document.Files[0].Code!.Types;

        var variance = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.IGenericVarianceFixture");
        Assert.Equal(["TOut", "TIn"], variance.GenericParameters);
        Assert.Collection(
            variance.GenericParameterDetails,
            parameter =>
            {
                Assert.Equal(0, parameter.Position);
                Assert.Equal(1, parameter.RawAttributes);
                Assert.Equal("out", parameter.Variance);
                Assert.True(parameter.Complete);
            },
            parameter =>
            {
                Assert.Equal(1, parameter.Position);
                Assert.Equal(2, parameter.RawAttributes);
                Assert.Equal("in", parameter.Variance);
                Assert.True(parameter.Complete);
            });
        var varianceDelegate = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericVarianceDelegateFixture");
        Assert.Equal(["out", "in"], varianceDelegate.GenericParameterDetails.Select(parameter => parameter.Variance));
        Assert.All(varianceDelegate.GenericParameterDetails, parameter => Assert.True(parameter.Complete));
        var constrainedType = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericConstraintFixture");
        Assert.True(constrainedType.GenericParametersComplete);
        var parameters = constrainedType.GenericParameterDetails.ToDictionary(parameter => parameter.Name);

        Assert.True(parameters["TClass"].ReferenceTypeConstraint);
        Assert.Equal("not-annotated", parameters["TClass"].Nullability);
        Assert.Equal(new byte[] { 1 }, parameters["TClass"].NullableFlags);
        Assert.True(parameters["TNullableClass"].ReferenceTypeConstraint);
        Assert.Equal("annotated", parameters["TNullableClass"].Nullability);
        Assert.Equal(new byte[] { 2 }, parameters["TNullableClass"].NullableFlags);

        var structParameter = parameters["TStruct"];
        Assert.Equal(24, structParameter.RawAttributes);
        Assert.True(structParameter.NotNullableValueTypeConstraint);
        Assert.True(structParameter.DefaultConstructorConstraint);
        var structMarker = Assert.Single(structParameter.TypeConstraints);
        Assert.Equal("System.ValueType", structMarker.Type);
        Assert.Equal("value-type-marker", structMarker.Kind);
        Assert.Empty(structMarker.RequiredModifiers);
        Assert.True(structParameter.Complete);

        var unmanagedParameter = parameters["TUnmanaged"];
        Assert.True(unmanagedParameter.HasUnmanagedAttribute);
        var unmanagedMarker = Assert.Single(unmanagedParameter.TypeConstraints);
        Assert.Equal("value-type-marker", unmanagedMarker.Kind);
        Assert.Equal(
            ["System.Runtime.InteropServices.UnmanagedType"],
            unmanagedMarker.RequiredModifiers);
        Assert.Empty(unmanagedMarker.OptionalModifiers);
        Assert.True(unmanagedParameter.Complete);

        Assert.Equal(0, parameters["TNotNull"].RawAttributes);
        Assert.Equal("not-annotated", parameters["TNotNull"].Nullability);
        Assert.True(parameters["TNotNull"].NotNullConstraint);
        Assert.False(parameters["TClass"].NotNullConstraint);
        Assert.False(parameters["TConstructed"].NotNullConstraint);
        var constructedParameter = parameters["TConstructed"];
        Assert.True(constructedParameter.DefaultConstructorConstraint);
        Assert.Collection(
            constructedParameter.TypeConstraints,
            constraint => Assert.Equal("class", constraint.Kind),
            constraint => Assert.Equal("interface", constraint.Kind));
        Assert.True(constructedParameter.Complete);

        var method = Assert.Single(constrainedType.Methods, method => method.Name == "Method");
        Assert.Equal(
            ["TMethodClass", "TMethodNullable", "TMethodNew", "TMethodLink"],
            method.GenericParameters);
        Assert.Equal([0, 1, 2, 3], method.GenericParameterDetails.Select(parameter => parameter.Position));
        var methodParameters = method.GenericParameterDetails.ToDictionary(parameter => parameter.Name);
        Assert.Equal("not-annotated", methodParameters["TMethodClass"].Nullability);
        Assert.Equal("annotated", methodParameters["TMethodNullable"].Nullability);
        Assert.True(methodParameters["TMethodNew"].DefaultConstructorConstraint);
        Assert.Equal("interface", Assert.Single(methodParameters["TMethodNew"].TypeConstraints).Kind);
        var linkedConstraint = Assert.Single(methodParameters["TMethodLink"].TypeConstraints);
        Assert.Equal("!4", linkedConstraint.Type);
        Assert.Equal("type-parameter", linkedConstraint.Kind);

        var nested = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericConstraintFixture.Nested");
        Assert.Equal(6, nested.InheritedGenericParameterCount);
        Assert.Equal(7, nested.GenericParameterDetails.Count);
        Assert.All(nested.GenericParameterDetails.Take(6), parameter => Assert.True(parameter.Complete));
        Assert.Equal(new byte[] { 1 }, nested.GenericParameterDetails[4].NullableFlags);
        var nestedParameter = nested.GenericParameterDetails[^1];
        Assert.Equal("TNested", nestedParameter.Name);
        Assert.Equal("!4", Assert.Single(nestedParameter.TypeConstraints).Type);
        Assert.True(nested.GenericParametersComplete);

        var byRefLike = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.IAllowsRefStructFixture");
        var byRefLikeParameter = Assert.Single(byRefLike.GenericParameterDetails);
        Assert.Equal(32, byRefLikeParameter.RawAttributes);
        Assert.True(byRefLikeParameter.AllowsRefStruct);
        Assert.True(byRefLikeParameter.Complete);

        var genericAttributeTarget = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericAttributeTarget");
        Assert.True(genericAttributeTarget.GenericParametersComplete);
        var attributedParameter = Assert.Single(genericAttributeTarget.GenericParameterDetails);
        Assert.Equal("T", attributedParameter.Name);
        Assert.True(attributedParameter.Complete);

        var nullableConstraints = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NullableTypeConstraintFixture");
        var nullableParameters = nullableConstraints.GenericParameterDetails.ToDictionary(parameter => parameter.Name);
        Assert.Equal(
            "annotated",
            Assert.Single(nullableParameters["TBase"].TypeConstraints).Nullability);
        Assert.Equal(
            "annotated",
            Assert.Single(nullableParameters["TInterface"].TypeConstraints).Nullability);
        var constructedConstraint = Assert.Single(nullableParameters["TConstructed"].TypeConstraints);
        Assert.Equal("System.Collections.Generic.IEnumerable<string>", constructedConstraint.Type);
        Assert.Equal("unknown", constructedConstraint.Kind);
        Assert.Equal(new byte[] { 1, 2 }, constructedConstraint.NullableFlags);
        Assert.False(constructedConstraint.Complete);
        Assert.False(nullableParameters["TConstructed"].Complete);
        Assert.NotNull(nullableParameters["TConstructed"].Error);
        Assert.False(nullableConstraints.GenericParametersComplete);
        Assert.NotNull(nullableConstraints.GenericParametersError);

        await using var temp = new TemporaryDirectory();
        var outputPath = Path.Combine(temp.Path, "blueprint.json");
        await BlueprintJsonWriter.WriteAsync(document, outputPath);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(outputPath));
        Assert.Equal("0.9", json.RootElement.GetProperty("schemaVersion").GetString());
        var constraintTypeJson = json.RootElement
            .GetProperty("files")[0]
            .GetProperty("code")
            .GetProperty("types")
            .EnumerateArray()
            .Single(type =>
                type.GetProperty("fullName").GetString() ==
                "ExeBlueprint.Core.Tests.GenericConstraintFixture");
        Assert.Equal(6, constraintTypeJson.GetProperty("genericParameters").GetArrayLength());
        var unmanagedJson = constraintTypeJson
            .GetProperty("genericParameterDetails")
            .EnumerateArray()
            .Single(parameter => parameter.GetProperty("name").GetString() == "TUnmanaged");
        Assert.Equal(24, unmanagedJson.GetProperty("rawAttributes").GetInt32());
        Assert.True(unmanagedJson.GetProperty("hasUnmanagedAttribute").GetBoolean());
        Assert.Equal(
            "System.Runtime.InteropServices.UnmanagedType",
            unmanagedJson
                .GetProperty("typeConstraints")[0]
                .GetProperty("requiredModifiers")[0]
                .GetString());
        var notNullJson = constraintTypeJson
            .GetProperty("genericParameterDetails")
            .EnumerateArray()
            .Single(parameter => parameter.GetProperty("name").GetString() == "TNotNull");
        Assert.True(notNullJson.GetProperty("notNullConstraint").GetBoolean());
        var nullableTypeJson = json.RootElement
            .GetProperty("files")[0]
            .GetProperty("code")
            .GetProperty("types")
            .EnumerateArray()
            .Single(type =>
                type.GetProperty("fullName").GetString() ==
                "ExeBlueprint.Core.Tests.NullableTypeConstraintFixture");
        var nullableFlagsJson = nullableTypeJson
            .GetProperty("genericParameterDetails")[2]
            .GetProperty("typeConstraints")[0]
            .GetProperty("nullableFlags");
        Assert.Equal([1, 2], nullableFlagsJson.EnumerateArray().Select(flag => flag.GetByte()));
    }

    [Fact]
    public void DistributesGenericArgumentsAcrossNestedTypeSegments()
    {
        var provider = SignatureTypeNameProvider.Instance;

        Assert.Equal(
            "Example.Outer<!0, !1>.Nested",
            provider.GetGenericInstantiation("Example.Outer`2.Nested", ["!0", "!1"]));
        Assert.Equal(
            "Example.Outer<!0>.Child<!!0>.Leaf",
            provider.GetGenericInstantiation("Example.Outer`1.Child`1.Leaf", ["!0", "!!0"]));
        Assert.Equal(
            "Example.Legacy<!0>",
            provider.GetGenericInstantiation("Example.Legacy", ["!0"]));
        Assert.Equal(
            "Example.Outer.Child<!0>",
            provider.GetGenericInstantiation("Example.Outer`1.Child`1", ["!0"]));
        Assert.Equal(
            "Example.Outer.Child<!0, !1, !!0>",
            provider.GetGenericInstantiation("Example.Outer`1.Child`1", ["!0", "!1", "!!0"]));
    }

    [Fact]
    public void InstantiatesMethodSpecificationSignatureTokensAtomically()
    {
        var arguments = Enumerable.Range(0, 11).Select(index => $"T{index}").ToArray();

        Assert.Equal(
            "Example<T10, T1, !0>",
            ManagedSymbolReader.InstantiateMethodSignatureType("Example<!!10, !!1, !0>", arguments));
        Assert.Equal(
            "Example<!!11, !!0Suffix>",
            ManagedSymbolReader.InstantiateMethodSignatureType("Example<!!11, !!0Suffix>", arguments));
    }

    [Fact]
    public async Task ExtractsRefLikeTypeShape()
    {
        var assemblyPath = typeof(RefStructFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.RefStructFixture");

        Assert.Equal("struct", fixture.Kind);
        Assert.True(fixture.IsRefLike);
        var buffer = Assert.Single(fixture.Properties, property => property.Name == nameof(RefStructFixture.Buffer));
        Assert.Equal("System.Span<byte>", buffer.Type);
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedSwitchTable()
    {
        var assemblyPath = typeof(SwitchFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.SwitchFixture");
        var method = Assert.Single(fixture.Methods, method => method.Name == nameof(SwitchFixture.TerminalCases));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("switch (value)", method.Body);
        Assert.Contains("    case 2:", method.Body);
        Assert.Contains("        return 99;", method.Body);
        Assert.Contains(method.Il, instruction => instruction.Contains("switch (IL_", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedSwitchWithSharedJoin()
    {
        var assemblyPath = typeof(SwitchFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.SwitchFixture");
        var method = Assert.Single(fixture.Methods, method => method.Name == nameof(SwitchFixture.JoinedCases));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("int v0 = default;", method.Body);
        Assert.Contains("        v0 = 30;", method.Body);
        Assert.Equal(4, method.Body.Count(line => line.Trim() == "break;"));
        Assert.Equal("return v0;", method.Body[^1]);
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedTryFinally()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.AddWithCleanup));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("try", method.Body);
        Assert.Contains("finally", method.Body);
        Assert.Contains(method.Body, line => line.Contains("+ 10", StringComparison.Ordinal));
        Assert.Equal("return v0;", method.Body[^1]);
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedCatch()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchAndReturn));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("catch (System.InvalidOperationException)", method.Body);
        Assert.Contains("    v0 = -1;", method.Body);
        Assert.Equal("return v0;", method.Body[^1]);
    }

    [Fact]
    public async Task ReconstructsMultipleCatchHandlers()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.MultipleCatch));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("catch (System.DivideByZeroException)", method.Body);
        Assert.Contains("catch (System.ArithmeticException)", method.Body);
        Assert.Equal(2, method.Body.Count(line => line.StartsWith("catch", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ReconstructsNamedCatchVariable()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchVariable));

        Assert.True(method.BodyReconstructed);
        Assert.Contains("catch (System.InvalidOperationException caughtException0)", method.Body);
        Assert.Contains(method.Body, line => line.Contains("caughtException0.HResult", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsCatchAllAndRethrow()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");

        var catchAll = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchAll));
        Assert.True(catchAll.BodyReconstructed);
        Assert.Contains("catch", catchAll.Body);

        var rethrow = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.Rethrow));
        Assert.True(rethrow.BodyReconstructed);
        Assert.Contains("catch (System.InvalidOperationException)", rethrow.Body);
        Assert.Contains("    throw;", rethrow.Body);
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedCatchAndFinally()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchAndFinally));

        Assert.True(method.BodyReconstructed);
        Assert.Equal(2, method.Body.Count(line => line.Trim() == "try"));
        Assert.Contains("    catch (System.DivideByZeroException caughtException0)", method.Body);
        Assert.Contains("    catch (System.ArithmeticException)", method.Body);
        Assert.Equal(2, method.Body.Count(line => line.TrimStart().StartsWith("catch", StringComparison.Ordinal)));
        Assert.Contains("finally", method.Body);
        Assert.Contains(method.Body, line => line.Contains("caughtException0.HResult", StringComparison.Ordinal));
        Assert.DoesNotContain(method.Body, line =>
            line.StartsWith("System.DivideByZeroException v", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsCompilerGeneratedCatchFilter()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchFilter));

        Assert.True(method.BodyReconstructed);
        var filter = Assert.Single(
            method.Body,
            line => line.StartsWith("catch (System.InvalidOperationException caughtException0) when (", StringComparison.Ordinal));
        Assert.Contains("caughtException0.HResult", filter, StringComparison.Ordinal);
        Assert.Contains("== value", filter, StringComparison.Ordinal);
        Assert.Contains("catch (System.InvalidOperationException)", method.Body);
        Assert.Equal(2, method.Body.Count(line => line.StartsWith("catch", StringComparison.Ordinal)));
        Assert.DoesNotContain(method.Body, line => line.Contains(" v3", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReconstructsCatchFilterCombinedWithFinally()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchFilterAndFinally));

        Assert.True(method.BodyReconstructed);
        Assert.Equal(2, method.Body.Count(line => line.Trim() == "try"));
        Assert.Contains(method.Body, line =>
            line.TrimStart().StartsWith("catch (System.DivideByZeroException caughtException0) when (", StringComparison.Ordinal));
        Assert.Contains("finally", method.Body);
        Assert.DoesNotContain(method.Body, line =>
            line.StartsWith("System.DivideByZeroException v", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(nameof(ExceptionHandlingFixture.CatchFilterAnd), " && ", "value < 10")]
    [InlineData(nameof(ExceptionHandlingFixture.CatchFilterOr), " || ", "value == 5")]
    public async Task ReconstructsShortCircuitCatchFilters(
        string methodName,
        string expectedOperator,
        string expectedRightCondition)
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(fixture.Methods, method => method.Name == methodName);

        Assert.True(method.BodyReconstructed);
        var filter = Assert.Single(
            method.Body,
            line => line.StartsWith("catch (System.InvalidOperationException caughtException0) when (", StringComparison.Ordinal));
        Assert.Contains(expectedOperator, filter, StringComparison.Ordinal);
        Assert.Equal(2, filter.Split(expectedOperator, StringSplitOptions.None).Length - 1);
        Assert.Contains("caughtException0.HResult", filter, StringComparison.Ordinal);
        Assert.Contains(expectedRightCondition, filter, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(nameof(ExceptionHandlingFixture.CatchFilterAndOr), " && ", " || ", "value == -1")]
    [InlineData(nameof(ExceptionHandlingFixture.CatchFilterOrAnd), " || ", " && ", "value < 10")]
    public async Task ReconstructsMixedShortCircuitCatchFilters(
        string methodName,
        string outerOperator,
        string innerOperator,
        string expectedLeaf)
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");
        var method = Assert.Single(fixture.Methods, method => method.Name == methodName);

        Assert.True(method.BodyReconstructed);
        var filter = Assert.Single(
            method.Body,
            line => line.StartsWith("catch (System.InvalidOperationException caughtException0) when (", StringComparison.Ordinal));
        Assert.Contains(outerOperator, filter, StringComparison.Ordinal);
        Assert.Contains(innerOperator, filter, StringComparison.Ordinal);
        Assert.Contains("caughtException0.HResult", filter, StringComparison.Ordinal);
        Assert.Contains(expectedLeaf, filter, StringComparison.Ordinal);
        Assert.DoesNotContain(" ? ", filter, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReconstructsTerminalProtectedTryRegions()
    {
        var assemblyPath = typeof(ExceptionHandlingFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExceptionHandlingFixture");

        var catchMethod = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchTerminalTry));
        Assert.True(catchMethod.BodyReconstructed);
        Assert.Contains(catchMethod.Body, line =>
            line.Trim() == "throw new System.InvalidOperationException();");
        Assert.Contains("catch (System.InvalidOperationException)", catchMethod.Body);
        Assert.Equal("return v0;", catchMethod.Body[^1]);

        var filterMethod = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.CatchFilterTerminalTry));
        Assert.True(filterMethod.BodyReconstructed);
        Assert.Contains(filterMethod.Body, line =>
            line.StartsWith("catch (System.InvalidOperationException caughtException0) when (", StringComparison.Ordinal));

        var finallyMethod = Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(ExceptionHandlingFixture.FinallyTerminalTry));
        Assert.True(finallyMethod.BodyReconstructed);
        Assert.Contains(finallyMethod.Body, line =>
            line.Trim() == "throw new System.InvalidOperationException();");
        Assert.Contains("finally", finallyMethod.Body);
        Assert.Contains(finallyMethod.Body, line => line.Contains("+ 10", StringComparison.Ordinal));
        Assert.Equal("}", finallyMethod.Body[^1]);
    }

    [Fact]
    public async Task ReadsEmbeddedManifestResources()
    {
        var assemblyPath = typeof(ManagedSymbolReaderTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var code = document.Files[0].Code!;

        var resource = Assert.Single(
            code.Resources,
            resource => resource.Name == "ExeBlueprint.Core.Tests.Fixtures.settings.json");

        Assert.Equal("embedded", resource.Location);
        Assert.Equal("設定檔", resource.Kind);
        // Fixtures\settings.json 內容固定為 27 個 ASCII 位元組。
        Assert.Equal(27, resource.Size);
        Assert.Contains(resource.Visibility, new[] { "public", "private" });
    }

    [Fact]
    public async Task ReadsStandardResourceTableKeysAndValues()
    {
        var assemblyPath = typeof(ManagedSymbolReaderTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var code = document.Files[0].Code!;

        var resource = Assert.Single(
            code.Resources,
            resource => resource.Name == "ExeBlueprint.Core.Tests.Fixtures.sample.resources");

        Assert.Null(resource.EntriesError);
        Assert.False(resource.EntriesTruncated);
        Assert.Equal(3, resource.Entries.Count);
        AssertResourceEntry(resource, "Greeting", "String", "哈囉 ExeBlueprint");

        var bamlEntry = Assert.Single(resource.Entries, entry => entry.Name == "mainwindow.baml");
        Assert.EndsWith("ByteArray", bamlEntry.Type, StringComparison.Ordinal);
        Assert.Equal("binary", bamlEntry.Status);
        Assert.Equal(1_009, bamlEntry.DataSize);
        Assert.NotNull(bamlEntry.Baml);
        Assert.Equal("parsed", bamlEntry.Baml.Status);
        Assert.Equal("MSBAML", bamlEntry.Baml.Signature);
        Assert.Equal("0.96", bamlEntry.Baml.ReaderVersion);
        Assert.Equal("0.96", bamlEntry.Baml.UpdaterVersion);
        Assert.Equal("0.96", bamlEntry.Baml.WriterVersion);
        Assert.Equal(24, bamlEntry.Baml.RecordCount);
        Assert.Equal(2, bamlEntry.Baml.ElementCount);
        Assert.Equal(4, bamlEntry.Baml.PropertyCount);
        Assert.Equal(0, bamlEntry.Baml.RootElementTypeId);
        Assert.Equal("BamlFixture.MainWindow", bamlEntry.Baml.RootElementType);
        Assert.False(bamlEntry.Baml.RecordsTruncated);
        Assert.False(bamlEntry.Baml.SymbolsTruncated);
        Assert.Null(bamlEntry.Baml.Error);
        Assert.Equal(6, Assert.Single(bamlEntry.Baml.RecordTypes, item => item.Name == "AssemblyInfo").Count);
        Assert.Equal(2, Assert.Single(bamlEntry.Baml.RecordTypes, item => item.Name == "ElementStart").Count);
        Assert.Equal(1, Assert.Single(bamlEntry.Baml.RecordTypes, item => item.Name == "DocumentEnd").Count);
        var customElement = Assert.Single(bamlEntry.Baml.ElementTypes, item => item.Id == 0);
        Assert.Equal("BamlFixture.MainWindow", customElement.Name);
        Assert.StartsWith("BamlFixture, Version=1.0.0.0", customElement.Assembly, StringComparison.Ordinal);
        Assert.Equal(1, customElement.Count);
        var builtInElement = Assert.Single(bamlEntry.Baml.ElementTypes, item => item.Id == -254);
        Assert.Equal("Grid", builtInElement.Name);
        Assert.False(bamlEntry.Baml.ElementsTruncated);
        Assert.True(bamlEntry.Baml.ElementTreeComplete);
        Assert.Null(bamlEntry.Baml.ElementTreeError);
        Assert.Equal(2, bamlEntry.Baml.Elements.Count);
        var rootElement = Assert.Single(bamlEntry.Baml.Elements, item => item.ParentId is null);
        Assert.Equal(0, rootElement.Id);
        Assert.Equal("BamlFixture.MainWindow", rootElement.Type);
        Assert.Equal(0, rootElement.Depth);
        Assert.True(rootElement.StartOffset > 0);
        Assert.NotNull(rootElement.EndOffset);
        Assert.True(rootElement.EndOffset > rootElement.StartOffset);
        Assert.Equal(1, rootElement.ChildCount);
        Assert.Equal(3, rootElement.PropertyValueCount);
        Assert.Equal("Content", rootElement.ContentPropertyName);
        var gridElement = Assert.Single(bamlEntry.Baml.Elements, item => item.ParentId == rootElement.Id);
        Assert.Equal("Grid", gridElement.Type);
        Assert.Equal(1, gridElement.Depth);
        Assert.Equal("Content", gridElement.ParentPropertyName);
        Assert.Equal("ContentControl", gridElement.ParentPropertyOwnerType);
        var titleProperty = Assert.Single(bamlEntry.Baml.Properties, item => item.Id == 0);
        Assert.Equal("Title", titleProperty.Name);
        Assert.Equal("Window", titleProperty.OwnerType);
        var widthProperty = Assert.Single(bamlEntry.Baml.Properties, item => item.Id == -57);
        Assert.Equal("Width", widthProperty.Name);
        Assert.Equal("FrameworkElement", widthProperty.OwnerType);
        var heightProperty = Assert.Single(bamlEntry.Baml.Properties, item => item.Id == -47);
        Assert.Equal("Height", heightProperty.Name);
        Assert.Equal("FrameworkElement", heightProperty.OwnerType);
        var contentProperty = Assert.Single(bamlEntry.Baml.Properties, item => item.Id == -14);
        Assert.Equal("Content", contentProperty.Name);
        Assert.Equal("ContentControl", contentProperty.OwnerType);
        Assert.Equal(4, bamlEntry.Baml.Properties.Count);
        Assert.Equal(3, bamlEntry.Baml.PropertyValueCount);
        Assert.False(bamlEntry.Baml.PropertyValuesTruncated);
        var titleValue = Assert.Single(
            bamlEntry.Baml.PropertyValues,
            item => item.PropertyName == "Title");
        Assert.Equal("BamlFixture.MainWindow", titleValue.ElementType);
        Assert.Equal("converted", titleValue.Kind);
        Assert.Equal("MainWindow", titleValue.Value);
        Assert.Equal(rootElement.Id, titleValue.ElementId);
        Assert.Contains(
            bamlEntry.Baml.PropertyValues,
            item => item.PropertyName == "Width" && item.Value == "800");
        Assert.Contains(
            bamlEntry.Baml.PropertyValues,
            item => item.PropertyName == "Height" && item.Value == "450");

        var deferredEntry = Assert.Single(resource.Entries, entry => entry.Name == "deferred.baml");
        Assert.Equal("parsed", deferredEntry.Baml!.Status);
        Assert.True(deferredEntry.Baml.DeferredResourcesComplete);
        Assert.Equal(2, deferredEntry.Baml.DeferredResourceCount);
        Assert.Equal(["primary", "Grid"], deferredEntry.Baml.DeferredResources.Select(item => item.Key));

        await using var temp = new TemporaryDirectory();
        var outputPath = Path.Combine(temp.Path, "blueprint.json");
        await BlueprintJsonWriter.WriteAsync(document, outputPath);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(outputPath));
        var resourceJson = json.RootElement
            .GetProperty("files")[0]
            .GetProperty("code")
            .GetProperty("resources")
            .EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == resource.Name);
        Assert.Equal(3, resourceJson.GetProperty("entries").GetArrayLength());
        Assert.False(resourceJson.GetProperty("entriesTruncated").GetBoolean());
        var bamlJson = resourceJson
            .GetProperty("entries")
            .EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == "mainwindow.baml")
            .GetProperty("baml");
        Assert.Equal("parsed", bamlJson.GetProperty("status").GetString());
        Assert.Equal(24, bamlJson.GetProperty("recordCount").GetInt32());
        Assert.Equal(11, bamlJson.GetProperty("recordTypes").GetArrayLength());
        Assert.Equal(2, bamlJson.GetProperty("elementCount").GetInt32());
        Assert.Equal(4, bamlJson.GetProperty("propertyCount").GetInt32());
        Assert.Equal("BamlFixture.MainWindow", bamlJson.GetProperty("rootElementType").GetString());
        Assert.Equal(2, bamlJson.GetProperty("elementTypes").GetArrayLength());
        Assert.Equal(2, bamlJson.GetProperty("elements").GetArrayLength());
        Assert.False(bamlJson.GetProperty("elementsTruncated").GetBoolean());
        Assert.True(bamlJson.GetProperty("elementTreeComplete").GetBoolean());
        Assert.False(bamlJson.TryGetProperty("elementTreeError", out _));
        Assert.Equal(4, bamlJson.GetProperty("properties").GetArrayLength());
        Assert.Equal(3, bamlJson.GetProperty("propertyValueCount").GetInt32());
        Assert.Equal(3, bamlJson.GetProperty("propertyValues").GetArrayLength());
        Assert.False(bamlJson.GetProperty("propertyValuesTruncated").GetBoolean());
        Assert.Equal(0, bamlJson.GetProperty("deferredResourceCount").GetInt32());
        Assert.Equal(0, bamlJson.GetProperty("deferredResources").GetArrayLength());
        Assert.False(bamlJson.GetProperty("deferredResourcesTruncated").GetBoolean());
        Assert.True(bamlJson.GetProperty("deferredResourcesComplete").GetBoolean());
        Assert.False(bamlJson.TryGetProperty("deferredResourcesError", out _));
        Assert.Equal(
            "Grid",
            bamlJson.GetProperty("elementTypes")
                .EnumerateArray()
                .Single(item => item.GetProperty("id").GetInt32() == -254)
                .GetProperty("name")
                .GetString());
        var deferredJson = resourceJson
            .GetProperty("entries")
            .EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == "deferred.baml")
            .GetProperty("baml");
        Assert.Equal(2, deferredJson.GetProperty("deferredResourceCount").GetInt32());
        Assert.Equal(2, deferredJson.GetProperty("deferredResources").GetArrayLength());
        Assert.True(deferredJson.GetProperty("deferredResourcesComplete").GetBoolean());
        Assert.Equal(
            "accent",
            deferredJson.GetProperty("propertyValues")[0].GetProperty("value").GetString());
    }

    [Fact]
    public void DecodesStandardResourceValueFormats()
    {
        AssertDecodedResource("Boolean", WriteResourceData(writer => writer.Write(true)), "true");
        AssertDecodedResource("Int32", WriteResourceData(writer => writer.Write(3)), "3");
        AssertDecodedResource("Double", WriteResourceData(writer => writer.Write(1.25)), "1.25");
        AssertDecodedResource(
            "TimeSpan",
            WriteResourceData(writer => writer.Write(TimeSpan.FromSeconds(90).Ticks)),
            "00:01:30");

        var binary = WriteResourceData(writer =>
        {
            writer.Write(3);
            writer.Write(new byte[] { 1, 2, 3 });
        });
        var binaryEntry = ManagedSymbolReader.DecodeResourceEntry(
            "Payload",
            "ResourceTypeCode.ByteArray",
            binary);
        Assert.Equal("binary", binaryEntry.Status);
        Assert.Equal(3, binaryEntry.DataSize);
        Assert.Null(binaryEntry.Value);

        var unsupported = ManagedSymbolReader.DecodeResourceEntry(
            "Custom",
            "Example.Widget, Example",
            [1, 2, 3]);
        Assert.Equal("unsupported", unsupported.Status);
        Assert.Equal(3, unsupported.DataSize);
        Assert.NotNull(unsupported.Error);

        var longText = new string('x', 4_097);
        var truncated = ManagedSymbolReader.DecodeResourceEntry(
            "LongText",
            "ResourceTypeCode.String",
            WriteResourceData(writer => writer.Write(longText)));
        Assert.True(truncated.ValueTruncated);
        Assert.Equal(4_096, truncated.Value!.Length);

        var invalidBinary = ManagedSymbolReader.DecodeResourceEntry(
            "InvalidPayload",
            "ResourceTypeCode.ByteArray",
            WriteResourceData(writer =>
            {
                writer.Write(4);
                writer.Write(new byte[] { 1, 2 });
            }));
        Assert.Equal("invalid", invalidBinary.Status);
        Assert.NotNull(invalidBinary.Error);
    }

    [Fact]
    public void KeepsInvalidAndUnsupportedBamlSummariesBounded()
    {
        var invalidHeader = ManagedSymbolReader.DecodeResourceEntry(
            "broken.baml",
            "ResourceTypeCode.ByteArray",
            WriteResourceData(writer =>
            {
                writer.Write(28);
                writer.Write(new byte[28]);
            }));
        Assert.Equal("binary", invalidHeader.Status);
        Assert.Equal("invalid", invalidHeader.Baml!.Status);
        Assert.NotNull(invalidHeader.Baml.Error);

        var unsupportedVersion = CreateBamlHeader(readerMinor: 97)
            .Concat(new byte[] { 2 })
            .ToArray();
        var unsupported = ManagedSymbolReader.DecodeResourceEntry(
            "future.baml",
            "ResourceTypeCode.Stream",
            WriteResourceData(writer =>
            {
                writer.Write(unsupportedVersion.Length);
                writer.Write(unsupportedVersion);
            }));
        Assert.Equal("partial", unsupported.Baml!.Status);
        Assert.Equal("0.97", unsupported.Baml.ReaderVersion);
        Assert.Equal(0, unsupported.Baml.RecordCount);
        Assert.NotNull(unsupported.Baml.Error);

        var truncatedRecord = CreateBamlHeader()
            .Concat(new byte[] { 1, 0 })
            .ToArray();
        var truncated = BamlSummaryReader.Read(truncatedRecord);
        Assert.Equal("partial", truncated.Status);
        Assert.Equal(0, truncated.RecordCount);
        Assert.NotNull(truncated.Error);

        using var partialAfterClosedTreeStream = new MemoryStream();
        partialAfterClosedTreeStream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(
                   partialAfterClosedTreeStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)4);
            writer.Write((byte)47);
        }

        var partialAfterClosedTree = BamlSummaryReader.Read(partialAfterClosedTreeStream.ToArray());
        Assert.Equal("partial", partialAfterClosedTree.Status);
        Assert.Equal(1, partialAfterClosedTree.ElementCount);
        Assert.Single(partialAfterClosedTree.Elements);
        Assert.False(partialAfterClosedTree.ElementTreeComplete);
        Assert.Contains("NamedElementStart", partialAfterClosedTree.ElementTreeError);

        var invalidTypeMap = CreateBamlHeader()
            .Concat(new byte[] { 29, 2, 0 })
            .ToArray();
        var invalidMap = BamlSummaryReader.Read(invalidTypeMap);
        Assert.Equal("partial", invalidMap.Status);
        Assert.Equal(0, invalidMap.RecordCount);
        Assert.Contains("type 對照表", invalidMap.Error);

        using var manyElements = new MemoryStream();
        manyElements.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(manyElements, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            for (short typeId = 0; typeId <= 2_000; typeId++)
            {
                writer.Write((byte)3);
                writer.Write(typeId);
                writer.Write((byte)0);
            }
        }

        var boundedSymbols = BamlSummaryReader.Read(manyElements.ToArray());
        Assert.Equal("parsed", boundedSymbols.Status);
        Assert.Equal(2_001, boundedSymbols.ElementCount);
        Assert.Equal(2_000, boundedSymbols.ElementTypes.Count);
        Assert.Equal(2_000, boundedSymbols.Elements.Count);
        Assert.True(boundedSymbols.ElementsTruncated);
        Assert.False(boundedSymbols.ElementTreeComplete);
        Assert.NotNull(boundedSymbols.ElementTreeError);
        Assert.Equal(1_999, boundedSymbols.Elements[^1].Depth);
        Assert.True(boundedSymbols.SymbolsTruncated);

        using var manyValues = new MemoryStream();
        manyValues.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(manyValues, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            for (var index = 0; index <= 2_000; index++)
            {
                WriteBamlVariableRecord(writer, 5, payload =>
                {
                    payload.Write((short)-57);
                    payload.Write(string.Empty);
                });
            }

            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var boundedValues = BamlSummaryReader.Read(manyValues.ToArray());
        Assert.Equal("parsed", boundedValues.Status);
        Assert.Equal(2_001, boundedValues.PropertyValueCount);
        Assert.Equal(2_000, boundedValues.PropertyValues.Count);
        Assert.True(boundedValues.PropertyValuesTruncated);
    }

    [Fact]
    public void ResolvesWpfBuiltInBamlIdsWithoutLoadingWpf()
    {
        Assert.Equal("AccessText", WpfBamlKnownIds.GetTypeName(-1));
        Assert.Equal("Grid", WpfBamlKnownIds.GetTypeName(-254));
        Assert.Equal("ZoomPercentageConverter", WpfBamlKnownIds.GetTypeName(-759));
        Assert.Null(WpfBamlKnownIds.GetTypeName(0));
        Assert.Null(WpfBamlKnownIds.GetTypeName(-760));
        Assert.Null(WpfBamlKnownIds.GetTypeName(short.MinValue));

        Assert.True(WpfBamlKnownIds.TryGetProperty(-1, out var accessTextOwner, out var accessTextName));
        Assert.Equal("AccessText", accessTextOwner);
        Assert.Equal("Text", accessTextName);
        Assert.True(WpfBamlKnownIds.TryGetProperty(-57, out var widthOwner, out var widthName));
        Assert.Equal("FrameworkElement", widthOwner);
        Assert.Equal("Width", widthName);
        Assert.True(WpfBamlKnownIds.TryGetProperty(-270, out var richTextBoxOwner, out var richTextBoxName));
        Assert.Equal("RichTextBox", richTextBoxOwner);
        Assert.Equal("IsReadOnly", richTextBoxName);
        Assert.False(WpfBamlKnownIds.TryGetProperty(-137, out _, out _));
        Assert.False(WpfBamlKnownIds.TryGetProperty(-271, out _, out _));
        Assert.False(WpfBamlKnownIds.TryGetProperty(0, out _, out _));

        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var summary = BamlSummaryReader.Read(stream.ToArray());
        Assert.Equal("parsed", summary.Status);
        Assert.Equal(-254, summary.RootElementTypeId);
        Assert.Equal("Grid", summary.RootElementType);
        Assert.Equal("Grid", Assert.Single(summary.ElementTypes).Name);
    }

    [Fact]
    public void BuildsBoundedFlatBamlElementTreeWithPropertyRelationships()
    {
        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)1);

            writer.Write((byte)46);
            writer.Write((short)-14);

            writer.Write((byte)3);
            writer.Write((short)-1);
            writer.Write((byte)0);
            WriteBamlVariableRecord(writer, 5, payload =>
            {
                payload.Write((short)-1);
                payload.Write("child");
            });
            writer.Write((byte)4);

            writer.Write((byte)7);
            writer.Write((short)-57);
            writer.Write((byte)3);
            writer.Write((short)-1);
            writer.Write((byte)2);
            writer.Write((byte)46);
            writer.Write((short)-14);
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)4);
            writer.Write((byte)4);
            writer.Write((byte)8);

            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var summary = BamlSummaryReader.Read(stream.ToArray());

        Assert.Equal("parsed", summary.Status);
        Assert.Equal(4, summary.ElementCount);
        Assert.Equal(4, summary.Elements.Count);
        Assert.False(summary.ElementsTruncated);
        Assert.True(summary.ElementTreeComplete);
        Assert.Null(summary.ElementTreeError);
        var root = summary.Elements[0];
        Assert.Equal("Grid", root.Type);
        Assert.True(root.CreateUsingTypeConverter);
        Assert.Equal(2, root.ChildCount);
        Assert.Equal("Content", root.ContentPropertyName);
        var contentChild = summary.Elements[1];
        Assert.Equal(root.Id, contentChild.ParentId);
        Assert.Equal("Content", contentChild.ParentPropertyName);
        Assert.Equal(1, contentChild.PropertyValueCount);
        var scopedChild = summary.Elements[2];
        Assert.Equal(root.Id, scopedChild.ParentId);
        Assert.Equal("Width", scopedChild.ParentPropertyName);
        Assert.True(scopedChild.IsInjected);
        Assert.Equal(1, scopedChild.ChildCount);
        var nestedChild = summary.Elements[3];
        Assert.Equal(scopedChild.Id, nestedChild.ParentId);
        Assert.Equal("Content", nestedChild.ParentPropertyName);
        var childValue = Assert.Single(summary.PropertyValues);
        Assert.Equal(contentChild.Id, childValue.ElementId);
        Assert.Equal("child", childValue.Value);

        var unmatchedEnd = BamlSummaryReader.Read(
            CreateBamlHeader().Concat(new byte[] { 4, 2 }).ToArray());
        Assert.Equal("parsed", unmatchedEnd.Status);
        Assert.False(unmatchedEnd.ElementTreeComplete);
        Assert.Contains("沒有對應", unmatchedEnd.ElementTreeError);

        using var unclosedScopeStream = new MemoryStream();
        unclosedScopeStream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(
                   unclosedScopeStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)7);
            writer.Write((short)-57);
            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var unclosedScope = BamlSummaryReader.Read(unclosedScopeStream.ToArray());
        Assert.Equal("parsed", unclosedScope.Status);
        Assert.False(unclosedScope.ElementTreeComplete);
        Assert.Contains("scope 未關閉", unclosedScope.ElementTreeError);

        using var mismatchedScopeStream = new MemoryStream();
        mismatchedScopeStream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(
                   mismatchedScopeStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)7);
            writer.Write((short)-57);
            writer.Write((byte)10);
            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var mismatchedScope = BamlSummaryReader.Read(mismatchedScopeStream.ToArray());
        Assert.False(mismatchedScope.ElementTreeComplete);
        Assert.Contains("不相符", mismatchedScope.ElementTreeError);

        using var ancestorScopeEndStream = new MemoryStream();
        ancestorScopeEndStream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(
                   ancestorScopeEndStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);
            writer.Write((byte)7);
            writer.Write((short)-57);
            writer.Write((byte)3);
            writer.Write((short)-1);
            writer.Write((byte)0);
            writer.Write((byte)8);
            writer.Write((byte)4);
            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var ancestorScopeEnd = BamlSummaryReader.Read(ancestorScopeEndStream.ToArray());
        Assert.False(ancestorScopeEnd.ElementTreeComplete);
        Assert.Contains("屬於 element 0", ancestorScopeEnd.ElementTreeError);

        using var outOfElementScopeStream = new MemoryStream();
        outOfElementScopeStream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(
                   outOfElementScopeStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writer.Write((byte)7);
            writer.Write((short)-57);
            writer.Write((byte)8);
            writer.Write((byte)46);
            writer.Write((short)-14);
            writer.Write((byte)2);
        }

        var outOfElementScope = BamlSummaryReader.Read(outOfElementScopeStream.ToArray());
        Assert.False(outOfElementScope.ElementTreeComplete);
        Assert.Contains("element 外", outOfElementScope.ElementTreeError);
    }

    [Fact]
    public void ReadsBoundedBamlPropertyValueKindsWithoutLoadingWpf()
    {
        var staticResourceExtensionId = FindKnownWpfTypeId("StaticResourceExtension");
        var booleanConverterId = FindKnownWpfTypeId("BooleanConverter");
        var lengthConverterId = FindKnownWpfTypeId("LengthConverter");
        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            writer.Write((byte)3);
            writer.Write((short)-254);
            writer.Write((byte)0);

            WriteBamlVariableRecord(writer, 32, payload =>
            {
                payload.Write((short)10);
                payload.Write("primary");
            });
            WriteBamlVariableRecord(writer, 5, payload =>
            {
                payload.Write((short)-57);
                payload.Write("640");
            });

            writer.Write((byte)33);
            writer.Write((short)-47);
            writer.Write((short)10);

            writer.Write((byte)34);
            writer.Write((short)-14);
            writer.Write((short)-254);

            writer.Write((byte)35);
            writer.Write((short)-14);
            writer.Write(staticResourceExtensionId);
            writer.Write((short)10);

            WriteBamlVariableRecord(writer, 36, payload =>
            {
                payload.Write((short)-57);
                payload.Write("42");
                payload.Write((short)-lengthConverterId);
            });
            WriteBamlVariableRecord(writer, 6, payload =>
            {
                payload.Write((short)-47);
                payload.Write(booleanConverterId);
                payload.Write((byte)1);
            });

            writer.Write((byte)56);
            writer.Write((short)-14);
            writer.Write((short)3);

            WriteBamlVariableRecord(writer, 5, payload =>
            {
                payload.Write((short)-57);
                payload.Write(new string('x', 4_097));
            });

            writer.Write((byte)4);
            writer.Write((byte)2);
        }

        var summary = BamlSummaryReader.Read(stream.ToArray());

        Assert.Equal("parsed", summary.Status);
        Assert.Equal(8, summary.PropertyValueCount);
        Assert.Equal(8, summary.PropertyValues.Count);
        Assert.All(summary.PropertyValues, value => Assert.Equal("Grid", value.ElementType));
        Assert.Contains(summary.PropertyValues, value => value.Kind == "literal" && value.Value == "640");
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "string-reference" && value.ReferenceId == 10 && value.Value == "primary");
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "type-reference" && value.Value == "Grid");
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "markup-extension"
            && value.RelatedType == "StaticResourceExtension"
            && value.Value == "primary");
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "converted" && value.RelatedType == "LengthConverter" && value.Value == "42");
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "custom-binary" && value.RelatedType == "BooleanConverter" && value.DataSize == 1);
        Assert.Contains(summary.PropertyValues, value =>
            value.Kind == "static-resource"
            && value.ReferenceId == 3
            && value.Value is null
            && value.DeferredResourceId is null);
        var longValue = Assert.Single(summary.PropertyValues, value => value.Value?.Length == 4_096);
        Assert.True(longValue.ValueTruncated);
        Assert.False(summary.PropertyValuesTruncated);
    }

    [Fact]
    public void LinksSimpleDeferredBamlKeysToKeyLocalStaticResources()
    {
        var summary = BamlSummaryReader.Read(Convert.FromBase64String(DeferredBamlFixtureBase64));

        Assert.Equal("parsed", summary.Status);
        Assert.Equal(2, summary.DeferredResourceCount);
        Assert.Equal(2, summary.DeferredResources.Count);
        Assert.False(summary.DeferredResourcesTruncated);
        Assert.True(summary.DeferredResourcesComplete);
        Assert.Null(summary.DeferredResourcesError);

        var stringKey = Assert.Single(summary.DeferredResources, resource => resource.Id == 0);
        Assert.Equal("string", stringKey.KeyKind);
        Assert.Equal(10, stringKey.KeyId);
        Assert.Equal("primary", stringKey.Key);
        Assert.Equal(60, stringKey.KeyRecordOffset);
        Assert.Equal(0, stringKey.ValuePosition);
        Assert.Equal(88, stringKey.ValueStartOffset);
        Assert.Equal(98, stringKey.ValueEndOffset);
        Assert.False(stringKey.Shared);
        Assert.False(stringKey.SharedSet);
        Assert.Equal(1, stringKey.ElementId);
        Assert.Equal(-1, stringKey.ElementTypeId);
        Assert.Equal("AccessText", stringKey.ElementType);
        Assert.False(stringKey.StaticResourcesTruncated);
        var accent = Assert.Single(stringKey.StaticResources);
        Assert.Equal(0, accent.Id);
        Assert.Equal("string-reference", accent.Kind);
        Assert.Equal(11, accent.ReferenceId);
        Assert.Equal("accent", accent.Value);

        var typeKey = Assert.Single(summary.DeferredResources, resource => resource.Id == 1);
        Assert.Equal("type", typeKey.KeyKind);
        Assert.Equal(-254, typeKey.KeyId);
        Assert.Equal("Grid", typeKey.Key);
        Assert.Equal(74, typeKey.KeyRecordOffset);
        Assert.Equal(10, typeKey.ValuePosition);
        Assert.Equal(98, typeKey.ValueStartOffset);
        Assert.Equal(108, typeKey.ValueEndOffset);
        Assert.True(typeKey.Shared);
        Assert.True(typeKey.SharedSet);
        Assert.Equal(2, typeKey.ElementId);
        Assert.Equal(-254, typeKey.ElementTypeId);
        Assert.Equal("Grid", typeKey.ElementType);
        Assert.False(typeKey.StaticResourcesTruncated);
        var accessText = Assert.Single(typeKey.StaticResources);
        Assert.Equal(0, accessText.Id);
        Assert.Equal("type-reference", accessText.Kind);
        Assert.Equal(-1, accessText.ReferenceId);
        Assert.Equal("AccessText", accessText.Value);

        var width = Assert.Single(summary.PropertyValues, value => value.PropertyName == "Width");
        Assert.Equal("static-resource", width.Kind);
        Assert.Equal(0, width.ReferenceId);
        Assert.Equal("accent", width.Value);
        Assert.Equal(stringKey.Id, width.DeferredResourceId);
        Assert.Equal(stringKey.ElementId, width.ElementId);

        var content = Assert.Single(summary.PropertyValues, value => value.PropertyName == "Content");
        Assert.Equal("static-resource", content.Kind);
        Assert.Equal(0, content.ReferenceId);
        Assert.Equal("AccessText", content.Value);
        Assert.Equal(typeKey.Id, content.DeferredResourceId);
        Assert.Equal(typeKey.ElementId, content.ElementId);
    }

    [Fact]
    public void RejectsUnsafeDeferredBamlContentAndValueOffsets()
    {
        var contentOutsideStream = ReadMutatedDeferredBaml(bytes => bytes[56] = 64);
        AssertIncompleteDeferredResources(contentOutsideStream);
        Assert.All(
            contentOutsideStream.PropertyValues.Where(value => value.Kind == "static-resource"),
            value =>
            {
                Assert.Null(value.Value);
                Assert.Null(value.DeferredResourceId);
            });

        var contentEndsAtValueElement = ReadMutatedDeferredBaml(bytes => bytes[56] = 37);
        AssertIncompleteDeferredResources(contentEndsAtValueElement);
        Assert.Contains("owner", contentEndsAtValueElement.DeferredResourcesError);

        var contentIncludesOwnerEnd = ReadMutatedDeferredBaml(bytes => bytes[56] = 49);
        AssertIncompleteDeferredResources(contentIncludesOwnerEnd);

        var valueInsideRecord = ReadMutatedDeferredBaml(bytes => bytes[64] = 1);
        AssertIncompleteDeferredResources(valueInsideRecord);
        var nonBoundaryWidth = Assert.Single(
            valueInsideRecord.PropertyValues,
            value => value.PropertyName == "Width");
        Assert.Null(nonBoundaryWidth.Value);
        Assert.Null(nonBoundaryWidth.DeferredResourceId);

        var decreasingPositions = ReadMutatedDeferredBaml(bytes =>
        {
            bytes[64] = 10;
            bytes[78] = 0;
        });
        AssertIncompleteDeferredResources(decreasingPositions);
        Assert.All(
            decreasingPositions.PropertyValues.Where(value => value.Kind == "static-resource"),
            value =>
            {
                Assert.Null(value.Value);
                Assert.Null(value.DeferredResourceId);
            });
    }

    [Fact]
    public void RejectsDeferredKeyThatTargetsNestedValueElement()
    {
        var summary = BamlSummaryReader.Read(CreateDeferredBamlWithNestedValueTarget());

        Assert.Equal("parsed", summary.Status);
        Assert.Equal(2, summary.DeferredResourceCount);
        Assert.Empty(summary.DeferredResources);
        AssertIncompleteDeferredResources(summary);
        Assert.Contains("直接子", summary.DeferredResourcesError);
        Assert.All(
            summary.PropertyValues.Where(value => value.Kind == "static-resource"),
            value =>
            {
                Assert.Null(value.Value);
                Assert.Null(value.DeferredResourceId);
            });
    }

    [Fact]
    public void RejectsOutOfRangeKeyLocalStaticResourceIdWithoutGlobalFallback()
    {
        var summary = ReadMutatedDeferredBaml(bytes => bytes[95] = 1);

        AssertIncompleteDeferredResources(summary);
        var width = Assert.Single(summary.PropertyValues, value => value.PropertyName == "Width");
        Assert.Equal(1, width.ReferenceId);
        Assert.Equal(0, width.DeferredResourceId);
        Assert.Null(width.Value);
        Assert.DoesNotContain(
            summary.PropertyValues,
            value => value.PropertyName == "Width" && value.Value is "accent" or "AccessText");
    }

    [Fact]
    public void ResolvesStaticMemberOptimizedResourceAndRejectsUnsupportedDeferredHeaders()
    {
        var staticMember = ReadMutatedDeferredBaml(bytes => bytes[85] = 2);
        Assert.True(staticMember.DeferredResourcesComplete);
        var typeKey = Assert.Single(staticMember.DeferredResources, resource => resource.KeyKind == "type");
        var member = Assert.Single(typeKey.StaticResources);
        Assert.Equal("property-reference", member.Kind);
        Assert.Equal("AccessText.Text", member.Value);
        Assert.Contains(
            staticMember.PropertyValues,
            value => value.DeferredResourceId == typeKey.Id && value.Value == "AccessText.Text");

        var complexKey = ReadMutatedDeferredBaml(bytes => bytes[60] = 40);
        AssertIncompleteDeferredResources(complexKey);
        Assert.Contains("KeyElementStart", complexKey.DeferredResourcesError);

        var verboseStaticResource = ReadMutatedDeferredBaml(bytes => bytes[70] = 48);
        AssertIncompleteDeferredResources(verboseStaticResource);
        Assert.Contains("StaticResourceStart", verboseStaticResource.DeferredResourcesError);

        var keylessContent = ReadMutatedDeferredBaml(bytes => bytes[60] = 51);
        AssertIncompleteDeferredResources(keylessContent);
        Assert.Contains("沒有可辨識的 key", keylessContent.DeferredResourcesError);

        var nestedStaticResource = BamlSummaryReader.Read(CreateDeferredBamlWithNestedStaticResourceId());
        AssertIncompleteDeferredResources(nestedStaticResource);
        Assert.Contains("nested indirection", nestedStaticResource.DeferredResourcesError);
    }

    [Fact]
    public void BoundsDeferredBamlKeysAndStaticResourceTables()
    {
        var manyKeys = BamlSummaryReader.Read(CreateLargeDeferredBaml(keyCount: 2_001, staticResourceCount: 0));
        Assert.Equal(2_001, manyKeys.DeferredResourceCount);
        Assert.Empty(manyKeys.DeferredResources);
        Assert.True(manyKeys.DeferredResourcesTruncated);
        AssertIncompleteDeferredResources(manyKeys);

        var manyStaticResources = BamlSummaryReader.Read(
            CreateLargeDeferredBaml(keyCount: 1, staticResourceCount: 2_001));
        var resource = Assert.Single(manyStaticResources.DeferredResources);
        Assert.Equal(2_000, resource.StaticResources.Count);
        Assert.True(resource.StaticResourcesTruncated);
        Assert.True(manyStaticResources.DeferredResourcesTruncated);
        AssertIncompleteDeferredResources(manyStaticResources);
    }

    [Fact]
    public async Task SummaryAggregatesManagedTypeAndMethodCounts()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        Assert.Equal("0.9", document.SchemaVersion);
        Assert.True(document.Summary.TypeCount > 0);
        Assert.True(document.Summary.MethodCount > 0);
        Assert.Equal(document.Files[0].Code!.TypeCount, document.Summary.TypeCount);
    }

    [Fact]
    public async Task NativeInputHasNoManagedCodeModel()
    {
        await using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "notes.txt");
        await File.WriteAllTextAsync(path, "這不是 PE 檔");

        var document = await new BlueprintAnalyzer().AnalyzeAsync(path);

        Assert.Null(Assert.Single(document.Files).Code);
    }

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }

    private static void AssertResourceEntry(
        ExeBlueprint.Models.ManagedResourceModel resource,
        string name,
        string typeSuffix,
        string value)
    {
        var entry = Assert.Single(resource.Entries, entry => entry.Name == name);
        Assert.EndsWith(typeSuffix, entry.Type, StringComparison.Ordinal);
        Assert.Equal("decoded", entry.Status);
        Assert.Equal(value, entry.Value);
        Assert.False(entry.ValueTruncated);
        Assert.Null(entry.Error);
    }

    private static void AssertDecodedResource(string typeCode, byte[] data, string expectedValue)
    {
        var entry = ManagedSymbolReader.DecodeResourceEntry(
            "Value",
            $"ResourceTypeCode.{typeCode}",
            data);

        Assert.Equal("decoded", entry.Status);
        Assert.Equal(expectedValue, entry.Value);
        Assert.Null(entry.Error);
    }

    private static byte[] WriteResourceData(Action<BinaryWriter> write)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
        {
            write(writer);
        }

        return stream.ToArray();
    }

    private const string DeferredBamlFixtureBase64 =
        "DAAAAE0AUwBCAEEATQBMAAAAYAAAAGAAAABgACALCgAHcHJpbWFyeSAKCwAGYWNjZW50AwL/ACUwAAAAJgkKAAAAAAAAADcACwAnAv8ACgAAAAEBNwH//wP//wA4x/8AAAQDAv8AOPL/AAAEBAI=";

    private static BamlSummaryModel ReadMutatedDeferredBaml(Action<byte[]> mutate)
    {
        var data = Convert.FromBase64String(DeferredBamlFixtureBase64);
        mutate(data);
        return BamlSummaryReader.Read(data);
    }

    private static byte[] CreateLargeDeferredBaml(int keyCount, int staticResourceCount)
    {
        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        writer.Write((byte)3);
        writer.Write((short)-254);
        writer.Write((byte)0);
        writer.Write((byte)37);
        var contentSizeOffset = stream.Position;
        writer.Write(0);
        var contentStart = stream.Position;

        for (var index = 0; index < keyCount; index++)
        {
            WriteBamlVariableRecord(writer, 38, payload =>
            {
                payload.Write((short)10);
                payload.Write(index * 5);
                payload.Write(false);
                payload.Write(false);
            });

            if (index == 0)
            {
                for (var staticIndex = 0; staticIndex < staticResourceCount; staticIndex++)
                {
                    writer.Write((byte)55);
                    writer.Write((byte)0);
                    writer.Write((short)10);
                }
            }
        }

        for (var index = 0; index < keyCount; index++)
        {
            writer.Write((byte)3);
            writer.Write((short)-1);
            writer.Write((byte)0);
            writer.Write((byte)4);
        }

        var contentEnd = stream.Position;
        stream.Position = contentSizeOffset;
        writer.Write(checked((int)(contentEnd - contentStart)));
        stream.Position = contentEnd;
        writer.Write((byte)4);
        writer.Write((byte)2);
        return stream.ToArray();
    }

    private static byte[] CreateDeferredBamlWithNestedStaticResourceId()
    {
        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        writer.Write((byte)3);
        writer.Write((short)-254);
        writer.Write((byte)0);
        writer.Write((byte)37);
        var contentSizeOffset = stream.Position;
        writer.Write(0);
        var contentStart = stream.Position;
        WriteBamlVariableRecord(writer, 38, payload =>
        {
            payload.Write((short)10);
            payload.Write(0);
            payload.Write(false);
            payload.Write(false);
        });
        writer.Write((byte)55);
        writer.Write((byte)0);
        writer.Write((short)10);
        writer.Write((byte)3);
        writer.Write((short)-1);
        writer.Write((byte)0);
        writer.Write((byte)50);
        writer.Write((short)0);
        writer.Write((byte)4);

        var contentEnd = stream.Position;
        stream.Position = contentSizeOffset;
        writer.Write(checked((int)(contentEnd - contentStart)));
        stream.Position = contentEnd;
        writer.Write((byte)4);
        writer.Write((byte)2);
        return stream.ToArray();
    }

    private static byte[] CreateDeferredBamlWithNestedValueTarget()
    {
        using var stream = new MemoryStream();
        stream.Write(CreateBamlHeader());
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        writer.Write((byte)3);
        writer.Write((short)-254);
        writer.Write((byte)0);
        writer.Write((byte)37);
        var contentSizeOffset = stream.Position;
        writer.Write(0);
        var contentStart = stream.Position;

        WriteBamlVariableRecord(writer, 38, payload =>
        {
            payload.Write((short)10);
            payload.Write(0);
            payload.Write(false);
            payload.Write(false);
        });
        writer.Write((byte)55);
        writer.Write((byte)0);
        writer.Write((short)10);

        var secondValuePositionOffset = stream.Position + 4;
        WriteBamlVariableRecord(writer, 38, payload =>
        {
            payload.Write((short)11);
            payload.Write(0);
            payload.Write(false);
            payload.Write(false);
        });
        writer.Write((byte)55);
        writer.Write((byte)0);
        writer.Write((short)11);

        var valuesStart = stream.Position;
        writer.Write((byte)3);
        writer.Write((short)-1);
        writer.Write((byte)0);
        var nestedValueStart = stream.Position;
        writer.Write((byte)3);
        writer.Write((short)-1);
        writer.Write((byte)0);
        writer.Write((byte)56);
        writer.Write((short)-57);
        writer.Write((short)0);
        writer.Write((byte)4);
        writer.Write((byte)4);

        writer.Write((byte)3);
        writer.Write((short)-1);
        writer.Write((byte)0);
        writer.Write((byte)56);
        writer.Write((short)-57);
        writer.Write((short)0);
        writer.Write((byte)4);

        var contentEnd = stream.Position;
        stream.Position = secondValuePositionOffset;
        writer.Write(checked((int)(nestedValueStart - valuesStart)));
        stream.Position = contentSizeOffset;
        writer.Write(checked((int)(contentEnd - contentStart)));
        stream.Position = contentEnd;
        writer.Write((byte)4);
        writer.Write((byte)2);
        return stream.ToArray();
    }

    private static void AssertIncompleteDeferredResources(BamlSummaryModel summary)
    {
        Assert.False(summary.DeferredResourcesComplete);
        Assert.NotNull(summary.DeferredResourcesError);
    }

    private static short FindKnownWpfTypeId(string name)
    {
        for (short id = 1; id <= 759; id++)
        {
            if (WpfBamlKnownIds.GetTypeName((short)-id) == name)
            {
                return id;
            }
        }

        throw new InvalidOperationException($"找不到 WPF 內建型別 {name}。");
    }

    private static void WriteBamlVariableRecord(
        BinaryWriter writer,
        byte recordType,
        Action<BinaryWriter> writePayload)
    {
        using var payloadStream = new MemoryStream();
        using (var payloadWriter = new BinaryWriter(
                   payloadStream,
                   System.Text.Encoding.UTF8,
                   leaveOpen: true))
        {
            writePayload(payloadWriter);
        }

        var payload = payloadStream.ToArray();
        var sizeFieldLength = 1;
        while (true)
        {
            var recordSize = checked(payload.Length + sizeFieldLength);
            var requiredLength = Get7BitEncodedLength(recordSize);
            if (requiredLength == sizeFieldLength)
            {
                writer.Write(recordType);
                Write7BitEncodedInt(writer, recordSize);
                writer.Write(payload);
                return;
            }

            sizeFieldLength = requiredLength;
        }
    }

    private static int Get7BitEncodedLength(int value)
    {
        var length = 1;
        while ((value >>= 7) != 0)
        {
            length++;
        }

        return length;
    }

    private static void Write7BitEncodedInt(BinaryWriter writer, int value)
    {
        var remaining = (uint)value;
        while (remaining >= 0x80)
        {
            writer.Write((byte)(remaining | 0x80));
            remaining >>= 7;
        }

        writer.Write((byte)remaining);
    }

    private static byte[] CreateBamlHeader(short readerMinor = 96)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, System.Text.Encoding.Unicode, leaveOpen: true))
        {
            writer.Write(12);
            writer.Write(System.Text.Encoding.Unicode.GetBytes("MSBAML"));
            writer.Write((short)0);
            writer.Write(readerMinor);
            writer.Write((short)0);
            writer.Write((short)96);
            writer.Write((short)0);
            writer.Write((short)96);
        }

        return stream.ToArray();
    }
}

internal enum LongBackedTestEnum : long
{
    Negative = -4,
    Zero = 0,
    Sparse = 42
}

internal class MemberShapeFixture
{
    public const string Label = "blueprint";

    protected internal static readonly int Counter = 1;

    public virtual string Name { get; protected set; } = string.Empty;

    public System.Text.StringBuilder Builder { get; } = new();

    internal static event EventHandler? Changed;

    protected virtual event EventHandler? Updated;

    private event EventHandler? Hidden;

    public void Touch()
    {
        Changed?.Invoke(null, EventArgs.Empty);
        Updated?.Invoke(this, EventArgs.Empty);
        Hidden?.Invoke(this, EventArgs.Empty);
    }
}

internal abstract class DispatchBaseFixture
{
    public abstract string Describe();

    public virtual int Transform(int value) => value + 1;

    public virtual int Value => 1;

    public virtual event EventHandler? Dispatched;

    protected void RaiseDispatched() => Dispatched?.Invoke(this, EventArgs.Empty);
}

internal sealed class DispatchDerivedFixture : DispatchBaseFixture, IDisposable
{
    public override string Describe() => "derived";

    public sealed override int Transform(int value) => value + 2;

    public override int Value => 2;

    public sealed override event EventHandler? Dispatched;

    public void Dispose()
    {
        Dispatched = null;
    }
}

internal class NestedTypeFixture<T>
{
    public sealed class Child<U>
    {
        public delegate T Projector(U value);

        public T? OuterValue { get; init; }

        public U? InnerValue { get; init; }

        public enum State : byte
        {
            Ready = 2
        }

        public readonly struct Leaf
        {
            public int Number { get; init; }
        }
    }
}

internal sealed class NestedTypeReferenceFixture<T, U>
{
    public NestedTypeFixture<T>.Child<U>.Leaf Leaf { get; init; }

    public NestedTypeFixture<T>.Child<U>.State State { get; init; }
}

internal readonly record struct StructInitializerFixture(string Value);

internal sealed record NullableHashFixture(int? Value);

internal delegate bool GenericPredicateFixture<T>(T value);

internal sealed class GenericInterfaceFixture<T> : IEqualityComparer<T>
{
    public bool Equals(T? x, T? y) => EqualityComparer<T>.Default.Equals(x, y);

    public int GetHashCode(T obj) => EqualityComparer<T>.Default.GetHashCode(obj!);
}

internal sealed class RefLikePropertyFixture
{
    private readonly byte[] _buffer = [];
    private int _value;

    public ReadOnlySpan<byte> Header => _buffer;

    public ref int ValueRef => ref _value;
}

internal ref struct RefStructFixture
{
    public Span<byte> Buffer { get; set; }
}

internal static class TypedArgumentFixture
{
    public static bool StartsWithLessThan(string value) => value.StartsWith('<');

    public static bool StartsWithIgnoreCase(string value) =>
        value.StartsWith("prefix", StringComparison.OrdinalIgnoreCase);

    public static void DeleteRecursively(string path) =>
        Directory.Delete(path, recursive: true);

    public static void DeleteNonRecursively(string path) =>
        Directory.Delete(path, recursive: false);

    public static char ReadCharacter(string value, int index) => value[index];

    public static void SetDictionaryValue(Dictionary<string, string> values, string key, string value) =>
        values[key] = value;
}

internal sealed class ReferenceConditionFixture(string? value)
{
    private readonly string? _value = value;

    public static bool HasParameter(ReferenceConditionFixture? value)
    {
        if (value is null)
        {
            return false;
        }

        return true;
    }

    public bool HasField()
    {
        if (_value is null)
        {
            return false;
        }

        return true;
    }
}

internal static class ExceptionHandlingFixture
{
    public static int AddWithCleanup(int value)
    {
        var result = value;
        try
        {
            result += 1;
        }
        finally
        {
            result += 10;
        }

        return result;
    }

    public static int CatchAndReturn(int value)
    {
        try
        {
            return value + 1;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    public static int MultipleCatch(int value)
    {
        try
        {
            return 10 / value;
        }
        catch (DivideByZeroException)
        {
            return -1;
        }
        catch (ArithmeticException)
        {
            return -2;
        }
    }

    public static int CatchVariable(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception)
        {
            return exception.HResult;
        }
    }

    public static int CatchAll(int value)
    {
        try
        {
            return 10 / value;
        }
        catch
        {
            return -1;
        }
    }

    public static int Rethrow(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }
        }
        catch (InvalidOperationException)
        {
            throw;
        }

        return value;
    }

    public static int CatchAndFinally(int value)
    {
        var result = 0;
        try
        {
            result = 10 / value;
        }
        catch (DivideByZeroException exception)
        {
            result = exception.HResult;
        }
        catch (ArithmeticException)
        {
            result = -1;
        }
        finally
        {
            result += 100;
        }

        return result;
    }

    public static int CatchFilter(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception) when (exception.HResult == value)
        {
            return -1;
        }
        catch (InvalidOperationException)
        {
            return -2;
        }
    }

    public static int CatchFilterAndFinally(int value)
    {
        var result = 0;
        try
        {
            result = 10 / value;
        }
        catch (DivideByZeroException exception) when (exception.HResult == value)
        {
            result = -1;
        }
        finally
        {
            result += 100;
        }

        return result;
    }

    public static int CatchFilterAnd(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception)
            when (exception.HResult == value && value > 0 && value < 10)
        {
            return -1;
        }
    }

    public static int CatchFilterOr(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception)
            when (exception.HResult == value || value > 10 || value == 5)
        {
            return -1;
        }
    }

    public static int CatchFilterAndOr(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception)
            when (exception.HResult == value && (value > 0 || value == -1))
        {
            return -1;
        }
    }

    public static int CatchFilterOrAnd(int value)
    {
        try
        {
            if (value < 0)
            {
                throw new InvalidOperationException();
            }

            return value;
        }
        catch (InvalidOperationException exception)
            when (exception.HResult == value || (value > 0 && value < 10))
        {
            return -1;
        }
    }

    public static int CatchTerminalTry()
    {
        try
        {
            throw new InvalidOperationException();
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    public static int FinallyTerminalTry(int value)
    {
        var result = value;
        try
        {
            throw new InvalidOperationException();
        }
        finally
        {
            result += 10;
        }
    }

    public static int CatchFilterTerminalTry(int value)
    {
        try
        {
            throw new InvalidOperationException();
        }
        catch (InvalidOperationException exception) when (exception.HResult == value)
        {
            return -1;
        }
        catch (InvalidOperationException)
        {
            return -2;
        }
    }
}

internal sealed class GenericEnumeratorFixture<T> : IEnumerator<T>
{
    public T Current => default!;

    object System.Collections.IEnumerator.Current => default!;

    public bool MoveNext() => false;

    public void Reset()
    {
    }

    public void Dispose()
    {
    }
}

internal sealed class ExplicitGenericComparerFixture<T> : IEqualityComparer<T>
{
    bool IEqualityComparer<T>.Equals(T? x, T? y) => EqualityComparer<T>.Default.Equals(x, y);

    int IEqualityComparer<T>.GetHashCode(T obj) => EqualityComparer<T>.Default.GetHashCode(obj!);
}

internal sealed class ExplicitGenericEnumeratorFixture<T> : IEnumerator<T>
{
    T IEnumerator<T>.Current => default!;

    object System.Collections.IEnumerator.Current => default!;

    bool System.Collections.IEnumerator.MoveNext() => false;

    void System.Collections.IEnumerator.Reset()
    {
    }

    void IDisposable.Dispose()
    {
    }
}

internal sealed class IndexedCurrentEnumeratorDecoyFixture<T> : IEnumerator<T>
{
    [System.Runtime.CompilerServices.IndexerName("Current")]
    public T this[int index] => default!;

    T IEnumerator<T>.Current => default!;

    object System.Collections.IEnumerator.Current => default!;

    bool System.Collections.IEnumerator.MoveNext() => false;

    void System.Collections.IEnumerator.Reset()
    {
    }

    void IDisposable.Dispose()
    {
    }
}

internal sealed class NullableValueComparerDecoyFixture : IEqualityComparer<int>
{
    bool IEqualityComparer<int>.Equals(int x, int y) => x == y;

    int IEqualityComparer<int>.GetHashCode(int obj) => obj;

    public bool Equals(int? x, int? y) => x == y;

    public int GetHashCode(int? obj) => obj.GetHashCode();
}

internal static class InterfaceDispatchFixture
{
    public static IEnumerator<T> EmptyEnumerator<T>() =>
        ((IEnumerable<T>)Array.Empty<T>()).GetEnumerator();

    public static void CopyTo<T>(List<T> items, Array array, int index) =>
        ((System.Collections.ICollection)items).CopyTo(array, index);

    public static string Read(DispatchImplementationFixture value) =>
        ((DispatchContractFixture)value).Read();
}

internal interface DispatchContractFixture
{
    string Read();
}

internal sealed class DispatchImplementationFixture : DispatchContractFixture
{
    public string Read() => "value";
}

internal static class NumericArgumentFixture
{
    public static int Log2(int value) => System.Numerics.BitOperations.Log2((uint)value);
}

internal static class UnsignedArithmeticFixture
{
    public static int Stored;

    public static uint Divide(uint left, uint right) => left / right;

    public static int DivideSigned(int left, int right) => unchecked((int)((uint)left / (uint)right));

    public static int StoreSignedField(int left, int right)
    {
        Stored = unchecked((int)((uint)left % (uint)right));
        return Stored;
    }

    public static bool GreaterThanUInt32(uint left, uint right) => left > right;

    public static bool LessThanUInt32(uint left, uint right) => left < right;

    public static bool GreaterThanUInt64(ulong left, ulong right) => left > right;

    public static bool LessThanUInt64(ulong left, ulong right) => left < right;

    public static bool GreaterThanNativeUInt(nuint left, nuint right) => left > right;

    public static bool LessThanNativeUInt(nuint left, nuint right) => left < right;

    public static int SelectAtLeastUInt32(uint left, uint right)
    {
        if (left >= right)
        {
            return 1;
        }

        return 0;
    }

    public static int SelectGreaterUInt64(ulong left, ulong right)
    {
        if (left > right)
        {
            return 1;
        }

        return 0;
    }

    public static int SelectAtMostNativeUInt(nuint left, nuint right)
    {
        if (left <= right)
        {
            return 1;
        }

        return 0;
    }
}
