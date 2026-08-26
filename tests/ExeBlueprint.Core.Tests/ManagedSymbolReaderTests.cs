using ExeBlueprint.Analysis;
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
    public async Task ReconstructsBooleanAndEnumCallArguments()
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
        Assert.Equal(2, resource.Entries.Count);
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
        Assert.Null(builtInElement.Name);
        var titleProperty = Assert.Single(bamlEntry.Baml.Properties, item => item.Id == 0);
        Assert.Equal("Title", titleProperty.Name);
        Assert.Null(titleProperty.OwnerType);
        Assert.Equal(4, bamlEntry.Baml.Properties.Count);

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
        Assert.Equal(2, resourceJson.GetProperty("entries").GetArrayLength());
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
        Assert.Equal(4, bamlJson.GetProperty("properties").GetArrayLength());
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
        Assert.True(boundedSymbols.SymbolsTruncated);
    }

    [Fact]
    public async Task SummaryAggregatesManagedTypeAndMethodCounts()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        Assert.Equal("0.2", document.SchemaVersion);
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

internal readonly record struct StructInitializerFixture(string Value);

internal sealed record NullableHashFixture(int? Value);

internal sealed class RefLikePropertyFixture
{
    private readonly byte[] _buffer = [];

    public ReadOnlySpan<byte> Header => _buffer;
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
