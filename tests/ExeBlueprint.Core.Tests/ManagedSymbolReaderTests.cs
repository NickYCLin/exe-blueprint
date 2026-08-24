using ExeBlueprint.Analysis;

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
                    trimmed.EndsWith(';') || trimmed is "{" or "}" or "else" || trimmed.StartsWith("if (", StringComparison.Ordinal),
                    $"未預期的重建輸出：{statement}");
            });
        }

        // record 產生的 Equals(object) 是典型直線方法，應被還原。
        Assert.Contains(reconstructed, method =>
            method.Name == "Equals"
            && method.Body.Any(statement => statement.Contains(" as ", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ReconstructsCharLiteralsAndTypedLocals()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var methods = document.Files[0].Code!.Types.SelectMany(type => type.Methods).ToArray();

        // char 參數的整數常值應還原成 char 常值（NormalizeFieldName 會呼叫 name.StartsWith('<')）。
        Assert.Contains(
            methods,
            method => method.Body.Any(line => line.Contains("StartsWith('<')", StringComparison.Ordinal)));

        // 讀得到區域變數型別時，宣告應用實際型別而非 var。
        Assert.Contains(
            methods,
            method => method.Body.Any(line => line.TrimStart().StartsWith("StringBuilder v", StringComparison.Ordinal)));
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
}
