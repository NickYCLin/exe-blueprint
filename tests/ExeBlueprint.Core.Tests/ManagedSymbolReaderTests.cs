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

        var reconstructed = code.Types
            .SelectMany(type => type.Methods)
            .Where(method => method.BodyReconstructed)
            .ToArray();

        Assert.NotEmpty(reconstructed);

        // 重建出來的陳述式都應以分號或區塊結尾，不能再殘留 <>k__BackingField 這種原始名稱。
        foreach (var method in reconstructed)
        {
            Assert.All(method.Body, statement => Assert.EndsWith(";", statement, StringComparison.Ordinal));
            Assert.DoesNotContain(method.Body, statement => statement.Contains("k__BackingField", StringComparison.Ordinal));
        }

        // record 產生的 Equals(object) 是典型直線方法，應被還原。
        Assert.Contains(reconstructed, method =>
            method.Name == "Equals"
            && method.Body.Any(statement => statement.Contains(" as ", StringComparison.Ordinal)));
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
