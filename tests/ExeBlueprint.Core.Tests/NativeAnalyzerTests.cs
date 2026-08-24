using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class NativeAnalyzerTests
{
    [Fact]
    public void ParsesGhidraFunctionJson()
    {
        const string json = """
        {
          "functions": [
            { "name": "main", "address": "0x401000", "signature": "int main(int argc)", "external": false },
            { "name": "printf", "address": "0x0", "signature": "int printf(char *)", "external": true },
            { "name": "", "address": "0x402000" }
          ]
        }
        """;

        var functions = GhidraOutputParser.Parse(json);

        Assert.Equal(2, functions.Count); // 空名稱的略過
        Assert.Equal("main", functions[0].Name);
        Assert.Equal("0x401000", functions[0].Address);
        Assert.False(functions[0].IsExternal);
        Assert.True(functions[1].IsExternal);
    }

    [Fact]
    public void ParseHandlesEmptyOrMalformedInput()
    {
        Assert.Empty(GhidraOutputParser.Parse(""));
        Assert.Empty(GhidraOutputParser.Parse("{}"));
        Assert.Empty(GhidraOutputParser.Parse("{\"functions\": 3}"));
    }

    [Fact]
    public async Task ReportsMissingBackendWhenGhidraNotConfigured()
    {
        var options = new AnalysisOptions
        {
            EnableNativeAnalysis = true,
            GhidraInstallDir = Path.Combine(Path.GetTempPath(), "exe-blueprint-no-ghidra-" + Guid.NewGuid().ToString("N"))
        };

        var result = await NativeAnalyzer.AnalyzeAsync(
            typeof(NativeAnalyzer).Assembly.Location,
            options,
            CancellationToken.None);

        Assert.Equal("none", result.Backend);
        Assert.NotNull(result.Note);
        Assert.Contains("Ghidra", result.Note!, StringComparison.Ordinal);
        Assert.Empty(result.Functions);
    }

    [Fact]
    public async Task LocatesConfiguredHeadlessLauncher()
    {
        await using var temp = new TemporaryDirectory();
        var supportDir = Path.Combine(temp.Path, "support");
        Directory.CreateDirectory(supportDir);
        var launcher = OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless";
        await File.WriteAllTextAsync(Path.Combine(supportDir, launcher), "echo test");

        var found = NativeAnalyzer.LocateHeadless(new AnalysisOptions { GhidraInstallDir = temp.Path });
        var missing = NativeAnalyzer.LocateHeadless(new AnalysisOptions { GhidraInstallDir = Path.Combine(temp.Path, "empty") });

        Assert.NotNull(found);
        Assert.Null(missing);
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
