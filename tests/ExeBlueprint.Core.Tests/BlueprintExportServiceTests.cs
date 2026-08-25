using ExeBlueprint.Application;

namespace ExeBlueprint.Core.Tests;

public sealed class BlueprintExportServiceTests
{
    [Fact]
    public void DefaultOutputDirectoryUsesInputNameAndTimestamp()
    {
        var timestamp = new DateTimeOffset(2026, 8, 25, 9, 30, 45, TimeSpan.FromHours(8));
        var output = BlueprintExportService.CreateDefaultOutputDirectory(
            Path.Combine("sample", "Demo App.exe"),
            Path.Combine(Path.GetTempPath(), "exe-blueprint-base"),
            timestamp);

        Assert.EndsWith(
            Path.Combine("exe-blueprint-output", "Demo App-20260825-093045"),
            output,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunWritesJsonReportAndRequestedSkeleton()
    {
        await using var temp = new TemporaryDirectory();
        var outputDirectory = Path.Combine(temp.Path, "result");
        var progress = new List<string>();
        var service = new BlueprintExportService();

        var result = await service.RunAsync(
            new BlueprintExportRequest
            {
                InputPath = typeof(BlueprintExportService).Assembly.Location,
                OutputDirectory = outputDirectory,
                EmitCSharp = true
            },
            new InlineProgress(value => progress.Add(value.Message)));

        Assert.Equal(Path.GetFullPath(outputDirectory), result.OutputDirectory);
        Assert.True(File.Exists(Path.Combine(outputDirectory, "blueprint.json")));
        Assert.True(File.Exists(Path.Combine(outputDirectory, "REPORT.md")));
        var skeleton = Assert.Single(result.Skeletons);
        Assert.Equal("C#", skeleton.Language);
        Assert.True(skeleton.FileCount > 0);
        Assert.Contains(progress, message => message.Contains("C#", StringComparison.Ordinal));
        Assert.Equal("分析完成。", progress[^1]);
    }

    [Fact]
    public async Task RunProtectsExistingAnalysisResult()
    {
        await using var temp = new TemporaryDirectory();
        var outputDirectory = Path.Combine(temp.Path, "result");
        Directory.CreateDirectory(outputDirectory);
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, "blueprint.json"), "keep");

        var exception = await Assert.ThrowsAsync<IOException>(() => new BlueprintExportService().RunAsync(
            new BlueprintExportRequest
            {
                InputPath = typeof(BlueprintExportService).Assembly.Location,
                OutputDirectory = outputDirectory
            }));

        Assert.Contains("已有分析結果", exception.Message, StringComparison.Ordinal);
        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(outputDirectory, "blueprint.json")));
    }

    private sealed class InlineProgress(Action<BlueprintExportProgress> report) : IProgress<BlueprintExportProgress>
    {
        public void Report(BlueprintExportProgress value) => report(value);
    }

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "exe-blueprint-tests",
                Guid.NewGuid().ToString("N"));
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
