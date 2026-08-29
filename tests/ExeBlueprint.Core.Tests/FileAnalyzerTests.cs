using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class FileAnalyzerTests
{
    [Fact]
    public async Task AnalyzeUsesLogicalPathForClassificationAndFileName()
    {
        var stagingPath = Path.Combine(Path.GetTempPath(), $"exe-blueprint-{Guid.NewGuid():N}.bin");
        try
        {
            await File.WriteAllTextAsync(stagingPath, "{}");
            var origin = new FileOrigin
            {
                Kind = "asar",
                Container = "resources/app.asar",
                Entry = "config/app.json",
                Depth = 1
            };

            var artifact = await new FileAnalyzer(new AnalysisOptions()).AnalyzeAsync(
                stagingPath,
                "resources/app.asar!/config/app.json",
                origin,
                CancellationToken.None);

            Assert.Equal("app.json", artifact.FileName);
            Assert.Equal("configuration", artifact.Category);
            Assert.Equal("JSON configuration", artifact.Format);
            Assert.Equal(origin, artifact.Origin);
        }
        finally
        {
            File.Delete(stagingPath);
        }
    }

    [Fact]
    public async Task SkippedArtifactUsesLogicalNameAndPreservesOrigin()
    {
        var stagingPath = Path.Combine(Path.GetTempPath(), $"exe-blueprint-{Guid.NewGuid():N}.bin");
        try
        {
            await File.WriteAllBytesAsync(stagingPath, [0, 1]);
            var origin = new FileOrigin
            {
                Kind = "asar",
                Container = "app.asar",
                Entry = "native/addon.node",
                Depth = 2
            };

            var artifact = await new FileAnalyzer(new AnalysisOptions { MaxFileBytes = 1 }).AnalyzeAsync(
                stagingPath,
                "app.asar!/native/addon.node",
                origin,
                CancellationToken.None);

            Assert.Equal("addon.node", artifact.FileName);
            Assert.Equal(origin, artifact.Origin);
            Assert.Equal("檔案超過單檔分析上限", artifact.AnalysisError);
        }
        finally
        {
            File.Delete(stagingPath);
        }
    }
}
