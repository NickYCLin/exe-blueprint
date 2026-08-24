using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class CSharpSkeletonGeneratorTests
{
    [Fact]
    public async Task GeneratesReadableSkeletonFromManagedAssembly()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var files = CSharpSkeletonGenerator.Generate(document);

        Assert.Contains(files, file => file.RelativePath.EndsWith(".csproj", StringComparison.Ordinal));
        Assert.Contains(files, file => file.RelativePath == "README.md");

        var modelsFile = Assert.Single(
            files,
            file => file.RelativePath.EndsWith("ExeBlueprint.Models.cs", StringComparison.Ordinal));
        Assert.Contains("namespace ExeBlueprint.Models;", modelsFile.Content);
        Assert.Contains("class FileArtifact", modelsFile.Content);
        Assert.Contains("throw new global::System.NotImplementedException();", modelsFile.Content);
    }

    [Fact]
    public async Task GeneratedTypeSignaturesAreCleanOfMetadataArtifacts()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var sourceFiles = CSharpSkeletonGenerator.Generate(document)
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(sourceFiles);
        foreach (var file in sourceFiles)
        {
            Assert.DoesNotContain('`', file.Content);
            Assert.DoesNotContain("op_", file.Content, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void GenerateReturnsEmptyWhenNoManagedCode()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "sample",
                Kind = "file",
                SourcePath = "sample",
                FileCount = 0,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary()
        };

        Assert.Empty(CSharpSkeletonGenerator.Generate(document));
    }
}
