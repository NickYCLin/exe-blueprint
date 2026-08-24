using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class MultiLanguageGeneratorTests
{
    [Fact]
    public async Task RustGeneratorEmitsStructsAndStubbedMethods()
    {
        var document = await AnalyzeSelf();
        var files = RustSkeletonGenerator.Generate(document);

        var source = SingleSource(files, ".rs");
        Assert.Contains("pub struct DependencyEdge", source);
        Assert.Contains("pub Source: String", source);
        Assert.Contains("unimplemented!()", source);
    }

    [Fact]
    public async Task GoGeneratorEmitsStructsAndStubbedMethods()
    {
        var document = await AnalyzeSelf();
        var files = GoSkeletonGenerator.Generate(document);

        var source = SingleSource(files, ".go");
        Assert.Contains("package reconstructed", source);
        Assert.Contains("type DependencyEdge struct", source);
        Assert.Contains("panic(\"not implemented\")", source);
    }

    [Fact]
    public async Task CppGeneratorEmitsClassesAndStubbedMethods()
    {
        var document = await AnalyzeSelf();
        var files = CppSkeletonGenerator.Generate(document);

        var source = SingleSource(files, ".hpp");
        Assert.Contains("#pragma once", source);
        Assert.Contains("class DependencyEdge", source);
        Assert.Contains("throw std::runtime_error(\"not implemented\")", source);
    }

    [Fact]
    public void AllGeneratorsReturnEmptyWhenNoManagedCode()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor { Name = "x", Kind = "file", SourcePath = "x", FileCount = 0, TotalBytes = 0 },
            Summary = new BlueprintSummary()
        };

        Assert.Empty(RustSkeletonGenerator.Generate(document));
        Assert.Empty(GoSkeletonGenerator.Generate(document));
        Assert.Empty(CppSkeletonGenerator.Generate(document));
    }

    private static async Task<BlueprintDocument> AnalyzeSelf() =>
        await new BlueprintAnalyzer().AnalyzeAsync(typeof(BlueprintAnalyzer).Assembly.Location);

    private static string SingleSource(IReadOnlyList<GeneratedFile> files, string extension) =>
        files.Single(file => file.RelativePath.EndsWith(extension, StringComparison.Ordinal)).Content;
}
