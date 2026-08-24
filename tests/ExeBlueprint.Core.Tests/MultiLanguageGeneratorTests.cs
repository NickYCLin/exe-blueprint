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

    [Fact]
    public async Task AllGeneratorsPreserveEnumValuesAndUnderlyingType()
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(typeof(LongBackedTestEnum).Assembly.Location);

        var csharp = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.Content.Contains("enum LongBackedTestEnum", StringComparison.Ordinal)).Content;
        Assert.Contains("internal enum LongBackedTestEnum : long", csharp);
        Assert.Contains("Negative = -4,", csharp);
        Assert.Contains("Sparse = 42,", csharp);

        var cpp = SingleSource(CppSkeletonGenerator.Generate(document), ".hpp");
        Assert.Contains("enum class LongBackedTestEnum : int64_t", cpp);
        Assert.Contains("Negative = -4", cpp);

        var rust = SingleSource(RustSkeletonGenerator.Generate(document), ".rs");
        Assert.Contains("#[repr(i64)]", rust);
        Assert.Contains("Negative = -4,", rust);

        var go = SingleSource(GoSkeletonGenerator.Generate(document), ".go");
        Assert.Contains("type LongBackedTestEnum int64", go);
        Assert.Contains("LongBackedTestEnumSparse LongBackedTestEnum = 42", go);
    }

    private static async Task<BlueprintDocument> AnalyzeSelf() =>
        await new BlueprintAnalyzer().AnalyzeAsync(typeof(BlueprintAnalyzer).Assembly.Location);

    private static string SingleSource(IReadOnlyList<GeneratedFile> files, string extension) =>
        files.Single(file => file.RelativePath.EndsWith(extension, StringComparison.Ordinal)).Content;
}
