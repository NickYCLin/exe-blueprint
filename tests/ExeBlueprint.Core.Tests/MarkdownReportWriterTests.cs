using ExeBlueprint.Models;
using ExeBlueprint.Reporting;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class MarkdownReportWriterTests
{
    [Fact]
    public void BuildUsesDirectTraditionalChineseWording()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "sample.zip",
                Kind = "zip",
                SourcePath = "sample.zip",
                FileCount = 0,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary()
        };

        var report = MarkdownReportWriter.Build(document);

        Assert.Contains("# ExeBlueprint 分析報告", report);
        Assert.Contains("靜態分析", report, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("AI 驅動", report, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BuildListsDecodedResourceTableEntries()
    {
        var assemblyPath = typeof(MarkdownReportWriterTests).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var report = MarkdownReportWriter.Build(document);

        Assert.Contains("資源表鍵值：", report);
        Assert.Contains("`Greeting`", report);
        Assert.Contains("`哈囉 ExeBlueprint`", report);
        Assert.Contains(
            "BAML 0.96，24 筆 record，2 個 element／4 個 property／根節點 BamlFixture.MainWindow，1009 B",
            report);
        Assert.Contains("BAML property 值：", report);
        Assert.Contains("`Window.Title`", report);
        Assert.Contains("`MainWindow`", report);
        Assert.Contains("`FrameworkElement.Width`", report);
        Assert.Contains("`800`", report);
    }
}
