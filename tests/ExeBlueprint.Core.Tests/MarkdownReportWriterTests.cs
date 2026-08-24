using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

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
}
