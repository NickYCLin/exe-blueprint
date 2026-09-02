using ExeBlueprint.Models;
using ExeBlueprint.Reporting;
using ExeBlueprint.Analysis;
using System.Text.Json;

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
        Assert.Contains("BAML element tree：", report);
        Assert.Contains("`BamlFixture.MainWindow`", report);
        Assert.Contains("`Grid`", report);
        Assert.Contains("`ContentControl.Content`", report);
        Assert.Contains("BAML property 值：", report);
        Assert.Contains("`Window.Title`", report);
        Assert.Contains("`MainWindow`", report);
        Assert.Contains("`FrameworkElement.Width`", report);
        Assert.Contains("`800`", report);
        Assert.Contains("BAML deferred resources：", report);
        Assert.Contains("`primary`（string）", report);
        Assert.Contains("`accent`", report);
        Assert.Contains("`AccessText`", report);
        Assert.Contains("[88, 98)", report);
        Assert.Contains("內嵌 JSON 設定結構：", report);
        Assert.Contains("`application.displayName`", report);
        Assert.DoesNotContain("Demo Console", report);
    }

    [Fact]
    public async Task BuildDescribesPreserializedResourceEnvelopeWithoutPretendingToDecodeIt()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "fixture.dll",
                Kind = "file",
                SourcePath = "fixture.dll",
                FileCount = 1,
                TotalBytes = 1
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                new FileArtifact
                {
                    Id = "fixture.dll",
                    RelativePath = "fixture.dll",
                    FileName = "fixture.dll",
                    Size = 1,
                    Sha256 = new string('0', 64),
                    Category = "library",
                    Format = ".NET assembly",
                    IsManaged = true,
                    Code = new CodeModel
                    {
                        Kind = "managed",
                        TypeCount = 1,
                        Resources =
                        [
                            new ManagedResourceModel
                            {
                                Name = "Fixture.resources",
                                Visibility = "private",
                                Location = "embedded",
                                Kind = ".NET 資源表",
                                Entries =
                                [
                                    new ManagedResourceEntryModel
                                    {
                                        Name = "accent-color",
                                        Type = "System.Drawing.Color, System.Drawing.Primitives",
                                        Status = "encoded",
                                        Value = "CornflowerBlue",
                                        DataSize = 16,
                                        Serialization = new ManagedResourceSerializationModel
                                        {
                                            Format = "type-converter-string",
                                            PayloadSize = 14,
                                            PayloadKind = "text",
                                            Complete = true
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        };

        var report = MarkdownReportWriter.Build(document);

        Assert.Contains("預序列化 type-converter-string", report);
        Assert.Contains("原始文字 `CornflowerBlue`", report);
        Assert.Contains("text，payload 14 B", report);

        var outputPath = Path.Combine(
            Path.GetTempPath(),
            $"exe-blueprint-report-{Guid.NewGuid():N}.json");
        try
        {
            await BlueprintJsonWriter.WriteAsync(document, outputPath);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(outputPath));
            var serialization = json.RootElement
                .GetProperty("files")[0]
                .GetProperty("code")
                .GetProperty("resources")[0]
                .GetProperty("entries")[0]
                .GetProperty("serialization");
            Assert.Equal("type-converter-string", serialization.GetProperty("format").GetString());
            Assert.Equal("text", serialization.GetProperty("payloadKind").GetString());
            Assert.True(serialization.GetProperty("complete").GetBoolean());
        }
        finally
        {
            File.Delete(outputPath);
        }
    }

    [Fact]
    public void BuildListsBoundedAsarStatusOriginsAndEscapesWarnings()
    {
        var archives = Enumerable.Range(0, 51)
            .Select(index => new ArchiveExpansion
            {
                ContainerPath = $"archive-{index}.asar",
                Depth = index % 3 + 1,
                HeaderBytes = 128,
                NodeCount = 3,
                PackedEntryCount = 1,
                UnpackedEntryCount = 1,
                LinkCount = 1,
                Complete = index != 0,
                Error = index == 0 ? "缺少 | sidecar" : null
            })
            .ToArray();
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "app.asar",
                Kind = "asar",
                SourcePath = "app.asar",
                FileCount = 1,
                TotalBytes = 2
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                new FileArtifact
                {
                    Id = "app.asar!/config/app.json",
                    RelativePath = "app.asar!/config/app.json",
                    FileName = "app.json",
                    Size = 2,
                    Sha256 = new string('0', 64),
                    Category = "configuration",
                    Format = "JSON configuration",
                    Origin = new FileOrigin
                    {
                        Kind = "asar",
                        Container = "app.asar",
                        Entry = "config/app.json",
                        Depth = 1
                    }
                }
            ],
            Archives = archives,
            Warnings = ["unsafe\n# heading | table"]
        };

        var report = MarkdownReportWriter.Build(document);

        Assert.Contains("## ASAR 展開狀態", report);
        Assert.Contains("| `archive-0.asar` | 1 | 128 B | 3 | 1 | 1 | 1 | 不完整：缺少 \\| sidecar |", report);
        Assert.Contains("| 路徑 | 來源 | 類型 | 大小 | SHA-256 |", report);
        Assert.Contains("asar d1：app.asar!/config/app.json", report);
        Assert.Contains("僅列出前 50 筆，共 51 筆 ASAR 展開紀錄", report);
        Assert.DoesNotContain("`archive-50.asar`", report);
        Assert.Contains("- unsafe \\# heading \\| table", report);
        Assert.DoesNotContain("\n# heading", report);
    }
}
