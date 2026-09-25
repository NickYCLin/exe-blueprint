using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class EmbeddedJsonConfigurationReaderTests
{
    [Fact]
    public void RecordsOnlyPropertyPathsAndNeverValues()
    {
        var summary = EmbeddedJsonConfigurationReader.Read(
            """{ "service": { "token": "private-value", "ports": [8080] } }"""u8.ToArray());

        Assert.Equal("parsed", summary.Status);
        Assert.Equal("object", summary.RootKind);
        Assert.Equal(3, summary.PropertyCount);
        Assert.Equal(["service", "service.token", "service.ports", "service.ports[]"], summary.PropertyPaths);
        Assert.DoesNotContain("private-value", summary.PropertyPaths);
        Assert.Null(summary.Error);
    }

    [Fact]
    public void RejectsMalformedJsonAndBoundsOversizedInput()
    {
        var malformed = EmbeddedJsonConfigurationReader.Read("{"u8.ToArray());
        Assert.Equal("invalid", malformed.Status);
        Assert.NotNull(malformed.Error);

        var oversized = EmbeddedJsonConfigurationReader.Read(
            new byte[EmbeddedJsonConfigurationReader.MaxBytes + 1]);
        Assert.Equal("partial", oversized.Status);
        Assert.NotNull(oversized.Error);
    }

    // JsonDocument.Parse 不驗證名稱中的代理字元跳脫與原始 UTF-8，讀取 property.Name 時才會失敗。
    // 這種輸入必須回報 invalid，而不是讓例外逃出、讓整個組件的分析結果被丟掉。
    [Fact]
    public void ReportsInvalidForUnreadablePropertyNamesInsteadOfThrowing()
    {
        var loneSurrogate = EmbeddedJsonConfigurationReader.Read("""{"\uD800":0}"""u8.ToArray());
        Assert.Equal("invalid", loneSurrogate.Status);
        Assert.NotNull(loneSurrogate.Error);

        var invalidUtf8 = EmbeddedJsonConfigurationReader.Read([0x7B, 0x22, 0xFF, 0x22, 0x3A, 0x30, 0x7D]);
        Assert.Equal("invalid", invalidUtf8.Status);
        Assert.NotNull(invalidUtf8.Error);
    }

    // JsonDocument.Parse(byte[]) 不處理 BOM，Visual Studio 存的 appsettings.json 卻常有；應視為合法。
    [Fact]
    public void AcceptsUtf8ByteOrderMark()
    {
        var summary = EmbeddedJsonConfigurationReader.Read([0xEF, 0xBB, 0xBF, 0x7B, 0x7D]);

        Assert.Equal("parsed", summary.Status);
        Assert.Equal("object", summary.RootKind);
        Assert.Equal(0, summary.PropertyCount);
        Assert.Null(summary.Error);
    }

    [Fact]
    public void StopsWhenPropertyBudgetIsReached()
    {
        var properties = string.Join(
            ',',
            Enumerable.Range(0, 10_001).Select(index => $"\"key{index}\":0"));
        var summary = EmbeddedJsonConfigurationReader.Read(
            System.Text.Encoding.UTF8.GetBytes($"{{{properties}}}"));

        Assert.Equal("partial", summary.Status);
        Assert.Equal(10_000, summary.PropertyCount);
        Assert.True(summary.PropertyPathsTruncated);
        Assert.NotNull(summary.Error);
    }
}
