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
