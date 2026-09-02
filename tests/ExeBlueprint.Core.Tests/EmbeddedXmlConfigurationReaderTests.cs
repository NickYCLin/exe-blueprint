using System.Text;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class EmbeddedXmlConfigurationReaderTests
{
    [Fact]
    public void ReadCapturesElementAndAttributeNamesWithoutValues()
    {
        var result = EmbeddedXmlConfigurationReader.Read(
            Encoding.UTF8.GetBytes("<configuration><appSettings><add key=\"Mode\" value=\"DoNotExpose\" /></appSettings></configuration>"));

        Assert.Equal("xml", result.Format);
        Assert.Equal("parsed", result.Status);
        Assert.Equal("configuration", result.RootKind);
        Assert.Equal(5, result.PropertyCount);
        Assert.Equal(
            ["configuration", "configuration/appSettings", "configuration/appSettings/add", "configuration/appSettings/add/@key", "configuration/appSettings/add/@value"],
            result.PropertyPaths);
        Assert.DoesNotContain("DoNotExpose", result.PropertyPaths);
        Assert.Null(result.Error);
    }

    [Fact]
    public void ReadRejectsDtdWithoutResolvingIt()
    {
        var result = EmbeddedXmlConfigurationReader.Read(
            Encoding.UTF8.GetBytes("<!DOCTYPE configuration [<!ENTITY input SYSTEM \"file:///not-read\">]><configuration>&input;</configuration>"));

        Assert.Equal("invalid", result.Status);
        Assert.Equal(0, result.PropertyCount);
        Assert.Empty(result.PropertyPaths);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void ReadStopsAtTheDocumentSizeLimit()
    {
        var result = EmbeddedXmlConfigurationReader.Read(new byte[EmbeddedXmlConfigurationReader.MaxBytes + 1]);

        Assert.Equal("partial", result.Status);
        Assert.Empty(result.PropertyPaths);
        Assert.NotNull(result.Error);
    }
}
