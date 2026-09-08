using System.Resources;
using System.Text;
using System.Text.Json;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

namespace ExeBlueprint.Core.Tests;

public sealed class ResourceImageHeaderTests
{
    // IHDR CRC 由 Python zlib 產生，和正式解析器的實作分開。
    private const string PngHeader = "89504e470d0a1a0a0000000d4948445200000140000000b40806000000e5e4f511";

    [Theory]
    [InlineData(PngHeader, 320, 180)]
    [InlineData("89504e470d0a1a0a0000000d49484452000000010000000101000000014069c9b2", 1, 1)]
    [InlineData("89504e470d0a1a0a0000000d494844527fffffff7fffffff1002000000cb3b4072", int.MaxValue, int.MaxValue)]
    public void ReadsPngHeaderWithoutAllocatingOrDecodingPixels(string hex, int width, int height)
    {
        var image = ResourceImageHeaderReader.Read(Convert.FromHexString(hex));
        AssertDimensions(image, "png", width, height);
    }

    [Theory]
    [InlineData("89504e470d0a1a0a0000000d4948445200000000000000010806000000f0d7afb7")]
    [InlineData("89504e470d0a1a0a0000000d4948445200000001800000000806000000b21c1763")]
    [InlineData("89504e470d0a1a0a0000000d4948445200000001000000011003000000785be8f8")]
    [InlineData("89504e470d0a1a0a0000000d49484452000000010000000108050000000da06b67")]
    [InlineData("89504e470d0a1a0a0000000d49484452000000010000000108060100001ed7aebe")]
    [InlineData("89504e470d0a1a0a0000000d4948445200000001000000010806000100060ef5c8")]
    [InlineData("89504e470d0a1a0a0000000d4948445200000001000000010806000002f11ba5a5")]
    public void RejectsInvalidPngFieldsEvenWithMatchingCrc(string hex) =>
        AssertInvalid(ResourceImageHeaderReader.Read(Convert.FromHexString(hex)), "png");

    [Fact]
    public void RejectsTruncatedPngHeadersWrongChunkAndBadCrc()
    {
        var header = Convert.FromHexString(PngHeader);
        for (var length = 8; length < header.Length; length++)
        {
            AssertInvalid(ResourceImageHeaderReader.Read(header.AsSpan(0, length)), "png");
        }

        foreach (var offset in new[] { 8, 12, 16, 29 })
        {
            var changed = header.ToArray();
            changed[offset] ^= 1;
            AssertInvalid(ResourceImageHeaderReader.Read(changed), "png");
        }

        header[0] = 0;
        Assert.Null(ResourceImageHeaderReader.Read(header));
    }

    [Theory]
    [InlineData("GIF87a")]
    [InlineData("GIF89a")]
    public void ReadsGifLogicalCanvasRatherThanAnAnimationFrame(string signature)
    {
        byte[] header = [.. Encoding.ASCII.GetBytes(signature), 0x40, 0x01, 0xB4, 0, 0, 0, 0];
        AssertDimensions(ResourceImageHeaderReader.Read(header), "gif", 320, 180);
        for (var length = 6; length < header.Length; length++)
        {
            AssertInvalid(ResourceImageHeaderReader.Read(header.AsSpan(0, length)), "gif");
        }

        header[6] = 0;
        header[7] = 0;
        AssertInvalid(ResourceImageHeaderReader.Read(header), "gif");
    }

    [Fact]
    public void UnknownSignaturesRemainUnknown()
    {
        Assert.Null(ResourceImageHeaderReader.Read([]));
        Assert.Null(ResourceImageHeaderReader.Read("GIF90a"u8));
        Assert.Null(ResourceImageHeaderReader.Read([0xFF, 0xD8, 0xFF]));
        Assert.Null(ResourceImageHeaderReader.Read("not-an-image.png"u8));
    }

    [Fact]
    public void ResourceTableReadsImageBytesAndStreamsByContent()
    {
        using var stream = new MemoryStream();
        using (var writer = new ResourceWriter(stream))
        {
            writer.AddResource("without-extension", Convert.FromHexString(PngHeader));
            writer.AddResource("animation", new MemoryStream([.. "GIF89a"u8, 0x40, 0x01, 0xB4, 0, 0, 0, 0]));
            writer.AddResource("fake.png", new byte[] { 1, 2, 3 });
            writer.Generate();
            var table = ManagedSymbolReader.ReadResourceTable(stream.ToArray(), 10);
            Assert.Null(table.Error);
            var png = Assert.Single(table.Entries, e => e.Name == "without-extension");
            Assert.Equal("binary", png.Status);
            AssertDimensions(png.ImageHeader, "png", 320, 180);
            var gif = Assert.Single(table.Entries, e => e.Name == "animation");
            AssertDimensions(gif.ImageHeader, "gif", 320, 180);
            Assert.Null(Assert.Single(table.Entries, e => e.Name == "fake.png").ImageHeader);
        }
    }

    [Theory]
    [InlineData(2)]
    [InlineData(4)]
    public void PreserializedPayloadsKeepTheirEnvelopeAndDoNotLoadCustomTypes(int format)
    {
        var entry = ManagedSymbolReader.DecodePreserializedResourceEntry(
            "image", "Missing.ImageType, AssemblyThatDoesNotExist", Envelope(format, Convert.FromHexString(PngHeader)));
        Assert.Equal("encoded", entry.Status);
        Assert.Null(entry.Value);
        Assert.True(entry.Serialization!.Complete);
        Assert.Equal("png", entry.Serialization.PayloadKind);
        AssertDimensions(entry.ImageHeader, "png", 320, 180);

        var invalid = ManagedSymbolReader.DecodePreserializedResourceEntry(
            "image", "Missing.ImageType, AssemblyThatDoesNotExist", Envelope(format, Convert.FromHexString(PngHeader)[..12]));
        Assert.Equal("encoded", invalid.Status);
        Assert.True(invalid.Serialization!.Complete);
        AssertInvalid(invalid.ImageHeader, "png");
    }

    [Fact]
    public void DoesNotInspectBinaryFormatterObjectsOrTrailingResourceBytes()
    {
        var formatter = ManagedSymbolReader.DecodePreserializedResourceEntry(
            "object", "Missing.Type, Missing", Envelope(1, Convert.FromHexString(PngHeader)));
        Assert.Null(formatter.ImageHeader);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(0);
        writer.Write(Convert.FromHexString(PngHeader));
        var entry = ManagedSymbolReader.DecodeResourceEntry("trailing.png", "ResourceTypeCode.ByteArray", stream.ToArray());
        Assert.Null(entry.ImageHeader);
    }

    [Fact]
    public async Task JsonAndReportDescribeOnlyHeaderEvidence()
    {
        var valid = ManagedSymbolReader.DecodePreserializedResourceEntry(
            "image", "Missing.Type, Missing", Envelope(2, Convert.FromHexString(PngHeader)));
        var invalid = valid with { Name = "invalid", ImageHeader = ResourceImageHeaderReader.Read(Convert.FromHexString(PngHeader)[..12]) };
        var plainBinary = valid with { Name = "binary", Status = "binary", Serialization = null };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor { Name = "fixture", Kind = "file", SourcePath = "fixture", FileCount = 1, TotalBytes = 33 },
            Summary = new BlueprintSummary(),
            Files = [new FileArtifact
            {
                Id = "fixture", RelativePath = "fixture.dll", FileName = "fixture.dll", Size = 33, Sha256 = new string('0', 64),
                Category = "library", Format = ".NET assembly", IsManaged = true,
                Code = new CodeModel
                {
                    Kind = "managed", TypeCount = 1,
                    Resources = [new ManagedResourceModel
                    {
                        Name = "Fixture.resources", Visibility = "private", Location = "embedded", Kind = ".NET 資源表",
                        Entries = [valid, invalid, plainBinary]
                    }]
                }
            }]
        };
        var report = MarkdownReportWriter.Build(document);
        Assert.Contains("PNG 檔頭尺寸 320 × 180 px（未驗證像素內容）", report);
        Assert.Contains("PNG 檔頭無效", report);
        Assert.Contains("預序列化 type-converter-byte-array", report);
        var path = Path.Combine(Path.GetTempPath(), $"resource-image-{Guid.NewGuid():N}.json");
        try
        {
            await BlueprintJsonWriter.WriteAsync(document, path);
            using var json = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var entries = json.RootElement.GetProperty("files")[0].GetProperty("code").GetProperty("resources")[0].GetProperty("entries");
            Assert.Equal(320, entries[0].GetProperty("imageHeader").GetProperty("width").GetInt32());
            Assert.Equal("invalid", entries[1].GetProperty("imageHeader").GetProperty("status").GetString());
            Assert.False(entries[1].GetProperty("imageHeader").TryGetProperty("width", out _));
        }
        finally { File.Delete(path); }
    }

    private static byte[] Envelope(int format, byte[] payload)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write7BitEncodedInt(format);
        writer.Write7BitEncodedInt(payload.Length);
        writer.Write(payload);
        return stream.ToArray();
    }

    private static void AssertDimensions(ResourceImageHeaderModel? image, string format, int width, int height)
    {
        Assert.NotNull(image);
        Assert.Equal("parsed", image.Status);
        Assert.Equal(format, image.Format);
        Assert.Equal(width, image.Width);
        Assert.Equal(height, image.Height);
        Assert.Null(image.Error);
    }

    private static void AssertInvalid(ResourceImageHeaderModel? image, string format)
    {
        Assert.NotNull(image);
        Assert.Equal("invalid", image.Status);
        Assert.Equal(format, image.Format);
        Assert.Null(image.Width);
        Assert.Null(image.Height);
        Assert.NotNull(image.Error);
    }
}
