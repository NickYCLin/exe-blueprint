using System.Buffers.Binary;
using System.Text;
using ExeBlueprint.Input;

namespace ExeBlueprint.Core.Tests;

public sealed class AsarArchiveTests
{
    private const int DefaultMaxFiles = 100;
    private const long DefaultMaxBytes = 1024 * 1024;

    [Fact]
    public async Task OpenAndCopyAcceptsOfficialDeduplicatedRangesAndSkipsExternalEntries()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "fixture.asar");
        const string header = """
            {
              "files": {
                "main.js": { "size": 4, "offset": "0", "executable": true },
                "copy.js": { "size": 4, "offset": "0" },
                "nested": { "files": { "data.bin": { "size": 3, "offset": "4" } } },
                "native.node": { "size": 10, "unpacked": true },
                "shortcut": { "link": "main.js" }
              }
            }
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header, "testxyz"u8.ToArray());

        await using var archive = await OpenAsync(archivePath);

        Assert.Equal(["main.js", "copy.js", "nested/data.bin"], archive.Entries.Select(entry => entry.RelativePath));
        Assert.Equal("native.node", Assert.Single(archive.UnpackedEntries).RelativePath);
        Assert.Equal("main.js", Assert.Single(archive.Links).Target);
        Assert.True(archive.Entries[0].Executable);
        Assert.Equal(6, archive.NodeCount);
        Assert.Contains(archive.Warnings, warning => warning.Contains("連結", StringComparison.Ordinal));

        await using var first = new MemoryStream();
        await archive.CopyEntryToAsync(archive.Entries[0], first, CancellationToken.None);
        Assert.Equal("test", Encoding.UTF8.GetString(first.ToArray()));

        await using var nested = new MemoryStream();
        await archive.CopyEntryToAsync(archive.Entries[2], nested, CancellationToken.None);
        Assert.Equal("xyz", Encoding.UTF8.GetString(nested.ToArray()));
    }

    [Fact]
    public async Task OpensArchiveProducedByOfficialElectronTool()
    {
        var archivePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "official-sample.asar");

        await using var archive = await OpenAsync(archivePath);

        Assert.Equal(["duplicate.js", "main.js", "config/settings.json"], archive.Entries.Select(entry => entry.RelativePath));
        Assert.Equal(archive.Entries[0].DataOffset, archive.Entries[1].DataOffset);
        Assert.Equal(archive.Entries[0].Size, archive.Entries[1].Size);
        await using var output = new MemoryStream();
        await archive.CopyEntryToAsync(archive.Entries[0], output, CancellationToken.None);
        Assert.Equal("module.exports = 42;\n", Encoding.UTF8.GetString(output.ToArray()));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"files\":{},\"files\":{}}")]
    [InlineData("{\"files\":{\"..\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"bad/name\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"file\":{\"files\":{},\"offset\":\"0\",\"size\":0}}}")]
    [InlineData("{\"files\":{\"file\":{\"size\":1.5,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"file\":{\"size\":0,\"offset\":\"+0\"}}}")]
    [InlineData("{\"files\":{\"file\":{\"size\":0,\"offset\":0}}}")]
    [InlineData("{\"files\":{\"file\":{\"size\":0,\"offset\":0,\"unpacked\":true}}}")]
    [InlineData("{\"files\":{\"CON.txt\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"COM¹\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"LPT².txt\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"stream:secret\":{\"size\":0,\"offset\":\"0\"}}}")]
    [InlineData("{\"files\":{\"trailing.\":{\"size\":0,\"offset\":\"0\"}}}")]
    public async Task RejectsInvalidHeaderTrees(string header)
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "invalid.asar");
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task RejectsCaseInsensitiveUnicodeNameCollisions()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "collision.asar");
        const string header = """
            {"files":{"é.js":{"size":0,"offset":"0"},"é.js":{"size":0,"offset":"0"}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task AllowsUnpackedMetadataOnDirectoryAndSkipsItsFiles()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "unpack-directory.asar");
        const string header = """
            {"files":{"native":{"files":{"addon.node":{"size":12,"unpacked":true}},"unpacked":true}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await using var archive = await OpenAsync(archivePath);

        Assert.Empty(archive.Entries);
        Assert.Equal("native/addon.node", Assert.Single(archive.UnpackedEntries).RelativePath);
        Assert.Empty(archive.Warnings);
    }

    [Theory]
    [InlineData("../../outside")]
    [InlineData("/absolute")]
    [InlineData("missing")]
    public async Task RejectsUnsafeOrMissingLinkTargets(string target)
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "link.asar");
        var header = "{\"files\":{\"shortcut\":{\"link\":\"" + target + "\"}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task RejectsLinkCycles()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "cycle.asar");
        const string header = """
            {"files":{"first":{"link":"second"},"second":{"link":"first"}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task RejectsOversizedLinkTargetBeforeNormalizingIt()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "long-link.asar");
        var target = new string('a', 16_385);
        var header = "{\"files\":{\"shortcut\":{\"link\":\"" + target + "\"}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task RejectsPartialOverlapButAcceptsExactSharedRange()
    {
        await using var temp = new TemporaryDirectory();
        var validPath = Path.Combine(temp.Path, "shared.asar");
        const string validHeader = """
            {"files":{"a":{"size":4,"offset":"0"},"b":{"size":4,"offset":"0"}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(validPath, validHeader, new byte[4]);
        await using var valid = await OpenAsync(validPath);
        Assert.Equal(2, valid.Entries.Count);

        var invalidPath = Path.Combine(temp.Path, "overlap.asar");
        const string invalidHeader = """
            {"files":{"a":{"size":4,"offset":"0"},"b":{"size":3,"offset":"2"}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(invalidPath, invalidHeader, new byte[5]);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(invalidPath));
    }

    [Theory]
    [InlineData("18446744073709551615", 0)]
    [InlineData("0", 2)]
    public async Task RejectsOverflowAndOutOfBoundsRanges(string offset, int size)
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "bounds.asar");
        var header = "{\"files\":{\"file\":{\"size\":" + size + ",\"offset\":\"" + offset + "\"}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header, new byte[1]);

        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(archivePath));
    }

    [Fact]
    public async Task EnforcesFileCountFileSizeAndAggregateLimits()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "limits.asar");
        const string header = """
            {"files":{"a":{"size":2,"offset":"0"},"b":{"size":2,"offset":"2"}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header, new byte[4]);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AsarArchive.OpenAsync(archivePath, 1, DefaultMaxBytes, DefaultMaxBytes, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AsarArchive.OpenAsync(archivePath, DefaultMaxFiles, 3, DefaultMaxBytes, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AsarArchive.OpenAsync(archivePath, DefaultMaxFiles, DefaultMaxBytes, 1, CancellationToken.None));
    }

    [Fact]
    public async Task EnforcesAggregateRetainedPathBudget()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "path-budget.asar");
        const string header = """
            {"files":{"directory":{"files":{"first-file":{"size":0,"offset":"0"},"second-file":{"size":0,"offset":"0"}}}}}
            """;
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AsarArchive.OpenAsync(
                archivePath,
                DefaultMaxFiles,
                DefaultMaxBytes,
                DefaultMaxBytes,
                maxRetainedPathCharacters: 20,
                CancellationToken.None));
    }

    [Fact]
    public async Task RejectsMalformedPicklesAndInvalidUtf8()
    {
        await using var temp = new TemporaryDirectory();

        var badOuterPath = Path.Combine(temp.Path, "outer.asar");
        var badOuter = AsarTestArchiveBuilder.Create("{\"files\":{}}");
        BinaryPrimitives.WriteUInt32LittleEndian(badOuter, 3);
        await File.WriteAllBytesAsync(badOuterPath, badOuter);
        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(badOuterPath));

        var badPaddingPath = Path.Combine(temp.Path, "padding.asar");
        var badPadding = AsarTestArchiveBuilder.Create("{\"files\":{}} ");
        badPadding[^1] = 1;
        await File.WriteAllBytesAsync(badPaddingPath, badPadding);
        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(badPaddingPath));

        var badUtf8Path = Path.Combine(temp.Path, "utf8.asar");
        var badUtf8 = AsarTestArchiveBuilder.Create([0xC3, 0x28]);
        await File.WriteAllBytesAsync(badUtf8Path, badUtf8);
        await Assert.ThrowsAsync<InvalidDataException>(() => OpenAsync(badUtf8Path));
    }

    [Fact]
    public async Task HonorsCancellationWhileOpening()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "cancelled.asar");
        await AsarTestArchiveBuilder.WriteAsync(archivePath, "{\"files\":{}}");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            AsarArchive.OpenAsync(
                archivePath,
                DefaultMaxFiles,
                DefaultMaxBytes,
                DefaultMaxBytes,
                cancellation.Token));
    }

    private static Task<AsarArchive> OpenAsync(string path) =>
        AsarArchive.OpenAsync(
            path,
            DefaultMaxFiles,
            DefaultMaxBytes,
            DefaultMaxBytes,
            CancellationToken.None);

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }
}
