using System.Buffers.Binary;
using System.IO.Compression;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ZipInputSafetyTests
{
    // ZipArchive 要先具現化整個 central directory 才能數項目數；EOCD 宣告的總數超過上限時，
    // 應在開檔前就拒絕，而不是先把上百萬筆目錄紀錄讀進記憶體。
    [Fact]
    public async Task ZipDeclaringTooManyEntriesIsRejectedBeforeCentralDirectoryIsRead()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "declared-huge.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            await using var stream = archive.CreateEntry("only.txt").Open();
            await using var writer = new StreamWriter(stream);
            await writer.WriteAsync("x");
        }

        // 把真實壓縮檔的 EOCD 總數改成 60,000（超過預設 25,000 上限），central directory 仍只有一筆。
        var bytes = await File.ReadAllBytesAsync(zipPath);
        var eocd = bytes.Length - 22;
        Assert.Equal(0x06054B50u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd, 4)));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 8, 2), 60_000);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(eocd + 10, 2), 60_000);
        await File.WriteAllBytesAsync(zipPath, bytes);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => new BlueprintAnalyzer().AnalyzeAsync(zipPath));

        Assert.Contains("項目數超過限制", exception.Message, StringComparison.Ordinal);
    }

    // 一般壓縮檔的宣告數量在上限內，預先過濾不得影響既有流程。
    [Fact]
    public async Task OrdinaryZipStillExpands()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "ordinary.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            await using var stream = archive.CreateEntry("readme.txt").Open();
            await using var writer = new StreamWriter(stream);
            await writer.WriteAsync("hello");
        }

        var document = await new BlueprintAnalyzer().AnalyzeAsync(zipPath);

        Assert.Contains(document.Files, file => file.RelativePath.EndsWith("readme.txt", StringComparison.Ordinal));
    }

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "exe-blueprint-tests",
                Guid.NewGuid().ToString("N"));
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
