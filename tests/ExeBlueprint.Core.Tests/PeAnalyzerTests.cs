using System.Buffers.Binary;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class PeAnalyzerTests
{
    // PEReader 對超過 int.MaxValue 的串流會丟 ArgumentException，FileAnalyzer 不會捕捉，整個分析
    // 就中止。超大的 PE（例如帶內嵌 payload 的安裝程式）應被記成略過，而不是讓其他檔案也失去結果。
    [Fact]
    public async Task ReportsPeLargerThanTwoGibAsBadImageInsteadOfAbortingRun()
    {
        if (OperatingSystem.IsWindows())
        {
            // NTFS 的 SetLength 會實際配置空間，2 GiB 對單元測試太重；只在支援稀疏檔的平台上驗證。
            return;
        }

        var directory = Path.Combine(Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "huge.exe");
        try
        {
            await using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // MZ、e_lfanew=0x40、0x40 處放 "PE\0\0"，讓簽章檢查通過後才碰到大小限制。
                var header = new byte[0x44];
                header[0] = (byte)'M';
                header[1] = (byte)'Z';
                BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(0x3C, 4), 0x40);
                "PE\0\0"u8.CopyTo(header.AsSpan(0x40, 4));
                await stream.WriteAsync(header);

                try
                {
                    stream.SetLength((long)int.MaxValue + 1);
                }
                catch (IOException)
                {
                    // 檔案系統不支援稀疏檔或空間不足，略過此驗證。
                    return;
                }
            }

            var exception = await Assert.ThrowsAsync<BadImageFormatException>(() =>
                PeAnalyzer.TryAnalyzeAsync(path, CancellationToken.None));

            Assert.Contains("2 GiB", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }
}
