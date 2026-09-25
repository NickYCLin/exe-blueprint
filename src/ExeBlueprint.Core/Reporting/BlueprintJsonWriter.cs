using System.Text.Json;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Reporting;

public static class BlueprintJsonWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    // 序列化成與檔案輸出一致的文字（含結尾換行），讓寫檔可以走 GeneratedProjectWriter 的安全路徑。
    public static string Serialize(BlueprintDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return JsonSerializer.Serialize(document, Options) + "\n";
    }

    // 與骨架相同：交給 GeneratedProjectWriter 做輸出根目錄與目標的 reparse point 檢查及原子取代。
    // 先前直接以 FileMode.Create 開檔，會跟隨既有的 symbolic link，也會就地截斷既有 hardlink 的外部 inode。
    public static async Task WriteAsync(
        BlueprintDocument document,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        await GeneratedProjectWriter.WriteSingleFileAsync(outputPath, Serialize(document), cancellationToken)
            .ConfigureAwait(false);
    }
}
