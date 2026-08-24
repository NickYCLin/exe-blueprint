using System.Globalization;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Reporting;

public static class MarkdownReportWriter
{
    public static async Task WriteAsync(
        BlueprintDocument document,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        var content = Build(document);
        await File.WriteAllTextAsync(outputPath, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken)
            .ConfigureAwait(false);
    }

    public static string Build(BlueprintDocument document)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# ExeBlueprint 分析報告");
        builder.AppendLine();
        builder.AppendLine($"- 輸入：`{EscapeInline(document.Input.Name)}`");
        builder.AppendLine($"- 類型：`{document.Input.Kind}`");
        builder.AppendLine($"- 檔案數：{document.Input.FileCount:N0}");
        builder.AppendLine($"- 總大小：{FormatBytes(document.Input.TotalBytes)}");
        builder.AppendLine($"- 產生時間：{document.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss} UTC");
        builder.AppendLine();

        builder.AppendLine("## 摘要");
        builder.AppendLine();
        builder.AppendLine("| 項目 | 數量 |");
        builder.AppendLine("| --- | ---: |");
        builder.AppendLine($"| 可執行檔 | {document.Summary.ExecutableCount} |");
        builder.AppendLine($"| 程式庫 | {document.Summary.LibraryCount} |");
        builder.AppendLine($"| .NET assemblies | {document.Summary.ManagedAssemblyCount} |");
        builder.AppendLine($"| 原生 PE | {document.Summary.NativePeCount} |");
        builder.AppendLine($"| 壓縮包／套件 | {document.Summary.ArchiveCount} |");
        builder.AppendLine($"| 設定檔 | {document.Summary.ConfigurationCount} |");
        builder.AppendLine($"| 資源檔 | {document.Summary.ResourceCount} |");
        builder.AppendLine($"| 套件內相依 | {document.Summary.InternalDependencyCount} |");
        builder.AppendLine($"| 外部相依 | {document.Summary.ExternalDependencyCount} |");
        builder.AppendLine();

        builder.AppendLine("## 辨識結果");
        builder.AppendLine();
        if (document.Technologies.Count == 0)
        {
            builder.AppendLine("目前沒有足夠證據判斷使用的語言或框架。");
        }
        else
        {
            builder.AppendLine("| 技術 | 類別 | 可信度 | 依據 |");
            builder.AppendLine("| --- | --- | ---: | --- |");
            foreach (var technology in document.Technologies)
            {
                builder.AppendLine($"| {EscapeCell(technology.Name)} | {EscapeCell(technology.Category)} | {technology.Confidence:P0} | {EscapeCell(string.Join("；", technology.Evidence))} |");
            }
        }

        builder.AppendLine();
        builder.AppendLine("## 程式入口");
        builder.AppendLine();
        var entryPoints = document.Files.Where(file => file.IsExecutable).ToArray();
        if (entryPoints.Length == 0)
        {
            builder.AppendLine("沒有找到 Windows PE 執行檔。");
        }
        else
        {
            builder.AppendLine("| 檔案 | 格式 | 架構 | 子系統 | 簽章資料 |");
            builder.AppendLine("| --- | --- | --- | --- | --- |");
            foreach (var file in entryPoints)
            {
                builder.AppendLine($"| `{EscapeInline(file.RelativePath)}` | {EscapeCell(file.Format)} | {EscapeCell(file.Architecture ?? "-")} | {EscapeCell(file.Subsystem ?? "-")} | {(file.HasAuthenticodeSignature ? "有" : "無")} |");
            }
        }

        builder.AppendLine();
        builder.AppendLine("## 檔案清單");
        builder.AppendLine();
        builder.AppendLine("| 路徑 | 類型 | 大小 | SHA-256 |");
        builder.AppendLine("| --- | --- | ---: | --- |");
        foreach (var file in document.Files)
        {
            var shortHash = string.IsNullOrWhiteSpace(file.Sha256) ? "-" : file.Sha256[..Math.Min(12, file.Sha256.Length)];
            builder.AppendLine($"| `{EscapeInline(file.RelativePath)}` | {EscapeCell(file.Format)} | {FormatBytes(file.Size)} | `{shortHash}` |");
        }

        builder.AppendLine();
        builder.AppendLine("## 套件內相依關係");
        builder.AppendLine();
        var internalDependencies = document.Dependencies.Where(edge => edge.ResolvedInsidePackage).ToArray();
        if (internalDependencies.Length == 0)
        {
            builder.AppendLine("目前沒有解析到套件內部的 PE 或 .NET 相依關係。");
        }
        else
        {
            builder.AppendLine("| 來源 | 關係 | 目標 |");
            builder.AppendLine("| --- | --- | --- |");
            foreach (var edge in internalDependencies)
            {
                builder.AppendLine($"| `{EscapeInline(edge.Source)}` | {edge.Kind} | `{EscapeInline(edge.Target)}` |");
            }
        }

        if (document.Warnings.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("## 警告");
            builder.AppendLine();
            foreach (var warning in document.Warnings)
            {
                builder.AppendLine($"- {warning}");
            }
        }

        builder.AppendLine();
        builder.AppendLine("## 目前限制");
        builder.AppendLine();
        builder.AppendLine("這份報告來自靜態分析，沒有執行輸入程式。語言與框架辨識是依據檔案結構、相依套件和特徵資料推斷，不等同原始碼證明。加殼、混淆、動態載入或自訂封裝都可能讓結果不完整。");
        return builder.ToString();
    }

    private static string EscapeCell(string value) => value.Replace("|", "\\|", StringComparison.Ordinal).ReplaceLineEndings(" ");

    private static string EscapeInline(string value) => value.Replace("`", "'", StringComparison.Ordinal).ReplaceLineEndings(" ");

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return string.Create(CultureInfo.InvariantCulture, $"{value:0.##} {units[unitIndex]}");
    }
}
