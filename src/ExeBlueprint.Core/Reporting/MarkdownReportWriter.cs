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
        builder.AppendLine($"| 型別（.NET） | {document.Summary.TypeCount} |");
        builder.AppendLine($"| 方法（.NET） | {document.Summary.MethodCount} |");
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

        AppendCodeStructure(builder, document);

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

    private const int MaxTypesPerFile = 20;
    private const int MaxCallEdgesPerFile = 30;

    private static void AppendCodeStructure(StringBuilder builder, BlueprintDocument document)
    {
        var codeFiles = document.Files
            .Where(file => file.Code is not null && file.Code.TypeCount > 0)
            .ToArray();

        builder.AppendLine();
        builder.AppendLine("## 程式碼結構（.NET）");
        builder.AppendLine();
        if (codeFiles.Length == 0)
        {
            builder.AppendLine("沒有可讀取的 .NET 受管組件，或組件內沒有可列出的型別。原生程式的函式還原需要另接反組譯後端。");
            return;
        }

        foreach (var file in codeFiles)
        {
            var code = file.Code!;
            builder.AppendLine($"### `{EscapeInline(file.RelativePath)}`");
            builder.AppendLine();
            builder.AppendLine($"- 程式入口：{(string.IsNullOrEmpty(code.EntryPointMethod) ? "無（程式庫或找不到入口）" : $"`{EscapeInline(code.EntryPointMethod)}`")}");
            builder.AppendLine($"- 命名空間：{code.NamespaceCount}；型別：{code.TypeCount}；方法：{code.MethodCount}；呼叫關係：{code.CallEdgeCount}");
            var methodsWithIl = code.Types.Sum(type => type.Methods.Count(method => method.Il.Count > 0));
            builder.AppendLine($"- 已反組譯出 IL 的方法：{methodsWithIl}（可用 `--emit-csharp` 產生 C# 骨架）");
            if (code.Truncated)
            {
                builder.AppendLine("- 內容過大，型別或呼叫關係已截斷，完整資料請看 blueprint.json。");
            }

            builder.AppendLine();

            var topTypes = code.Types
                .OrderByDescending(type => type.Methods.Count)
                .ThenBy(type => type.FullName, StringComparer.Ordinal)
                .Take(MaxTypesPerFile)
                .ToArray();
            builder.AppendLine("| 型別 | 種類 | 存取 | 方法數 |");
            builder.AppendLine("| --- | --- | --- | ---: |");
            foreach (var type in topTypes)
            {
                builder.AppendLine($"| `{EscapeInline(type.FullName)}` | {EscapeCell(type.Kind)} | {EscapeCell(type.Accessibility)} | {type.Methods.Count} |");
            }

            if (code.Types.Count > topTypes.Length)
            {
                builder.AppendLine();
                builder.AppendLine($"（僅列出方法數最多的 {topTypes.Length} 個型別，其餘 {code.Types.Count - topTypes.Length} 個請看 blueprint.json）");
            }

            builder.AppendLine();
            if (code.CallGraph.Count == 0)
            {
                builder.AppendLine("沒有解析到方法呼叫關係。");
            }
            else
            {
                builder.AppendLine("呼叫流程範例：");
                builder.AppendLine();
                builder.AppendLine("| 來源方法 | 關係 | 目標方法 |");
                builder.AppendLine("| --- | --- | --- |");
                var sampleEdges = code.CallGraph
                    .OrderBy(edge => IsCompilerGenerated(edge.Caller) ? 1 : 0)
                    .Take(MaxCallEdgesPerFile);
                foreach (var edge in sampleEdges)
                {
                    builder.AppendLine($"| `{EscapeInline(edge.Caller)}` | {edge.Kind} | `{EscapeInline(edge.Callee)}` |");
                }

                if (code.CallGraph.Count > MaxCallEdgesPerFile)
                {
                    builder.AppendLine();
                    builder.AppendLine($"（僅列出前 {MaxCallEdgesPerFile} 筆，共 {code.CallGraph.Count} 筆呼叫關係，完整內容請看 blueprint.json）");
                }
            }

            builder.AppendLine();
        }
    }

    private static bool IsCompilerGenerated(string methodFullName) =>
        methodFullName.Contains('<', StringComparison.Ordinal) || methodFullName.Contains('>', StringComparison.Ordinal);

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
