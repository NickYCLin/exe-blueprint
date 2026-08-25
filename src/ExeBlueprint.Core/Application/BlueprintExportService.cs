using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

namespace ExeBlueprint.Application;

public sealed record BlueprintExportRequest
{
    public required string InputPath { get; init; }

    public string? OutputDirectory { get; init; }

    public string BaseDirectory { get; init; } = Environment.CurrentDirectory;

    public bool Overwrite { get; init; }

    public bool JsonOnly { get; init; }

    public bool EmitCSharp { get; init; }

    public bool EmitCpp { get; init; }

    public bool EmitRust { get; init; }

    public bool EmitGo { get; init; }

    public bool EnableNativeAnalysis { get; init; }

    public string? GhidraInstallDir { get; init; }
}

public sealed record BlueprintExportProgress(string Message);

public sealed record SkeletonExportResult(string Language, string Directory, int FileCount);

public sealed record BlueprintExportResult(
    BlueprintDocument Document,
    string OutputDirectory,
    IReadOnlyList<SkeletonExportResult> Skeletons);

public sealed class BlueprintExportService
{
    public async Task<BlueprintExportResult> RunAsync(
        BlueprintExportRequest request,
        IProgress<BlueprintExportProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.InputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.BaseDirectory);

        var inputPath = Path.GetFullPath(request.InputPath);
        if (!File.Exists(inputPath) && !Directory.Exists(inputPath))
        {
            throw new FileNotFoundException("找不到要分析的檔案或資料夾。", inputPath);
        }

        var outputDirectory = string.IsNullOrWhiteSpace(request.OutputDirectory)
            ? CreateDefaultOutputDirectory(inputPath, request.BaseDirectory)
            : Path.GetFullPath(request.OutputDirectory);
        var jsonPath = Path.Combine(outputDirectory, "blueprint.json");
        var reportPath = Path.Combine(outputDirectory, "REPORT.md");

        if (!request.Overwrite && (File.Exists(jsonPath) || File.Exists(reportPath)))
        {
            throw new IOException("輸出目錄已有分析結果。請更換目錄，或允許覆寫既有結果。");
        }

        Directory.CreateDirectory(outputDirectory);
        progress?.Report(new BlueprintExportProgress("正在掃描檔案並建立分析資料…"));

        var analyzer = new BlueprintAnalyzer();
        var analysisOptions = new AnalysisOptions
        {
            EnableNativeAnalysis = request.EnableNativeAnalysis,
            GhidraInstallDir = NullIfWhiteSpace(request.GhidraInstallDir)
        };
        var document = await analyzer.AnalyzeAsync(inputPath, analysisOptions, cancellationToken)
            .ConfigureAwait(false);

        progress?.Report(new BlueprintExportProgress("正在寫入 blueprint.json…"));
        await BlueprintJsonWriter.WriteAsync(document, jsonPath, cancellationToken).ConfigureAwait(false);
        if (!request.JsonOnly)
        {
            progress?.Report(new BlueprintExportProgress("正在整理繁體中文報告…"));
            await MarkdownReportWriter.WriteAsync(document, reportPath, cancellationToken).ConfigureAwait(false);
        }

        var skeletons = new List<SkeletonExportResult>();
        await EmitSkeletonAsync(request.EmitCSharp, "C#", "reconstructed-csharp", CSharpSkeletonGenerator.Generate);
        await EmitSkeletonAsync(request.EmitCpp, "C++", "reconstructed-cpp", CppSkeletonGenerator.Generate);
        await EmitSkeletonAsync(request.EmitRust, "Rust", "reconstructed-rust", RustSkeletonGenerator.Generate);
        await EmitSkeletonAsync(request.EmitGo, "Go", "reconstructed-go", GoSkeletonGenerator.Generate);

        progress?.Report(new BlueprintExportProgress("分析完成。"));
        return new BlueprintExportResult(document, Path.GetFullPath(outputDirectory), skeletons);

        async Task EmitSkeletonAsync(
            bool enabled,
            string language,
            string directoryName,
            Func<BlueprintDocument, IReadOnlyList<GeneratedFile>> generator)
        {
            if (!enabled)
            {
                return;
            }

            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report(new BlueprintExportProgress($"正在產生 {language} 骨架…"));
            var generated = generator(document);
            if (generated.Count == 0)
            {
                return;
            }

            var directory = Path.Combine(outputDirectory, directoryName);
            await GeneratedProjectWriter.WriteAsync(generated, directory, cancellationToken).ConfigureAwait(false);
            skeletons.Add(new SkeletonExportResult(language, Path.GetFullPath(directory), generated.Count));
        }
    }

    public static string CreateDefaultOutputDirectory(
        string inputPath,
        string baseDirectory,
        DateTimeOffset? timestamp = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);

        var fullPath = Path.GetFullPath(inputPath);
        var name = Directory.Exists(fullPath)
            ? new DirectoryInfo(fullPath).Name
            : Path.GetFileNameWithoutExtension(fullPath);
        var safeName = string.Concat(name.Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character));
        var value = timestamp ?? DateTimeOffset.Now;
        return Path.Combine(
            Path.GetFullPath(baseDirectory),
            "exe-blueprint-output",
            $"{safeName}-{value:yyyyMMdd-HHmmss}");
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Path.GetFullPath(value);
}
