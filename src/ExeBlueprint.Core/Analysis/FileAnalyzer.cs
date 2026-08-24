using System.Security.Cryptography;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

internal sealed class FileAnalyzer
{
    private readonly AnalysisOptions _options;

    public FileAnalyzer(AnalysisOptions options)
    {
        _options = options;
    }

    public async Task<FileArtifact> AnalyzeAsync(
        string fullPath,
        string relativePath,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(fullPath);
        if (info.Length > _options.MaxFileBytes)
        {
            return CreateSkippedArtifact(relativePath, info, "檔案超過單檔分析上限");
        }

        try
        {
            var sha256 = await ComputeSha256Async(fullPath, cancellationToken).ConfigureAwait(false);
            var signals = await BinarySignalReader.CreateAsync(
                fullPath,
                _options.BinarySignalSampleBytes,
                cancellationToken).ConfigureAwait(false);
            var pe = await PeAnalyzer.TryAnalyzeAsync(fullPath, cancellationToken).ConfigureAwait(false);

            var (category, format) = pe is null
                ? FileClassifier.Classify(fullPath, signals.Header)
                : (pe.IsLibrary ? "library" : "executable", pe.IsManaged ? ".NET Portable Executable" : "Native Portable Executable");
            var technologies = TechnologyDetector.DetectFile(relativePath, pe, signals);

            return new FileArtifact
            {
                Id = relativePath,
                RelativePath = relativePath,
                FileName = info.Name,
                Size = info.Length,
                Sha256 = sha256,
                Category = category,
                Format = format,
                IsPortableExecutable = pe is not null,
                IsExecutable = pe?.IsExecutable == true,
                IsLibrary = pe?.IsLibrary == true,
                IsManaged = pe?.IsManaged == true,
                Architecture = pe?.Architecture,
                Subsystem = pe?.Subsystem,
                AssemblyName = pe?.AssemblyName,
                AssemblyVersion = pe?.AssemblyVersion,
                CorFlags = pe?.CorFlags,
                HasAuthenticodeSignature = pe?.HasAuthenticodeSignature == true,
                Sections = pe?.Sections ?? [],
                ImportedModules = pe?.ImportedModules ?? [],
                ManagedReferences = pe?.ManagedReferences ?? [],
                Technologies = technologies
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or BadImageFormatException or InvalidDataException)
        {
            return CreateSkippedArtifact(relativePath, info, exception.Message);
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static FileArtifact CreateSkippedArtifact(string relativePath, FileInfo info, string error) => new()
    {
        Id = relativePath,
        RelativePath = relativePath,
        FileName = info.Name,
        Size = info.Exists ? info.Length : 0,
        Sha256 = string.Empty,
        Category = "unknown",
        Format = "Unanalyzed",
        AnalysisError = error
    };
}
