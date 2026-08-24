using ExeBlueprint.Input;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

public sealed class BlueprintAnalyzer
{
    public async Task<BlueprintDocument> AnalyzeAsync(
        string inputPath,
        AnalysisOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new AnalysisOptions();
        ValidateOptions(options);

        await using var workspace = await InputWorkspace.OpenAsync(
            inputPath,
            options.MaxFiles,
            options.MaxTotalBytes,
            cancellationToken).ConfigureAwait(false);

        var warnings = workspace.Warnings.ToList();
        var paths = workspace.EnumerateFiles(options.MaxFiles, warnings)
            .Select(path => new InputFile(path, workspace.GetRelativePath(path)))
            .OrderBy(file => file.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var totalBytes = paths.Sum(file => new FileInfo(file.FullPath).Length);
        if (totalBytes > options.MaxTotalBytes)
        {
            throw new InvalidDataException($"輸入總大小超過限制：{options.MaxTotalBytes:N0} bytes");
        }

        var fileAnalyzer = new FileAnalyzer(options);
        var artifacts = new List<FileArtifact>(paths.Length);
        foreach (var file in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var artifact = await fileAnalyzer.AnalyzeAsync(
                file.FullPath,
                file.RelativePath,
                cancellationToken).ConfigureAwait(false);
            artifacts.Add(artifact);
            if (!string.IsNullOrWhiteSpace(artifact.AnalysisError))
            {
                warnings.Add($"{artifact.RelativePath}：{artifact.AnalysisError}");
            }
        }

        var technologies = TechnologyDetector.DetectPackage(artifacts);
        var dependencies = DependencyGraphBuilder.Build(artifacts);
        var summary = CreateSummary(artifacts, dependencies);

        return new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = workspace.Name,
                Kind = workspace.Kind,
                SourcePath = workspace.Name,
                FileCount = artifacts.Count,
                TotalBytes = totalBytes
            },
            Summary = summary,
            Files = artifacts,
            Dependencies = dependencies,
            Technologies = technologies,
            Warnings = warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
        };
    }

    private static BlueprintSummary CreateSummary(
        IReadOnlyList<FileArtifact> files,
        IReadOnlyList<DependencyEdge> dependencies) => new()
        {
            ExecutableCount = files.Count(file => file.IsExecutable),
            LibraryCount = files.Count(file => file.IsLibrary),
            ManagedAssemblyCount = files.Count(file => file.IsManaged),
            NativePeCount = files.Count(file => file.IsPortableExecutable && !file.IsManaged),
            ArchiveCount = files.Count(file => file.Category == "archive"),
            ConfigurationCount = files.Count(file => file.Category == "configuration"),
            ResourceCount = files.Count(file => file.Category == "resource"),
            UnknownCount = files.Count(file => file.Category == "unknown"),
            InternalDependencyCount = dependencies.Count(edge => edge.ResolvedInsidePackage),
            ExternalDependencyCount = dependencies.Count(edge => !edge.ResolvedInsidePackage),
            TypeCount = files.Sum(file => file.Code?.TypeCount ?? 0),
            MethodCount = files.Sum(file => file.Code?.MethodCount ?? 0)
        };

    private static void ValidateOptions(AnalysisOptions options)
    {
        if (options.MaxFiles <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxFiles 必須大於零。");
        }

        if (options.MaxTotalBytes <= 0 || options.MaxFileBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "檔案大小限制必須大於零。");
        }

        if (options.BinarySignalSampleBytes < 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "BinarySignalSampleBytes 不得小於 4096。");
        }
    }

    private sealed record InputFile(string FullPath, string RelativePath);
}
