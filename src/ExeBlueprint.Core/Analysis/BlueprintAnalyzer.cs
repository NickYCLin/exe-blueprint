using ExeBlueprint.Input;
using ExeBlueprint.Models;
using System.Diagnostics;

namespace ExeBlueprint.Analysis;

public sealed class BlueprintAnalyzer
{
    public async Task<BlueprintDocument> AnalyzeAsync(
        string inputPath,
        AnalysisOptions? options = null,
        CancellationToken cancellationToken = default,
        IProgress<AnalysisProgress>? progress = null)
    {
        options ??= new AnalysisOptions();
        if (options.EnableSourceAnalysis && !options.SourceMode)
            options = options with { SourceMode = true };
        ValidateOptions(options);

        await using var workspace = await InputWorkspace.OpenAsync(
            inputPath,
            options,
            cancellationToken).ConfigureAwait(false);

        var warnings = workspace.Warnings.ToList();
        var fileAnalyzer = new FileAnalyzer(options);
        var results = new FileArtifact[workspace.Files.Count];
        var completedFiles = 0;
        var progressLock = new object();
        progress?.Report(new AnalysisProgress(0, workspace.Files.Count, null));
        var lastProgress = Stopwatch.GetTimestamp();
        if (options.InventoryOnly)
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, workspace.Files.Count), new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Min(4, Environment.ProcessorCount),
                CancellationToken = cancellationToken
            }, AnalyzeFileAsync).ConfigureAwait(false);
        }
        else
        {
            for (var index = 0; index < workspace.Files.Count; index++)
                await AnalyzeFileAsync(index, cancellationToken).ConfigureAwait(false);
        }
        var artifacts = results.ToList();
        foreach (var artifact in artifacts)
        {
            if (!string.IsNullOrWhiteSpace(artifact.AnalysisError))
                warnings.Add($"{artifact.RelativePath}：{artifact.AnalysisError}");
            if (artifact.NativeCode is { Note: { Length: > 0 } note }) warnings.Add(note);
        }

        async ValueTask AnalyzeFileAsync(int index, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var file = workspace.Files[index];
            results[index] = await fileAnalyzer.AnalyzeAsync(
                file.PhysicalPath,
                file.LogicalPath,
                file.Origin,
                token).ConfigureAwait(false);
            lock (progressLock)
            {
                completedFiles++;
                if (completedFiles == workspace.Files.Count || Stopwatch.GetElapsedTime(lastProgress).TotalMilliseconds >= 100)
                {
                    progress?.Report(new AnalysisProgress(completedFiles, workspace.Files.Count, file.LogicalPath));
                    lastProgress = Stopwatch.GetTimestamp();
                }
            }
        }

        progress?.Report(new AnalysisProgress(artifacts.Count, workspace.Files.Count, null, "projects"));
        var technologies = TechnologyDetector.DetectPackage(artifacts);
        var dependencies = DependencyGraphBuilder.Build(artifacts);
        var projectGraph = await ProjectGraphAnalyzer.AnalyzeAsync(workspace.Files, artifacts, dependencies, cancellationToken)
            .ConfigureAwait(false);
        var notedProjects = projectGraph.Components.Count(component => component.Notes.Count > 0);
        if (notedProjects > 0) warnings.Add($"有 {notedProjects:N0} 個專案描述檔含未求值或未完整解析項目，請查看專案總覽的注意事項。");
        if (projectGraph.Truncated) warnings.Add("專案圖已達安全上限，請查看 projectGraph.truncated；目前結果不是完整專案圖。");
        SourceCodeAnalysis? sourceCode = null;
        if (options.EnableSourceAnalysis)
        {
            progress?.Report(new AnalysisProgress(artifacts.Count, workspace.Files.Count, null, "source"));
            sourceCode = await SourceSemanticAnalyzer.AnalyzeAsync(workspace.Files, projectGraph, cancellationToken)
                .ConfigureAwait(false);
            warnings.AddRange(sourceCode.Warnings);
            var incompleteProjects = sourceCode.Projects.Count(project => !project.Complete);
            if (incompleteProjects > 0)
                warnings.Add($"有 {incompleteProjects:N0} 個 C# 專案的語意索引不完整，請查看 sourceCode.projects[].notes。");
            if (sourceCode.Truncated)
                warnings.Add("C# 語意索引已達安全上限，請查看 sourceCode.truncated；缺少宣告或呼叫不代表不存在。");
        }
        var summary = CreateSummary(artifacts, dependencies);

        return new BlueprintDocument
        {
            AnalysisMode = options.InventoryOnly ? "inventory" : "full",
            ProjectGraph = projectGraph,
            SourceCode = sourceCode,
            Input = new InputDescriptor
            {
                Name = workspace.Name,
                Kind = workspace.Kind,
                SourcePath = workspace.Name,
                FileCount = artifacts.Count,
                TotalBytes = workspace.TotalBytes
            },
            Summary = summary,
            Files = artifacts,
            Archives = workspace.Archives,
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

        if (options.MaxArchiveDepth <= 0 || options.MaxArchiveDepth > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxArchiveDepth 必須介於 1 到 64。");
        }

        if (options.MaxWorkspacePathCharacters <= 0 ||
            options.MaxWorkspaceArchives <= 0 ||
            options.MaxWorkspaceArchiveHeaderBytes <= 0 ||
            options.MaxWorkspaceArchiveNodes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "workspace 安全限制必須大於零。");
        }

        if (options.BinarySignalSampleBytes < 4096)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "BinarySignalSampleBytes 不得小於 4096。");
        }
    }

}
