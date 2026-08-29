using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

internal static class DependencyGraphBuilder
{
    public static IReadOnlyList<DependencyEdge> Build(IReadOnlyList<FileArtifact> files)
    {
        var filesByName = files
            .GroupBy(file => file.FileName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        var assembliesByName = files
            .Where(file => !string.IsNullOrWhiteSpace(file.AssemblyName))
            .GroupBy(file => file.AssemblyName!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<string, DependencyEdge>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            foreach (var module in file.ImportedModules)
            {
                string? target = null;
                var resolved = filesByName.TryGetValue(module, out var targets) &&
                               TrySelectTarget(file, targets!, out target);
                target ??= module;
                Add(edges, file.Id, target, "pe-import", resolved);
            }

            foreach (var reference in file.ManagedReferences)
            {
                string? target = null;
                var resolved = assembliesByName.TryGetValue(reference, out var targets) &&
                               TrySelectTarget(file, targets!, out target);
                target ??= reference;
                Add(edges, file.Id, target, "assembly-reference", resolved);
            }
        }

        return edges.Values
            .OrderBy(edge => edge.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(edge => edge.Kind, StringComparer.OrdinalIgnoreCase)
            .ThenBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool TrySelectTarget(
        FileArtifact source,
        IReadOnlyList<FileArtifact> candidates,
        out string? targetId)
    {
        targetId = null;
        if (candidates.Count == 0)
        {
            return false;
        }

        if (candidates.Count == 1)
        {
            targetId = candidates[0].Id;
            return true;
        }

        var sameContainer = candidates
            .Where(candidate => HasSameImmediateArchiveContainer(source, candidate))
            .ToArray();
        var compareWithinContainer = sameContainer.Length > 0;
        var eligible = compareWithinContainer ? sameContainer : candidates;
        var sourcePath = RankingPath(source, compareWithinContainer);
        var ranked = eligible
            .Select(candidate => new
            {
                Candidate = candidate,
                CommonDirectoryPrefix = CommonDirectoryPrefixLength(
                    sourcePath,
                    RankingPath(candidate, compareWithinContainer))
            })
            .ToArray();
        var bestPrefix = ranked.Max(item => item.CommonDirectoryPrefix);
        var best = ranked
            .Where(item => item.CommonDirectoryPrefix == bestPrefix)
            .Select(item => item.Candidate)
            .ToArray();
        if (best.Length != 1)
        {
            return false;
        }

        targetId = best[0].Id;
        return true;
    }

    private static bool HasSameImmediateArchiveContainer(FileArtifact source, FileArtifact candidate) =>
        !string.IsNullOrWhiteSpace(source.Origin.Container) &&
        !string.IsNullOrWhiteSpace(candidate.Origin.Container) &&
        string.Equals(source.Origin.Kind, candidate.Origin.Kind, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(source.Origin.Container, candidate.Origin.Container, StringComparison.OrdinalIgnoreCase);

    private static string RankingPath(FileArtifact file, bool withinSameContainer) =>
        withinSameContainer && !string.IsNullOrWhiteSpace(file.Origin.Entry)
            ? file.Origin.Entry
            : file.RelativePath;

    private static int CommonDirectoryPrefixLength(string left, string right)
    {
        var leftSegments = DirectorySegments(left);
        var rightSegments = DirectorySegments(right);
        var commonLength = 0;
        while (commonLength < leftSegments.Length &&
               commonLength < rightSegments.Length &&
               string.Equals(leftSegments[commonLength], rightSegments[commonLength], StringComparison.OrdinalIgnoreCase))
        {
            commonLength++;
        }

        return commonLength;
    }

    private static string[] DirectorySegments(string logicalPath)
    {
        var normalized = logicalPath.Replace('\\', '/');
        var separator = normalized.LastIndexOf('/');
        return separator <= 0
            ? []
            : normalized[..separator].Split('/', StringSplitOptions.RemoveEmptyEntries);
    }

    private static void Add(
        IDictionary<string, DependencyEdge> edges,
        string source,
        string target,
        string kind,
        bool resolved)
    {
        var key = $"{source}\0{kind}\0{target}";
        edges.TryAdd(key, new DependencyEdge
        {
            Source = source,
            Target = target,
            Kind = kind,
            ResolvedInsidePackage = resolved
        });
    }
}
