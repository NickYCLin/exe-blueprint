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
                var resolved = filesByName.TryGetValue(module, out var targets);
                var target = resolved ? targets![0].Id : module;
                Add(edges, file.Id, target, "pe-import", resolved);
            }

            foreach (var reference in file.ManagedReferences)
            {
                var resolved = assembliesByName.TryGetValue(reference, out var targets);
                var target = resolved ? targets![0].Id : reference;
                Add(edges, file.Id, target, "assembly-reference", resolved);
            }
        }

        return edges.Values
            .OrderBy(edge => edge.Source, StringComparer.OrdinalIgnoreCase)
            .ThenBy(edge => edge.Kind, StringComparer.OrdinalIgnoreCase)
            .ThenBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase)
            .ToArray();
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
