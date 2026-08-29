using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class DependencyGraphBuilderTests
{
    [Fact]
    public void PrefersCandidatesFromTheSameImmediateArchiveContainer()
    {
        var source = CreateArtifact(
            "apps/app.asar/feature/bin/app.exe",
            origin: AsarOrigin("apps/app.asar", "feature/bin/app.exe", depth: 1),
            importedModules: ["native.dll"],
            managedReferences: ["Demo.Library"]);
        var sameNative = CreateArtifact(
            "apps/app.asar/shared/native.dll",
            origin: AsarOrigin("apps/app.asar", "shared/native.dll", depth: 1));
        var nestedNative = CreateArtifact(
            "apps/app.asar/feature/bin/nested.asar/native.dll",
            origin: AsarOrigin(
                "apps/app.asar/feature/bin/nested.asar",
                "native.dll",
                depth: 2));
        var sameManaged = CreateArtifact(
            "apps/app.asar/shared/Demo.Library.dll",
            assemblyName: "Demo.Library",
            origin: AsarOrigin("apps/app.asar", "shared/Demo.Library.dll", depth: 1));
        var nestedManaged = CreateArtifact(
            "apps/app.asar/feature/bin/nested.asar/Demo.Library.dll",
            assemblyName: "Demo.Library",
            origin: AsarOrigin(
                "apps/app.asar/feature/bin/nested.asar",
                "Demo.Library.dll",
                depth: 2));

        var dependencies = DependencyGraphBuilder.Build(
            [source, nestedNative, nestedManaged, sameNative, sameManaged]);

        AssertResolved(dependencies, "pe-import", sameNative.Id);
        AssertResolved(dependencies, "assembly-reference", sameManaged.Id);
    }

    [Fact]
    public void UsesLongestCommonLogicalDirectoryPrefixWhenNoContainerMatches()
    {
        var source = CreateArtifact(
            "suite/bin/tools/app.exe",
            importedModules: ["native.dll"],
            managedReferences: ["Demo.Library"]);
        var nearNative = CreateArtifact("suite/bin/tools/native.dll");
        var farNative = CreateArtifact("suite/lib/native.dll");
        var nearManaged = CreateArtifact(
            "suite/bin/tools/Demo.Library.dll",
            assemblyName: "Demo.Library");
        var farManaged = CreateArtifact(
            "suite/lib/Demo.Library.dll",
            assemblyName: "Demo.Library");

        var dependencies = DependencyGraphBuilder.Build(
            [farNative, farManaged, source, nearNative, nearManaged]);

        AssertResolved(dependencies, "pe-import", nearNative.Id);
        AssertResolved(dependencies, "assembly-reference", nearManaged.Id);
    }

    [Fact]
    public void LeavesDependenciesUnresolvedWhenTheBestCandidatesRemainTied()
    {
        var source = CreateArtifact(
            "apps/app.asar/bin/app.exe",
            origin: AsarOrigin("apps/app.asar", "bin/app.exe", depth: 1),
            importedModules: ["native.dll"],
            managedReferences: ["Demo.Library"]);
        var nativeA = CreateArtifact(
            "apps/app.asar/a/native.dll",
            origin: AsarOrigin("apps/app.asar", "a/native.dll", depth: 1));
        var nativeB = CreateArtifact(
            "apps/app.asar/b/native.dll",
            origin: AsarOrigin("apps/app.asar", "b/native.dll", depth: 1));
        var managedA = CreateArtifact(
            "apps/app.asar/a/Demo.Library.dll",
            assemblyName: "Demo.Library",
            origin: AsarOrigin("apps/app.asar", "a/Demo.Library.dll", depth: 1));
        var managedB = CreateArtifact(
            "apps/app.asar/b/Demo.Library.dll",
            assemblyName: "Demo.Library",
            origin: AsarOrigin("apps/app.asar", "b/Demo.Library.dll", depth: 1));

        var dependencies = DependencyGraphBuilder.Build(
            [managedB, nativeB, source, nativeA, managedA]);

        AssertUnresolved(dependencies, "pe-import", "native.dll");
        AssertUnresolved(dependencies, "assembly-reference", "Demo.Library");
    }

    private static void AssertResolved(
        IReadOnlyList<DependencyEdge> dependencies,
        string kind,
        string target)
    {
        var dependency = Assert.Single(dependencies, edge => edge.Kind == kind);
        Assert.True(dependency.ResolvedInsidePackage);
        Assert.Equal(target, dependency.Target);
    }

    private static void AssertUnresolved(
        IReadOnlyList<DependencyEdge> dependencies,
        string kind,
        string target)
    {
        var dependency = Assert.Single(dependencies, edge => edge.Kind == kind);
        Assert.False(dependency.ResolvedInsidePackage);
        Assert.Equal(target, dependency.Target);
    }

    private static FileOrigin AsarOrigin(string container, string entry, int depth) => new()
    {
        Kind = "asar",
        Container = container,
        Entry = entry,
        Depth = depth
    };

    private static FileArtifact CreateArtifact(
        string relativePath,
        string? assemblyName = null,
        FileOrigin? origin = null,
        IReadOnlyList<string>? importedModules = null,
        IReadOnlyList<string>? managedReferences = null) => new()
        {
            Id = relativePath,
            RelativePath = relativePath,
            FileName = Path.GetFileName(relativePath.Replace('\\', '/')),
            Size = 1,
            Sha256 = new string('0', 64),
            Category = "library",
            Format = "test fixture",
            Origin = origin ?? new FileOrigin(),
            AssemblyName = assemblyName,
            ImportedModules = importedModules ?? [],
            ManagedReferences = managedReferences ?? []
        };
}
