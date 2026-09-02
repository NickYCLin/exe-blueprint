namespace ExeBlueprint.Models;

public sealed record BlueprintDocument
{
    public string SchemaVersion { get; init; } = "0.14";

    public DateTimeOffset GeneratedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public required InputDescriptor Input { get; init; }

    public required BlueprintSummary Summary { get; init; }

    public IReadOnlyList<FileArtifact> Files { get; init; } = [];

    public IReadOnlyList<ArchiveExpansion> Archives { get; init; } = [];

    public IReadOnlyList<DependencyEdge> Dependencies { get; init; } = [];

    public IReadOnlyList<TechnologyDetection> Technologies { get; init; } = [];

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record ArchiveExpansion
{
    public required string ContainerPath { get; init; }

    public int Depth { get; init; }

    public long HeaderBytes { get; init; }

    public int NodeCount { get; init; }

    public int PackedEntryCount { get; init; }

    public int UnpackedEntryCount { get; init; }

    public int LinkCount { get; init; }

    public bool Complete { get; init; }

    public string? Error { get; init; }
}

public sealed record InputDescriptor
{
    public required string Name { get; init; }

    public required string Kind { get; init; }

    public required string SourcePath { get; init; }

    public required int FileCount { get; init; }

    public required long TotalBytes { get; init; }
}

public sealed record BlueprintSummary
{
    public int ExecutableCount { get; init; }

    public int LibraryCount { get; init; }

    public int ManagedAssemblyCount { get; init; }

    public int NativePeCount { get; init; }

    public int ArchiveCount { get; init; }

    public int ConfigurationCount { get; init; }

    public int ResourceCount { get; init; }

    public int UnknownCount { get; init; }

    public int InternalDependencyCount { get; init; }

    public int ExternalDependencyCount { get; init; }

    public int TypeCount { get; init; }

    public int MethodCount { get; init; }
}
