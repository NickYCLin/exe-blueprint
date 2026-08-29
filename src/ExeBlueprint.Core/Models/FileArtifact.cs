namespace ExeBlueprint.Models;

public sealed record FileArtifact
{
    public required string Id { get; init; }

    public required string RelativePath { get; init; }

    public required string FileName { get; init; }

    public required long Size { get; init; }

    public required string Sha256 { get; init; }

    public required string Category { get; init; }

    public required string Format { get; init; }

    public FileOrigin Origin { get; init; } = new();

    public bool IsPortableExecutable { get; init; }

    public bool IsExecutable { get; init; }

    public bool IsLibrary { get; init; }

    public bool IsManaged { get; init; }

    public string? Architecture { get; init; }

    public string? Subsystem { get; init; }

    public string? AssemblyName { get; init; }

    public string? AssemblyVersion { get; init; }

    public string? CorFlags { get; init; }

    public bool HasAuthenticodeSignature { get; init; }

    public IReadOnlyList<string> Sections { get; init; } = [];

    public IReadOnlyList<string> ImportedModules { get; init; } = [];

    public IReadOnlyList<string> ManagedReferences { get; init; } = [];

    public IReadOnlyList<TechnologyDetection> Technologies { get; init; } = [];

    public CodeModel? Code { get; init; }

    public NativeCodeModel? NativeCode { get; init; }

    public string? AnalysisError { get; init; }
}

public sealed record FileOrigin
{
    public string Kind { get; init; } = "direct";

    public string? Container { get; init; }

    public string? Entry { get; init; }

    public int Depth { get; init; }
}

public sealed record TechnologyDetection
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Category { get; init; }

    public required double Confidence { get; init; }

    public IReadOnlyList<string> Evidence { get; init; } = [];
}

public sealed record DependencyEdge
{
    public required string Source { get; init; }

    public required string Target { get; init; }

    public required string Kind { get; init; }

    public required bool ResolvedInsidePackage { get; init; }
}
