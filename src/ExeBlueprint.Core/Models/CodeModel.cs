namespace ExeBlueprint.Models;

public sealed record CodeModel
{
    public required string Kind { get; init; }

    public string? EntryPointMethod { get; init; }

    public int NamespaceCount { get; init; }

    public int TypeCount { get; init; }

    public int MethodCount { get; init; }

    public int CallEdgeCount { get; init; }

    public bool Truncated { get; init; }

    public IReadOnlyList<TypeModel> Types { get; init; } = [];

    public IReadOnlyList<CallEdge> CallGraph { get; init; } = [];
}

public sealed record TypeModel
{
    public required string FullName { get; init; }

    public required string Namespace { get; init; }

    public required string Name { get; init; }

    public required string Kind { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsAbstract { get; init; }

    public bool IsSealed { get; init; }

    public bool IsNested { get; init; }

    public string? BaseType { get; init; }

    public IReadOnlyList<string> Interfaces { get; init; } = [];

    public IReadOnlyList<string> GenericParameters { get; init; } = [];

    public IReadOnlyList<FieldModel> Fields { get; init; } = [];

    public IReadOnlyList<PropertyModel> Properties { get; init; } = [];

    public IReadOnlyList<MethodModel> Methods { get; init; } = [];
}

public sealed record FieldModel
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsConstant { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ConstantValueModel? ConstantValue { get; init; }
}

public sealed record ConstantValueModel
{
    public required string Type { get; init; }

    public string? Value { get; init; }
}

public sealed record PropertyModel
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public bool HasGetter { get; init; }

    public bool HasSetter { get; init; }
}

public sealed record MethodModel
{
    public required string Name { get; init; }

    public required string Signature { get; init; }

    public required string ReturnType { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsAbstract { get; init; }

    public bool IsVirtual { get; init; }

    public bool IsConstructor { get; init; }

    public bool IsEntryPoint { get; init; }

    public bool HasBody { get; init; }

    public IReadOnlyList<string> GenericParameters { get; init; } = [];

    public IReadOnlyList<ParameterModel> Parameters { get; init; } = [];

    public IReadOnlyList<string> Il { get; init; } = [];

    public bool IlTruncated { get; init; }

    public IReadOnlyList<string> Body { get; init; } = [];

    public bool BodyReconstructed { get; init; }
}

public sealed record ParameterModel
{
    public required string Name { get; init; }

    public required string Type { get; init; }
}

public sealed record CallEdge
{
    public required string Caller { get; init; }

    public required string Callee { get; init; }

    public required string Kind { get; init; }
}
