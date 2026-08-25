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

    public IReadOnlyList<ManagedResourceModel> Resources { get; init; } = [];
}

// .NET assembly 內嵌或連結的 manifest 資源（.resources、WPF BAML、內嵌設定檔或 DLL 等）。
public sealed record ManagedResourceModel
{
    public required string Name { get; init; }

    // "public" 代表其他組件可讀，"private" 只給自己用。
    public required string Visibility { get; init; }

    // "embedded"＝內嵌在這個檔；"file:<檔名>"＝放在套件內的另一個檔；"assembly:<名稱>"＝在別的組件。
    public required string Location { get; init; }

    // 依名稱判斷的用途，僅供參考。
    public required string Kind { get; init; }

    // 只有內嵌資源讀得到大小（位元組）。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public long? Size { get; init; }
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

    public bool IsRefLike { get; init; }

    public bool IsNested { get; init; }

    public string? DeclaringType { get; init; }

    public int InheritedGenericParameterCount { get; init; }

    public string? BaseType { get; init; }

    public IReadOnlyList<string> Interfaces { get; init; } = [];

    public IReadOnlyList<string> GenericParameters { get; init; } = [];

    public IReadOnlyList<FieldModel> Fields { get; init; } = [];

    public IReadOnlyList<PropertyModel> Properties { get; init; } = [];

    public IReadOnlyList<EventModel> Events { get; init; } = [];

    public IReadOnlyList<MethodModel> Methods { get; init; } = [];
}

public sealed record FieldModel
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsConstant { get; init; }

    public bool IsReadOnly { get; init; }

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

    public required string Accessibility { get; init; }

    public string? GetterAccessibility { get; init; }

    public string? SetterAccessibility { get; init; }

    public bool HasGetter { get; init; }

    public bool HasSetter { get; init; }

    public bool IsStatic { get; init; }

    public bool IsAbstract { get; init; }

    public bool IsVirtual { get; init; }

    public bool IsFinal { get; init; }

    public bool IsNewSlot { get; init; }
}

public sealed record EventModel
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public required string Accessibility { get; init; }

    public bool IsStatic { get; init; }

    public bool IsAbstract { get; init; }

    public bool IsVirtual { get; init; }

    public bool IsFinal { get; init; }

    public bool IsNewSlot { get; init; }
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

    public bool IsFinal { get; init; }

    public bool IsNewSlot { get; init; }

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
