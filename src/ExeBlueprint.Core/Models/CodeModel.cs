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

    // .resources 資源表內安全讀出的鍵值；其他 manifest resource 保持空集合。
    public IReadOnlyList<ManagedResourceEntryModel> Entries { get; init; } = [];

    // 達到單一 assembly 的鍵值數量上限時為 true。
    public bool EntriesTruncated { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? EntriesError { get; init; }
}

public sealed record ManagedResourceEntryModel
{
    public required string Name { get; init; }

    // ResourceReader 回傳的 ResourceTypeCode 或自訂型別完整名稱。
    public required string Type { get; init; }

    // decoded、binary、unsupported 或 invalid。
    public required string Status { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; init; }

    public bool ValueTruncated { get; init; }

    // binary 為內容長度；unsupported／invalid 為尚未解碼的原始資料長度。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? DataSize { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }

    // 僅做靜態位元組摘要，不載入 WPF 型別，也不建立任何 UI 物件。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public BamlSummaryModel? Baml { get; init; }
}

public sealed record BamlSummaryModel
{
    // parsed、partial 或 invalid。
    public required string Status { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Signature { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ReaderVersion { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? UpdaterVersion { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? WriterVersion { get; init; }

    public int RecordCount { get; init; }

    public IReadOnlyList<BamlRecordCountModel> RecordTypes { get; init; } = [];

    public int ElementCount { get; init; }

    public int PropertyCount { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? RootElementTypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RootElementType { get; init; }

    public IReadOnlyList<BamlTypeUsageModel> ElementTypes { get; init; } = [];

    // 以 flat node + parent ID 表示，避免深層 BAML 造成遞迴序列化風險。
    public IReadOnlyList<BamlElementModel> Elements { get; init; } = [];

    public bool ElementsTruncated { get; init; }

    public bool ElementTreeComplete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ElementTreeError { get; init; }

    public IReadOnlyList<BamlPropertyUsageModel> Properties { get; init; } = [];

    // 具有可安全摘要之 inline value 或 reference 的 property record 總數。
    public int PropertyValueCount { get; init; }

    public IReadOnlyList<BamlPropertyValueModel> PropertyValues { get; init; } = [];

    public bool PropertyValuesTruncated { get; init; }

    public bool RecordsTruncated { get; init; }

    public bool SymbolsTruncated { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed record BamlRecordCountModel
{
    public required int Code { get; init; }

    public required string Name { get; init; }

    public required int Count { get; init; }
}

public sealed record BamlTypeUsageModel
{
    public required int Id { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Assembly { get; init; }

    public required int Count { get; init; }
}

public sealed record BamlElementModel
{
    public required int Id { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ParentId { get; init; }

    public required int Depth { get; init; }

    public required int StartOffset { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? EndOffset { get; init; }

    public required int TypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Type { get; init; }

    public bool IsInjected { get; init; }

    public bool CreateUsingTypeConverter { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ParentPropertyId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ParentPropertyName { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ParentPropertyOwnerType { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ContentPropertyId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ContentPropertyName { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ContentPropertyOwnerType { get; init; }

    public int ChildCount { get; init; }

    public int PropertyValueCount { get; init; }
}

public sealed record BamlPropertyUsageModel
{
    public required int Id { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? OwnerType { get; init; }

    public required int Count { get; init; }
}

public sealed record BamlPropertyValueModel
{
    public required int PropertyId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PropertyName { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PropertyOwnerType { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ElementTypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ElementId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ElementType { get; init; }

    // literal、string-reference、type-reference、markup-extension、converted、custom-binary 或 static-resource。
    public required string Kind { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; init; }

    public bool ValueTruncated { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ReferenceId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? RelatedTypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RelatedType { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? DataSize { get; init; }
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

    // 非空時代表 metadata property signature 的 index parameters。
    public IReadOnlyList<ParameterModel> Parameters { get; init; } = [];

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
