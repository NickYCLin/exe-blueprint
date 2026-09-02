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

    // 內嵌 JSON／XML 設定檔的安全結構摘要；只保留欄位路徑，不保存設定值。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ManagedResourceConfigurationModel? Configuration { get; init; }
}

public sealed record ManagedResourceConfigurationModel
{
    // 目前支援 json 與 xml。
    public required string Format { get; init; }

    // parsed、partial 或 invalid。
    public required string Status { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RootKind { get; init; }

    // 已走訪的結構節點數；JSON 為 object 欄位，XML 為元素與屬性。partial 時是已讀上限，而非總數。
    public int PropertyCount { get; init; }

    // 只保留 key path，例如 logging.level、features[] 或 configuration/appSettings/add/@key；永不保存 value。
    public IReadOnlyList<string> PropertyPaths { get; init; } = [];

    public bool PropertyPathsTruncated { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed record ManagedResourceEntryModel
{
    public required string Name { get; init; }

    // ResourceReader 回傳的 ResourceTypeCode 或自訂型別完整名稱。
    public required string Type { get; init; }

    // decoded、binary、encoded、unsupported 或 invalid。
    public required string Status { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; init; }

    public bool ValueTruncated { get; init; }

    // binary 為內容長度；unsupported／invalid 為尚未解碼的原始資料長度。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? DataSize { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }

    // 自訂型別的預序列化 envelope；只保存輸入摘要，不載入型別或建立物件。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ManagedResourceSerializationModel? Serialization { get; init; }

    // 僅做靜態位元組摘要，不載入 WPF 型別，也不建立任何 UI 物件。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public BamlSummaryModel? Baml { get; init; }
}

public sealed record ManagedResourceSerializationModel
{
    // binary-formatter、type-converter-byte-array、type-converter-string 或 activator-stream。
    public required string Format { get; init; }

    public required int PayloadSize { get; init; }

    // text、nrbf、png、jpeg、gif、bmp、ico、zip、pe、pdf 或 binary。
    public required string PayloadKind { get; init; }

    public bool Complete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
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

    // ResourceDictionary deferred section 中可安全定位的 string/type key。
    public int DeferredResourceCount { get; init; }

    public IReadOnlyList<BamlDeferredResourceModel> DeferredResources { get; init; } = [];

    public bool DeferredResourcesTruncated { get; init; }

    public bool DeferredResourcesComplete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? DeferredResourcesError { get; init; }

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

    // record 50／56 的 local StaticResource ID 所屬 deferred resource，可與 DeferredResources.Id 對接。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? DeferredResourceId { get; init; }
}

public sealed record BamlDeferredResourceModel
{
    public required int Id { get; init; }

    // string、type 或 complex；complex key 不執行 markup extension。
    public required string KeyKind { get; init; }

    public required int KeyId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Key { get; init; }

    public required int KeyRecordOffset { get; init; }

    // 相對 deferred keys/header 結束後 values 區起點的位置。
    public required int ValuePosition { get; init; }

    public required int ValueStartOffset { get; init; }

    // Exclusive end offset；範圍表示為 [ValueStartOffset, ValueEndOffset)。
    public required int ValueEndOffset { get; init; }

    public bool Shared { get; init; }

    public bool SharedSet { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ElementId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ElementTypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ElementType { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public BamlComplexKeyModel? ComplexKey { get; init; }

    // ID 是 key-local 0-based index，供 value 內的 StaticResourceId record 對照。
    public IReadOnlyList<BamlStaticResourceModel> StaticResources { get; init; } = [];

    public bool StaticResourcesTruncated { get; init; }
}

public sealed record BamlStaticResourceModel
{
    public required int Id { get; init; }

    // optimized record 使用 string/type/property-reference；verbose record 使用 verbose。
    public required string Kind { get; init; }

    public required int StartOffset { get; init; }

    // Exclusive end offset；verbose 範圍包含 StaticResourceEnd record。
    public required int EndOffset { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ReferenceId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? TypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Type { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ValueKind { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; init; }

    public bool ValueTruncated { get; init; }

    public bool Complete { get; init; } = true;

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed record BamlComplexKeyModel
{
    public required int StartOffset { get; init; }

    // Exclusive end offset；範圍包含 KeyElementEnd record。
    public required int EndOffset { get; init; }

    public required int TypeId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Type { get; init; }

    public bool IsInjected { get; init; }

    public bool CreateUsingTypeConverter { get; init; }

    public required int ValueCount { get; init; }

    public IReadOnlyList<BamlComplexKeyValueModel> Values { get; init; } = [];

    public bool ValuesTruncated { get; init; }

    public bool Complete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed record BamlComplexKeyValueModel
{
    // constructor-parameter、content 或 property。
    public required string Role { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? PropertyId { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PropertyName { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PropertyOwnerType { get; init; }

    // literal、string-reference、type-reference、property-reference、markup-extension 或 converted。
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
}

public sealed record TypeModel
{
    // TypeDef token 只在同一個 managed artifact 內當作穩定 identity；舊 schema 可以沒有此欄位。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? TypeDefinitionToken { get; init; }

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

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? DeclaringTypeDefinitionToken { get; init; }

    public int InheritedGenericParameterCount { get; init; }

    public string? BaseType { get; init; }

    public IReadOnlyList<string> Interfaces { get; init; } = [];

    public IReadOnlyList<string> GenericParameters { get; init; } = [];

    // 保留 GenericParameters 的相容名稱陣列，另以 additive 明細保存 metadata flags 與 constraints。
    public IReadOnlyList<GenericParameterModel> GenericParameterDetails { get; init; } = [];

    public bool GenericParametersComplete { get; init; } = true;

    // 只證明 owner 的 raw arity、row owner、position/name 與 inherited prefix 完整；
    // 不代表每個 constraint 都能表示。舊 blueprint 缺少此欄位時維持 false，避免猜測 domain。
    public bool GenericParameterDomainComplete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? GenericParametersError { get; init; }

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

public sealed record ConstructorInitializerModel
{
    // base 或 this；產生器只接受這兩個白名單值。
    public required string Kind { get; init; }

    public IReadOnlyList<string> Arguments { get; init; } = [];
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

    public IReadOnlyList<GenericParameterModel> GenericParameterDetails { get; init; } = [];

    public bool GenericParametersComplete { get; init; } = true;

    // 與 type owner 相同，只保存 generic parameter declaration domain 的獨立證據。
    public bool GenericParameterDomainComplete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? GenericParametersError { get; init; }

    public IReadOnlyList<ParameterModel> Parameters { get; init; } = [];

    public IReadOnlyList<string> Il { get; init; } = [];

    public bool IlTruncated { get; init; }

    public IReadOnlyList<string> Body { get; init; } = [];

    public bool BodyReconstructed { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ConstructorInitializerModel? ConstructorInitializer { get; init; }

    // 成功還原的 body 使用 pointer／function pointer local、field 或 call signature 時才會設定。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool RequiresUnsafeContext { get; init; }
}

public sealed record GenericParameterModel
{
    public int Position { get; init; }

    public required string Name { get; init; }

    public int RawAttributes { get; init; }

    // none、out、in 或 invalid。
    public required string Variance { get; init; }

    public bool ReferenceTypeConstraint { get; init; }

    public bool NotNullableValueTypeConstraint { get; init; }

    // Roslyn 以 generic parameter 上的直接 NullableAttribute(1) 表示 notnull；context fallback 不算。
    public bool NotNullConstraint { get; init; }

    public bool DefaultConstructorConstraint { get; init; }

    public bool AllowsRefStruct { get; init; }

    // oblivious、not-annotated、annotated 或 invalid。
    public required string Nullability { get; init; }

    // 保留 NullableAttribute 的完整 flags；context fallback 為單一 flag。
    public IReadOnlyList<byte> NullableFlags { get; init; } = [];

    public bool HasUnmanagedAttribute { get; init; }

    public IReadOnlyList<GenericTypeConstraintModel> TypeConstraints { get; init; } = [];

    // null 代表 primary constraint 無法獨立證明；目前 reader 只輸出 none 或 struct。
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ProvenPrimaryConstraintKind { get; init; }

    public bool Complete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
}

public sealed record GenericTypeConstraintModel
{
    public required string Type { get; init; }

    // class、interface、type-parameter、value-type-marker、unknown 或 unsupported。
    public required string Kind { get; init; }

    public required string Nullability { get; init; }

    public IReadOnlyList<byte> NullableFlags { get; init; } = [];

    public IReadOnlyList<string> RequiredModifiers { get; init; } = [];

    public IReadOnlyList<string> OptionalModifiers { get; init; } = [];

    public bool Complete { get; init; }

    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }
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
