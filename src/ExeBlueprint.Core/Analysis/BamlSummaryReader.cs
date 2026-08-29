using System.Buffers.Binary;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 只讀 BAML 位元組與安全的字串／ID reference，不載入 WPF assembly，也不執行 converter 或 serializer。
internal static class BamlSummaryReader
{
    private const int HeaderSize = 28;
    private const int MaxRecords = 100_000;
    private const int MaxSymbols = 2_000;
    private const int MaxElements = 2_000;
    private const int MaxMetadataStringBytes = 8_192;
    private const int MaxPropertyValues = 2_000;
    private const int MaxPropertyValueBytes = 16_384;
    private const int MaxPropertyValueChars = 4_096;
    private const int VariableRecord = -1;
    private const int UnsupportedRecord = -2;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private static readonly string[] RecordTypeNames =
    [
        "Unknown",
        "DocumentStart",
        "DocumentEnd",
        "ElementStart",
        "ElementEnd",
        "Property",
        "PropertyCustom",
        "PropertyComplexStart",
        "PropertyComplexEnd",
        "PropertyArrayStart",
        "PropertyArrayEnd",
        "PropertyIListStart",
        "PropertyIListEnd",
        "PropertyIDictionaryStart",
        "PropertyIDictionaryEnd",
        "LiteralContent",
        "Text",
        "TextWithConverter",
        "RoutedEvent",
        "ClrEvent",
        "XmlnsProperty",
        "XmlAttribute",
        "ProcessingInstruction",
        "Comment",
        "DefTag",
        "DefAttribute",
        "EndAttributes",
        "PIMapping",
        "AssemblyInfo",
        "TypeInfo",
        "TypeSerializerInfo",
        "AttributeInfo",
        "StringInfo",
        "PropertyStringReference",
        "PropertyTypeReference",
        "PropertyWithExtension",
        "PropertyWithConverter",
        "DeferableContentStart",
        "DefAttributeKeyString",
        "DefAttributeKeyType",
        "KeyElementStart",
        "KeyElementEnd",
        "ConstructorParametersStart",
        "ConstructorParametersEnd",
        "ConstructorParameterType",
        "ConnectionId",
        "ContentProperty",
        "NamedElementStart",
        "StaticResourceStart",
        "StaticResourceEnd",
        "StaticResourceId",
        "TextWithId",
        "PresentationOptionsAttribute",
        "LineNumberAndPosition",
        "LinePosition",
        "OptimizedStaticResource",
        "PropertyWithStaticResourceId"
    ];

    public static BamlSummaryModel Read(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
        {
            return Invalid("BAML 資料不足 28 bytes，無法讀取完整檔頭。");
        }

        var signatureByteLength = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (signatureByteLength != 12)
        {
            return Invalid("BAML 簽章長度不正確。");
        }

        var signature = Encoding.Unicode.GetString(data.Slice(sizeof(int), signatureByteLength));
        if (!string.Equals(signature, "MSBAML", StringComparison.Ordinal))
        {
            return Invalid("找不到 MSBAML 簽章。", signature);
        }

        var readerVersion = ReadVersion(data, 16);
        var updaterVersion = ReadVersion(data, 20);
        var writerVersion = ReadVersion(data, 24);
        if (readerVersion != "0.96")
        {
            return Partial(
                signature,
                readerVersion,
                updaterVersion,
                writerVersion,
                new Dictionary<byte, int>(),
                false,
                $"尚未支援 BAML reader version {readerVersion} 的 record 格式。");
        }

        var position = HeaderSize;
        var recordCounts = new Dictionary<byte, int>();
        var symbols = new SymbolTable();
        while (position < data.Length && recordCounts.Values.Sum() < MaxRecords)
        {
            var recordOffset = position;
            var recordType = data[position++];
            var payloadSize = GetRecordPayloadSize(recordType);
            if (payloadSize == UnsupportedRecord)
            {
                return Partial(
                    signature,
                    readerVersion,
                    updaterVersion,
                    writerVersion,
                    recordCounts,
                    false,
                    $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度規則不受支援，停止於 offset {recordOffset}。",
                    symbols);
            }

            if (payloadSize == VariableRecord)
            {
                var sizeFieldOffset = position;
                if (!TryRead7BitEncodedInt(data, ref position, out var recordSize))
                {
                    return Partial(
                        signature,
                        readerVersion,
                        updaterVersion,
                        writerVersion,
                        recordCounts,
                        false,
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度欄位已截斷。",
                        symbols);
                }

                var sizeFieldLength = position - sizeFieldOffset;
                var nextPosition = (long)sizeFieldOffset + recordSize;
                if (recordSize < sizeFieldLength || nextPosition > data.Length)
                {
                    return Partial(
                        signature,
                        readerVersion,
                        updaterVersion,
                        writerVersion,
                        recordCounts,
                        false,
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度超出資料範圍。",
                        symbols);
                }

                if (!symbols.TryReadRecord(recordType, recordOffset, data[position..(int)nextPosition], out var symbolError))
                {
                    return Partial(
                        signature,
                        readerVersion,
                        updaterVersion,
                        writerVersion,
                        recordCounts,
                        false,
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的型別／屬性資料無效：{symbolError}",
                        symbols);
                }

                position = (int)nextPosition;
            }
            else
            {
                if (payloadSize > data.Length - position)
                {
                    return Partial(
                        signature,
                        readerVersion,
                        updaterVersion,
                        writerVersion,
                        recordCounts,
                        false,
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的內容已截斷。",
                        symbols);
                }

                var nextPosition = position + payloadSize;
                if (!symbols.TryReadRecord(recordType, recordOffset, data[position..nextPosition], out var symbolError))
                {
                    return Partial(
                        signature,
                        readerVersion,
                        updaterVersion,
                        writerVersion,
                        recordCounts,
                        false,
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的型別／屬性資料無效：{symbolError}",
                        symbols);
                }

                position = nextPosition;
            }

            recordCounts[recordType] = recordCounts.GetValueOrDefault(recordType) + 1;
        }

        var truncated = position < data.Length;
        return new BamlSummaryModel
        {
            Status = truncated ? "partial" : "parsed",
            Signature = signature,
            ReaderVersion = readerVersion,
            UpdaterVersion = updaterVersion,
            WriterVersion = writerVersion,
            RecordCount = recordCounts.Values.Sum(),
            RecordTypes = BuildRecordCounts(recordCounts),
            ElementCount = symbols.ElementCount,
            PropertyCount = symbols.PropertyCount,
            RootElementTypeId = symbols.RootElementTypeId,
            RootElementType = symbols.ResolveRootElementType(),
            ElementTypes = symbols.BuildElementTypes(),
            Elements = symbols.BuildElements(),
            ElementsTruncated = symbols.ElementsTruncated,
            ElementTreeComplete = !truncated && symbols.ElementTreeComplete,
            ElementTreeError = symbols.ElementTreeError
                ?? (truncated ? "BAML record 達解析上限，element tree 可能不完整。" : null),
            Properties = symbols.BuildProperties(),
            PropertyValueCount = symbols.PropertyValueCount,
            PropertyValues = symbols.BuildPropertyValues(),
            PropertyValuesTruncated = symbols.PropertyValuesTruncated,
            RecordsTruncated = truncated,
            SymbolsTruncated = symbols.Truncated,
            Error = truncated ? $"BAML record 超過 {MaxRecords:N0} 筆安全解析上限。" : null
        };
    }

    private static string ReadVersion(ReadOnlySpan<byte> data, int offset)
    {
        var major = BinaryPrimitives.ReadInt16LittleEndian(data[offset..]);
        var minor = BinaryPrimitives.ReadInt16LittleEndian(data[(offset + sizeof(short))..]);
        return $"{major}.{minor}";
    }

    private static bool TryRead7BitEncodedInt(ReadOnlySpan<byte> data, ref int position, out int value)
    {
        value = 0;
        for (var index = 0; index < 5; index++)
        {
            if (position >= data.Length)
            {
                return false;
            }

            var current = data[position++];
            if (index == 4 && (current & 0xF0) != 0)
            {
                return false;
            }

            value |= (current & 0x7F) << (index * 7);
            if ((current & 0x80) == 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int GetRecordPayloadSize(byte recordType) => recordType switch
    {
        5 or 6 or 15 or 16 or 17 or 18 or 20 or 25 or 27 or 28 or 29 or 30 or 31 or 32 or 36 or 38 or 51 or 52
            => VariableRecord,
        1 => 6,
        2 or 4 or 8 or 10 or 12 or 14 or 41 or 42 or 43 or 49 => 0,
        3 or 48 or 55 => 3,
        7 or 9 or 11 or 13 or 44 or 46 or 50 => 2,
        33 or 34 or 37 or 45 or 54 or 56 => 4,
        35 => 6,
        39 or 40 => 9,
        53 => 8,
        _ => UnsupportedRecord
    };

    private static string GetRecordName(byte code) =>
        code < RecordTypeNames.Length ? RecordTypeNames[code] : "Unknown";

    private static IReadOnlyList<BamlRecordCountModel> BuildRecordCounts(IReadOnlyDictionary<byte, int> counts) =>
        counts
            .OrderBy(pair => pair.Key)
            .Select(pair => new BamlRecordCountModel
            {
                Code = pair.Key,
                Name = GetRecordName(pair.Key),
                Count = pair.Value
            })
            .ToArray();

    private static BamlSummaryModel Partial(
        string signature,
        string readerVersion,
        string updaterVersion,
        string writerVersion,
        IReadOnlyDictionary<byte, int> recordCounts,
        bool recordsTruncated,
        string error,
        SymbolTable? symbols = null) =>
        new()
        {
            Status = "partial",
            Signature = signature,
            ReaderVersion = readerVersion,
            UpdaterVersion = updaterVersion,
            WriterVersion = writerVersion,
            RecordCount = recordCounts.Values.Sum(),
            RecordTypes = BuildRecordCounts(recordCounts),
            ElementCount = symbols?.ElementCount ?? 0,
            PropertyCount = symbols?.PropertyCount ?? 0,
            RootElementTypeId = symbols?.RootElementTypeId,
            RootElementType = symbols?.ResolveRootElementType(),
            ElementTypes = symbols?.BuildElementTypes() ?? [],
            Elements = symbols?.BuildElements() ?? [],
            ElementsTruncated = symbols?.ElementsTruncated ?? false,
            ElementTreeComplete = false,
            ElementTreeError = symbols?.ElementTreeError ?? error,
            Properties = symbols?.BuildProperties() ?? [],
            PropertyValueCount = symbols?.PropertyValueCount ?? 0,
            PropertyValues = symbols?.BuildPropertyValues() ?? [],
            PropertyValuesTruncated = symbols?.PropertyValuesTruncated ?? false,
            RecordsTruncated = recordsTruncated,
            SymbolsTruncated = symbols?.Truncated ?? false,
            Error = error
        };

    private static BamlSummaryModel Invalid(string error, string? signature = null) =>
        new()
        {
            Status = "invalid",
            Signature = signature,
            Error = error
        };

    private static bool TryReadInt16(ReadOnlySpan<byte> data, ref int position, out short value)
    {
        if (position > data.Length - sizeof(short))
        {
            value = default;
            return false;
        }

        value = BinaryPrimitives.ReadInt16LittleEndian(data[position..]);
        position += sizeof(short);
        return true;
    }

    private static bool TryReadString(ReadOnlySpan<byte> data, ref int position, out string value)
    {
        value = string.Empty;
        if (!TryRead7BitEncodedInt(data, ref position, out var byteLength)
            || byteLength < 0
            || byteLength > MaxMetadataStringBytes
            || byteLength > data.Length - position)
        {
            return false;
        }

        try
        {
            value = StrictUtf8.GetString(data.Slice(position, byteLength));
            position += byteLength;
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryReadPropertyValueString(
        ReadOnlySpan<byte> data,
        ref int position,
        out string value,
        out bool truncated)
    {
        value = string.Empty;
        truncated = false;
        if (!TryRead7BitEncodedInt(data, ref position, out var byteLength)
            || byteLength < 0
            || byteLength > data.Length - position)
        {
            return false;
        }

        var bytesToDecode = Math.Min(byteLength, MaxPropertyValueBytes);
        var minimumBytes = bytesToDecode == byteLength
            ? bytesToDecode
            : Math.Max(0, bytesToDecode - 3);
        var decoded = false;
        for (var candidateLength = bytesToDecode; candidateLength >= minimumBytes; candidateLength--)
        {
            try
            {
                value = StrictUtf8.GetString(data.Slice(position, candidateLength));
                bytesToDecode = candidateLength;
                decoded = true;
                break;
            }
            catch (DecoderFallbackException)
            {
                if (bytesToDecode == byteLength)
                {
                    return false;
                }

                // 截斷點可能落在 UTF-8 字元中間，最多向前退三個 byte 找完整邊界。
            }
        }

        if (!decoded)
        {
            return false;
        }

        position += byteLength;
        truncated = bytesToDecode < byteLength;
        if (value.Length > MaxPropertyValueChars)
        {
            var outputLength = MaxPropertyValueChars;
            if (char.IsHighSurrogate(value[outputLength - 1]))
            {
                outputLength--;
            }

            value = value[..outputLength];
            truncated = true;
        }

        return true;
    }

    private sealed class SymbolTable
    {
        private readonly Dictionary<short, string> _assemblies = [];
        private readonly Dictionary<short, TypeDeclaration> _types = [];
        private readonly Dictionary<short, AttributeDeclaration> _attributes = [];
        private readonly Dictionary<short, BoundedText> _strings = [];
        private readonly Dictionary<short, int> _elementTypes = [];
        private readonly Dictionary<short, int> _properties = [];
        private readonly List<ElementData> _elements = [];
        private readonly List<PropertyValueData> _propertyValues = [];
        private readonly Stack<ElementContext> _elementStack = [];
        private readonly Stack<PropertyScope> _propertyScopes = [];
        private string? _elementTreeError;

        public int ElementCount { get; private set; }

        public int PropertyCount { get; private set; }

        public int PropertyValueCount { get; private set; }

        public short? RootElementTypeId { get; private set; }

        public bool Truncated { get; private set; }

        public bool ElementsTruncated { get; private set; }

        public bool ElementTreeComplete =>
            !ElementsTruncated
            && _elementStack.Count == 0
            && _propertyScopes.Count == 0
            && _elementTreeError is null;

        public string? ElementTreeError =>
            _elementTreeError
            ?? (ElementsTruncated ? $"BAML element 超過 {MaxElements:N0} 個安全解析上限。" : null)
            ?? (_elementStack.Count > 0 ? $"BAML 結束時仍有 {_elementStack.Count} 個 element 未關閉。" : null)
            ?? (_propertyScopes.Count > 0 ? $"BAML 結束時仍有 {_propertyScopes.Count} 個 property scope 未關閉。" : null);

        public bool PropertyValuesTruncated { get; private set; }

        public bool TryReadRecord(
            byte recordType,
            int recordOffset,
            ReadOnlySpan<byte> payload,
            out string? error)
        {
            error = null;
            return recordType switch
            {
                3 => TryReadElement(payload, recordOffset, out error),
                4 => TryReadElementEnd(recordOffset, out error),
                28 => TryReadAssembly(payload, out error),
                29 => TryReadType(payload, hasSerializer: false, out error),
                30 => TryReadType(payload, hasSerializer: true, out error),
                31 => TryReadAttribute(payload, out error),
                32 => TryReadStringInfo(payload, out error),
                5 => TryReadLiteralProperty(payload, out error),
                6 => TryReadCustomProperty(payload, out error),
                33 => TryReadReferencedProperty(payload, "string-reference", ReferenceKind.String, out error),
                34 => TryReadReferencedProperty(payload, "type-reference", ReferenceKind.Type, out error),
                35 => TryReadMarkupExtensionProperty(payload, out error),
                36 => TryReadConvertedProperty(payload, out error),
                56 => TryReadReferencedProperty(payload, "static-resource", ReferenceKind.StaticResource, out error),
                7 or 9 or 11 or 13 => TryReadPropertyScopeStart(recordType, payload, out error),
                8 or 10 or 12 or 14 => TryReadPropertyScopeEnd(recordType, out error),
                46 => TryReadContentProperty(payload, out error),
                18 => TryReadProperty(payload, out error),
                _ => true
            };
        }

        public string? ResolveRootElementType() =>
            RootElementTypeId is { } id ? ResolveTypeName(id) : null;

        public IReadOnlyList<BamlTypeUsageModel> BuildElementTypes() =>
            _elementTypes
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key)
                .Select(pair =>
                {
                    TypeDeclaration? declaration = null;
                    if (pair.Key >= 0)
                    {
                        _types.TryGetValue(pair.Key, out declaration);
                    }

                    return new BamlTypeUsageModel
                    {
                        Id = pair.Key,
                        Name = ResolveTypeName(pair.Key),
                        Assembly = declaration is { } type
                            && _assemblies.TryGetValue(type.AssemblyId, out var assembly)
                                ? assembly
                                : null,
                        Count = pair.Value
                    };
                })
                .ToArray();

        public IReadOnlyList<BamlElementModel> BuildElements() =>
            _elements
                .Select(element =>
                {
                    var (parentPropertyName, parentPropertyOwnerType) = element.ParentPropertyId is { } parentPropertyId
                        ? ResolveProperty(parentPropertyId)
                        : (null, null);
                    var (contentPropertyName, contentPropertyOwnerType) = element.ContentPropertyId is { } contentPropertyId
                        ? ResolveProperty(contentPropertyId)
                        : (null, null);
                    return new BamlElementModel
                    {
                        Id = element.Id,
                        ParentId = element.ParentId,
                        Depth = element.Depth,
                        StartOffset = element.StartOffset,
                        EndOffset = element.EndOffset,
                        TypeId = element.TypeId,
                        Type = ResolveTypeName(element.TypeId),
                        IsInjected = element.IsInjected,
                        CreateUsingTypeConverter = element.CreateUsingTypeConverter,
                        ParentPropertyId = element.ParentPropertyId,
                        ParentPropertyName = parentPropertyName,
                        ParentPropertyOwnerType = parentPropertyOwnerType,
                        ContentPropertyId = element.ContentPropertyId,
                        ContentPropertyName = contentPropertyName,
                        ContentPropertyOwnerType = contentPropertyOwnerType,
                        ChildCount = element.ChildCount,
                        PropertyValueCount = element.PropertyValueCount
                    };
                })
                .ToArray();

        public IReadOnlyList<BamlPropertyUsageModel> BuildProperties() =>
            _properties
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key)
                .Select(pair =>
                {
                    AttributeDeclaration? declaration = null;
                    if (pair.Key >= 0)
                    {
                        _attributes.TryGetValue(pair.Key, out declaration);
                    }

                    var name = declaration?.Name;
                    var ownerType = declaration is { } attribute
                        ? ResolveTypeName(attribute.OwnerTypeId)
                        : null;
                    if (declaration is null
                        && WpfBamlKnownIds.TryGetProperty(pair.Key, out var knownOwnerType, out var knownName))
                    {
                        name = knownName;
                        ownerType = knownOwnerType;
                    }

                    return new BamlPropertyUsageModel
                    {
                        Id = pair.Key,
                        Name = name,
                        OwnerType = ownerType,
                        Count = pair.Value
                    };
                })
                .ToArray();

        public IReadOnlyList<BamlPropertyValueModel> BuildPropertyValues() =>
            _propertyValues
                .Select(value =>
                {
                    var (propertyName, propertyOwnerType) = ResolveProperty(value.PropertyId);
                    return new BamlPropertyValueModel
                    {
                        PropertyId = value.PropertyId,
                        PropertyName = propertyName,
                        PropertyOwnerType = propertyOwnerType,
                        ElementTypeId = value.ElementTypeId,
                        ElementId = value.ElementId,
                        ElementType = value.ElementTypeId is { } elementTypeId
                            ? ResolveTypeName(elementTypeId)
                            : null,
                        Kind = value.Kind,
                        Value = value.Value ?? ResolveReference(value),
                        ValueTruncated = value.ValueTruncated || IsReferencedStringTruncated(value),
                        ReferenceId = value.ReferenceId,
                        RelatedTypeId = value.RelatedTypeId,
                        RelatedType = ResolveRelatedType(value),
                        DataSize = value.DataSize
                    };
                })
                .ToArray();

        private bool IsReferencedStringTruncated(PropertyValueData value)
        {
            if (value.ReferenceId is not { } referenceId)
            {
                return false;
            }

            if (value.ReferenceKind == ReferenceKind.String)
            {
                return _strings.TryGetValue(referenceId, out var text) && text.Truncated;
            }

            if (value.ReferenceKind != ReferenceKind.ExtensionArgument)
            {
                return false;
            }

            var extensionType = ResolveRelatedType(value);
            return extensionType is not ("TypeExtension" or "StaticExtension" or "TemplateBindingExtension")
                && _strings.TryGetValue(referenceId, out var extensionText)
                && extensionText.Truncated;
        }

        private string? ResolveTypeName(short id) =>
            id < 0
                ? WpfBamlKnownIds.GetTypeName(id)
                : _types.TryGetValue(id, out var declaration)
                    ? declaration.Name
                    : null;

        private (string? Name, string? OwnerType) ResolveProperty(short id)
        {
            if (id >= 0 && _attributes.TryGetValue(id, out var declaration))
            {
                return (declaration.Name, ResolveTypeName(declaration.OwnerTypeId));
            }

            return WpfBamlKnownIds.TryGetProperty(id, out var ownerType, out var name)
                ? (name, ownerType)
                : (null, null);
        }

        private string? ResolveReference(PropertyValueData value)
        {
            if (value.ReferenceId is not { } referenceId)
            {
                return null;
            }

            return value.ReferenceKind switch
            {
                ReferenceKind.String => _strings.TryGetValue(referenceId, out var text) ? text.Value : null,
                ReferenceKind.Type => ResolveTypeName(referenceId),
                ReferenceKind.Property => FormatPropertyReference(referenceId),
                ReferenceKind.ExtensionArgument => ResolveExtensionArgument(value, referenceId),
                _ => null
            };
        }

        private string? ResolveRelatedType(PropertyValueData value)
        {
            if (value.RelatedTypeId is not { } relatedTypeId)
            {
                return null;
            }

            return value.RelatedTypeIsKnownElementId && relatedTypeId > 0
                ? WpfBamlKnownIds.GetTypeName((short)-relatedTypeId)
                : ResolveTypeName(relatedTypeId);
        }

        private string? ResolveExtensionArgument(PropertyValueData value, short referenceId)
        {
            var extensionType = ResolveRelatedType(value);
            if (extensionType == "TypeExtension")
            {
                return ResolveTypeName(referenceId);
            }

            if (extensionType is "StaticExtension" or "TemplateBindingExtension")
            {
                return FormatPropertyReference(referenceId);
            }

            if (_strings.TryGetValue(referenceId, out var text))
            {
                return text.Value;
            }

            return ResolveTypeName(referenceId) ?? FormatPropertyReference(referenceId);
        }

        private string? FormatPropertyReference(short id)
        {
            var (name, ownerType) = ResolveProperty(id);
            if (name is null)
            {
                return null;
            }

            return ownerType is null ? name : $"{ownerType}.{name}";
        }

        private bool TryReadAssembly(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var id)
                || !TryReadString(payload, ref position, out var name))
            {
                error = "assembly 對照表已截斷或字串格式錯誤。";
                return false;
            }

            AddDeclaration(_assemblies, id, name);
            error = null;
            return true;
        }

        private bool TryReadType(ReadOnlySpan<byte> payload, bool hasSerializer, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var id)
                || !TryReadInt16(payload, ref position, out var assemblyAndFlags)
                || !TryReadString(payload, ref position, out var name)
                || (hasSerializer && !TryReadInt16(payload, ref position, out _)))
            {
                error = "type 對照表已截斷或字串格式錯誤。";
                return false;
            }

            var assemblyId = (short)(assemblyAndFlags & 0x0FFF);
            AddDeclaration(_types, id, new TypeDeclaration(name, assemblyId));
            error = null;
            return true;
        }

        private bool TryReadAttribute(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var id)
                || !TryReadInt16(payload, ref position, out var ownerTypeId)
                || position >= payload.Length)
            {
                error = "attribute 對照表已截斷。";
                return false;
            }

            position++;
            if (!TryReadString(payload, ref position, out var name))
            {
                error = "attribute 對照表的名稱格式錯誤。";
                return false;
            }

            AddDeclaration(_attributes, id, new AttributeDeclaration(name, ownerTypeId));
            error = null;
            return true;
        }

        private bool TryReadStringInfo(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var id)
                || !TryReadPropertyValueString(payload, ref position, out var value, out var truncated))
            {
                error = "string 對照表已截斷或字串格式錯誤。";
                return false;
            }

            AddDeclaration(_strings, id, new BoundedText(value, truncated));
            error = null;
            return true;
        }

        private bool TryReadElement(ReadOnlySpan<byte> payload, int recordOffset, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var typeId) || position >= payload.Length)
            {
                error = "element type ID 或 flags 已截斷。";
                return false;
            }

            var flags = payload[position];
            var parent = _elementStack.TryPeek(out var parentContext) ? parentContext : null;
            short? parentPropertyId = null;
            if (parent is not null)
            {
                parentPropertyId = _propertyScopes.TryPeek(out var propertyScope)
                    && propertyScope.ElementId == parent.Id
                        ? propertyScope.PropertyId
                        : parent.ContentPropertyId;
            }

            var elementId = ElementCount;
            ElementData? element = null;
            if (_elements.Count < MaxElements)
            {
                element = new ElementData(
                    elementId,
                    parent?.Id,
                    _elementStack.Count,
                    recordOffset,
                    typeId,
                    parentPropertyId,
                    (flags & 2) != 0,
                    (flags & 1) != 0);
                _elements.Add(element);
            }
            else
            {
                ElementsTruncated = true;
            }

            parent?.Data?.IncrementChildCount();
            RootElementTypeId ??= typeId;
            ElementCount++;
            AddUsage(_elementTypes, typeId);
            _elementStack.Push(new ElementContext(elementId, typeId, element));
            error = null;
            return true;
        }

        private bool TryReadElementEnd(int recordOffset, out string? error)
        {
            if (!_elementStack.TryPop(out var elementContext))
            {
                SetElementTreeError($"offset {recordOffset} 出現沒有對應 start 的 ElementEnd。 ");
                error = null;
                return true;
            }

            if (_propertyScopes.TryPeek(out var propertyScope)
                && propertyScope.ElementId == elementContext.Id)
            {
                SetElementTreeError($"element {elementContext.Id} 結束時仍有 property scope 未關閉。");
                while (_propertyScopes.TryPeek(out propertyScope)
                       && propertyScope.ElementId == elementContext.Id)
                {
                    _propertyScopes.Pop();
                }
            }

            elementContext.Data?.SetEndOffset(recordOffset);
            error = null;
            return true;
        }

        private bool TryReadPropertyScopeStart(
            byte recordType,
            ReadOnlySpan<byte> payload,
            out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId))
            {
                error = "property scope attribute ID 已截斷。";
                return false;
            }

            PropertyCount++;
            AddUsage(_properties, attributeId);
            var elementId = CurrentElementId;
            if (elementId is null)
            {
                SetElementTreeError("element 外出現 property scope start。");
            }

            _propertyScopes.Push(new PropertyScope(elementId, attributeId, recordType));
            error = null;
            return true;
        }

        private bool TryReadPropertyScopeEnd(byte recordType, out string? error)
        {
            if (!_propertyScopes.TryPeek(out var scope))
            {
                SetElementTreeError("出現沒有對應 start 的 property scope end。");
            }
            else if (scope.ElementId != CurrentElementId)
            {
                SetElementTreeError(
                    $"element {CurrentElementId?.ToString() ?? "-"} 出現屬於 element {scope.ElementId?.ToString() ?? "-"} 的 property scope end。");
            }
            else if (scope.StartRecordType != recordType - 1)
            {
                SetElementTreeError(
                    $"property scope {scope.StartRecordType} 由不相符的 record {recordType} 結束。");
            }
            else
            {
                _propertyScopes.Pop();
            }

            error = null;
            return true;
        }

        private void SetElementTreeError(string error) =>
            _elementTreeError ??= error.TrimEnd();

        private bool TryReadContentProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId))
            {
                error = "content property attribute ID 已截斷。";
                return false;
            }

            PropertyCount++;
            AddUsage(_properties, attributeId);
            if (_elementStack.TryPeek(out var elementContext))
            {
                elementContext.SetContentProperty(attributeId);
            }
            else
            {
                SetElementTreeError("element 外出現 ContentProperty。");
            }

            error = null;
            return true;
        }

        private bool TryReadLiteralProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId)
                || !TryReadPropertyValueString(payload, ref position, out var value, out var truncated))
            {
                error = "property 字串值已截斷或格式錯誤。";
                return false;
            }

            AddPropertyValue(new PropertyValueData(attributeId, CurrentElementTypeId, "literal")
            {
                Value = value,
                ValueTruncated = truncated
            });
            error = null;
            return true;
        }

        private bool TryReadCustomProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId)
                || !TryReadInt16(payload, ref position, out var serializerAndFlags))
            {
                error = "custom property 的 attribute 或 serializer type ID 已截斷。";
                return false;
            }

            var serializerTypeId = (short)(serializerAndFlags & ~0x4000);
            AddPropertyValue(new PropertyValueData(attributeId, CurrentElementTypeId, "custom-binary")
            {
                RelatedTypeId = serializerTypeId,
                RelatedTypeIsKnownElementId = true,
                DataSize = payload.Length - position
            });
            error = null;
            return true;
        }

        private bool TryReadReferencedProperty(
            ReadOnlySpan<byte> payload,
            string kind,
            ReferenceKind referenceKind,
            out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId)
                || !TryReadInt16(payload, ref position, out var referenceId))
            {
                error = $"{kind} property 的 attribute 或 reference ID 已截斷。";
                return false;
            }

            AddPropertyValue(new PropertyValueData(attributeId, CurrentElementTypeId, kind)
            {
                ReferenceId = referenceId,
                ReferenceKind = referenceKind
            });
            error = null;
            return true;
        }

        private bool TryReadMarkupExtensionProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId)
                || !TryReadInt16(payload, ref position, out var extensionAndFlags)
                || !TryReadInt16(payload, ref position, out var referenceId))
            {
                error = "markup-extension property 的 attribute、extension type 或 value ID 已截斷。";
                return false;
            }

            var referenceKind = (extensionAndFlags & 0x4000) != 0
                ? ReferenceKind.Type
                : (extensionAndFlags & 0x2000) != 0
                    ? ReferenceKind.Property
                    : ReferenceKind.ExtensionArgument;
            AddPropertyValue(new PropertyValueData(attributeId, CurrentElementTypeId, "markup-extension")
            {
                ReferenceId = referenceId,
                ReferenceKind = referenceKind,
                RelatedTypeId = (short)(extensionAndFlags & 0x0FFF),
                RelatedTypeIsKnownElementId = true
            });
            error = null;
            return true;
        }

        private bool TryReadConvertedProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId)
                || !TryReadPropertyValueString(payload, ref position, out var value, out var truncated)
                || !TryReadInt16(payload, ref position, out var converterTypeId))
            {
                error = "converted property 的字串值或 converter type ID 已截斷。";
                return false;
            }

            AddPropertyValue(new PropertyValueData(attributeId, CurrentElementTypeId, "converted")
            {
                Value = value,
                ValueTruncated = truncated,
                RelatedTypeId = converterTypeId
            });
            error = null;
            return true;
        }

        private bool TryReadProperty(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId))
            {
                error = "property attribute ID 已截斷。";
                return false;
            }

            PropertyCount++;
            AddUsage(_properties, attributeId);
            error = null;
            return true;
        }

        private short? CurrentElementTypeId =>
            _elementStack.TryPeek(out var element) ? element.TypeId : null;

        private int? CurrentElementId =>
            _elementStack.TryPeek(out var element) ? element.Id : null;

        private void AddPropertyValue(PropertyValueData value)
        {
            value = value with { ElementId = CurrentElementId };
            PropertyCount++;
            PropertyValueCount++;
            AddUsage(_properties, value.PropertyId);
            if (_elementStack.TryPeek(out var elementContext))
            {
                elementContext.Data?.IncrementPropertyValueCount();
            }
            if (_propertyValues.Count < MaxPropertyValues)
            {
                _propertyValues.Add(value);
            }
            else
            {
                PropertyValuesTruncated = true;
            }
        }

        private void AddDeclaration<T>(Dictionary<short, T> declarations, short id, T value)
        {
            if (declarations.ContainsKey(id) || declarations.Count < MaxSymbols)
            {
                declarations[id] = value;
            }
            else
            {
                Truncated = true;
            }
        }

        private void AddUsage(Dictionary<short, int> usages, short id)
        {
            if (usages.TryGetValue(id, out var count))
            {
                usages[id] = count + 1;
            }
            else if (usages.Count < MaxSymbols)
            {
                usages[id] = 1;
            }
            else
            {
                Truncated = true;
            }
        }

        private sealed record TypeDeclaration(string Name, short AssemblyId);

        private sealed record AttributeDeclaration(string Name, short OwnerTypeId);

        private sealed record BoundedText(string Value, bool Truncated);

        private sealed class ElementContext(int id, short typeId, ElementData? data)
        {
            public int Id { get; } = id;

            public short TypeId { get; } = typeId;

            public ElementData? Data { get; } = data;

            public short? ContentPropertyId { get; private set; }

            public void SetContentProperty(short propertyId)
            {
                ContentPropertyId = propertyId;
                if (Data is not null)
                {
                    Data.ContentPropertyId = propertyId;
                }
            }
        }

        private sealed class ElementData(
            int id,
            int? parentId,
            int depth,
            int startOffset,
            short typeId,
            short? parentPropertyId,
            bool isInjected,
            bool createUsingTypeConverter)
        {
            public int Id { get; } = id;

            public int? ParentId { get; } = parentId;

            public int Depth { get; } = depth;

            public int StartOffset { get; } = startOffset;

            public int? EndOffset { get; private set; }

            public short TypeId { get; } = typeId;

            public short? ParentPropertyId { get; } = parentPropertyId;

            public bool IsInjected { get; } = isInjected;

            public bool CreateUsingTypeConverter { get; } = createUsingTypeConverter;

            public short? ContentPropertyId { get; set; }

            public int ChildCount { get; private set; }

            public int PropertyValueCount { get; private set; }

            public void IncrementChildCount() => ChildCount++;

            public void IncrementPropertyValueCount() => PropertyValueCount++;

            public void SetEndOffset(int endOffset) => EndOffset = endOffset;
        }

        private sealed record PropertyScope(int? ElementId, short PropertyId, byte StartRecordType);

        private sealed record PropertyValueData(short PropertyId, short? ElementTypeId, string Kind)
        {
            public int? ElementId { get; init; }

            public string? Value { get; init; }

            public bool ValueTruncated { get; init; }

            public short? ReferenceId { get; init; }

            public ReferenceKind ReferenceKind { get; init; }

            public short? RelatedTypeId { get; init; }

            public bool RelatedTypeIsKnownElementId { get; init; }

            public int? DataSize { get; init; }
        }

        private enum ReferenceKind
        {
            None,
            String,
            Type,
            Property,
            ExtensionArgument,
            StaticResource
        }
    }
}
