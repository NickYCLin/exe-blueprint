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
    private const int MaxDeferredResources = 2_000;
    private const int MaxDeferredStaticResources = 2_000;
    private const int MaxDeferredComplexKeyValues = 2_000;
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
        var recordSpans = new List<BamlRecordSpan>();
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

                var payloadOffset = position;
                if (!symbols.TryReadRecord(recordType, recordOffset, data[payloadOffset..(int)nextPosition], out var symbolError))
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

                recordSpans.Add(new BamlRecordSpan(recordType, recordOffset, payloadOffset, (int)nextPosition));
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

                var payloadOffset = position;
                var nextPosition = payloadOffset + payloadSize;
                if (!symbols.TryReadRecord(recordType, recordOffset, data[payloadOffset..nextPosition], out var symbolError))
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

                recordSpans.Add(new BamlRecordSpan(recordType, recordOffset, payloadOffset, nextPosition));
                position = nextPosition;
            }

            recordCounts[recordType] = recordCounts.GetValueOrDefault(recordType) + 1;
        }

        var truncated = position < data.Length;
        var deferred = symbols.BuildDeferredResources(data, recordSpans);
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
            PropertyValues = symbols.BuildPropertyValues(deferred.PropertyLinks),
            PropertyValuesTruncated = symbols.PropertyValuesTruncated,
            DeferredResourceCount = deferred.ResourceCount,
            DeferredResources = deferred.Resources,
            DeferredResourcesTruncated = deferred.Truncated,
            DeferredResourcesComplete = !truncated && deferred.Complete,
            DeferredResourcesError = deferred.Error
                ?? (truncated ? "BAML record 達解析上限，deferred resource 關係可能不完整。" : null),
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
            DeferredResourcesComplete = false,
            DeferredResourcesError = error,
            RecordsTruncated = recordsTruncated,
            SymbolsTruncated = symbols?.Truncated ?? false,
            Error = error
        };

    private static BamlSummaryModel Invalid(string error, string? signature = null) =>
        new()
        {
            Status = "invalid",
            Signature = signature,
            DeferredResourcesComplete = false,
            DeferredResourcesError = error,
            Error = error
        };

    private readonly record struct BamlRecordSpan(
        byte Type,
        int StartOffset,
        int PayloadOffset,
        int EndOffset);

    private sealed record DeferredAnalysis(
        int ResourceCount,
        IReadOnlyList<BamlDeferredResourceModel> Resources,
        bool Truncated,
        bool Complete,
        string? Error,
        IReadOnlyDictionary<int, DeferredPropertyLink> PropertyLinks);

    private sealed record DeferredPropertyLink(int ResourceId, string? Value);

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
        private readonly Stack<byte> _deferredHeaderScopes = [];
        private readonly Dictionary<int, int?> _deferredSectionOwners = [];
        private int? _activeDeferredContentEnd;
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

            if (_activeDeferredContentEnd is { } deferredContentEnd
                && recordOffset >= deferredContentEnd)
            {
                _deferredHeaderScopes.Clear();
                _activeDeferredContentEnd = null;
            }

            // complex key 與 verbose StaticResource 是 deferred header 內的物件子樹，
            // 不應污染實際 UI element/property 統計；關係由第二階段以 record 範圍安全解析。
            if (_deferredHeaderScopes.TryPeek(out var expectedEndRecord))
            {
                if (recordType is 40 or 48)
                {
                    _deferredHeaderScopes.Push((byte)(recordType + 1));
                }
                else if (recordType == expectedEndRecord)
                {
                    _deferredHeaderScopes.Pop();
                }

                return true;
            }

            if ((recordType is 40 or 48) && _activeDeferredContentEnd is not null)
            {
                _deferredHeaderScopes.Push((byte)(recordType + 1));
                return true;
            }

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
                37 => TryReadDeferableContentStart(payload, recordOffset, out error),
                50 => TryReadStaticResourceId(payload, recordOffset, out error),
                56 => TryReadReferencedProperty(
                    payload,
                    "static-resource",
                    ReferenceKind.StaticResource,
                    out error,
                    recordOffset),
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

        public IReadOnlyList<BamlPropertyValueModel> BuildPropertyValues(
            IReadOnlyDictionary<int, DeferredPropertyLink>? deferredLinks = null) =>
            _propertyValues
                .Select(value =>
                {
                    var (propertyName, propertyOwnerType) = ResolveProperty(value.PropertyId);
                    DeferredPropertyLink? deferredLink = null;
                    if (value.RecordOffset is { } recordOffset)
                    {
                        deferredLinks?.TryGetValue(recordOffset, out deferredLink);
                    }

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
                        Value = value.Value ?? deferredLink?.Value ?? ResolveReference(value),
                        ValueTruncated = value.ValueTruncated || IsReferencedStringTruncated(value),
                        ReferenceId = value.ReferenceId,
                        RelatedTypeId = value.RelatedTypeId,
                        RelatedType = ResolveRelatedType(value),
                        DataSize = value.DataSize,
                        DeferredResourceId = deferredLink?.ResourceId
                    };
                })
                .ToArray();

        public DeferredAnalysis BuildDeferredResources(
            ReadOnlySpan<byte> data,
            IReadOnlyList<BamlRecordSpan> records)
        {
            var recordByStartOffset = records.ToDictionary(record => record.StartOffset);

            var resolvedResources = new List<DeferredResourceData>();
            var propertyLinks = new Dictionary<int, DeferredPropertyLink>();
            var elementByStartOffset = new Dictionary<int, ElementData>();
            var elementById = new Dictionary<int, ElementData>();
            foreach (var element in _elements)
            {
                elementByStartOffset.TryAdd(element.StartOffset, element);
                elementById.TryAdd(element.Id, element);
            }

            var resourceCount = 0;
            var staticResourceCount = 0;
            var complexKeyValueCount = 0;
            var truncated = false;
            var complete = true;
            string? firstError = null;
            var previousSectionEnd = -1;

            void SetError(string message)
            {
                complete = false;
                firstError ??= message;
            }

            bool IsElementOrDescendant(int? elementId, ElementData root)
            {
                var remaining = elementById.Count + 1;
                while (elementId is { } currentId && remaining-- > 0)
                {
                    if (currentId == root.Id)
                    {
                        return true;
                    }

                    if (!elementById.TryGetValue(currentId, out var currentElement))
                    {
                        return false;
                    }

                    elementId = currentElement.ParentId;
                }

                return false;
            }

            for (var recordIndex = 0; recordIndex < records.Count; recordIndex++)
            {
                var sectionRecord = records[recordIndex];
                if (sectionRecord.Type != 37)
                {
                    continue;
                }

                if (sectionRecord.EndOffset - sectionRecord.PayloadOffset != sizeof(int))
                {
                    SetError($"offset {sectionRecord.StartOffset} 的 DeferableContentStart 長度不是 4 bytes。");
                    continue;
                }

                var contentSize = BinaryPrimitives.ReadInt32LittleEndian(data[sectionRecord.PayloadOffset..]);
                var contentEndLong = (long)sectionRecord.EndOffset + contentSize;
                if (contentSize < 0 || contentEndLong > data.Length)
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 的 deferred content size {contentSize} 超出 BAML 資料範圍。");
                    continue;
                }

                var contentEnd = (int)contentEndLong;
                if (!recordByStartOffset.TryGetValue(contentEnd, out var closingRecord)
                    || closingRecord.Type != 4)
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 的 deferred content 結尾 {contentEnd} 不是 owner ElementEnd。");
                    continue;
                }

                if (!_deferredSectionOwners.TryGetValue(sectionRecord.StartOffset, out var ownerId)
                    || ownerId is null
                    || !elementById.TryGetValue(ownerId.Value, out var ownerElement)
                    || ownerElement.EndOffset != contentEnd)
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 的 deferred content 結尾未對準其 owner element。");
                    continue;
                }

                if (sectionRecord.StartOffset < previousSectionEnd)
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 出現巢狀或重疊的 deferred content，目前不安全解析其關係。");
                    continue;
                }

                previousSectionEnd = contentEnd;
                var sectionResources = new List<DeferredResourceData>();
                DeferredResourceData? currentResource = null;
                var currentKeyExists = false;
                var sectionKeyCount = 0;
                var valuesStart = contentEnd;
                var sectionSupported = true;

                for (var headerIndex = recordIndex + 1; headerIndex < records.Count; headerIndex++)
                {
                    var headerRecord = records[headerIndex];
                    if (headerRecord.StartOffset >= contentEnd)
                    {
                        break;
                    }

                    if (headerRecord.EndOffset > contentEnd)
                    {
                        SetError(
                            $"offset {headerRecord.StartOffset} 的 record 跨出 deferred content 結尾 {contentEnd}。");
                        sectionSupported = false;
                        break;
                    }

                    if (headerRecord.Type is 38 or 39)
                    {
                        var payload = data[headerRecord.PayloadOffset..headerRecord.EndOffset];
                        var expectedSize = headerRecord.Type == 38 ? 8 : 9;
                        if (payload.Length != expectedSize)
                        {
                            SetError(
                                $"offset {headerRecord.StartOffset} 的 {GetRecordName(headerRecord.Type)} payload 長度不正確。");
                            sectionSupported = false;
                            break;
                        }

                        short keyId;
                        int valuePosition;
                        bool shared;
                        bool sharedSet;
                        string keyKind;
                        string? key;
                        if (headerRecord.Type == 38)
                        {
                            keyId = BinaryPrimitives.ReadInt16LittleEndian(payload);
                            valuePosition = BinaryPrimitives.ReadInt32LittleEndian(payload[sizeof(short)..]);
                            shared = payload[6] != 0;
                            sharedSet = payload[7] != 0;
                            keyKind = "string";
                            key = _strings.TryGetValue(keyId, out var keyText) ? keyText.Value : null;
                        }
                        else
                        {
                            keyId = BinaryPrimitives.ReadInt16LittleEndian(payload);
                            valuePosition = BinaryPrimitives.ReadInt32LittleEndian(payload[3..]);
                            shared = payload[7] != 0;
                            sharedSet = payload[8] != 0;
                            keyKind = "type";
                            key = ResolveTypeName(keyId);
                        }

                        var resourceId = resourceCount++;
                        sectionKeyCount++;
                        currentKeyExists = true;
                        if (resourceId < MaxDeferredResources)
                        {
                            currentResource = new DeferredResourceData(
                                resourceId,
                                keyKind,
                                keyId,
                                key,
                                headerRecord.StartOffset,
                                valuePosition,
                                shared,
                                sharedSet);
                            sectionResources.Add(currentResource);
                        }
                        else
                        {
                            currentResource = null;
                            truncated = true;
                            SetError($"BAML deferred resource 超過 {MaxDeferredResources:N0} 筆安全保留上限。");
                        }

                        continue;
                    }

                    if (headerRecord.Type == 40)
                    {
                        var remainingComplexKeyValues = Math.Max(
                            0,
                            MaxDeferredComplexKeyValues - complexKeyValueCount);
                        var complexKey = ReadComplexKey(
                            data,
                            records,
                            headerIndex,
                            contentEnd,
                            remainingComplexKeyValues);
                        if (complexKey.EndRecordIndex <= headerIndex || complexKey.Model is null)
                        {
                            SetError(complexKey.Error ??
                                $"offset {headerRecord.StartOffset} 的 complex key 範圍無效。");
                            sectionSupported = false;
                            break;
                        }

                        complexKeyValueCount += complexKey.Model.ValueCount;
                        if (!complexKey.Model.Complete)
                        {
                            SetError(complexKey.Model.Error ??
                                $"offset {headerRecord.StartOffset} 的 complex key 關係不完整。");
                        }

                        if (complexKey.Model.ValuesTruncated)
                        {
                            truncated = true;
                            SetError(
                                $"BAML complex key 值超過 {MaxDeferredComplexKeyValues:N0} 筆安全保留上限。");
                        }

                        var resourceId = resourceCount++;
                        sectionKeyCount++;
                        currentKeyExists = true;
                        if (resourceId < MaxDeferredResources)
                        {
                            currentResource = new DeferredResourceData(
                                resourceId,
                                complexKey.KeyKind,
                                (short)complexKey.Model.TypeId,
                                complexKey.Key,
                                headerRecord.StartOffset,
                                complexKey.ValuePosition,
                                complexKey.Shared,
                                complexKey.SharedSet)
                            {
                                ComplexKey = complexKey.Model
                            };
                            sectionResources.Add(currentResource);
                        }
                        else
                        {
                            currentResource = null;
                            truncated = true;
                            SetError($"BAML deferred resource 超過 {MaxDeferredResources:N0} 筆安全保留上限。");
                        }

                        headerIndex = complexKey.EndRecordIndex;
                        continue;
                    }

                    if (headerRecord.Type == 55)
                    {
                        if (!currentKeyExists)
                        {
                            SetError(
                                $"offset {headerRecord.StartOffset} 的 OptimizedStaticResource 前沒有 deferred key。");
                            sectionSupported = false;
                            break;
                        }

                        var payload = data[headerRecord.PayloadOffset..headerRecord.EndOffset];
                        if (payload.Length != 3)
                        {
                            SetError(
                                $"offset {headerRecord.StartOffset} 的 OptimizedStaticResource payload 長度不正確。");
                            sectionSupported = false;
                            break;
                        }

                        var flags = payload[0];
                        var referenceId = BinaryPrimitives.ReadInt16LittleEndian(payload[1..]);
                        var localId = currentResource?.StaticResourceCount ?? 0;
                        currentResource?.IncrementStaticResourceCount();
                        staticResourceCount++;

                        string kind;
                        string? value;
                        if (flags == 0)
                        {
                            kind = "string-reference";
                            value = _strings.TryGetValue(referenceId, out var text) ? text.Value : null;
                        }
                        else if (flags == 1)
                        {
                            kind = "type-reference";
                            value = ResolveTypeName(referenceId);
                        }
                        else if (flags == 2)
                        {
                            kind = "property-reference";
                            value = FormatPropertyReference(referenceId);
                        }
                        else
                        {
                            kind = "unknown";
                            value = null;
                            SetError(
                                $"offset {headerRecord.StartOffset} 的 OptimizedStaticResource flags 0x{flags:X2} 不受支援。");
                        }

                        if (currentResource is not null)
                        {
                            if (staticResourceCount <= MaxDeferredStaticResources)
                            {
                                currentResource.StaticResources.Add(new BamlStaticResourceModel
                                {
                                    Id = localId,
                                    Kind = kind,
                                    StartOffset = headerRecord.StartOffset,
                                    EndOffset = headerRecord.EndOffset,
                                    ReferenceId = referenceId,
                                    ValueKind = kind,
                                    Value = value
                                });
                            }
                            else
                            {
                                currentResource.StaticResourcesTruncated = true;
                                truncated = true;
                                SetError(
                                    $"BAML deferred StaticResource 超過 {MaxDeferredStaticResources:N0} 筆安全保留上限。");
                            }
                        }

                        continue;
                    }

                    if (headerRecord.Type == 48)
                    {
                        if (!currentKeyExists)
                        {
                            SetError(
                                $"offset {headerRecord.StartOffset} 的 StaticResourceStart 前沒有 deferred key。");
                            sectionSupported = false;
                            break;
                        }

                        var verbose = ReadVerboseStaticResource(data, records, headerIndex, contentEnd);
                        if (verbose.EndRecordIndex <= headerIndex)
                        {
                            SetError(verbose.Error ??
                                $"offset {headerRecord.StartOffset} 的 verbose StaticResource 範圍無效。");
                            sectionSupported = false;
                            break;
                        }

                        var localId = currentResource?.StaticResourceCount ?? 0;
                        currentResource?.IncrementStaticResourceCount();
                        staticResourceCount++;
                        if (!verbose.Complete)
                        {
                            SetError(verbose.Error ??
                                $"offset {headerRecord.StartOffset} 的 verbose StaticResource 關係不完整。");
                        }

                        if (currentResource is not null)
                        {
                            if (staticResourceCount <= MaxDeferredStaticResources)
                            {
                                currentResource.StaticResources.Add(new BamlStaticResourceModel
                                {
                                    Id = localId,
                                    Kind = "verbose",
                                    StartOffset = headerRecord.StartOffset,
                                    EndOffset = verbose.EndOffset,
                                    ReferenceId = verbose.ReferenceId,
                                    TypeId = verbose.TypeId,
                                    Type = verbose.Type,
                                    ValueKind = verbose.ValueKind,
                                    Value = verbose.Value,
                                    ValueTruncated = verbose.ValueTruncated,
                                    Complete = verbose.Complete,
                                    Error = verbose.Error
                                });
                            }
                            else
                            {
                                currentResource.StaticResourcesTruncated = true;
                                truncated = true;
                                SetError(
                                    $"BAML deferred StaticResource 超過 {MaxDeferredStaticResources:N0} 筆安全保留上限。");
                            }
                        }

                        headerIndex = verbose.EndRecordIndex;
                        continue;
                    }

                    if (headerRecord.Type is 41 or 49 or 50)
                    {
                        SetError(
                            $"deferred header 的 {GetRecordName(headerRecord.Type)} ({headerRecord.Type}) 關係目前不受支援。");
                        sectionSupported = false;
                        break;
                    }

                    valuesStart = headerRecord.StartOffset;
                    break;
                }

                if (sectionSupported && sectionKeyCount == 0 && contentSize > 0)
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 的非空 deferred content 沒有可辨識的 key header。");
                    continue;
                }

                if (!sectionSupported || sectionResources.Count == 0)
                {
                    continue;
                }

                if (sectionKeyCount != sectionResources.Count)
                {
                    // 截斷後無法安全得知最後一筆已保留 resource 的 value 結尾。
                    continue;
                }

                var absoluteStarts = new int[sectionResources.Count];
                var valueElements = new ElementData[sectionResources.Count];
                var positionsValid = true;
                var previousValuePosition = -1;
                for (var index = 0; index < sectionResources.Count; index++)
                {
                    var resource = sectionResources[index];
                    var absoluteStartLong = (long)valuesStart + resource.ValuePosition;
                    if (resource.ValuePosition < 0
                        || resource.ValuePosition <= previousValuePosition
                        || absoluteStartLong < valuesStart
                        || absoluteStartLong >= contentEnd
                        || !recordByStartOffset.TryGetValue((int)absoluteStartLong, out var valueStartRecord)
                        || valueStartRecord.Type != 3)
                    {
                        SetError(
                            $"offset {resource.KeyRecordOffset} 的 deferred ValuePosition {resource.ValuePosition} 無效或不在 record 邊界。");
                        positionsValid = false;
                        break;
                    }

                    var absoluteStart = (int)absoluteStartLong;
                    if (!elementByStartOffset.TryGetValue(absoluteStart, out var valueElement)
                        || valueElement.ParentId != ownerElement.Id
                        || valueElement.EndOffset is null)
                    {
                        SetError(
                            $"offset {resource.KeyRecordOffset} 的 deferred value 必須是 owner 的完整直接子 element。");
                        positionsValid = false;
                        break;
                    }

                    absoluteStarts[index] = absoluteStart;
                    valueElements[index] = valueElement;
                    previousValuePosition = resource.ValuePosition;
                }

                if (!positionsValid)
                {
                    continue;
                }

                var directValueChildStarts = _elements
                    .Where(element => element.ParentId == ownerElement.Id
                                      && element.StartOffset >= valuesStart
                                      && element.StartOffset < contentEnd)
                    .Select(element => element.StartOffset)
                    .OrderBy(offset => offset)
                    .ToArray();
                if (!absoluteStarts.SequenceEqual(directValueChildStarts))
                {
                    SetError(
                        $"offset {sectionRecord.StartOffset} 的 deferred key offsets 未與 owner 直接子 elements 一一對應。");
                    continue;
                }

                var valueRangesValid = true;
                for (var index = 0; index < sectionResources.Count; index++)
                {
                    var valueEndOffset = index + 1 < absoluteStarts.Length
                        ? absoluteStarts[index + 1]
                        : contentEnd;
                    var elementEndOffset = valueElements[index].EndOffset!.Value;
                    if (elementEndOffset <= absoluteStarts[index]
                        || elementEndOffset >= valueEndOffset)
                    {
                        SetError(
                            $"deferred resource {sectionResources[index].Id} 的 value element 超出其 key range。");
                        valueRangesValid = false;
                        break;
                    }
                }

                if (!valueRangesValid)
                {
                    continue;
                }

                for (var index = 0; index < sectionResources.Count; index++)
                {
                    var resource = sectionResources[index];
                    resource.ValueStartOffset = absoluteStarts[index];
                    resource.ValueEndOffset = index + 1 < absoluteStarts.Length
                        ? absoluteStarts[index + 1]
                        : contentEnd;
                    resource.Element = valueElements[index];

                    resolvedResources.Add(resource);
                }
            }

            var scopedStaticResourceOffsets = _propertyValues
                .Where(value => value.ReferenceKind == ReferenceKind.StaticResource
                                && value.RecordOffset is not null)
                .Select(value => value.RecordOffset!.Value)
                .ToHashSet();
            var resourceRangeIndex = 0;
            foreach (var record in records)
            {
                if (record.Type != 50)
                {
                    continue;
                }

                while (resourceRangeIndex < resolvedResources.Count
                       && record.StartOffset >= resolvedResources[resourceRangeIndex].ValueEndOffset)
                {
                    resourceRangeIndex++;
                }

                if (resourceRangeIndex >= resolvedResources.Count)
                {
                    break;
                }

                var resource = resolvedResources[resourceRangeIndex];
                if (record.StartOffset < resource.ValueStartOffset)
                {
                    continue;
                }

                if (!scopedStaticResourceOffsets.Contains(record.StartOffset))
                {
                    SetError(
                        $"offset {record.StartOffset} 的 StaticResourceId 無法安全對應到 value element 的 property scope。");
                }
            }

            foreach (var propertyValue in _propertyValues)
            {
                if (propertyValue.ReferenceKind != ReferenceKind.StaticResource
                    || propertyValue.RecordOffset is not { } recordOffset
                    || propertyValue.ReferenceId is not { } referenceId)
                {
                    continue;
                }

                var resource = resolvedResources.FirstOrDefault(
                    candidate => recordOffset >= candidate.ValueStartOffset
                                 && recordOffset < candidate.ValueEndOffset);
                if (resource is null)
                {
                    continue;
                }

                var valueElement = resource.Element;
                if (valueElement?.EndOffset is not { } valueElementEnd
                    || recordOffset <= valueElement.StartOffset
                    || recordOffset >= valueElementEnd
                    || !IsElementOrDescendant(propertyValue.ElementId, valueElement))
                {
                    SetError(
                        $"offset {recordOffset} 的 StaticResourceId 不在 deferred resource {resource.Id} 的 value element 子樹內。");
                    continue;
                }

                var staticResource = referenceId >= 0
                    ? resource.StaticResources.FirstOrDefault(candidate => candidate.Id == referenceId)
                    : null;
                propertyLinks[recordOffset] = new DeferredPropertyLink(resource.Id, staticResource?.Value);
                if (staticResource is null)
                {
                    SetError(
                        $"deferred resource {resource.Id} 的 local StaticResource ID {referenceId} 超出範圍。");
                }
            }

            if (resourceCount > 0 && !ElementTreeComplete)
            {
                SetError("BAML element tree 不完整，無法證明所有 deferred resource 的 element 關係。");
            }

            if (resourceCount > 0 && PropertyValuesTruncated)
            {
                SetError("BAML property value 已截斷，deferred StaticResource 關係可能不完整。");
            }

            var models = resolvedResources
                .Select(resource => new BamlDeferredResourceModel
                {
                    Id = resource.Id,
                    KeyKind = resource.KeyKind,
                    KeyId = resource.KeyId,
                    Key = resource.Key,
                    KeyRecordOffset = resource.KeyRecordOffset,
                    ValuePosition = resource.ValuePosition,
                    ValueStartOffset = resource.ValueStartOffset,
                    ValueEndOffset = resource.ValueEndOffset,
                    Shared = resource.Shared,
                    SharedSet = resource.SharedSet,
                    ElementId = resource.Element?.Id,
                    ElementTypeId = resource.Element?.TypeId,
                    ElementType = resource.Element is { } element
                        ? ResolveTypeName(element.TypeId)
                        : null,
                    ComplexKey = resource.ComplexKey,
                    StaticResources = resource.StaticResources.ToArray(),
                    StaticResourcesTruncated = resource.StaticResourcesTruncated
                })
                .ToArray();

            return new DeferredAnalysis(
                resourceCount,
                models,
                truncated,
                complete,
                firstError,
                propertyLinks);
        }

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

        private ComplexKeyData ReadComplexKey(
            ReadOnlySpan<byte> data,
            IReadOnlyList<BamlRecordSpan> records,
            int startIndex,
            int contentEnd,
            int retentionLimit)
        {
            var startRecord = records[startIndex];
            var payload = data[startRecord.PayloadOffset..startRecord.EndOffset];
            if (payload.Length != 9)
            {
                return ComplexKeyData.Invalid(
                    startIndex,
                    $"offset {startRecord.StartOffset} 的 KeyElementStart payload 長度不正確。");
            }

            var typeId = BinaryPrimitives.ReadInt16LittleEndian(payload);
            var flags = payload[2];
            var valuePosition = BinaryPrimitives.ReadInt32LittleEndian(payload[3..]);
            var shared = payload[7] != 0;
            var sharedSet = payload[8] != 0;
            var type = ResolveTypeName(typeId);
            var values = new List<BamlComplexKeyValueModel>();
            var valueCount = 0;
            var valuesTruncated = false;
            string? firstError = null;
            var depth = 1;
            var insideConstructorParameters = false;

            void AddValue(BamlComplexKeyValueModel value)
            {
                valueCount++;
                if (values.Count < retentionLimit)
                {
                    values.Add(value);
                }
                else
                {
                    valuesTruncated = true;
                }
            }

            for (var index = startIndex + 1; index < records.Count; index++)
            {
                var record = records[index];
                if (record.StartOffset >= contentEnd || record.EndOffset > contentEnd)
                {
                    break;
                }

                if (record.Type == 40)
                {
                    depth++;
                    firstError ??= $"offset {record.StartOffset} 的巢狀 complex key 目前不受支援。";
                    continue;
                }

                if (record.Type == 41)
                {
                    depth--;
                    if (depth == 0)
                    {
                        if (insideConstructorParameters)
                        {
                            firstError ??= $"offset {startRecord.StartOffset} 的 complex key constructor parameters 未關閉。";
                        }

                        var summary = SummarizeComplexKey(type, values);
                        firstError ??= summary.Error;
                        if (valuesTruncated)
                        {
                            firstError ??= $"offset {startRecord.StartOffset} 的 complex key 值已達安全保留上限。";
                        }

                        var model = new BamlComplexKeyModel
                        {
                            StartOffset = startRecord.StartOffset,
                            EndOffset = record.EndOffset,
                            TypeId = typeId,
                            Type = type,
                            IsInjected = (flags & 2) != 0,
                            CreateUsingTypeConverter = (flags & 1) != 0,
                            ValueCount = valueCount,
                            Values = values.ToArray(),
                            ValuesTruncated = valuesTruncated,
                            Complete = firstError is null,
                            Error = firstError
                        };
                        return new ComplexKeyData(
                            index,
                            valuePosition,
                            shared,
                            sharedSet,
                            summary.Kind,
                            summary.Value,
                            model,
                            null);
                    }

                    continue;
                }

                if (depth != 1)
                {
                    continue;
                }

                if (record.Type == 42)
                {
                    if (insideConstructorParameters)
                    {
                        firstError ??= $"offset {record.StartOffset} 出現巢狀 ConstructorParametersStart。";
                    }

                    insideConstructorParameters = true;
                    continue;
                }

                if (record.Type == 43)
                {
                    if (!insideConstructorParameters)
                    {
                        firstError ??= $"offset {record.StartOffset} 出現沒有 start 的 ConstructorParametersEnd。";
                    }

                    insideConstructorParameters = false;
                    continue;
                }

                var role = insideConstructorParameters ? "constructor-parameter" : "content";
                if (record.Type is 16 or 17)
                {
                    var textPayload = data[record.PayloadOffset..record.EndOffset];
                    var textPosition = 0;
                    if (!TryReadPropertyValueString(
                            textPayload,
                            ref textPosition,
                            out var text,
                            out var textTruncated))
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key 文字格式錯誤。";
                        continue;
                    }

                    short? converterTypeId = null;
                    if (record.Type == 17)
                    {
                        if (!TryReadInt16(textPayload, ref textPosition, out var converterId))
                        {
                            firstError ??= $"offset {record.StartOffset} 的 complex key converter type ID 已截斷。";
                            continue;
                        }

                        converterTypeId = converterId;
                    }

                    AddValue(new BamlComplexKeyValueModel
                    {
                        Role = role,
                        Kind = record.Type == 16 ? "literal" : "converted",
                        Value = text,
                        ValueTruncated = textTruncated,
                        RelatedTypeId = converterTypeId,
                        RelatedType = converterTypeId is { } converter
                            ? ResolveTypeName(converter)
                            : null
                    });
                    if (textTruncated)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key 文字已達安全截斷上限。";
                    }

                    continue;
                }

                if (record.Type == 51)
                {
                    var textPayload = data[record.PayloadOffset..record.EndOffset];
                    var textPosition = 0;
                    if (!TryReadInt16(textPayload, ref textPosition, out var textId))
                    {
                        firstError ??= $"offset {record.StartOffset} 的 TextWithId reference 已截斷。";
                        continue;
                    }

                    _strings.TryGetValue(textId, out var textReference);
                    AddValue(new BamlComplexKeyValueModel
                    {
                        Role = role,
                        Kind = "string-reference",
                        Value = textReference?.Value,
                        ValueTruncated = textReference?.Truncated ?? false,
                        ReferenceId = textId
                    });
                    if (textReference is null)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key string ID {textId} 無法解析。";
                    }

                    continue;
                }

                if (record.Type == 44)
                {
                    var typePayload = data[record.PayloadOffset..record.EndOffset];
                    if (typePayload.Length != sizeof(short))
                    {
                        firstError ??= $"offset {record.StartOffset} 的 ConstructorParameterType payload 長度不正確。";
                        continue;
                    }

                    var referenceId = BinaryPrimitives.ReadInt16LittleEndian(typePayload);
                    var referenceValue = ResolveTypeName(referenceId);
                    AddValue(new BamlComplexKeyValueModel
                    {
                        Role = role,
                        Kind = "type-reference",
                        Value = referenceValue,
                        ReferenceId = referenceId
                    });
                    if (referenceValue is null)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key type ID {referenceId} 無法解析。";
                    }

                    continue;
                }

                if (record.Type is 5 or 33 or 34 or 35 or 36)
                {
                    if (!TryReadSafePropertyValue(
                            data[record.PayloadOffset..record.EndOffset],
                            record.Type,
                            out var propertyValue,
                            out var propertyError))
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key property 無法安全解析：{propertyError}";
                        continue;
                    }

                    var (propertyName, propertyOwnerType) = ResolveProperty(propertyValue.PropertyId);
                    var resolvedValue = propertyValue.Value ?? ResolveReference(propertyValue);
                    var resolvedTruncated = propertyValue.ValueTruncated || IsReferencedStringTruncated(propertyValue);
                    AddValue(new BamlComplexKeyValueModel
                    {
                        Role = "property",
                        PropertyId = propertyValue.PropertyId,
                        PropertyName = propertyName,
                        PropertyOwnerType = propertyOwnerType,
                        Kind = propertyValue.Kind,
                        Value = resolvedValue,
                        ValueTruncated = resolvedTruncated,
                        ReferenceId = propertyValue.ReferenceId,
                        RelatedTypeId = propertyValue.RelatedTypeId,
                        RelatedType = ResolveRelatedType(propertyValue)
                    });
                    if (propertyName is null || resolvedValue is null || resolvedTruncated)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 complex key property 無法完整解析。";
                    }

                    continue;
                }

                if (record.Type is not 53 and not 54)
                {
                    firstError ??=
                        $"offset {record.StartOffset} 的 complex key 內含不受支援的 {GetRecordName(record.Type)} ({record.Type})。";
                }
            }

            return ComplexKeyData.Invalid(
                startIndex,
                $"offset {startRecord.StartOffset} 的 KeyElementStart 找不到對應的 KeyElementEnd。");
        }

        private static ComplexKeySummary SummarizeComplexKey(
            string? type,
            IReadOnlyList<BamlComplexKeyValueModel> values)
        {
            BamlComplexKeyValueModel? FindArgument(params string[] propertyNames)
            {
                if (propertyNames.Length > 0)
                {
                    var namedArgument = values.FirstOrDefault(value =>
                        value.Role == "property"
                        && value.PropertyName is { } propertyName
                        && propertyNames.Contains(propertyName));
                    if (namedArgument is not null)
                    {
                        return namedArgument;
                    }
                }

                return values.FirstOrDefault(value => value.Role != "property");
            }

            if (type == "StaticExtension")
            {
                var member = FindArgument("Member");
                return member?.Value is { } value
                    ? new ComplexKeySummary("complex-static", value, null)
                    : new ComplexKeySummary("complex-static", null, "StaticExtension key 缺少可安全讀取的 member。");
            }

            if (type == "TypeExtension")
            {
                var targetType = FindArgument("Type", "TypeName");
                return targetType?.Value is { } value
                    ? new ComplexKeySummary("complex-type", value, null)
                    : new ComplexKeySummary("complex-type", null, "TypeExtension key 缺少可安全讀取的 type。");
            }

            if (type == "String")
            {
                var text = FindArgument();
                return text?.Value is { } value
                    ? new ComplexKeySummary("complex-string", value, null)
                    : new ComplexKeySummary("complex-string", null, "String complex key 缺少可安全讀取的文字。");
            }

            if (type == "ComponentResourceKey")
            {
                var targetType = values.FirstOrDefault(value => value.PropertyName == "TypeInTargetAssembly");
                var resourceId = values.FirstOrDefault(value => value.PropertyName == "ResourceId");
                return targetType?.Value is { } typeValue && resourceId?.Value is { } resourceValue
                    ? new ComplexKeySummary("complex-resource", $"{typeValue}:{resourceValue}", null)
                    : new ComplexKeySummary(
                        "complex-resource",
                        null,
                        "ComponentResourceKey 缺少可安全讀取的 TypeInTargetAssembly 或 ResourceId。");
            }

            return new ComplexKeySummary(
                "complex",
                null,
                $"complex key 型別 {type ?? "unknown"} 不在安全摘要白名單。");
        }

        private VerboseStaticResourceData ReadVerboseStaticResource(
            ReadOnlySpan<byte> data,
            IReadOnlyList<BamlRecordSpan> records,
            int startIndex,
            int contentEnd)
        {
            var startRecord = records[startIndex];
            var payload = data[startRecord.PayloadOffset..startRecord.EndOffset];
            if (payload.Length != 3)
            {
                return VerboseStaticResourceData.Invalid(
                    startIndex,
                    startRecord.EndOffset,
                    $"offset {startRecord.StartOffset} 的 StaticResourceStart payload 長度不正確。");
            }

            var typeId = BinaryPrimitives.ReadInt16LittleEndian(payload);
            var type = ResolveTypeName(typeId);
            string? firstError = type == "StaticResourceExtension"
                ? null
                : $"offset {startRecord.StartOffset} 的 verbose StaticResource 型別 {type ?? typeId.ToString()} 不受支援。";
            string? valueKind = null;
            short? referenceId = null;
            string? value = null;
            var valueTruncated = false;
            var resourceKeyCount = 0;
            var depth = 1;

            for (var index = startIndex + 1; index < records.Count; index++)
            {
                var record = records[index];
                if (record.StartOffset >= contentEnd || record.EndOffset > contentEnd)
                {
                    break;
                }

                if (record.Type == 48)
                {
                    depth++;
                    firstError ??= $"offset {record.StartOffset} 的巢狀 verbose StaticResource 目前不受支援。";
                    continue;
                }

                if (record.Type == 49)
                {
                    depth--;
                    if (depth == 0)
                    {
                        if (resourceKeyCount == 0)
                        {
                            firstError ??= $"offset {startRecord.StartOffset} 的 verbose StaticResource 沒有可安全讀取的 ResourceKey。";
                        }

                        return new VerboseStaticResourceData(
                            index,
                            record.EndOffset,
                            typeId,
                            type,
                            valueKind,
                            referenceId,
                            value,
                            valueTruncated,
                            firstError is null,
                            firstError);
                    }

                    continue;
                }

                if (depth != 1)
                {
                    continue;
                }

                if (record.Type is 5 or 33 or 34 or 35 or 36)
                {
                    if (!TryReadVerboseResourceKey(
                            data[record.PayloadOffset..record.EndOffset],
                            record.Type,
                            out var isResourceKey,
                            out var candidateKind,
                            out var candidateReferenceId,
                            out var candidateValue,
                            out var candidateTruncated,
                            out var propertyError))
                    {
                        firstError ??= $"offset {record.StartOffset} 的 verbose StaticResource property 無法安全解析：{propertyError}";
                        continue;
                    }

                    if (!isResourceKey)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 verbose StaticResource 含有非 ResourceKey property。";
                        continue;
                    }

                    resourceKeyCount++;
                    if (resourceKeyCount > 1)
                    {
                        firstError ??= $"offset {startRecord.StartOffset} 的 verbose StaticResource 含有重複 ResourceKey。";
                        continue;
                    }

                    valueKind = candidateKind;
                    referenceId = candidateReferenceId;
                    value = candidateValue;
                    valueTruncated = candidateTruncated;
                    if (candidateTruncated)
                    {
                        firstError ??= $"offset {record.StartOffset} 的 verbose StaticResource ResourceKey 已達安全截斷上限。";
                    }

                    continue;
                }

                firstError ??=
                    $"offset {record.StartOffset} 的 verbose StaticResource 內含不受支援的 {GetRecordName(record.Type)} ({record.Type})。";
            }

            return VerboseStaticResourceData.Invalid(
                startIndex,
                startRecord.EndOffset,
                $"offset {startRecord.StartOffset} 的 StaticResourceStart 找不到對應的 StaticResourceEnd。");
        }

        private bool TryReadVerboseResourceKey(
            ReadOnlySpan<byte> payload,
            byte recordType,
            out bool isResourceKey,
            out string? kind,
            out short? referenceId,
            out string? value,
            out bool valueTruncated,
            out string? error)
        {
            isResourceKey = false;
            kind = null;
            referenceId = null;
            value = null;
            valueTruncated = false;
            if (!TryReadSafePropertyValue(payload, recordType, out var propertyValue, out error))
            {
                return false;
            }

            var (propertyName, _) = ResolveProperty(propertyValue.PropertyId);
            isResourceKey = propertyName == "ResourceKey";
            kind = propertyValue.Kind;
            referenceId = propertyValue.ReferenceId;
            value = propertyValue.Value ?? ResolveReference(propertyValue);
            valueTruncated = propertyValue.ValueTruncated || IsReferencedStringTruncated(propertyValue);
            return true;
        }

        private static bool TryReadSafePropertyValue(
            ReadOnlySpan<byte> payload,
            byte recordType,
            out PropertyValueData propertyValue,
            out string? error)
        {
            propertyValue = null!;
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var attributeId))
            {
                error = "attribute ID 已截斷。";
                return false;
            }

            switch (recordType)
            {
                case 5:
                case 36:
                    if (!TryReadPropertyValueString(payload, ref position, out var text, out var valueTruncated))
                    {
                        error = "字串值已截斷或格式錯誤。";
                        return false;
                    }

                    short? converterTypeId = null;
                    if (recordType == 36)
                    {
                        if (!TryReadInt16(payload, ref position, out var converterId))
                        {
                            error = "converter type ID 已截斷。";
                            return false;
                        }

                        converterTypeId = converterId;
                    }

                    propertyValue = new PropertyValueData(
                        attributeId,
                        null,
                        recordType == 5 ? "literal" : "converted")
                    {
                        Value = text,
                        ValueTruncated = valueTruncated,
                        RelatedTypeId = converterTypeId
                    };
                    break;
                case 33:
                case 34:
                    if (!TryReadInt16(payload, ref position, out var simpleReferenceId))
                    {
                        error = "reference ID 已截斷。";
                        return false;
                    }

                    propertyValue = new PropertyValueData(
                        attributeId,
                        null,
                        recordType == 33 ? "string-reference" : "type-reference")
                    {
                        ReferenceId = simpleReferenceId,
                        ReferenceKind = recordType == 33 ? ReferenceKind.String : ReferenceKind.Type
                    };
                    break;
                case 35:
                    if (!TryReadInt16(payload, ref position, out var extensionAndFlags)
                        || !TryReadInt16(payload, ref position, out var extensionReferenceId))
                    {
                        error = "markup extension type 或 value ID 已截斷。";
                        return false;
                    }

                    var referenceKind = (extensionAndFlags & 0x4000) != 0
                        ? ReferenceKind.Type
                        : (extensionAndFlags & 0x2000) != 0
                            ? ReferenceKind.Property
                            : ReferenceKind.ExtensionArgument;
                    propertyValue = new PropertyValueData(attributeId, null, "markup-extension")
                    {
                        ReferenceId = extensionReferenceId,
                        ReferenceKind = referenceKind,
                        RelatedTypeId = (short)(extensionAndFlags & 0x0FFF),
                        RelatedTypeIsKnownElementId = true
                    };
                    break;
                default:
                    error = $"record {recordType} 不受支援。";
                    return false;
            }

            error = null;
            return true;
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

        private bool TryReadDeferableContentStart(
            ReadOnlySpan<byte> payload,
            int recordOffset,
            out string? error)
        {
            _deferredSectionOwners[recordOffset] = CurrentElementId;
            if (payload.Length == sizeof(int))
            {
                var contentSize = BinaryPrimitives.ReadInt32LittleEndian(payload);
                var contentEnd = (long)recordOffset + 1 + payload.Length + contentSize;
                _activeDeferredContentEnd = contentSize >= 0 && contentEnd <= int.MaxValue
                    ? (int)contentEnd
                    : null;
            }

            error = null;
            return true;
        }

        private bool TryReadStaticResourceId(
            ReadOnlySpan<byte> payload,
            int recordOffset,
            out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var referenceId))
            {
                error = "StaticResourceId 的 local ID 已截斷。";
                return false;
            }

            if (!_propertyScopes.TryPeek(out var propertyScope)
                || propertyScope.ElementId != CurrentElementId)
            {
                // record 50 也可能出現在 collection/object 位置；沒有 property scope 時
                // 先保留原始 record，第二階段會將無法安全連結的關係標成不完整。
                error = null;
                return true;
            }

            AddPropertyValue(new PropertyValueData(propertyScope.PropertyId, CurrentElementTypeId, "static-resource")
            {
                ReferenceId = referenceId,
                ReferenceKind = ReferenceKind.StaticResource,
                RecordOffset = recordOffset
            });
            error = null;
            return true;
        }

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
            out string? error,
            int? recordOffset = null)
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
                ReferenceKind = referenceKind,
                RecordOffset = recordOffset
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

        private sealed class DeferredResourceData(
            int id,
            string keyKind,
            short keyId,
            string? key,
            int keyRecordOffset,
            int valuePosition,
            bool shared,
            bool sharedSet)
        {
            public int Id { get; } = id;

            public string KeyKind { get; } = keyKind;

            public short KeyId { get; } = keyId;

            public string? Key { get; } = key;

            public int KeyRecordOffset { get; } = keyRecordOffset;

            public int ValuePosition { get; } = valuePosition;

            public bool Shared { get; } = shared;

            public bool SharedSet { get; } = sharedSet;

            public int ValueStartOffset { get; set; }

            public int ValueEndOffset { get; set; }

            public ElementData? Element { get; set; }

            public BamlComplexKeyModel? ComplexKey { get; set; }

            public List<BamlStaticResourceModel> StaticResources { get; } = [];

            public int StaticResourceCount { get; private set; }

            public bool StaticResourcesTruncated { get; set; }

            public void IncrementStaticResourceCount() => StaticResourceCount++;
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

            public int? RecordOffset { get; init; }
        }

        private sealed record VerboseStaticResourceData(
            int EndRecordIndex,
            int EndOffset,
            short TypeId,
            string? Type,
            string? ValueKind,
            short? ReferenceId,
            string? Value,
            bool ValueTruncated,
            bool Complete,
            string? Error)
        {
            public static VerboseStaticResourceData Invalid(
                int startIndex,
                int endOffset,
                string error) =>
                new(startIndex, endOffset, 0, null, null, null, null, false, false, error);
        }

        private sealed record ComplexKeyData(
            int EndRecordIndex,
            int ValuePosition,
            bool Shared,
            bool SharedSet,
            string KeyKind,
            string? Key,
            BamlComplexKeyModel? Model,
            string? Error)
        {
            public static ComplexKeyData Invalid(int startIndex, string error) =>
                new(startIndex, 0, false, false, "complex", null, null, error);
        }

        private sealed record ComplexKeySummary(string Kind, string? Value, string? Error);

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
