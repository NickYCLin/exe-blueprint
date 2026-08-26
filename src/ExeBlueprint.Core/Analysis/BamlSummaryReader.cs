using System.Buffers.Binary;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 只讀 BAML 檔頭、record 邊界及檔案內宣告的型別／屬性 ID，不解析屬性值，也不載入 WPF assembly。
internal static class BamlSummaryReader
{
    private const int HeaderSize = 28;
    private const int MaxRecords = 100_000;
    private const int MaxSymbols = 2_000;
    private const int MaxMetadataStringBytes = 8_192;
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
                    $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度規則不受支援，停止於 offset {recordOffset}。");
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
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度欄位已截斷。");
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
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的長度超出資料範圍。");
                }

                if (!symbols.TryReadRecord(recordType, data[position..(int)nextPosition], out var symbolError))
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
                        $"BAML record {GetRecordName(recordType)} ({recordType}) 的內容已截斷。");
                }

                var nextPosition = position + payloadSize;
                if (!symbols.TryReadRecord(recordType, data[position..nextPosition], out var symbolError))
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
            Properties = symbols.BuildProperties(),
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
            Properties = symbols?.BuildProperties() ?? [],
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

    private sealed class SymbolTable
    {
        private readonly Dictionary<short, string> _assemblies = [];
        private readonly Dictionary<short, TypeDeclaration> _types = [];
        private readonly Dictionary<short, AttributeDeclaration> _attributes = [];
        private readonly Dictionary<short, int> _elementTypes = [];
        private readonly Dictionary<short, int> _properties = [];

        public int ElementCount { get; private set; }

        public int PropertyCount { get; private set; }

        public short? RootElementTypeId { get; private set; }

        public bool Truncated { get; private set; }

        public bool TryReadRecord(byte recordType, ReadOnlySpan<byte> payload, out string? error)
        {
            error = null;
            return recordType switch
            {
                3 => TryReadElement(payload, out error),
                28 => TryReadAssembly(payload, out error),
                29 => TryReadType(payload, hasSerializer: false, out error),
                30 => TryReadType(payload, hasSerializer: true, out error),
                31 => TryReadAttribute(payload, out error),
                5 or 6 or 7 or 9 or 11 or 13 or 18 or 33 or 34 or 35 or 36 or 46 or 56
                    => TryReadProperty(payload, out error),
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

        private string? ResolveTypeName(short id) =>
            id < 0
                ? WpfBamlKnownIds.GetTypeName(id)
                : _types.TryGetValue(id, out var declaration)
                    ? declaration.Name
                    : null;

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

        private bool TryReadElement(ReadOnlySpan<byte> payload, out string? error)
        {
            var position = 0;
            if (!TryReadInt16(payload, ref position, out var typeId))
            {
                error = "element type ID 已截斷。";
                return false;
            }

            RootElementTypeId ??= typeId;
            ElementCount++;
            AddUsage(_elementTypes, typeId);
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
    }
}
