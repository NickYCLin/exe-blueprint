using System.Buffers.Binary;
using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 只讀 BAML 檔頭與 record 邊界，不解析屬性值，也不載入 WPF assembly。
internal static class BamlSummaryReader
{
    private const int HeaderSize = 28;
    private const int MaxRecords = 100_000;
    private const int VariableRecord = -1;
    private const int UnsupportedRecord = -2;

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

                position += payloadSize;
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
            RecordsTruncated = truncated,
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
        string error) =>
        new()
        {
            Status = "partial",
            Signature = signature,
            ReaderVersion = readerVersion,
            UpdaterVersion = updaterVersion,
            WriterVersion = writerVersion,
            RecordCount = recordCounts.Values.Sum(),
            RecordTypes = BuildRecordCounts(recordCounts),
            RecordsTruncated = recordsTruncated,
            Error = error
        };

    private static BamlSummaryModel Invalid(string error, string? signature = null) =>
        new()
        {
            Status = "invalid",
            Signature = signature,
            Error = error
        };
}
