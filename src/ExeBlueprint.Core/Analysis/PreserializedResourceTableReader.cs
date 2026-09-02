using System.Buffers.Binary;
using System.Text;

namespace ExeBlueprint.Analysis;

// 只解析 System.Resources.Extensions 的表格與原始 payload，不載入自訂型別。
internal static class PreserializedResourceTableReader
{
    private const int ResourceManagerMagic = unchecked((int)0xBEEFCACE);
    private const int ResourceManagerHeaderVersion = 1;
    private const int ResourceFileVersion = 2;
    private const int StartOfUserTypes = 64;
    private const int MaxDeclaredEntries = 100_000;
    private const int MaxDeclaredTypes = 2_000;
    private const int MaxHeaderStringBytes = 16_384;
    private const int MaxTypeNameBytes = 8_192;
    private const int MaxResourceNameBytes = 8_192;
    private const string ReaderTypePrefix =
        "System.Resources.Extensions.DeserializingResourceReader,";

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly UnicodeEncoding StrictUtf16 = new(false, false, true);

    public static PreserializedResourceTableReadResult TryRead(byte[] data, int entryLimit)
    {
        var position = 0;
        if (!TryReadInt32(data, ref position, out var magic)
            || magic != ResourceManagerMagic
            || !TryReadInt32(data, ref position, out var headerVersion)
            || !TryReadInt32(data, ref position, out var headerByteCount)
            || headerVersion != ResourceManagerHeaderVersion
            || headerByteCount < 0
            || headerByteCount > data.Length - position)
        {
            return PreserializedResourceTableReadResult.NotMatched;
        }

        var headerEnd = position + headerByteCount;
        if (!TryReadString(
                data,
                ref position,
                headerEnd,
                MaxHeaderStringBytes,
                StrictUtf8,
                out var readerType)
            || !readerType.StartsWith(ReaderTypePrefix, StringComparison.Ordinal))
        {
            return PreserializedResourceTableReadResult.NotMatched;
        }

        if (!TryReadString(
                data,
                ref position,
                headerEnd,
                MaxHeaderStringBytes,
                StrictUtf8,
                out _)
            || position > headerEnd)
        {
            return Invalid("預序列化資源的 ResourceManager header 格式損壞。");
        }

        position = headerEnd;
        if (!TryReadInt32(data, ref position, out var version)
            || version != ResourceFileVersion)
        {
            return Invalid("預序列化資源只支援 .resources v2 格式。");
        }

        if (!TryReadInt32(data, ref position, out var resourceCount)
            || resourceCount < 0
            || resourceCount > MaxDeclaredEntries)
        {
            return Invalid($"預序列化資源數量超過 {MaxDeclaredEntries:N0} 筆安全解析上限或格式無效。");
        }

        if (!TryReadInt32(data, ref position, out var typeCount)
            || typeCount < 0
            || typeCount > MaxDeclaredTypes)
        {
            return Invalid($"預序列化資源型別超過 {MaxDeclaredTypes:N0} 筆安全解析上限或格式無效。");
        }

        var typeNames = new string[typeCount];
        for (var index = 0; index < typeNames.Length; index++)
        {
            if (!TryReadString(
                    data,
                    ref position,
                    data.Length,
                    MaxTypeNameBytes,
                    StrictUtf8,
                    out typeNames[index]))
            {
                return Invalid("預序列化資源的型別名稱已截斷、過長或不是有效 UTF-8。");
            }
        }

        var alignmentBytes = (8 - (position & 7)) & 7;
        if (alignmentBytes > data.Length - position)
        {
            return Invalid("預序列化資源的 alignment padding 已截斷。");
        }

        position += alignmentBytes;
        var tableBytes = checked((long)resourceCount * sizeof(int));
        if (tableBytes > data.Length - position)
        {
            return Invalid("預序列化資源的 name hash 表已截斷。");
        }

        position += (int)tableBytes;
        if (tableBytes > data.Length - position)
        {
            return Invalid("預序列化資源的 name position 表已截斷。");
        }

        var namePositions = new int[resourceCount];
        for (var index = 0; index < namePositions.Length; index++)
        {
            if (!TryReadInt32(data, ref position, out namePositions[index])
                || namePositions[index] < 0)
            {
                return Invalid("預序列化資源包含無效的 name position。");
            }
        }

        if (!TryReadInt32(data, ref position, out var dataSectionOffset)
            || dataSectionOffset < position
            || dataSectionOffset > data.Length
            || resourceCount > 0 && dataSectionOffset == data.Length)
        {
            return Invalid("預序列化資源包含無效的 data section offset。");
        }

        var nameSectionOffset = position;
        var dataSectionLength = data.Length - dataSectionOffset;
        var dataPositions = new int[resourceCount];
        var retained = new List<PreserializedResourceDataEntry>(Math.Min(resourceCount, entryLimit));
        for (var index = 0; index < resourceCount; index++)
        {
            if (namePositions[index] > dataSectionOffset - nameSectionOffset)
            {
                return Invalid("預序列化資源包含超出 name section 的位置。");
            }

            var namePosition = nameSectionOffset + namePositions[index];
            if (!TryReadString(
                    data,
                    ref namePosition,
                    dataSectionOffset,
                    MaxResourceNameBytes,
                    StrictUtf16,
                    out var name)
                || !TryReadInt32(data, ref namePosition, out var dataPosition)
                || dataPosition < 0
                || dataPosition >= dataSectionLength)
            {
                return Invalid("預序列化資源包含無效的名稱或資料位置。");
            }

            dataPositions[index] = dataPosition;
            if (retained.Count < entryLimit)
            {
                retained.Add(new PreserializedResourceDataEntry(name, dataPosition, string.Empty, []));
            }
        }

        var sortedDataPositions = (int[])dataPositions.Clone();
        Array.Sort(sortedDataPositions);
        for (var index = 1; index < sortedDataPositions.Length; index++)
        {
            if (sortedDataPositions[index] == sortedDataPositions[index - 1])
            {
                return Invalid("預序列化資源包含重複的資料位置。");
            }
        }

        for (var index = 0; index < retained.Count; index++)
        {
            var entry = retained[index];
            var sortedIndex = Array.BinarySearch(sortedDataPositions, entry.DataPosition);
            if (sortedIndex < 0)
            {
                return Invalid("預序列化資源的資料位置索引不一致。");
            }

            var dataEnd = sortedIndex + 1 < sortedDataPositions.Length
                ? dataSectionOffset + sortedDataPositions[sortedIndex + 1]
                : data.Length;
            var dataPosition = dataSectionOffset + entry.DataPosition;
            if (!TryRead7BitEncodedInt(data, ref dataPosition, dataEnd, out var typeCode)
                || !TryResolveTypeName(typeCode, typeNames, out var typeName))
            {
                return Invalid($"預序列化資源 `{entry.Name}` 包含無效的型別代碼。");
            }

            retained[index] = entry with
            {
                Type = typeName,
                Data = data.AsSpan(dataPosition, dataEnd - dataPosition).ToArray()
            };
        }

        return new PreserializedResourceTableReadResult(
            true,
            retained,
            resourceCount > retained.Count,
            null);
    }

    private static bool TryResolveTypeName(int typeCode, IReadOnlyList<string> typeNames, out string typeName)
    {
        typeName = string.Empty;
        if (TryGetBuiltInTypeName(typeCode, out var builtInType))
        {
            typeName = $"ResourceTypeCode.{builtInType}";
            return true;
        }

        var typeIndex = typeCode - StartOfUserTypes;
        if (typeIndex < 0 || typeIndex >= typeNames.Count)
        {
            return false;
        }

        typeName = typeNames[typeIndex];
        return true;
    }

    private static bool TryGetBuiltInTypeName(int typeCode, out string name)
    {
        name = typeCode switch
        {
            0 => "Null",
            1 => "String",
            2 => "Boolean",
            3 => "Char",
            4 => "Byte",
            5 => "SByte",
            6 => "Int16",
            7 => "UInt16",
            8 => "Int32",
            9 => "UInt32",
            10 => "Int64",
            11 => "UInt64",
            12 => "Single",
            13 => "Double",
            14 => "Decimal",
            15 => "DateTime",
            16 => "TimeSpan",
            32 => "ByteArray",
            33 => "Stream",
            _ => string.Empty
        };
        return name.Length > 0;
    }

    private static bool TryReadString(
        byte[] data,
        ref int position,
        int end,
        int byteLimit,
        Encoding encoding,
        out string value)
    {
        value = string.Empty;
        if (!TryRead7BitEncodedInt(data, ref position, end, out var byteLength)
            || byteLength > byteLimit
            || encoding == StrictUtf16 && (byteLength & 1) != 0
            || byteLength > end - position)
        {
            return false;
        }

        try
        {
            value = encoding.GetString(data, position, byteLength);
            position += byteLength;
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool TryRead7BitEncodedInt(byte[] data, ref int position, int end, out int value)
    {
        value = 0;
        uint result = 0;
        for (var index = 0; index < 5; index++)
        {
            if (position >= end)
            {
                return false;
            }

            var current = data[position++];
            if (index == 4 && current > 0x07)
            {
                return false;
            }

            result |= (uint)(current & 0x7F) << (index * 7);
            if ((current & 0x80) == 0)
            {
                if ((index > 0 && result < 1u << (index * 7)) || result > int.MaxValue)
                {
                    return false;
                }

                value = (int)result;
                return true;
            }
        }

        return false;
    }

    private static bool TryReadInt32(byte[] data, ref int position, out int value)
    {
        value = 0;
        if (position < 0 || data.Length - position < sizeof(int))
        {
            return false;
        }

        value = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(position, sizeof(int)));
        position += sizeof(int);
        return true;
    }

    private static PreserializedResourceTableReadResult Invalid(string error) =>
        new(true, [], false, error);
}

internal sealed record PreserializedResourceDataEntry(
    string Name,
    int DataPosition,
    string Type,
    byte[] Data);

internal sealed record PreserializedResourceTableReadResult(
    bool Matched,
    IReadOnlyList<PreserializedResourceDataEntry> Entries,
    bool Truncated,
    string? Error)
{
    public static PreserializedResourceTableReadResult NotMatched { get; } =
        new(false, [], false, null);
}
