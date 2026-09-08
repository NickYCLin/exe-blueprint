using System.Buffers.Binary;
using ExeBlueprint.Models;

namespace ExeBlueprint.Analysis;

// 只讀固定長度的檔頭，不解壓像素、不讀取中繼資料，也不載入影像函式庫。
internal static class ResourceImageHeaderReader
{
    internal static ResourceImageHeaderModel? Read(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<byte> pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if (data.StartsWith(pngSignature))
        {
            return ReadPng(data);
        }

        if (data.StartsWith("GIF87a"u8) || data.StartsWith("GIF89a"u8))
        {
            return ReadGif(data);
        }

        return null;
    }

    private static ResourceImageHeaderModel ReadPng(ReadOnlySpan<byte> data)
    {
        if (data.Length < 33)
        {
            return Invalid("png", "PNG 的 IHDR 檔頭不完整。");
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(data[8..]) != 13 || !data.Slice(12, 4).SequenceEqual("IHDR"u8))
        {
            return Invalid("png", "PNG 第一個 chunk 不是長度為 13 的 IHDR。");
        }

        if (Crc32(data.Slice(12, 17)) != BinaryPrimitives.ReadUInt32BigEndian(data[29..]))
        {
            return Invalid("png", "PNG 的 IHDR CRC 不符。");
        }

        var width = BinaryPrimitives.ReadUInt32BigEndian(data[16..]);
        var height = BinaryPrimitives.ReadUInt32BigEndian(data[20..]);
        if (width is 0 or > int.MaxValue || height is 0 or > int.MaxValue)
        {
            return Invalid("png", "PNG 檔頭的寬高不在有效範圍。");
        }

        var validDepth = data[25] switch
        {
            0 => data[24] is 1 or 2 or 4 or 8 or 16,
            2 or 4 or 6 => data[24] is 8 or 16,
            3 => data[24] is 1 or 2 or 4 or 8,
            _ => false
        };
        if (!validDepth || data[26] != 0 || data[27] != 0 || data[28] > 1)
        {
            return Invalid("png", "PNG 檔頭的色彩、位元深度或編碼欄位無效。");
        }

        return Parsed("png", (int)width, (int)height);
    }

    private static ResourceImageHeaderModel ReadGif(ReadOnlySpan<byte> data)
    {
        if (data.Length < 13)
        {
            return Invalid("gif", "GIF 的 logical screen descriptor 不完整。");
        }

        var width = BinaryPrimitives.ReadUInt16LittleEndian(data[6..]);
        var height = BinaryPrimitives.ReadUInt16LittleEndian(data[8..]);
        return width == 0 || height == 0
            ? Invalid("gif", "GIF 檔頭的畫布寬高不可為零。")
            : Parsed("gif", width, height);
    }

    private static uint Crc32(ReadOnlySpan<byte> bytes)
    {
        var crc = uint.MaxValue;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc >> 1) ^ ((crc & 1) == 0 ? 0u : 0xEDB88320u);
            }
        }

        return ~crc;
    }

    private static ResourceImageHeaderModel Parsed(string format, int width, int height) =>
        new() { Format = format, Status = "parsed", Width = width, Height = height };

    private static ResourceImageHeaderModel Invalid(string format, string error) =>
        new() { Format = format, Status = "invalid", Error = error };
}
