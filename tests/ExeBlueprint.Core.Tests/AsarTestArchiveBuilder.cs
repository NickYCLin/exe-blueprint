using System.Buffers.Binary;
using System.Text;

namespace ExeBlueprint.Core.Tests;

internal static class AsarTestArchiveBuilder
{
    public static byte[] Create(string headerJson, ReadOnlySpan<byte> data = default) =>
        Create(Encoding.UTF8.GetBytes(headerJson), data);

    public static byte[] Create(ReadOnlySpan<byte> headerJson, ReadOnlySpan<byte> data = default)
    {
        var alignedJsonLength = AlignToFour(headerJson.Length);
        var headerPayloadLength = checked(sizeof(int) + alignedJsonLength);
        var headerPickleLength = checked(sizeof(uint) + headerPayloadLength);
        var result = new byte[checked(8 + headerPickleLength + data.Length)];

        BinaryPrimitives.WriteUInt32LittleEndian(result, sizeof(uint));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(sizeof(uint)), (uint)headerPickleLength);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), (uint)headerPayloadLength);
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(12), headerJson.Length);
        headerJson.CopyTo(result.AsSpan(16));
        data.CopyTo(result.AsSpan(8 + headerPickleLength));
        return result;
    }

    public static Task WriteAsync(
        string path,
        string headerJson,
        ReadOnlyMemory<byte> data = default) =>
        File.WriteAllBytesAsync(path, Create(headerJson, data.Span));

    private static int AlignToFour(int value) => checked((value + 3) & ~3);
}
