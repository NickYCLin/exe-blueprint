using System.Text;
using System.Buffers.Binary;

namespace ExeBlueprint.Analysis;

internal sealed class BinarySignalReader
{
    private static readonly byte[] DotNetBundleMarker = Convert.FromHexString(
        "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");

    private readonly byte[] _sample;
    private readonly bool _isDotNetBundle;

    private BinarySignalReader(byte[] sample, bool isDotNetBundle)
    {
        _sample = sample;
        _isDotNetBundle = isDotNetBundle;
    }

    public static async Task<BinarySignalReader> CreateAsync(
        string path,
        int maxSampleBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            useAsync: true);
        var isDotNetBundle = await DetectDotNetBundleAsync(stream, cancellationToken).ConfigureAwait(false);
        stream.Position = 0;

        if (stream.Length <= maxSampleBytes)
        {
            var bytes = new byte[checked((int)stream.Length)];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            return new BinarySignalReader(bytes, isDotNetBundle);
        }

        var half = maxSampleBytes / 2;
        var sample = new byte[maxSampleBytes];
        await stream.ReadExactlyAsync(sample.AsMemory(0, half), cancellationToken).ConfigureAwait(false);
        stream.Seek(-half, SeekOrigin.End);
        await stream.ReadExactlyAsync(sample.AsMemory(half, half), cancellationToken).ConfigureAwait(false);
        return new BinarySignalReader(sample, isDotNetBundle);
    }

    public ReadOnlySpan<byte> Header => _sample.AsSpan(0, Math.Min(_sample.Length, 4096));

    public bool Contains(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        return _sample.AsSpan().IndexOf(Encoding.ASCII.GetBytes(text)) >= 0 ||
               _sample.AsSpan().IndexOf(Encoding.Unicode.GetBytes(text)) >= 0;
    }

    public bool IsDotNetSingleFileBundle() => _isDotNetBundle;

    private static async Task<bool> DetectDotNetBundleAsync(
        FileStream stream,
        CancellationToken cancellationToken)
    {
        const int chunkSize = 1024 * 1024;
        var overlapSize = DotNetBundleMarker.Length + sizeof(long) - 1;
        var buffer = new byte[chunkSize + overlapSize];
        var carry = 0;
        long consumed = 0;

        while (true)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(carry, chunkSize),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            var available = carry + read;
            var searchStart = 0;
            while (searchStart <= available - DotNetBundleMarker.Length)
            {
                var relativeIndex = buffer.AsSpan(searchStart, available - searchStart).IndexOf(DotNetBundleMarker);
                if (relativeIndex < 0)
                {
                    break;
                }

                var markerIndex = searchStart + relativeIndex;
                if (markerIndex >= sizeof(long))
                {
                    var headerOffset = BinaryPrimitives.ReadInt64LittleEndian(
                        buffer.AsSpan(markerIndex - sizeof(long), sizeof(long)));
                    var markerFileOffset = consumed - carry + markerIndex;
                    if (headerOffset > markerFileOffset && headerOffset < stream.Length)
                    {
                        return true;
                    }
                }

                searchStart = markerIndex + 1;
            }

            carry = Math.Min(overlapSize, available);
            Buffer.BlockCopy(buffer, available - carry, buffer, 0, carry);
            consumed += read;
        }
    }
}
