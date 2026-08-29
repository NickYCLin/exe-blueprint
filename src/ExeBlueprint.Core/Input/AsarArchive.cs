using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace ExeBlueprint.Input;

internal sealed class AsarArchive : IAsyncDisposable
{
    private const int OuterPickleSize = 8;
    private const int MaximumHeaderBytes = 32 * 1024 * 1024;
    private const int MaximumHeaderNodes = 100_000;
    private const int MaximumDirectoryDepth = 64;
    private const int MaximumLogicalPathCharacters = 16_384;
    private const int MaximumRetainedPathCharacters = 8 * 1024 * 1024;
    private const int MaximumWarningCount = 100;
    private const long MaximumJavaScriptSafeInteger = 9_007_199_254_740_991;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly FileStream _stream;

    private AsarArchive(
        FileStream stream,
        IReadOnlyList<AsarArchiveEntry> entries,
        IReadOnlyList<AsarUnpackedEntry> unpackedEntries,
        IReadOnlyList<AsarLinkEntry> links,
        IReadOnlyList<string> warnings,
        int headerBytes,
        int nodeCount)
    {
        _stream = stream;
        Entries = entries;
        UnpackedEntries = unpackedEntries;
        Links = links;
        Warnings = warnings;
        HeaderBytes = headerBytes;
        NodeCount = nodeCount;
    }

    public IReadOnlyList<AsarArchiveEntry> Entries { get; }

    public IReadOnlyList<AsarUnpackedEntry> UnpackedEntries { get; }

    public IReadOnlyList<AsarLinkEntry> Links { get; }

    public IReadOnlyList<string> Warnings { get; }

    public int HeaderBytes { get; }

    public int NodeCount { get; }

    public static async Task<AsarArchive> OpenAsync(
        string archivePath,
        int maxFiles,
        long maxTotalBytes,
        long maxFileBytes,
        CancellationToken cancellationToken) =>
        await OpenAsync(
            archivePath,
            maxFiles,
            maxTotalBytes,
            maxFileBytes,
            MaximumRetainedPathCharacters,
            cancellationToken).ConfigureAwait(false);

    internal static async Task<AsarArchive> OpenAsync(
        string archivePath,
        int maxFiles,
        long maxTotalBytes,
        long maxFileBytes,
        int maxRetainedPathCharacters,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(archivePath);
        if (maxFiles <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxFiles));
        }

        if (maxTotalBytes <= 0 || maxFileBytes <= 0 || maxRetainedPathCharacters <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxTotalBytes));
        }

        FileStream? stream = null;
        try
        {
            stream = new FileStream(
                Path.GetFullPath(archivePath),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                81920,
                FileOptions.Asynchronous | FileOptions.RandomAccess);

            var prefix = new byte[OuterPickleSize];
            await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
            if (BinaryPrimitives.ReadUInt32LittleEndian(prefix) != sizeof(uint))
            {
                throw Invalid("外層 Pickle payload 長度不是 4 bytes");
            }

            var headerPickleSize = BinaryPrimitives.ReadUInt32LittleEndian(prefix.AsSpan(sizeof(uint)));
            if (headerPickleSize < 8 ||
                headerPickleSize > MaximumHeaderBytes ||
                (headerPickleSize & 3) != 0 ||
                headerPickleSize > stream.Length - OuterPickleSize)
            {
                throw Invalid("header Pickle 長度無效或超過限制");
            }

            var headerBuffer = new byte[checked((int)headerPickleSize)];
            await ReadExactlyAsync(stream, headerBuffer, cancellationToken).ConfigureAwait(false);
            var headerJson = ReadHeaderJson(headerBuffer);
            var dataOffset = checked(OuterPickleSize + (long)headerPickleSize);
            var parsed = ParseHeader(
                headerJson,
                dataOffset,
                stream.Length,
                maxFiles,
                maxTotalBytes,
                maxFileBytes,
                maxRetainedPathCharacters);

            var archive = new AsarArchive(
                stream,
                parsed.Entries,
                parsed.UnpackedEntries,
                parsed.Links,
                parsed.Warnings,
                headerBuffer.Length,
                parsed.NodeCount);
            stream = null;
            return archive;
        }
        catch (EndOfStreamException exception)
        {
            throw Invalid("檔案在 ASAR header 結束前已截斷", exception);
        }
        finally
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public async Task CopyEntryToAsync(
        AsarArchiveEntry entry,
        Stream destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(destination);
        if (!destination.CanWrite)
        {
            throw new ArgumentException("目的串流不可寫入。", nameof(destination));
        }

        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long copied = 0;
            while (copied < entry.Size)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var requested = (int)Math.Min(buffer.Length, entry.Size - copied);
                var read = await RandomAccess.ReadAsync(
                    _stream.SafeFileHandle,
                    buffer.AsMemory(0, requested),
                    checked(entry.DataOffset + copied),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw Invalid($"項目 {entry.RelativePath} 的內容已截斷");
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                copied += read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public ValueTask DisposeAsync() => _stream.DisposeAsync();

    private static string ReadHeaderJson(byte[] headerBuffer)
    {
        var payloadSize = BinaryPrimitives.ReadUInt32LittleEndian(headerBuffer);
        if ((ulong)payloadSize + sizeof(uint) != (ulong)headerBuffer.Length)
        {
            throw Invalid("header Pickle payload 長度與外層宣告不一致");
        }

        var stringSize = BinaryPrimitives.ReadInt32LittleEndian(headerBuffer.AsSpan(sizeof(uint)));
        if (stringSize < 0)
        {
            throw Invalid("header JSON 長度不可為負數");
        }

        if (stringSize > headerBuffer.Length - (sizeof(uint) + sizeof(int)))
        {
            throw Invalid("header JSON 長度超出 header Pickle");
        }

        var alignedStringSize = AlignToFour(stringSize);
        if (checked(sizeof(int) + alignedStringSize) != payloadSize)
        {
            throw Invalid("header JSON 長度或 Pickle padding 無效");
        }

        var jsonStart = sizeof(uint) + sizeof(int);
        var jsonEnd = checked(jsonStart + stringSize);
        for (var index = jsonEnd; index < headerBuffer.Length; index++)
        {
            if (headerBuffer[index] != 0)
            {
                throw Invalid("header Pickle padding 必須為零");
            }
        }

        try
        {
            return StrictUtf8.GetString(headerBuffer, jsonStart, stringSize);
        }
        catch (DecoderFallbackException exception)
        {
            throw Invalid("header JSON 不是有效的 UTF-8", exception);
        }
    }

    private static ParsedAsarHeader ParseHeader(
        string headerJson,
        long dataOffset,
        long archiveLength,
        int maxFiles,
        long maxTotalBytes,
        long maxFileBytes,
        int maxRetainedPathCharacters)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(
                headerJson,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = checked((MaximumDirectoryDepth * 2) + 8)
                });
        }
        catch (JsonException exception)
        {
            throw Invalid("header JSON 無效", exception);
        }

        using (document)
        {
            var root = document.RootElement;
            RequireObject(root, "/");
            EnsureUniqueProperties(root, "/");
            if (!root.TryGetProperty("files", out var rootFiles) || rootFiles.ValueKind != JsonValueKind.Object)
            {
                throw Invalid("header 根節點缺少 files 物件");
            }

            var entries = new List<AsarArchiveEntry>();
            var unpackedEntries = new List<AsarUnpackedEntry>();
            var warnings = new List<string>();
            var pending = new Queue<PendingDirectory>();
            pending.Enqueue(new PendingDirectory(rootFiles, string.Empty, 0));
            var nodeKinds = new Dictionary<string, AsarNodeKind>(StringComparer.Ordinal);
            var links = new List<AsarLinkEntry>();
            var nodeCount = 0;
            var fileCount = 0;
            var omittedWarningCount = 0;
            long totalBytes = 0;
            long retainedPathCharacters = 0;

            while (pending.Count > 0)
            {
                var directory = pending.Dequeue();
                if (directory.Depth > MaximumDirectoryDepth)
                {
                    throw Invalid($"ASAR 目錄深度超過限制：{MaximumDirectoryDepth}");
                }

                EnsureUniqueProperties(directory.Files, DisplayPath(directory.RelativePath));
                var portableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var child in directory.Files.EnumerateObject())
                {
                    nodeCount++;
                    if (nodeCount > MaximumHeaderNodes)
                    {
                        throw Invalid($"ASAR header 節點數超過限制：{MaximumHeaderNodes:N0}");
                    }

                    ValidateEntryName(child.Name);
                    string portableName;
                    try
                    {
                        portableName = child.Name.Normalize(NormalizationForm.FormC);
                    }
                    catch (ArgumentException exception)
                    {
                        throw Invalid($"ASAR 項目名稱包含無效 Unicode：{child.Name}", exception);
                    }

                    if (!portableNames.Add(portableName))
                    {
                        throw Invalid($"ASAR 目錄含有跨平台會衝突的名稱：{child.Name}");
                    }

                    var relativePath = directory.RelativePath.Length == 0
                        ? child.Name
                        : $"{directory.RelativePath}/{child.Name}";
                    if (relativePath.Length > MaximumLogicalPathCharacters)
                    {
                        throw Invalid($"ASAR 邏輯路徑超過限制：{MaximumLogicalPathCharacters:N0} 字元");
                    }

                    ReservePathCharacters(
                        ref retainedPathCharacters,
                        relativePath.Length,
                        maxRetainedPathCharacters);

                    var node = child.Value;
                    RequireObject(node, relativePath);
                    EnsureUniqueProperties(node, relativePath);
                    ValidateOptionalBoolean(node, "unpacked", relativePath);
                    ValidateOptionalBoolean(node, "executable", relativePath);
                    ValidateOptionalIntegrity(node, relativePath);

                    var hasLink = node.TryGetProperty("link", out var link);
                    var hasFiles = node.TryGetProperty("files", out var files);
                    var hasOffset = node.TryGetProperty("offset", out var offset);
                    var unpacked = node.TryGetProperty("unpacked", out var unpackedValue) && unpackedValue.GetBoolean();
                    if ((hasLink && (hasFiles || hasOffset)) || (hasFiles && hasOffset))
                    {
                        throw Invalid($"ASAR 項目類型不明或互相衝突：{relativePath}");
                    }

                    if (hasOffset && offset.ValueKind != JsonValueKind.String)
                    {
                        throw Invalid($"ASAR 項目 offset 必須是十進位字串：{relativePath}");
                    }

                    if (hasLink)
                    {
                        if (link.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(link.GetString()))
                        {
                            throw Invalid($"ASAR link 必須是非空字串：{relativePath}");
                        }

                        var rawTarget = link.GetString()!;
                        if (rawTarget.Length > MaximumLogicalPathCharacters)
                        {
                            throw Invalid($"ASAR link 目標超過限制：{MaximumLogicalPathCharacters:N0} 字元");
                        }

                        ReservePathCharacters(
                            ref retainedPathCharacters,
                            rawTarget.Length,
                            maxRetainedPathCharacters);
                        var target = NormalizeLinkTarget(rawTarget, relativePath);
                        nodeKinds.Add(relativePath, AsarNodeKind.Link);
                        links.Add(new AsarLinkEntry(relativePath, target));
                        AddWarning(
                            warnings,
                            ref omittedWarningCount,
                            $"略過 ASAR 連結：{relativePath}");
                        continue;
                    }

                    if (hasFiles)
                    {
                        if (files.ValueKind != JsonValueKind.Object)
                        {
                            throw Invalid($"ASAR 目錄的 files 必須是物件：{relativePath}");
                        }

                        nodeKinds.Add(relativePath, AsarNodeKind.Directory);
                        pending.Enqueue(new PendingDirectory(files, relativePath, directory.Depth + 1));
                        continue;
                    }

                    if (!hasOffset && !unpacked)
                    {
                        throw Invalid($"ASAR 項目類型不明：{relativePath}");
                    }

                    fileCount++;
                    if (fileCount > maxFiles)
                    {
                        throw Invalid($"ASAR 檔案數超過限制：{maxFiles:N0}");
                    }

                    var size = ReadSize(node, relativePath);
                    if (size > maxFileBytes)
                    {
                        throw Invalid($"ASAR 項目超過單檔限制：{relativePath}");
                    }

                    if (unpacked)
                    {
                        nodeKinds.Add(relativePath, AsarNodeKind.File);
                        unpackedEntries.Add(new AsarUnpackedEntry(
                            relativePath,
                            size,
                            node.TryGetProperty("executable", out var unpackedExecutable) && unpackedExecutable.GetBoolean()));
                        continue;
                    }

                    if (!hasOffset)
                    {
                        throw Invalid($"ASAR 項目 offset 必須是十進位字串：{relativePath}");
                    }

                    totalBytes = CheckedAdd(totalBytes, size, $"ASAR 項目總大小溢位：{relativePath}");
                    if (totalBytes > maxTotalBytes)
                    {
                        throw Invalid($"ASAR 項目總大小超過限制：{maxTotalBytes:N0} bytes");
                    }

                    var relativeOffsetText = offset.GetString()!;
                    if (relativeOffsetText.Length == 0 ||
                        relativeOffsetText.Any(character => character is < '0' or > '9') ||
                        !ulong.TryParse(relativeOffsetText, NumberStyles.None, CultureInfo.InvariantCulture, out var relativeOffset))
                    {
                        throw Invalid($"ASAR 項目 offset 無效：{relativePath}");
                    }

                    var absoluteOffset = CheckedAdd((ulong)dataOffset, relativeOffset, $"ASAR 項目 offset 溢位：{relativePath}");
                    var endOffset = CheckedAdd(absoluteOffset, (ulong)size, $"ASAR 項目範圍溢位：{relativePath}");
                    if (absoluteOffset > long.MaxValue || endOffset > (ulong)archiveLength)
                    {
                        throw Invalid($"ASAR 項目超出封存範圍：{relativePath}");
                    }

                    entries.Add(new AsarArchiveEntry(
                        relativePath,
                        (long)absoluteOffset,
                        size,
                        node.TryGetProperty("executable", out var executable) && executable.GetBoolean()));
                    nodeKinds.Add(relativePath, AsarNodeKind.File);
                }
            }

            ValidateLinks(links, nodeKinds);
            ValidateIntervals(entries);
            if (omittedWarningCount > 0)
            {
                warnings.Add($"另有 {omittedWarningCount:N0} 個 ASAR 警告未逐項列出。");
            }

            return new ParsedAsarHeader(entries, unpackedEntries, links, warnings, nodeCount);
        }
    }

    private static void ValidateIntervals(IReadOnlyList<AsarArchiveEntry> entries)
    {
        AsarArchiveEntry? previous = null;
        foreach (var entry in entries
                     .Where(item => item.Size > 0)
                     .OrderBy(item => item.DataOffset)
                     .ThenBy(item => item.Size))
        {
            if (previous is not null && entry.DataOffset < checked(previous.DataOffset + previous.Size))
            {
                if (entry.DataOffset != previous.DataOffset || entry.Size != previous.Size)
                {
                    throw Invalid($"ASAR 項目資料範圍重疊：{previous.RelativePath}、{entry.RelativePath}");
                }

                continue;
            }

            previous = entry;
        }
    }

    private static void ValidateEntryName(string name)
    {
        if (name.Length == 0 ||
            name is "." or ".." ||
            name.IndexOfAny(['/', '\\', ':', '<', '>', '"', '|', '?', '*']) >= 0 ||
            name.Any(char.IsControl) ||
            name.EndsWith(' ') ||
            name.EndsWith('.') ||
            Encoding.UTF8.GetByteCount(name) > 255 ||
            IsWindowsReservedName(name))
        {
            throw Invalid($"ASAR 項目名稱不安全：{name}");
        }
    }

    private static bool IsWindowsReservedName(string name)
    {
        var stem = name.Split('.', 2)[0];
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("NUL", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return stem.Length == 4 &&
               (stem[3] is >= '1' and <= '9' or '\u00B9' or '\u00B2' or '\u00B3') &&
               (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase));
    }

    private static string NormalizeLinkTarget(string target, string linkPath)
    {
        var normalized = target.Replace('\\', '/');
        if (normalized.StartsWith('/') || normalized.EndsWith('/'))
        {
            throw Invalid($"ASAR link 目標不安全：{linkPath}");
        }

        var segments = normalized.Split('/');
        if (segments.Length == 0)
        {
            throw Invalid($"ASAR link 目標不安全：{linkPath}");
        }

        foreach (var segment in segments)
        {
            ValidateEntryName(segment);
        }

        return string.Join('/', segments);
    }

    private static void ValidateLinks(
        IReadOnlyList<AsarLinkEntry> links,
        IReadOnlyDictionary<string, AsarNodeKind> nodeKinds)
    {
        const int maximumLinkDepth = 40;
        var targets = links.ToDictionary(link => link.RelativePath, link => link.Target, StringComparer.Ordinal);
        foreach (var link in links)
        {
            var target = link.Target;
            var visited = new HashSet<string>(StringComparer.Ordinal) { link.RelativePath };
            for (var depth = 0; ; depth++)
            {
                if (!nodeKinds.TryGetValue(target, out var kind))
                {
                    throw Invalid($"ASAR link 目標不存在：{link.RelativePath}");
                }

                if (kind != AsarNodeKind.Link)
                {
                    break;
                }

                if (depth >= maximumLinkDepth || !visited.Add(target))
                {
                    throw Invalid($"ASAR link 循環或超過 {maximumLinkDepth} 層：{link.RelativePath}");
                }

                target = targets[target];
            }
        }
    }

    private static void ReservePathCharacters(
        ref long retainedPathCharacters,
        int characters,
        int maximum)
    {
        retainedPathCharacters = CheckedAdd(
            retainedPathCharacters,
            characters,
            "ASAR 保留路徑字元數溢位");
        if (retainedPathCharacters > maximum)
        {
            throw Invalid($"ASAR 保留路徑字元數超過限制：{maximum:N0}");
        }
    }

    private static void AddWarning(
        ICollection<string> warnings,
        ref int omittedWarningCount,
        string warning)
    {
        if (warnings.Count < MaximumWarningCount)
        {
            warnings.Add(warning);
        }
        else
        {
            omittedWarningCount++;
        }
    }

    private static long ReadSize(JsonElement node, string path)
    {
        if (!node.TryGetProperty("size", out var size) ||
            size.ValueKind != JsonValueKind.Number ||
            !size.TryGetInt64(out var value) ||
            value < 0 ||
            value > MaximumJavaScriptSafeInteger)
        {
            throw Invalid($"ASAR 項目 size 必須是安全的非負整數：{path}");
        }

        return value;
    }

    private static void ValidateOptionalBoolean(JsonElement node, string propertyName, string path)
    {
        if (node.TryGetProperty(propertyName, out var value) &&
            value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw Invalid($"ASAR 項目 {propertyName} 必須是布林值：{path}");
        }
    }

    private static void ValidateOptionalIntegrity(JsonElement node, string path)
    {
        if (!node.TryGetProperty("integrity", out var integrity))
        {
            return;
        }

        RequireObject(integrity, $"{path}.integrity");
        EnsureUniqueProperties(integrity, $"{path}.integrity");
        if (!integrity.TryGetProperty("algorithm", out var algorithm) ||
            algorithm.ValueKind != JsonValueKind.String ||
            string.IsNullOrEmpty(algorithm.GetString()) ||
            algorithm.GetString()!.Length > 64 ||
            !integrity.TryGetProperty("hash", out var hash) ||
            hash.ValueKind != JsonValueKind.String ||
            hash.GetString()!.Length > 256 ||
            !integrity.TryGetProperty("blockSize", out var blockSize) ||
            blockSize.ValueKind != JsonValueKind.Number ||
            !blockSize.TryGetInt64(out var blockSizeValue) ||
            blockSizeValue <= 0 ||
            blockSizeValue > int.MaxValue ||
            !integrity.TryGetProperty("blocks", out var blocks) ||
            blocks.ValueKind != JsonValueKind.Array)
        {
            throw Invalid($"ASAR 項目 integrity 結構無效：{path}");
        }

        foreach (var block in blocks.EnumerateArray())
        {
            if (block.ValueKind != JsonValueKind.String || block.GetString()!.Length > 256)
            {
                throw Invalid($"ASAR 項目 integrity block 無效：{path}");
            }
        }
    }

    private static void RequireObject(JsonElement element, string path)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw Invalid($"ASAR 節點必須是物件：{path}");
        }
    }

    private static void EnsureUniqueProperties(JsonElement element, string path)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                throw Invalid($"ASAR JSON 含有重複屬性：{path}.{property.Name}");
            }
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                throw new EndOfStreamException();
            }

            read += current;
        }
    }

    private static int AlignToFour(int value) => checked((value + 3) & ~3);

    private static long CheckedAdd(long left, long right, string message)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw Invalid(message, exception);
        }
    }

    private static ulong CheckedAdd(ulong left, ulong right, string message)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw Invalid(message, exception);
        }
    }

    private static string DisplayPath(string path) => path.Length == 0 ? "/" : path;

    private static InvalidDataException Invalid(string message, Exception? innerException = null) =>
        new($"ASAR 格式無效：{message}", innerException);

    private sealed record PendingDirectory(JsonElement Files, string RelativePath, int Depth);

    private enum AsarNodeKind
    {
        Directory,
        File,
        Link
    }

    private sealed record ParsedAsarHeader(
        IReadOnlyList<AsarArchiveEntry> Entries,
        IReadOnlyList<AsarUnpackedEntry> UnpackedEntries,
        IReadOnlyList<AsarLinkEntry> Links,
        IReadOnlyList<string> Warnings,
        int NodeCount);
}

internal sealed record AsarArchiveEntry(
    string RelativePath,
    long DataOffset,
    long Size,
    bool Executable);

internal sealed record AsarUnpackedEntry(
    string RelativePath,
    long Size,
    bool Executable);

internal sealed record AsarLinkEntry(
    string RelativePath,
    string Target);
