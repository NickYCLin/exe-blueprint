using System.IO.Compression;

namespace ExeBlueprint.Input;

internal sealed class InputWorkspace : IAsyncDisposable
{
    private readonly string? _temporaryDirectory;

    private InputWorkspace(
        string sourcePath,
        string rootPath,
        string kind,
        string name,
        string? singleFilePath,
        string? temporaryDirectory,
        IReadOnlyList<string> warnings)
    {
        SourcePath = sourcePath;
        RootPath = rootPath;
        Kind = kind;
        Name = name;
        SingleFilePath = singleFilePath;
        _temporaryDirectory = temporaryDirectory;
        Warnings = warnings;
    }

    public string SourcePath { get; }

    public string RootPath { get; }

    public string Kind { get; }

    public string Name { get; }

    public string? SingleFilePath { get; }

    public IReadOnlyList<string> Warnings { get; }

    public static async Task<InputWorkspace> OpenAsync(
        string inputPath,
        int maxFiles,
        long maxTotalBytes,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);

        var fullPath = Path.GetFullPath(inputPath);
        if (Directory.Exists(fullPath))
        {
            return new InputWorkspace(
                fullPath,
                fullPath,
                "directory",
                new DirectoryInfo(fullPath).Name,
                null,
                null,
                []);
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("找不到輸入檔案或資料夾。", fullPath);
        }

        if (!IsZipFile(fullPath))
        {
            return new InputWorkspace(
                fullPath,
                Path.GetDirectoryName(fullPath)!,
                "file",
                Path.GetFileName(fullPath),
                fullPath,
                null,
                []);
        }

        var tempRoot = Path.Combine(Path.GetTempPath(), "exe-blueprint");
        Directory.CreateDirectory(tempRoot);
        var extractionDirectory = Path.Combine(tempRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(extractionDirectory);

        try
        {
            var warnings = await ExtractZipSafelyAsync(
                fullPath,
                extractionDirectory,
                maxFiles,
                maxTotalBytes,
                cancellationToken).ConfigureAwait(false);

            return new InputWorkspace(
                fullPath,
                extractionDirectory,
                "zip",
                Path.GetFileNameWithoutExtension(fullPath),
                null,
                extractionDirectory,
                warnings);
        }
        catch
        {
            Directory.Delete(extractionDirectory, recursive: true);
            throw;
        }
    }

    public IEnumerable<string> EnumerateFiles(int maxFiles, ICollection<string> warnings)
    {
        if (SingleFilePath is not null)
        {
            yield return SingleFilePath;
            yield break;
        }

        var pending = new Stack<string>();
        pending.Push(RootPath);
        var count = 0;

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(current).EnumerateFileSystemInfos();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                warnings.Add($"無法讀取目錄：{GetRelativePath(current)}（{exception.Message}）");
                continue;
            }

            foreach (var entry in entries)
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    warnings.Add($"略過重新解析點：{GetRelativePath(entry.FullName)}");
                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    pending.Push(directory.FullName);
                    continue;
                }

                count++;
                if (count > maxFiles)
                {
                    throw new InvalidDataException($"檔案數超過限制：{maxFiles:N0}");
                }

                yield return entry.FullName;
            }
        }
    }

    public string GetRelativePath(string filePath)
    {
        if (SingleFilePath is not null)
        {
            return Path.GetFileName(filePath);
        }

        return Path.GetRelativePath(RootPath, filePath).Replace('\\', '/');
    }

    public ValueTask DisposeAsync()
    {
        if (_temporaryDirectory is not null && Directory.Exists(_temporaryDirectory))
        {
            Directory.Delete(_temporaryDirectory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private static bool IsZipFile(string path)
    {
        Span<byte> signature = stackalloc byte[4];
        using var stream = File.OpenRead(path);
        return stream.Read(signature) == signature.Length &&
               signature[0] == 0x50 &&
               signature[1] == 0x4B &&
               signature[2] is 0x03 or 0x05 or 0x07 &&
               signature[3] is 0x04 or 0x06 or 0x08;
    }

    private static async Task<IReadOnlyList<string>> ExtractZipSafelyAsync(
        string archivePath,
        string destinationRoot,
        int maxFiles,
        long maxTotalBytes,
        CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        var normalizedRoot = Path.GetFullPath(destinationRoot)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count > maxFiles)
        {
            throw new InvalidDataException($"壓縮檔項目數超過限制：{maxFiles:N0}");
        }

        long totalBytes = 0;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (IsSymbolicLink(entry))
            {
                warnings.Add($"略過符號連結：{entry.FullName}");
                continue;
            }

            totalBytes = checked(totalBytes + entry.Length);
            if (totalBytes > maxTotalBytes)
            {
                throw new InvalidDataException($"解壓後大小超過限制：{maxTotalBytes:N0} bytes");
            }

            var relativeName = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
            var destinationPath = Path.GetFullPath(Path.Combine(destinationRoot, relativeName));
            if (!destinationPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"壓縮檔包含不安全路徑：{entry.FullName}");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                Directory.CreateDirectory(destinationPath);
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            await using var input = entry.Open();
            await using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                81920,
                useAsync: true);
            await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
        }

        return warnings;
    }

    private static bool IsSymbolicLink(ZipArchiveEntry entry)
    {
        const int fileTypeMask = 0xF000;
        const int symbolicLinkType = 0xA000;
        var unixMode = (entry.ExternalAttributes >> 16) & fileTypeMask;
        return unixMode == symbolicLinkType;
    }
}
