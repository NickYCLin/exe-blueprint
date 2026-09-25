using System.Text;

namespace ExeBlueprint.Generation;

public static class GeneratedProjectWriter
{
    private const int MaximumPortablePathBytes = 1_023;
    private const int MaximumPortableSegmentBytes = 255;

    private static readonly HashSet<string> WindowsDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$"
    };

    public static async Task WriteAsync(
        IReadOnlyList<GeneratedFile> files,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);

        cancellationToken.ThrowIfCancellationRequested();
        var outputRoot = Path.GetFullPath(outputDirectory);
        EnsureSafeOutputRoot(outputRoot);
        var plannedFiles = PlanFiles(files, outputRoot);
        foreach (var planned in plannedFiles)
        {
            EnsureSafeExistingPath(outputRoot, planned.TargetPath);
        }

        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        foreach (var planned in plannedFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = Path.GetDirectoryName(planned.TargetPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            EnsureSafeOutputRoot(outputRoot);
            EnsureSafeExistingPath(outputRoot, planned.TargetPath);
            await WriteAtomicallyAsync(
                    planned,
                    encoding,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    // 單一報告檔（blueprint.json、REPORT.md）也走同一條安全路徑：把路徑拆成輸出根目錄與檔名，
    // 沿用根目錄／目標的 reparse point 檢查與 opaque 暫存檔加 move 的原子取代，讓既有的
    // symbolic link 不會被跟隨、既有的 hardlink 也不會讓外部 inode 被截斷。
    internal static Task WriteSingleFileAsync(
        string outputPath,
        string content,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(content);

        var fullPath = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory))
        {
            throw new InvalidDataException($"報告輸出路徑必須位於某個目錄之下：{outputPath}");
        }

        return WriteAsync(
            [new GeneratedFile { RelativePath = Path.GetFileName(fullPath), Content = content }],
            directory,
            cancellationToken);
    }

    private static IReadOnlyList<PlannedFile> PlanFiles(
        IReadOnlyList<GeneratedFile> files,
        string outputRoot)
    {
        var planned = new List<PlannedFile>(files.Count);
        var filePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var directoryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            if (file is null || file.Content is null)
            {
                throw InvalidPath("產生檔案及其內容不可為 null。");
            }

            var segments = ValidatePortableRelativePath(file.RelativePath);
            var portablePath = string.Join('/', segments);
            var collisionKey = CreateCollisionKey(portablePath);
            if (!filePaths.Add(collisionKey) || directoryPaths.Contains(collisionKey))
            {
                throw InvalidPath($"產生檔案路徑重複或與目錄衝突：{file.RelativePath}");
            }

            var prefix = string.Empty;
            for (var index = 0; index < segments.Length - 1; index++)
            {
                prefix = prefix.Length == 0 ? segments[index] : $"{prefix}/{segments[index]}";
                var directoryKey = CreateCollisionKey(prefix);
                if (filePaths.Contains(directoryKey))
                {
                    throw InvalidPath($"產生檔案路徑與既有檔案衝突：{file.RelativePath}");
                }

                directoryPaths.Add(directoryKey);
            }

            var targetPath = Path.GetFullPath(
                Path.Combine([outputRoot, .. segments]));
            if (!IsStrictDescendant(outputRoot, targetPath) ||
                Encoding.UTF8.GetByteCount(targetPath) > MaximumPortablePathBytes)
            {
                throw InvalidPath($"產生檔案路徑超出輸出目錄或 portable 長度限制：{file.RelativePath}");
            }

            planned.Add(new PlannedFile(file, targetPath));
        }

        return planned;
    }

    private static string[] ValidatePortableRelativePath(string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            Path.IsPathRooted(relativePath) ||
            relativePath.Contains('\\', StringComparison.Ordinal) ||
            relativePath.StartsWith("/", StringComparison.Ordinal) ||
            Encoding.UTF8.GetByteCount(relativePath) > MaximumPortablePathBytes)
        {
            throw InvalidPath($"產生檔案必須使用 portable 相對路徑：{relativePath}");
        }

        var segments = relativePath.Split('/');
        foreach (var segment in segments)
        {
            if (segment.Length == 0 || segment is "." or ".." ||
                segment.EndsWith(' ') || segment.EndsWith('.') ||
                segment.Any(IsInvalidPortableFileNameCharacter) ||
                Encoding.UTF8.GetByteCount(segment) > MaximumPortableSegmentBytes ||
                IsWindowsDeviceName(segment))
            {
                throw InvalidPath($"產生檔案含有不安全的路徑片段：{relativePath}");
            }
        }

        return segments;
    }

    private static bool IsInvalidPortableFileNameCharacter(char character) =>
        char.IsControl(character) || character is '"' or '<' or '>' or '|' or ':' or '*' or '?';

    private static bool IsWindowsDeviceName(string segment)
    {
        var extension = segment.IndexOf('.');
        var baseName = extension < 0 ? segment : segment[..extension];
        return WindowsDeviceNames.Contains(baseName) ||
               baseName.Length == 4 &&
               baseName[3] is >= '1' and <= '9' or '\u00B9' or '\u00B2' or '\u00B3' &&
               (baseName.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                baseName.StartsWith("LPT", StringComparison.OrdinalIgnoreCase));
    }

    private static string CreateCollisionKey(string path)
    {
        try
        {
            return path.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException($"產生檔案路徑包含無效 Unicode：{path}", exception);
        }
    }

    private static bool IsStrictDescendant(string root, string target)
    {
        var rootWithSeparator = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return target.StartsWith(rootWithSeparator, comparison);
    }

    private static void EnsureSafeExistingPath(string root, string target)
    {
        var relativePath = Path.GetRelativePath(root, target);
        var current = root;
        var segments = relativePath.Split(Path.DirectorySeparatorChar);
        for (var index = 0; index < segments.Length; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (!TryGetAttributes(current, out var attributes))
            {
                break;
            }

            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw InvalidPath($"產生檔案路徑不可通過重新解析點：{relativePath}");
            }

            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            var isTarget = index == segments.Length - 1;
            if (!isTarget && !isDirectory)
            {
                throw InvalidPath($"產生檔案的中間路徑已是一般檔案：{relativePath}");
            }

            if (isTarget && isDirectory)
            {
                throw InvalidPath($"產生檔案目標已是目錄：{relativePath}");
            }
        }
    }

    // 匯出服務在分析前也會呼叫，讓不安全的輸出根目錄在做完整分析之前就失敗；這裡不只守骨架，
    // 也守 blueprint.json 與 REPORT.md 所在的同一個輸出根目錄。
    internal static void EnsureSafeOutputRoot(string outputRoot)
    {
        if (!TryGetAttributes(outputRoot, out var attributes))
        {
            return;
        }

        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw InvalidPath("輸出根目錄不可為 symbolic link 或重新解析點。");
        }

        if ((attributes & FileAttributes.Directory) == 0)
        {
            throw InvalidPath("輸出根路徑已是一般檔案。");
        }
    }

    private static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException)
        {
            if (IsDanglingSymbolicLink(path))
            {
                attributes = FileAttributes.ReparsePoint;
                return true;
            }

            attributes = default;
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            if (IsDanglingSymbolicLink(path))
            {
                attributes = FileAttributes.ReparsePoint;
                return true;
            }

            attributes = default;
            return false;
        }
    }

    private static bool IsDanglingSymbolicLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget is not null ||
                   new DirectoryInfo(path).LinkTarget is not null;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static async Task WriteAtomicallyAsync(
        PlannedFile planned,
        Encoding encoding,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(planned.TargetPath)!;
        var temporaryPath = Path.Combine(
            directory,
            $".exe-blueprint-{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                             temporaryPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             bufferSize: 4_096,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (var writer = new StreamWriter(
                             stream,
                             encoding,
                             bufferSize: 4_096,
                             leaveOpen: false))
            {
                await writer.WriteAsync(planned.File.Content.AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            File.Move(temporaryPath, planned.TargetPath, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (IOException)
            {
                // 原始寫入或 replace 例外較具診斷價值；暫存清理失敗不覆蓋它。
            }
            catch (UnauthorizedAccessException)
            {
                // 同上；私人 opaque 暫存名稱不會被當成產生結果回報。
            }
        }
    }

    private static InvalidDataException InvalidPath(string message) => new(message);

    private sealed record PlannedFile(GeneratedFile File, string TargetPath);
}
