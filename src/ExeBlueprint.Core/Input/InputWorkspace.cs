using System.Buffers;
using System.IO.Compression;
using System.Text;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Input;

internal sealed class InputWorkspace : IAsyncDisposable
{
    private const int MaximumLogicalPathCharacters = 32_768;
    private readonly string? _temporaryDirectory;

    private InputWorkspace(
        string sourcePath,
        string kind,
        string name,
        string? temporaryDirectory,
        IReadOnlyList<WorkspaceFile> files,
        IReadOnlyList<ArchiveExpansion> archives,
        IReadOnlyList<string> warnings,
        long totalBytes)
    {
        SourcePath = sourcePath;
        Kind = kind;
        Name = name;
        _temporaryDirectory = temporaryDirectory;
        Files = files;
        Archives = archives;
        Warnings = warnings;
        TotalBytes = totalBytes;
    }

    public string SourcePath { get; }

    public string Kind { get; }

    public string Name { get; }

    public IReadOnlyList<WorkspaceFile> Files { get; }

    public IReadOnlyList<ArchiveExpansion> Archives { get; }

    public IReadOnlyList<string> Warnings { get; }

    public long TotalBytes { get; }

    public static async Task<InputWorkspace> OpenAsync(
        string inputPath,
        AnalysisOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentNullException.ThrowIfNull(options);

        var fullPath = Path.GetFullPath(inputPath);
        var warnings = new WarningCollector();
        var states = new List<WorkspaceFileState>();
        string? temporaryDirectory = null;
        string kind;
        string name;

        try
        {
            if (Directory.Exists(fullPath))
            {
                states.AddRange(EnumerateDirectoryFiles(fullPath, options, warnings));
                kind = "directory";
                name = new DirectoryInfo(fullPath).Name;
            }
            else
            {
                if (!File.Exists(fullPath))
                {
                    throw new FileNotFoundException("找不到輸入檔案或資料夾。", fullPath);
                }

                if (IsZipFile(fullPath))
                {
                    temporaryDirectory = CreatePrivateTemporaryDirectory();
                    states.AddRange(await ExtractZipSafelyAsync(
                        fullPath,
                        temporaryDirectory,
                        options,
                        warnings,
                        cancellationToken).ConfigureAwait(false));
                    kind = "zip";
                    name = Path.GetFileNameWithoutExtension(fullPath);
                }
                else
                {
                    var info = new FileInfo(fullPath);
                    EnsureWorkspacePathBudget(info.Name.Length, options);
                    states.Add(new WorkspaceFileState(new WorkspaceFile(
                        fullPath,
                        info.Name,
                        info.Length,
                        new FileOrigin { Kind = "direct", Depth = 0 })));
                    TryAddDirectDotNetAppHostSidecar(info, states);
                    kind = IsAsarPath(info.Name) ? "asar" : "file";
                    name = info.Name;
                }
            }

            var budget = ExpansionBudget.Create(states, options);
            var byLogicalPath = CreateLogicalPathMap(states);
            var archiveQueue = new Queue<WorkspaceFileState>(states
                .Where(state => IsAsarPath(state.File.LogicalPath))
                .OrderBy(state => state.File.LogicalPath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(state => state.File.LogicalPath, StringComparer.Ordinal));
            var archives = new List<ArchiveExpansion>();
            var stageOrdinal = 0;

            if (archiveQueue.Count > 0 && temporaryDirectory is null)
            {
                temporaryDirectory = CreatePrivateTemporaryDirectory();
            }

            while (archiveQueue.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var container = archiveQueue.Dequeue();
                if (container.Suppressed)
                {
                    continue;
                }

                budget.AddArchiveAttempt();
                if (container.File.Origin.Depth >= options.MaxArchiveDepth)
                {
                    var error = $"已達 ASAR 展開深度限制：{options.MaxArchiveDepth}";
                    warnings.Add($"{container.File.LogicalPath}：{error}");
                    archives.Add(CreateFailedArchive(container.File, error));
                    continue;
                }

                await ExpandAsarAsync(
                    container,
                    states,
                    byLogicalPath,
                    archiveQueue,
                    archives,
                    budget,
                    temporaryDirectory!,
                    options,
                    warnings,
                    stageOrdinal++,
                    cancellationToken).ConfigureAwait(false);
            }

            foreach (var orphan in states
                         .Where(state => !state.Suppressed &&
                                         state.File.Origin.Kind is "directory" or "zip" &&
                                         IsPotentialOrphanSidecar(state.File.LogicalPath))
                         .OrderBy(state => state.File.LogicalPath, StringComparer.OrdinalIgnoreCase))
            {
                warnings.Add($"未被有效 ASAR 索引引用的 sidecar 項目：{orphan.File.LogicalPath}");
            }

            var files = states
                .Where(state => !state.Suppressed)
                .Select(state => state.File)
                .OrderBy(file => file.LogicalPath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(file => file.LogicalPath, StringComparer.Ordinal)
                .ToArray();

            return new InputWorkspace(
                fullPath,
                kind,
                name,
                temporaryDirectory,
                files,
                archives
                    .OrderBy(archive => archive.Depth)
                    .ThenBy(archive => archive.ContainerPath, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                warnings.ToArray(),
                budget.TotalBytes);
        }
        catch
        {
            DeleteTemporaryDirectory(temporaryDirectory);
            throw;
        }
    }

    public ValueTask DisposeAsync()
    {
        DeleteTemporaryDirectory(_temporaryDirectory);
        return ValueTask.CompletedTask;
    }

    private static IReadOnlyList<WorkspaceFileState> EnumerateDirectoryFiles(
        string rootPath,
        AnalysisOptions options,
        WarningCollector warnings)
    {
        var files = new List<WorkspaceFileState>();
        var pending = new Stack<string>();
        pending.Push(rootPath);
        long totalBytes = 0;
        long observedPathCharacters = 0;
        var visitedNodes = 0;

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            FileSystemInfo[] entries;
            try
            {
                entries = new DirectoryInfo(current).GetFileSystemInfos();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                warnings.Add($"無法讀取目錄：{GetDirectoryRelativePath(rootPath, current)}（{exception.Message}）");
                continue;
            }

            foreach (var entry in entries.OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase))
            {
                visitedNodes++;
                if (visitedNodes > 100_000)
                {
                    throw new InvalidDataException("輸入目錄項目數超過限制：100,000");
                }

                var observedLogicalPath = GetDirectoryRelativePath(rootPath, entry.FullName);
                observedPathCharacters = CheckedAdd(observedPathCharacters, observedLogicalPath.Length);
                EnsureWorkspacePathBudget(observedPathCharacters, options);

                FileAttributes attributes;
                try
                {
                    attributes = entry.Attributes;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    warnings.Add($"無法讀取檔案屬性：{GetDirectoryRelativePath(rootPath, entry.FullName)}（{exception.Message}）");
                    continue;
                }

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    warnings.Add($"略過重新解析點：{GetDirectoryRelativePath(rootPath, entry.FullName)}");
                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    pending.Push(directory.FullName);
                    continue;
                }

                var file = (FileInfo)entry;
                var logicalPath = observedLogicalPath;
                var length = file.Length;
                totalBytes = CheckedAdd(totalBytes, length);
                EnsureSeedBudget(files.Count + 1, totalBytes, options);
                files.Add(new WorkspaceFileState(new WorkspaceFile(
                    file.FullName,
                    logicalPath,
                    length,
                    new FileOrigin
                    {
                        Kind = "directory",
                        Entry = logicalPath,
                        Depth = 0
                    })));
            }
        }

        return files;
    }

    private static async Task<IReadOnlyList<WorkspaceFileState>> ExtractZipSafelyAsync(
        string archivePath,
        string temporaryDirectory,
        AnalysisOptions options,
        WarningCollector warnings,
        CancellationToken cancellationToken)
    {
        var destinationRoot = Path.Combine(temporaryDirectory, "zip");
        CreatePrivateDirectory(destinationRoot);
        using var archive = ZipFile.OpenRead(archivePath);
        if (archive.Entries.Count > options.MaxFiles)
        {
            throw new InvalidDataException($"壓縮檔項目數超過限制：{options.MaxFiles:N0}");
        }

        var candidates = new List<ZipCandidate>();
        var logicalPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalBytes = 0;
        long observedPathCharacters = 0;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var logicalPath = ValidateZipPath(entry.FullName, string.IsNullOrEmpty(entry.Name));
            if (logicalPath.Length == 0)
            {
                continue;
            }

            var logicalKey = CreateLogicalPathKey(logicalPath);
            observedPathCharacters = CheckedAdd(observedPathCharacters, logicalPath.Length);
            EnsureWorkspacePathBudget(observedPathCharacters, options);
            if (!logicalPaths.Add(logicalKey))
            {
                throw new InvalidDataException($"壓縮檔包含重複或跨平台衝突路徑：{logicalPath}");
            }

            if (IsSymbolicLink(entry))
            {
                warnings.Add($"略過符號連結：{logicalPath}");
                continue;
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            totalBytes = CheckedAdd(totalBytes, entry.Length);
            EnsureSeedBudget(candidates.Count + 1, totalBytes, options);
            candidates.Add(new ZipCandidate(entry, logicalPath, entry.Length));
        }

        ValidateNoFileDirectoryConflicts(candidates.Select(candidate => candidate.LogicalPath));
        var files = new List<WorkspaceFileState>(candidates.Count);
        var containerName = Path.GetFileName(archivePath);
        var ordinal = 0;
        foreach (var candidate in candidates
                     .OrderBy(item => item.LogicalPath, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(item => item.LogicalPath, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var destinationPath = Path.Combine(destinationRoot, GetOpaqueFileName(ordinal++, candidate.LogicalPath));
            await using var input = candidate.Entry.Open();
            await using var output = CreatePrivateOutputFile(destinationPath);
            await CopyExactlyAsync(input, output, candidate.Length, cancellationToken).ConfigureAwait(false);
            files.Add(new WorkspaceFileState(new WorkspaceFile(
                destinationPath,
                candidate.LogicalPath,
                candidate.Length,
                new FileOrigin
                {
                    Kind = "zip",
                    Container = containerName,
                    Entry = candidate.LogicalPath,
                    Depth = 1
                })));
        }

        return files;
    }

    private static async Task ExpandAsarAsync(
        WorkspaceFileState container,
        ICollection<WorkspaceFileState> states,
        IDictionary<string, WorkspaceFileState> byLogicalPath,
        Queue<WorkspaceFileState> archiveQueue,
        ICollection<ArchiveExpansion> archives,
        ExpansionBudget budget,
        string temporaryDirectory,
        AnalysisOptions options,
        WarningCollector warnings,
        int stageOrdinal,
        CancellationToken cancellationToken)
    {
        AsarArchive archive;
        try
        {
            archive = await AsarArchive.OpenAsync(
                container.File.PhysicalPath,
                options.MaxFiles,
                options.MaxTotalBytes,
                options.MaxFileBytes,
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidDataException exception)
        {
            warnings.Add($"{container.File.LogicalPath}：{exception.Message}");
            archives.Add(CreateFailedArchive(container.File, exception.Message));
            return;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            const string error = "無法讀取 ASAR 封存內容";
            warnings.Add($"{container.File.LogicalPath}：{error}（{exception.GetType().Name}）");
            archives.Add(CreateFailedArchive(container.File, error));
            return;
        }

        await using (archive.ConfigureAwait(false))
        {
            budget.AddArchiveInspection(archive.HeaderBytes, archive.NodeCount);
            foreach (var warning in archive.Warnings)
            {
                warnings.Add($"{container.File.LogicalPath}：{warning}");
            }

            var childDepth = checked(container.File.Origin.Depth + 1);
            var plannedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var packed = new List<PlannedPackedEntry>();
            var sidecars = new List<PlannedSidecarEntry>();
            var missingSidecars = 0;
            long committedPathCharacters = 0;

            try
            {
                foreach (var entry in archive.Entries
                             .OrderBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase)
                             .ThenBy(item => item.RelativePath, StringComparer.Ordinal))
                {
                    var logicalPath = CombineArchivePath(container.File.LogicalPath, entry.RelativePath);
                    var retainedCharacters = checked(logicalPath.Length + entry.RelativePath.Length);
                    committedPathCharacters = CheckedAdd(committedPathCharacters, retainedCharacters);
                    budget.EnsureAdditional(0, 0, committedPathCharacters);
                    EnsureLogicalPathAvailable(logicalPath, byLogicalPath, plannedKeys);
                    packed.Add(new PlannedPackedEntry(entry, logicalPath));
                }

                foreach (var entry in archive.UnpackedEntries
                             .OrderBy(item => item.RelativePath, StringComparer.OrdinalIgnoreCase)
                             .ThenBy(item => item.RelativePath, StringComparer.Ordinal))
                {
                    var logicalPath = CombineArchivePath(container.File.LogicalPath, entry.RelativePath);
                    var retainedCharacters = checked(logicalPath.Length + entry.RelativePath.Length);
                    budget.EnsureAdditional(
                        0,
                        0,
                        CheckedAdd(committedPathCharacters, retainedCharacters));
                    EnsureLogicalPathAvailable(logicalPath, byLogicalPath, plannedKeys);
                    var sidecarLogicalPath = $"{container.File.LogicalPath}.unpacked/{entry.RelativePath}";
                    if (sidecarLogicalPath.Length > MaximumLogicalPathCharacters)
                    {
                        throw new AsarExpansionException(
                            $"ASAR sidecar 邏輯路徑超過限制：{sidecarLogicalPath.Length:N0} 字元");
                    }

                    string? directError = null;
                    if (TryFindInventorySidecar(
                            sidecarLogicalPath,
                            entry.Size,
                            byLogicalPath,
                            out var existing,
                            out var inventoryError))
                    {
                        committedPathCharacters = CheckedAdd(
                            committedPathCharacters,
                            retainedCharacters);
                        sidecars.Add(new PlannedSidecarEntry(entry, logicalPath, existing!, IsExisting: true));
                        continue;
                    }

                    if (container.File.Origin.Kind == "direct" &&
                        TryFindDirectSidecar(
                            container.File.PhysicalPath,
                            entry.RelativePath,
                            entry.Size,
                            out var directPath,
                            out directError))
                    {
                        committedPathCharacters = CheckedAdd(
                            committedPathCharacters,
                            retainedCharacters);
                        sidecars.Add(new PlannedSidecarEntry(
                            entry,
                            logicalPath,
                            new WorkspaceFileState(new WorkspaceFile(
                                directPath!,
                                sidecarLogicalPath,
                                entry.Size,
                                new FileOrigin { Kind = "direct", Depth = 0 })),
                            IsExisting: false));
                        continue;
                    }

                    missingSidecars++;
                    var detail = inventoryError ?? directError ?? "找不到對應檔案";
                    warnings.Add($"{container.File.LogicalPath}：ASAR 外置項目 {entry.RelativePath} 無法讀取（{detail}）");
                }
            }
            catch (AsarExpansionException exception)
            {
                warnings.Add($"{container.File.LogicalPath}：{exception.Message}");
                archives.Add(CreateArchiveResult(archive, container.File, complete: false, exception.Message));
                return;
            }

            var additionalCount = checked(packed.Count + sidecars.Count(sidecar => !sidecar.IsExisting));
            long additionalBytes = 0;
            foreach (var entry in packed)
            {
                additionalBytes = CheckedAdd(additionalBytes, entry.Entry.Size);
            }

            foreach (var sidecar in sidecars)
            {
                if (!sidecar.IsExisting)
                {
                    additionalBytes = CheckedAdd(additionalBytes, sidecar.Entry.Size);
                }
            }

            budget.EnsureAdditional(additionalCount, additionalBytes, committedPathCharacters);

            var staged = new List<WorkspaceFileState>(packed.Count);
            string? archiveStage = null;
            try
            {
                if (packed.Count > 0 || sidecars.Count > 0)
                {
                    archiveStage = Path.Combine(temporaryDirectory, $"asar-{stageOrdinal:D8}");
                    CreatePrivateDirectory(archiveStage);
                }

                var entryOrdinal = 0;
                foreach (var item in packed)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var destinationPath = Path.Combine(
                        archiveStage!,
                        GetOpaqueFileName(entryOrdinal++, item.LogicalPath));
                    await using var output = CreatePrivateOutputFile(destinationPath);
                    await archive.CopyEntryToAsync(item.Entry, output, cancellationToken).ConfigureAwait(false);
                    staged.Add(new WorkspaceFileState(new WorkspaceFile(
                        destinationPath,
                        item.LogicalPath,
                        item.Entry.Size,
                        CreateAsarOrigin(container.File.LogicalPath, item.Entry.RelativePath, childDepth))));
                }

                foreach (var sidecar in sidecars)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var destinationPath = Path.Combine(
                        archiveStage!,
                        GetOpaqueFileName(entryOrdinal++, sidecar.LogicalPath));
                    await using var input = OpenSidecarForCopy(
                        sidecar.Source.File.PhysicalPath,
                        sidecar.Entry.Size);
                    await using var output = CreatePrivateOutputFile(destinationPath);
                    await CopyExactlyAsync(
                        input,
                        output,
                        sidecar.Entry.Size,
                        cancellationToken).ConfigureAwait(false);
                    staged.Add(new WorkspaceFileState(new WorkspaceFile(
                        destinationPath,
                        sidecar.LogicalPath,
                        sidecar.Entry.Size,
                        CreateAsarOrigin(container.File.LogicalPath, sidecar.Entry.RelativePath, childDepth))));
                }
            }
            catch
            {
                DeleteTemporaryDirectory(archiveStage);
                throw;
            }

            foreach (var sidecar in sidecars)
            {
                if (sidecar.IsExisting)
                {
                    sidecar.Source.Suppressed = true;
                }
            }

            budget.Add(additionalCount, additionalBytes, committedPathCharacters);
            foreach (var child in staged
                         .OrderBy(state => state.File.LogicalPath, StringComparer.OrdinalIgnoreCase)
                         .ThenBy(state => state.File.LogicalPath, StringComparer.Ordinal))
            {
                states.Add(child);
                byLogicalPath[CreateLogicalPathKey(child.File.LogicalPath)] = child;
                if (IsAsarPath(child.File.LogicalPath))
                {
                    archiveQueue.Enqueue(child);
                }
            }

            var complete = archive.Links.Count == 0 && missingSidecars == 0;
            string? error = null;
            if (archive.Links.Count > 0 || missingSidecars > 0)
            {
                error = $"略過連結 {archive.Links.Count:N0} 個；無法讀取外置項目 {missingSidecars:N0} 個";
            }

            archives.Add(CreateArchiveResult(archive, container.File, complete, error));
        }
    }

    private static FileOrigin CreateAsarOrigin(string container, string entry, int depth) => new()
    {
        Kind = "asar",
        Container = container,
        Entry = entry,
        Depth = depth
    };

    private static ArchiveExpansion CreateArchiveResult(
        AsarArchive archive,
        WorkspaceFile container,
        bool complete,
        string? error) => new()
        {
            ContainerPath = container.LogicalPath,
            Depth = container.Origin.Depth,
            HeaderBytes = archive.HeaderBytes,
            NodeCount = archive.NodeCount,
            PackedEntryCount = archive.Entries.Count,
            UnpackedEntryCount = archive.UnpackedEntries.Count,
            LinkCount = archive.Links.Count,
            Complete = complete,
            Error = error
        };

    private static ArchiveExpansion CreateFailedArchive(WorkspaceFile container, string error) => new()
    {
        ContainerPath = container.LogicalPath,
        Depth = container.Origin.Depth,
        HeaderBytes = 0,
        NodeCount = 0,
        PackedEntryCount = 0,
        UnpackedEntryCount = 0,
        LinkCount = 0,
        Complete = false,
        Error = error
    };

    private static bool TryFindInventorySidecar(
        string logicalPath,
        long expectedSize,
        IDictionary<string, WorkspaceFileState> byLogicalPath,
        out WorkspaceFileState? state,
        out string? error)
    {
        if (!byLogicalPath.TryGetValue(CreateLogicalPathKey(logicalPath), out state))
        {
            error = null;
            return false;
        }

        if (state.Suppressed)
        {
            error = "sidecar 已被其他 ASAR 使用";
            return false;
        }

        if (state.File.Size != expectedSize)
        {
            error = $"宣告 {expectedSize:N0} bytes，實際 {state.File.Size:N0} bytes";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryFindDirectSidecar(
        string archivePath,
        string entryPath,
        long expectedSize,
        out string? physicalPath,
        out string? error)
    {
        physicalPath = null;
        var sidecarRoot = Path.GetFullPath($"{archivePath}.unpacked");
        if (!Directory.Exists(sidecarRoot))
        {
            error = "找不到 .asar.unpacked 目錄";
            return false;
        }

        try
        {
            if ((File.GetAttributes(sidecarRoot) & FileAttributes.ReparsePoint) != 0)
            {
                error = ".asar.unpacked 目錄是重新解析點";
                return false;
            }

            var current = sidecarRoot;
            var segments = entryPath.Split('/');
            for (var index = 0; index < segments.Length; index++)
            {
                current = Path.Combine(current, segments[index]);
                if (index < segments.Length - 1)
                {
                    if (!Directory.Exists(current) ||
                        (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    {
                        error = "sidecar 路徑包含遺失目錄或重新解析點";
                        return false;
                    }

                    continue;
                }

                if (!File.Exists(current) ||
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    error = "sidecar 檔案遺失或是重新解析點";
                    return false;
                }

                var info = new FileInfo(current);
                if (info.Length != expectedSize)
                {
                    error = $"宣告 {expectedSize:N0} bytes，實際 {info.Length:N0} bytes";
                    return false;
                }

                physicalPath = info.FullName;
                error = null;
                return true;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error = exception.GetType().Name;
            return false;
        }

        error = "sidecar 路徑無效";
        return false;
    }

    private static void EnsureLogicalPathAvailable(
        string logicalPath,
        IDictionary<string, WorkspaceFileState> existing,
        ISet<string> planned)
    {
        if (logicalPath.Length > MaximumLogicalPathCharacters)
        {
            throw new AsarExpansionException($"ASAR 邏輯路徑超過限制：{logicalPath.Length:N0} 字元");
        }

        var key = CreateLogicalPathKey(logicalPath);
        if ((existing.TryGetValue(key, out var state) && !state.Suppressed) || !planned.Add(key))
        {
            throw new AsarExpansionException($"ASAR 展開路徑與既有項目衝突：{logicalPath}");
        }
    }

    private static Dictionary<string, WorkspaceFileState> CreateLogicalPathMap(
        IEnumerable<WorkspaceFileState> states)
    {
        var result = new Dictionary<string, WorkspaceFileState>(StringComparer.OrdinalIgnoreCase);
        foreach (var state in states)
        {
            var key = CreateLogicalPathKey(state.File.LogicalPath);
            if (!result.TryAdd(key, state))
            {
                throw new InvalidDataException($"輸入包含重複或跨平台衝突路徑：{state.File.LogicalPath}");
            }
        }

        return result;
    }

    private static string CreateLogicalPathKey(string path)
    {
        try
        {
            return path.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException($"輸入路徑包含無效 Unicode：{path}", exception);
        }
    }

    private static string CombineArchivePath(string containerPath, string entryPath) =>
        $"{containerPath}/{entryPath}";

    private static string ValidateZipPath(string fullName, bool isDirectory)
    {
        if (fullName.IndexOf('\\') >= 0 || fullName.Any(char.IsControl))
        {
            throw new InvalidDataException($"壓縮檔包含不安全路徑：{fullName}");
        }

        var path = isDirectory ? fullName.TrimEnd('/') : fullName;
        if (path.Length == 0)
        {
            return string.Empty;
        }

        if (path.Length > MaximumLogicalPathCharacters || path.StartsWith('/'))
        {
            throw new InvalidDataException($"壓縮檔包含不安全路徑：{fullName}");
        }

        foreach (var segment in path.Split('/'))
        {
            ValidatePortableSegment(segment, fullName);
        }

        return path;
    }

    private static void ValidatePortableSegment(string segment, string fullPath)
    {
        if (segment.Length == 0 ||
            segment is "." or ".." ||
            segment.IndexOfAny([':', '<', '>', '"', '|', '?', '*']) >= 0 ||
            segment.Any(char.IsControl) ||
            segment.EndsWith(' ') ||
            segment.EndsWith('.') ||
            Encoding.UTF8.GetByteCount(segment) > 255 ||
            IsWindowsReservedName(segment))
        {
            throw new InvalidDataException($"壓縮檔包含不安全路徑：{fullPath}");
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

    private static void ValidateNoFileDirectoryConflicts(IEnumerable<string> paths)
    {
        var filePaths = paths
            .Select(CreateLogicalPathKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var path in filePaths)
        {
            var separator = path.IndexOf('/');
            while (separator >= 0)
            {
                var prefix = path[..separator];
                if (filePaths.Contains(prefix))
                {
                    throw new InvalidDataException($"壓縮檔路徑同時是檔案與目錄：{prefix}");
                }

                separator = path.IndexOf('/', separator + 1);
            }
        }
    }

    private static string GetDirectoryRelativePath(string rootPath, string fullPath) =>
        Path.GetRelativePath(rootPath, fullPath).Replace('\\', '/');

    private static string GetOpaqueFileName(int ordinal, string logicalPath)
    {
        var extension = Path.GetExtension(logicalPath);
        if (extension.Length is <= 1 or > 16 ||
            extension.Skip(1).Any(character => !char.IsAsciiLetterOrDigit(character)))
        {
            extension = ".bin";
        }

        return $"file-{ordinal:D8}{extension.ToLowerInvariant()}";
    }

    private static FileStream CreatePrivateOutputFile(string path)
    {
        var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            81920,
            FileOptions.Asynchronous);
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static FileStream OpenSidecarForCopy(string path, long expectedLength)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("ASAR sidecar 檔案是重新解析點。");
        }

        var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length == expectedLength)
        {
            return stream;
        }

        stream.Dispose();
        throw new InvalidDataException("ASAR sidecar 檔案大小在展開期間發生變更。");
    }

    private static async Task CopyExactlyAsync(
        Stream input,
        Stream output,
        long expectedLength,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            long total = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total = CheckedAdd(total, read);
                if (total > expectedLength)
                {
                    throw new InvalidDataException("壓縮檔項目實際大小超過宣告值。");
                }

                await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }

            if (total != expectedLength)
            {
                throw new InvalidDataException("壓縮檔項目實際大小與宣告值不符。");
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static string CreatePrivateTemporaryDirectory()
    {
        var directory = Directory.CreateTempSubdirectory("exe-blueprint-");
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    directory.FullName,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            return directory.FullName;
        }
        catch
        {
            DeleteTemporaryDirectory(directory.FullName);
            throw;
        }
    }

    private static void CreatePrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void DeleteTemporaryDirectory(string? path)
    {
        if (path is not null && Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
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

    // .NET 發佈預設會把原生 apphost、同名受管 DLL 與 runtimeconfig 放在同一資料夾。
    // 直接選擇 apphost 時一併納入 DLL，讓型別與資源仍可從受管組件讀取。
    private static void TryAddDirectDotNetAppHostSidecar(
        FileInfo executable,
        ICollection<WorkspaceFileState> states)
    {
        if (executable.DirectoryName is null ||
            (executable.Extension.Length > 0 &&
             !executable.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        var baseName = Path.GetFileNameWithoutExtension(executable.Name);
        var assemblyPath = Path.Combine(executable.DirectoryName, $"{baseName}.dll");
        var runtimeConfigPath = Path.Combine(executable.DirectoryName, $"{baseName}.runtimeconfig.json");
        if (!File.Exists(assemblyPath) || !File.Exists(runtimeConfigPath))
        {
            return;
        }

        try
        {
            if ((File.GetAttributes(assemblyPath) & FileAttributes.ReparsePoint) != 0)
            {
                return;
            }

            var assembly = new FileInfo(assemblyPath);
            if (!assembly.Exists)
            {
                return;
            }

            states.Add(new WorkspaceFileState(new WorkspaceFile(
                assembly.FullName,
                assembly.Name,
                assembly.Length,
                new FileOrigin { Kind = "direct", Depth = 0 })));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // 側檔無法安全讀取時維持原本只分析 apphost 的行為。
        }
    }

    private static bool IsAsarPath(string path) =>
        path.EndsWith(".asar", StringComparison.OrdinalIgnoreCase);

    private static bool IsPotentialOrphanSidecar(string path) =>
        path.Contains(".asar.unpacked/", StringComparison.OrdinalIgnoreCase);

    private static bool IsSymbolicLink(ZipArchiveEntry entry)
    {
        const int fileTypeMask = 0xF000;
        const int symbolicLinkType = 0xA000;
        var unixMode = (entry.ExternalAttributes >> 16) & fileTypeMask;
        return unixMode == symbolicLinkType;
    }

    private static long CheckedAdd(long left, long right)
    {
        try
        {
            return checked(left + right);
        }
        catch (OverflowException exception)
        {
            throw new InvalidDataException("輸入總大小溢位。", exception);
        }
    }

    private static void EnsureSeedBudget(int fileCount, long totalBytes, AnalysisOptions options)
    {
        if (fileCount > options.MaxFiles)
        {
            throw new InvalidDataException($"檔案數超過限制：{options.MaxFiles:N0}");
        }

        if (totalBytes > options.MaxTotalBytes)
        {
            throw new InvalidDataException($"輸入總大小超過限制：{options.MaxTotalBytes:N0} bytes");
        }
    }

    private static void EnsureWorkspacePathBudget(long characters, AnalysisOptions options)
    {
        if (characters > options.MaxWorkspacePathCharacters)
        {
            throw new InvalidDataException(
                $"workspace 保留路徑字元數超過限制：{options.MaxWorkspacePathCharacters:N0}");
        }
    }

    private sealed record ZipCandidate(ZipArchiveEntry Entry, string LogicalPath, long Length);

    private sealed record PlannedPackedEntry(AsarArchiveEntry Entry, string LogicalPath);

    private sealed record PlannedSidecarEntry(
        AsarUnpackedEntry Entry,
        string LogicalPath,
        WorkspaceFileState Source,
        bool IsExisting);

    private sealed class WorkspaceFileState
    {
        public WorkspaceFileState(WorkspaceFile file)
        {
            File = file;
        }

        public WorkspaceFile File { get; }

        public bool Suppressed { get; set; }
    }

    private sealed class ExpansionBudget
    {
        private readonly AnalysisOptions _options;

        private ExpansionBudget(
            AnalysisOptions options,
            int fileCount,
            long totalBytes,
            long retainedPathCharacters)
        {
            _options = options;
            FileCount = fileCount;
            TotalBytes = totalBytes;
            RetainedPathCharacters = retainedPathCharacters;
        }

        public int FileCount { get; private set; }

        public long TotalBytes { get; private set; }

        public long RetainedPathCharacters { get; private set; }

        public int ArchiveAttempts { get; private set; }

        public long ArchiveHeaderBytes { get; private set; }

        public int ArchiveNodes { get; private set; }

        public static ExpansionBudget Create(
            IReadOnlyCollection<WorkspaceFileState> states,
            AnalysisOptions options)
        {
            long totalBytes = 0;
            long retainedPathCharacters = 0;
            foreach (var state in states)
            {
                totalBytes = CheckedAdd(totalBytes, state.File.Size);
                retainedPathCharacters = CheckedAdd(
                    retainedPathCharacters,
                    state.File.LogicalPath.Length);
            }

            EnsureSeedBudget(states.Count, totalBytes, options);
            EnsureWorkspacePathBudget(retainedPathCharacters, options);
            return new ExpansionBudget(options, states.Count, totalBytes, retainedPathCharacters);
        }

        public void EnsureAdditional(
            int fileCount,
            long totalBytes,
            long retainedPathCharacters)
        {
            int nextCount;
            long nextBytes;
            long nextPathCharacters;
            try
            {
                nextCount = checked(FileCount + fileCount);
                nextBytes = checked(TotalBytes + totalBytes);
                nextPathCharacters = checked(RetainedPathCharacters + retainedPathCharacters);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("ASAR 展開後的檔案數或大小溢位。", exception);
            }

            EnsureSeedBudget(nextCount, nextBytes, _options);
            EnsureWorkspacePathBudget(nextPathCharacters, _options);
        }

        public void Add(int fileCount, long totalBytes, long retainedPathCharacters)
        {
            EnsureAdditional(fileCount, totalBytes, retainedPathCharacters);
            FileCount = checked(FileCount + fileCount);
            TotalBytes = checked(TotalBytes + totalBytes);
            RetainedPathCharacters = checked(RetainedPathCharacters + retainedPathCharacters);
        }

        public void AddArchiveAttempt()
        {
            ArchiveAttempts = checked(ArchiveAttempts + 1);
            if (ArchiveAttempts > _options.MaxWorkspaceArchives)
            {
                throw new InvalidDataException(
                    $"ASAR 封存數超過限制：{_options.MaxWorkspaceArchives:N0}");
            }
        }

        public void AddArchiveInspection(long headerBytes, int nodes)
        {
            try
            {
                ArchiveHeaderBytes = checked(ArchiveHeaderBytes + headerBytes);
                ArchiveNodes = checked(ArchiveNodes + nodes);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("ASAR header 或節點累計值溢位。", exception);
            }

            if (ArchiveHeaderBytes > _options.MaxWorkspaceArchiveHeaderBytes)
            {
                throw new InvalidDataException(
                    $"ASAR header 累計大小超過限制：{_options.MaxWorkspaceArchiveHeaderBytes:N0} bytes");
            }

            if (ArchiveNodes > _options.MaxWorkspaceArchiveNodes)
            {
                throw new InvalidDataException(
                    $"ASAR header 累計節點數超過限制：{_options.MaxWorkspaceArchiveNodes:N0}");
            }
        }

    }

    private sealed class WarningCollector
    {
        private const int MaximumWarnings = 200;
        private readonly List<string> _warnings = [];
        private int _omitted;

        public void Add(string warning)
        {
            if (_warnings.Count < MaximumWarnings)
            {
                _warnings.Add(warning);
            }
            else
            {
                _omitted++;
            }
        }

        public IReadOnlyList<string> ToArray()
        {
            if (_omitted == 0)
            {
                return _warnings.ToArray();
            }

            return [.. _warnings, $"另有 {_omitted:N0} 個輸入警告未逐項列出。"];
        }
    }

    private sealed class AsarExpansionException : Exception
    {
        public AsarExpansionException(string message)
            : base(message)
        {
        }
    }
}

internal sealed record WorkspaceFile(
    string PhysicalPath,
    string LogicalPath,
    long Size,
    FileOrigin Origin);
