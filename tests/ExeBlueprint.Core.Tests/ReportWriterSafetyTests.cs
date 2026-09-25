using System.Runtime.InteropServices;
using ExeBlueprint.Application;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

namespace ExeBlueprint.Core.Tests;

// blueprint.json 與 REPORT.md 和骨架寫進同一個輸出根目錄，必須享有同一套防護：
// 不跟隨既有 symbolic link、不截斷既有 hardlink 的外部 inode、輸出根目錄本身不可是連結。
public sealed class ReportWriterSafetyTests
{
    [Fact]
    public async Task JsonWriterRefusesSymbolicLinkTarget()
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var outside = Path.Combine(temp.Path, "outside.json");
        await File.WriteAllTextAsync(outside, "outside");
        var target = Path.Combine(output, "blueprint.json");
        if (!TryCreateFileSymbolicLink(target, outside))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => BlueprintJsonWriter.WriteAsync(MinimalDocument(), target));

        Assert.Equal("outside", await File.ReadAllTextAsync(outside));
    }

    [Fact]
    public async Task MarkdownWriterReplacesHardLinkWithoutTouchingOutsideInode()
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var outside = Path.Combine(temp.Path, "outside.md");
        await File.WriteAllTextAsync(outside, "outside");
        var target = Path.Combine(output, "REPORT.md");
        CreateHardLinkForTest(outside, target);

        await MarkdownReportWriter.WriteAsync(MinimalDocument(), target);

        Assert.StartsWith("# ExeBlueprint 分析報告", await File.ReadAllTextAsync(target), StringComparison.Ordinal);
        Assert.Equal("outside", await File.ReadAllTextAsync(outside));
    }

    [Fact]
    public async Task JsonWriterRefusesSymbolicLinkOutputRoot()
    {
        await using var temp = new TemporaryDirectory();
        var outside = Directory.CreateDirectory(Path.Combine(temp.Path, "outside")).FullName;
        var output = Path.Combine(temp.Path, "output");
        if (!TryCreateDirectorySymbolicLink(output, outside))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            BlueprintJsonWriter.WriteAsync(MinimalDocument(), Path.Combine(output, "blueprint.json")));

        Assert.False(File.Exists(Path.Combine(outside, "blueprint.json")));
    }

    [Fact]
    public async Task ExportRefusesSymbolicLinkOutputRootBeforeAnalysis()
    {
        await using var temp = new TemporaryDirectory();
        var outside = Directory.CreateDirectory(Path.Combine(temp.Path, "outside")).FullName;
        var output = Path.Combine(temp.Path, "output");
        if (!TryCreateDirectorySymbolicLink(output, outside))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => new BlueprintExportService().RunAsync(
            new BlueprintExportRequest
            {
                InputPath = typeof(BlueprintExportService).Assembly.Location,
                OutputDirectory = output
            }));

        Assert.False(File.Exists(Path.Combine(outside, "blueprint.json")));
        Assert.False(File.Exists(Path.Combine(outside, "REPORT.md")));
    }

    private static BlueprintDocument MinimalDocument() => new()
    {
        Input = new InputDescriptor { Name = "x", Kind = "file", SourcePath = "x", FileCount = 0, TotalBytes = 0 },
        Summary = new BlueprintSummary()
    };

    private static bool TryCreateDirectorySymbolicLink(string path, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (
            OperatingSystem.IsWindows() &&
            exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static bool TryCreateFileSymbolicLink(string path, string target)
    {
        try
        {
            File.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (
            OperatingSystem.IsWindows() &&
            exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private static void CreateHardLinkForTest(string existingPath, string newPath)
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.True(
                CreateHardLinkWindows(newPath, existingPath, IntPtr.Zero),
                $"CreateHardLinkW failed with {Marshal.GetLastWin32Error()}.");
            return;
        }

        Assert.Equal(0, CreateHardLinkUnix(existingPath, newPath));
    }

    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int CreateHardLinkUnix(string existingPath, string newPath);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateHardLinkW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkWindows(
        string fileName,
        string existingFileName,
        IntPtr securityAttributes);

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "exe-blueprint-tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }
}
