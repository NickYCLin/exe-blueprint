using ExeBlueprint.Generation;
using System.Runtime.InteropServices;

namespace ExeBlueprint.Core.Tests;

public sealed class GeneratedProjectWriterTests
{
    [Fact]
    public async Task WritesPortableNestedRelativePaths()
    {
        await using var temp = new TemporaryDirectory();
        var output = Path.Combine(temp.Path, "output");

        await GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "Project/Source.cs", Content = "source" },
            new GeneratedFile { RelativePath = "README.md", Content = "readme" }
        ], output);

        Assert.Equal("source", await File.ReadAllTextAsync(Path.Combine(output, "Project", "Source.cs")));
        Assert.Equal("readme", await File.ReadAllTextAsync(Path.Combine(output, "README.md")));
    }

    [Theory]
    [InlineData("")]
    [InlineData("../escape.txt")]
    [InlineData("nested/../../escape.txt")]
    [InlineData("/absolute.txt")]
    [InlineData("//server/share/escape.txt")]
    [InlineData("\\absolute.txt")]
    [InlineData("\\\\server\\share\\escape.txt")]
    [InlineData("C:/escape.txt")]
    [InlineData("C:\\escape.txt")]
    [InlineData("C:drive-relative.txt")]
    [InlineData("nested\\escape.txt")]
    [InlineData("nested//escape.txt")]
    [InlineData("nested/./escape.txt")]
    [InlineData("nested/trailing. ")]
    [InlineData("CON.txt")]
    [InlineData("COM¹.txt")]
    [InlineData("LPT³.txt")]
    [InlineData("control\u0085.txt")]
    public async Task RejectsNonPortableOrEscapingPathsBeforeWritingAnything(string relativePath)
    {
        await using var temp = new TemporaryDirectory();
        var output = Path.Combine(temp.Path, "output");
        var outside = Path.Combine(temp.Path, "escape.txt");

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "safe.txt", Content = "must-not-be-written" },
            new GeneratedFile { RelativePath = relativePath, Content = "escape" }
        ], output));

        Assert.False(File.Exists(Path.Combine(output, "safe.txt")));
        Assert.False(File.Exists(outside));
    }

    [Theory]
    [InlineData("same.txt", "SAME.TXT")]
    [InlineData("node", "node/child.txt")]
    [InlineData("node/child.txt", "node")]
    [InlineData("caf\u00E9.txt", "cafe\u0301.txt")]
    public async Task RejectsPortablePathCollisionsBeforeWritingAnything(
        string firstPath,
        string secondPath)
    {
        await using var temp = new TemporaryDirectory();
        var output = Path.Combine(temp.Path, "output");

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = firstPath, Content = "first" },
            new GeneratedFile { RelativePath = secondPath, Content = "second" }
        ], output));

        Assert.False(Directory.Exists(output));
    }

    [Fact]
    public async Task RejectsExistingReparsePointBelowOutputRoot()
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(temp.Path, "outside")).FullName;
        if (!TryCreateDirectorySymbolicLink(Path.Combine(output, "linked"), outside))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "linked/escape.txt", Content = "escape" }
        ], output));

        Assert.False(File.Exists(Path.Combine(outside, "escape.txt")));
    }

    [Fact]
    public async Task RejectsOutputRootThatIsAReparsePoint()
    {
        await using var temp = new TemporaryDirectory();
        var outside = Directory.CreateDirectory(Path.Combine(temp.Path, "outside")).FullName;
        var output = Path.Combine(temp.Path, "output");
        if (!TryCreateDirectorySymbolicLink(output, outside))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "escape.txt", Content = "escape" }
        ], output));

        Assert.False(File.Exists(Path.Combine(outside, "escape.txt")));
    }

    [Fact]
    public async Task RejectsDanglingSymbolicLinkTarget()
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var outside = Directory.CreateDirectory(Path.Combine(temp.Path, "outside")).FullName;
        if (!TryCreateFileSymbolicLink(
                Path.Combine(output, "dangling.txt"),
                Path.Combine(outside, "missing.txt")))
        {
            return;
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "dangling.txt", Content = "escape" }
        ], output));

        Assert.False(File.Exists(Path.Combine(outside, "missing.txt")));
    }

    [Fact]
    public async Task ReplacesExistingHardLinkWithoutMutatingOutsideInode()
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var outside = Path.Combine(temp.Path, "outside.txt");
        await File.WriteAllTextAsync(outside, "outside");
        var target = Path.Combine(output, "target.txt");
        CreateHardLinkForTest(outside, target);

        await GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "target.txt", Content = "generated" }
        ], output);

        Assert.Equal("generated", await File.ReadAllTextAsync(target));
        Assert.Equal("outside", await File.ReadAllTextAsync(outside));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RejectsExistingFileDirectoryConflictsBeforeWritingAnything(
        bool targetIsDirectory)
    {
        await using var temp = new TemporaryDirectory();
        var output = Directory.CreateDirectory(Path.Combine(temp.Path, "output")).FullName;
        var occupied = Path.Combine(output, "occupied");
        var conflictingPath = "occupied";
        if (targetIsDirectory)
        {
            Directory.CreateDirectory(occupied);
        }
        else
        {
            await File.WriteAllTextAsync(occupied, "existing");
            conflictingPath = "occupied/child.txt";
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "safe.txt", Content = "must-not-be-written" },
            new GeneratedFile { RelativePath = conflictingPath, Content = "conflict" }
        ], output));

        Assert.False(File.Exists(Path.Combine(output, "safe.txt")));
    }

    [Fact]
    public async Task RejectsOutputRootThatIsAnExistingFile()
    {
        await using var temp = new TemporaryDirectory();
        var output = Path.Combine(temp.Path, "output");
        await File.WriteAllTextAsync(output, "existing");

        await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
        [
            new GeneratedFile { RelativePath = "safe.txt", Content = "must-not-be-written" }
        ], output));

        Assert.Equal("existing", await File.ReadAllTextAsync(output));
    }

    [Fact]
    public async Task RejectsInvalidUnicodeOrOverlongPathsBeforeWritingAnything()
    {
        await using var temp = new TemporaryDirectory();
        var output = Path.Combine(temp.Path, "output");
        var overlongSegment = $"{new string('a', 256)}.txt";
        var overlongPath = string.Join('/', Enumerable.Repeat(new string('b', 200), 6)) + "/file.txt";

        var invalidUnicode = $"invalid-{new string('\uD800', 1)}.txt";

        foreach (var invalidPath in new[] { invalidUnicode, overlongSegment, overlongPath })
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => GeneratedProjectWriter.WriteAsync(
            [
                new GeneratedFile { RelativePath = "safe.txt", Content = "must-not-be-written" },
                new GeneratedFile { RelativePath = invalidPath, Content = "invalid" }
            ], output));

            Assert.False(File.Exists(Path.Combine(output, "safe.txt")));
        }
    }

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
