using System.IO.Compression;
using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class BlueprintAnalyzerTests
{
    [Fact]
    public async Task AnalyzeManagedAssemblyReadsMetadataAndReferences()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var artifact = Assert.Single(document.Files);
        Assert.True(artifact.IsPortableExecutable);
        Assert.True(artifact.IsManaged);
        Assert.True(artifact.IsLibrary);
        Assert.Equal("ExeBlueprint.Core", artifact.AssemblyName);
        Assert.Contains(document.Technologies, item => item.Id == "dotnet" && item.Confidence == 1.0);
        Assert.DoesNotContain(document.Technologies, item => item.Id is "easy-language" or "go" or "inno-setup" or "nsis");
        Assert.Equal(64, artifact.Sha256.Length);
    }

    [Fact]
    public async Task AnalyzeDirectoryDetectsEasyLanguageRuntimePackage()
    {
        await using var temp = new TemporaryDirectory();
        await File.WriteAllTextAsync(Path.Combine(temp.Path, "krnln.fnr"), "test fixture");
        await File.WriteAllTextAsync(Path.Combine(temp.Path, "app.ini"), "[app]");

        var document = await new BlueprintAnalyzer().AnalyzeAsync(temp.Path);

        Assert.Equal(2, document.Input.FileCount);
        Assert.Contains(document.Technologies, item => item.Id == "easy-language" && item.Confidence >= 0.99);
        Assert.Equal(1, document.Summary.ConfigurationCount);
    }

    [Fact]
    public async Task ZipWithParentTraversalIsRejected()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "unsafe.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("../escape.txt");
            await using var stream = entry.Open();
            await using var writer = new StreamWriter(stream);
            await writer.WriteAsync("blocked");
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => new BlueprintAnalyzer().AnalyzeAsync(zipPath));
        Assert.False(File.Exists(Path.Combine(temp.Path, "escape.txt")));
    }

    [Fact]
    public async Task ZipInputKeepsRelativePathsAndBuildsReportData()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "package.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("config/app.json");
            await using var stream = entry.Open();
            await using var writer = new StreamWriter(stream);
            await writer.WriteAsync("{}");
        }

        var document = await new BlueprintAnalyzer().AnalyzeAsync(zipPath);

        Assert.Equal("zip", document.Input.Kind);
        Assert.Equal("config/app.json", Assert.Single(document.Files).RelativePath);
        Assert.Equal(1, document.Summary.ConfigurationCount);
    }

    [Fact]
    public async Task ZipRejectsFileDirectoryConflictEvenWhenSortNeighborsDiffer()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "conflict.zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
        {
            foreach (var name in new[] { "a", "a-b", "a/child.txt" })
            {
                var entry = archive.CreateEntry(name);
                await using var output = entry.Open();
                await output.WriteAsync("x"u8.ToArray());
            }
        }

        await Assert.ThrowsAsync<InvalidDataException>(() => new BlueprintAnalyzer().AnalyzeAsync(zipPath));
    }

    [Fact]
    public async Task DotNetBundleMarkerPreventsEmbeddedDetectorStringsFromCausingFalsePositives()
    {
        await using var temp = new TemporaryDirectory();
        var path = Path.Combine(temp.Path, "bundle.bin");
        var marker = Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");
        var bytes = new byte[512];
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(120, sizeof(long)), 300);
        marker.CopyTo(bytes, 128);
        System.Text.Encoding.ASCII.GetBytes("krnln.fnr Inno Setup Nullsoft.NSIS Go build ID: PyInstaller rust_begin_unwind")
            .CopyTo(bytes, 200);
        await File.WriteAllBytesAsync(path, bytes);

        var signals = await BinarySignalReader.CreateAsync(path, 4096, CancellationToken.None);
        var pe = new PeAnalysis
        {
            IsExecutable = true,
            IsLibrary = false,
            IsManaged = false,
            Architecture = "x64",
            Subsystem = Subsystem.WindowsCui.ToString()
        };

        var detections = TechnologyDetector.DetectFile("bundle.exe", pe, signals);

        Assert.Contains(detections, item => item.Id == "dotnet-single-file" && item.Confidence == 1.0);
        Assert.DoesNotContain(detections, item => item.Id is "easy-language" or "go" or "inno-setup" or "nsis" or "pyinstaller" or "rust");
    }

    [Fact]
    public void DependencyGraphResolvesFilesInsideTheSamePackage()
    {
        var app = CreateArtifact(
            "app.exe",
            importedModules: ["native.dll"],
            managedReferences: ["Managed.Library"]);
        var native = CreateArtifact("native.dll");
        var managed = CreateArtifact("Managed.Library.dll", assemblyName: "Managed.Library");

        var dependencies = DependencyGraphBuilder.Build([app, native, managed]);

        Assert.Contains(dependencies, edge => edge.Source == "app.exe" && edge.Target == "native.dll" && edge.ResolvedInsidePackage);
        Assert.Contains(dependencies, edge => edge.Source == "app.exe" && edge.Target == "Managed.Library.dll" && edge.ResolvedInsidePackage);
    }

    private static FileArtifact CreateArtifact(
        string relativePath,
        string? assemblyName = null,
        IReadOnlyList<string>? importedModules = null,
        IReadOnlyList<string>? managedReferences = null) => new()
        {
            Id = relativePath,
            RelativePath = relativePath,
            FileName = System.IO.Path.GetFileName(relativePath),
            Size = 1,
            Sha256 = new string('0', 64),
            Category = "library",
            Format = "test fixture",
            AssemblyName = assemblyName,
            ImportedModules = importedModules ?? [],
            ManagedReferences = managedReferences ?? []
        };

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "exe-blueprint-tests", Guid.NewGuid().ToString("N"));
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
