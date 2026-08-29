using System.IO.Compression;
using System.Security.Cryptography;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class AsarInputIntegrationTests
{
    private const string AppHeader =
        "{\"files\":{\"config\":{\"files\":{\"app.json\":{\"size\":2,\"offset\":\"0\"}}}}}";

    [Fact]
    public async Task DirectAsarRetainsContainerAndUsesAsarInputKind()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "app.asar");
        await AsarTestArchiveBuilder.WriteAsync(archivePath, AppHeader, "{}"u8.ToArray());

        var document = await AnalyzeAsync(archivePath);

        Assert.Equal("asar", document.Input.Kind);
        Assert.Contains(document.Technologies, technology => technology.Id == "electron");
        AssertOrigin(AssertArtifact(document, "app.asar"), "direct", depth: 0);
        AssertAsarOrigin(
            AssertArtifact(document, "app.asar/config/app.json"),
            "app.asar",
            "config/app.json",
            depth: 1);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "app.asar" && expansion.Complete);
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task DirectoryResourcesAppAsarRetainsContainerAndUsesDepthOne()
    {
        await using var temp = new TemporaryDirectory();
        var resourcesPath = Directory.CreateDirectory(Path.Combine(temp.Path, "resources")).FullName;
        var archivePath = Path.Combine(resourcesPath, "app.asar");
        await AsarTestArchiveBuilder.WriteAsync(archivePath, AppHeader, "{}"u8.ToArray());

        var document = await AnalyzeAsync(temp.Path);

        Assert.Equal("directory", document.Input.Kind);
        AssertOrigin(AssertArtifact(document, "resources/app.asar"), "directory", depth: 0);
        AssertAsarOrigin(
            AssertArtifact(document, "resources/app.asar/config/app.json"),
            "resources/app.asar",
            "config/app.json",
            depth: 1);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "resources/app.asar" && expansion.Complete);
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task ZipResourcesAppAsarRetainsContainerAndUsesDepthTwo()
    {
        await using var temp = new TemporaryDirectory();
        var zipPath = Path.Combine(temp.Path, "package.zip");
        var asarBytes = AsarTestArchiveBuilder.Create(AppHeader, "{}"u8);
        await WriteZipAsync(zipPath, "resources/app.asar", asarBytes);

        var document = await AnalyzeAsync(zipPath);

        Assert.Equal("zip", document.Input.Kind);
        AssertOrigin(AssertArtifact(document, "resources/app.asar"), "zip", depth: 1);
        AssertAsarOrigin(
            AssertArtifact(document, "resources/app.asar/config/app.json"),
            "resources/app.asar",
            "config/app.json",
            depth: 2);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "resources/app.asar" && expansion.Complete);
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task NestedAsarRetainsBothContainersAndUsesImmediateContainerOrigin()
    {
        await using var temp = new TemporaryDirectory();
        var innerBytes = CreateRootFileArchive("inside.json", "{}"u8);
        var outerBytes = CreateRootFileArchive("nested.asar", innerBytes);
        var outerPath = Path.Combine(temp.Path, "outer.asar");
        await File.WriteAllBytesAsync(outerPath, outerBytes);

        var document = await AnalyzeAsync(outerPath);

        AssertOrigin(AssertArtifact(document, "outer.asar"), "direct", depth: 0);
        AssertAsarOrigin(
            AssertArtifact(document, "outer.asar/nested.asar"),
            "outer.asar",
            "nested.asar",
            depth: 1);
        AssertAsarOrigin(
            AssertArtifact(document, "outer.asar/nested.asar/inside.json"),
            "outer.asar/nested.asar",
            "inside.json",
            depth: 2);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "outer.asar" && expansion.Complete);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "outer.asar/nested.asar" && expansion.Complete);
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task AsarUnpackedEntryIsMappedOnceAndRawSidecarPathIsHidden()
    {
        await using var temp = new TemporaryDirectory();
        var resourcesPath = Directory.CreateDirectory(Path.Combine(temp.Path, "resources")).FullName;
        var archivePath = Path.Combine(resourcesPath, "app.asar");
        const string header =
            "{\"files\":{\"native\":{\"files\":{\"addon.node\":{\"size\":4,\"unpacked\":true}},\"unpacked\":true}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);
        var unpackedPath = Path.Combine(resourcesPath, "app.asar.unpacked", "native", "addon.node");
        Directory.CreateDirectory(Path.GetDirectoryName(unpackedPath)!);
        byte[] unpackedBytes = [0x7F, (byte)'E', (byte)'L', (byte)'F'];
        await File.WriteAllBytesAsync(unpackedPath, unpackedBytes);

        var document = await AnalyzeAsync(temp.Path);

        var mapped = AssertArtifact(document, "resources/app.asar/native/addon.node");
        AssertAsarOrigin(mapped, "resources/app.asar", "native/addon.node", depth: 1);
        Assert.Equal(unpackedBytes.Length, mapped.Size);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(unpackedBytes)).ToLowerInvariant(), mapped.Sha256);
        Assert.Equal(1, document.Files.Count(artifact => artifact.FileName == "addon.node"));
        Assert.DoesNotContain(
            document.Files,
            artifact => artifact.RelativePath.Contains(".asar.unpacked", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "resources/app.asar" &&
                         expansion.UnpackedEntryCount == 1 &&
                         expansion.Complete);
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task DirectAsarReadsUnpackedEntryFromAdjacentSidecar()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "app.asar");
        const string header =
            "{\"files\":{\"native\":{\"files\":{\"addon.node\":{\"size\":4,\"unpacked\":true}},\"unpacked\":true}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header);
        var unpackedPath = Path.Combine(temp.Path, "app.asar.unpacked", "native", "addon.node");
        Directory.CreateDirectory(Path.GetDirectoryName(unpackedPath)!);
        byte[] unpackedBytes = [0x7F, (byte)'E', (byte)'L', (byte)'F'];
        await File.WriteAllBytesAsync(unpackedPath, unpackedBytes);

        var document = await AnalyzeAsync(archivePath);

        var mapped = AssertArtifact(document, "app.asar/native/addon.node");
        AssertAsarOrigin(mapped, "app.asar", "native/addon.node", depth: 1);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(unpackedBytes)).ToLowerInvariant(), mapped.Sha256);
        Assert.Contains(
            document.Archives,
            expansion => expansion.ContainerPath == "app.asar" &&
                         expansion.UnpackedEntryCount == 1 &&
                         expansion.Complete);
        Assert.DoesNotContain(document.Warnings, warning => warning.Contains("外置項目", StringComparison.Ordinal));
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task PackedDirectoryNamedLikeSidecarDoesNotProduceOrphanWarning()
    {
        await using var temp = new TemporaryDirectory();
        var archivePath = Path.Combine(temp.Path, "app.asar");
        const string header =
            "{\"files\":{\"assets.asar.unpacked\":{\"files\":{\"data.txt\":{\"size\":2,\"offset\":\"0\"}}}}}";
        await AsarTestArchiveBuilder.WriteAsync(archivePath, header, "ok"u8.ToArray());

        var document = await AnalyzeAsync(archivePath);

        AssertArtifact(document, "app.asar/assets.asar.unpacked/data.txt");
        Assert.DoesNotContain(
            document.Warnings,
            warning => warning.Contains("未被有效 ASAR 索引引用", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MalformedNestedAsarRetainsContainerAndAddsIncompleteWarning()
    {
        await using var temp = new TemporaryDirectory();
        var outerPath = Path.Combine(temp.Path, "outer.asar");
        var malformed = "not an asar"u8.ToArray();
        await File.WriteAllBytesAsync(outerPath, CreateRootFileArchive("broken.asar", malformed));

        var document = await AnalyzeAsync(outerPath);

        AssertOrigin(AssertArtifact(document, "outer.asar"), "direct", depth: 0);
        AssertAsarOrigin(
            AssertArtifact(document, "outer.asar/broken.asar"),
            "outer.asar",
            "broken.asar",
            depth: 1);
        var failedExpansion = Assert.Single(
            document.Archives,
            expansion => expansion.ContainerPath == "outer.asar/broken.asar");
        Assert.False(failedExpansion.Complete);
        Assert.False(string.IsNullOrWhiteSpace(failedExpansion.Error));
        Assert.Contains(
            document.Warnings,
            warning => warning.Contains("outer.asar/broken.asar", StringComparison.OrdinalIgnoreCase) &&
                       warning.Contains("ASAR", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            document.Files,
            artifact => artifact.RelativePath.StartsWith("outer.asar/broken.asar/", StringComparison.Ordinal));
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task MaxFilesAndMaxTotalBytesAreSharedByContainersAndExpandedEntries()
    {
        await using var temp = new TemporaryDirectory();
        var fileLimitPath = Path.Combine(temp.Path, "file-limit.asar");
        const string twoFilesHeader =
            "{\"files\":{\"first.json\":{\"size\":0,\"offset\":\"0\"},\"second.json\":{\"size\":0,\"offset\":\"0\"}}}";
        await AsarTestArchiveBuilder.WriteAsync(fileLimitPath, twoFilesHeader);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AnalyzeAsync(
                fileLimitPath,
                new AnalysisOptions
                {
                    MaxFiles = 2,
                    MaxArchiveDepth = 4
                }));

        var byteLimitPath = Path.Combine(temp.Path, "byte-limit.asar");
        var content = "expanded payload"u8.ToArray();
        await File.WriteAllBytesAsync(byteLimitPath, CreateRootFileArchive("payload.bin", content));
        var archiveBytes = new FileInfo(byteLimitPath).Length;

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AnalyzeAsync(
                byteLimitPath,
                new AnalysisOptions
                {
                    MaxFiles = 10,
                    MaxTotalBytes = checked(archiveBytes + content.Length - 1),
                    MaxArchiveDepth = 4
                }));
    }

    [Fact]
    public async Task MaxArchiveDepthRetainsNestedContainerButDoesNotExpandItsChildren()
    {
        await using var temp = new TemporaryDirectory();
        var innerBytes = CreateRootFileArchive("inside.json", "{}"u8);
        var outerPath = Path.Combine(temp.Path, "outer.asar");
        await File.WriteAllBytesAsync(outerPath, CreateRootFileArchive("nested.asar", innerBytes));

        var document = await AnalyzeAsync(
            outerPath,
            new AnalysisOptions
            {
                MaxFiles = 10,
                MaxArchiveDepth = 1
            });

        AssertArtifact(document, "outer.asar");
        AssertAsarOrigin(
            AssertArtifact(document, "outer.asar/nested.asar"),
            "outer.asar",
            "nested.asar",
            depth: 1);
        Assert.DoesNotContain(
            document.Files,
            artifact => artifact.RelativePath == "outer.asar/nested.asar/inside.json");
        var blockedExpansion = Assert.Single(
            document.Archives,
            expansion => expansion.ContainerPath == "outer.asar/nested.asar");
        Assert.False(blockedExpansion.Complete);
        Assert.Contains("深度", blockedExpansion.Error);
        Assert.Contains(document.Warnings, warning => warning.Contains("深度", StringComparison.OrdinalIgnoreCase));
        AssertNoBangPaths(document);
    }

    [Fact]
    public async Task WorkspacePathBudgetIncludesRepeatedNestedContainerPrefixes()
    {
        await using var temp = new TemporaryDirectory();
        var outerPath = Path.Combine(temp.Path, "long-container-name.asar");
        const string header =
            "{\"files\":{\"first.json\":{\"size\":0,\"offset\":\"0\"},\"second.json\":{\"size\":0,\"offset\":\"0\"}}}";
        await AsarTestArchiveBuilder.WriteAsync(outerPath, header);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AnalyzeAsync(
                outerPath,
                new AnalysisOptions
                {
                    MaxFiles = 10,
                    MaxArchiveDepth = 4,
                    MaxWorkspacePathCharacters = 60
                }));
    }

    [Fact]
    public async Task ArchiveAttemptsAndHeaderNodesShareWorkspaceLimits()
    {
        await using var temp = new TemporaryDirectory();
        await AsarTestArchiveBuilder.WriteAsync(
            Path.Combine(temp.Path, "first.asar"),
            "{\"files\":{\"one\":{\"size\":0,\"offset\":\"0\"}}}");
        await AsarTestArchiveBuilder.WriteAsync(
            Path.Combine(temp.Path, "second.asar"),
            "{\"files\":{\"two\":{\"size\":0,\"offset\":\"0\"}}}");

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AnalyzeAsync(
                temp.Path,
                new AnalysisOptions
                {
                    MaxFiles = 10,
                    MaxArchiveDepth = 4,
                    MaxWorkspaceArchives = 1
                }));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            AnalyzeAsync(
                temp.Path,
                new AnalysisOptions
                {
                    MaxFiles = 10,
                    MaxArchiveDepth = 4,
                    MaxWorkspaceArchiveNodes = 1
                }));
    }

    [Fact]
    public async Task MissingSidecarDoesNotConsumeRetainedPathBudgetForLaterArchives()
    {
        await using var temp = new TemporaryDirectory();
        const string missingEntry = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        await AsarTestArchiveBuilder.WriteAsync(
            Path.Combine(temp.Path, "first.asar"),
            $"{{\"files\":{{\"{missingEntry}\":{{\"size\":1,\"unpacked\":true}}}}}}");
        await AsarTestArchiveBuilder.WriteAsync(
            Path.Combine(temp.Path, "second.asar"),
            "{\"files\":{\"ok\":{\"size\":0,\"offset\":\"0\"}}}");

        var document = await AnalyzeAsync(
            temp.Path,
            new AnalysisOptions
            {
                MaxFiles = 10,
                MaxArchiveDepth = 4,
                MaxWorkspacePathCharacters = 100
            });

        AssertArtifact(document, "second.asar/ok");
        Assert.Contains(document.Warnings, warning => warning.Contains("外置項目", StringComparison.Ordinal));
    }

    private static Task<BlueprintDocument> AnalyzeAsync(
        string inputPath,
        AnalysisOptions? options = null) =>
        new BlueprintAnalyzer().AnalyzeAsync(inputPath, options);

    private static byte[] CreateRootFileArchive(string entryName, ReadOnlySpan<byte> content)
    {
        var header =
            $"{{\"files\":{{\"{entryName}\":{{\"size\":{content.Length},\"offset\":\"0\"}}}}}}";
        return AsarTestArchiveBuilder.Create(header, content);
    }

    private static async Task WriteZipAsync(string zipPath, string entryName, ReadOnlyMemory<byte> content)
    {
        using var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create);
        var entry = archive.CreateEntry(entryName, CompressionLevel.NoCompression);
        await using var output = entry.Open();
        await output.WriteAsync(content);
    }

    private static FileArtifact AssertArtifact(BlueprintDocument document, string relativePath) =>
        Assert.Single(document.Files, artifact => artifact.RelativePath == relativePath);

    private static void AssertOrigin(FileArtifact artifact, string kind, int depth)
    {
        Assert.Equal(kind, artifact.Origin.Kind);
        Assert.Equal(depth, artifact.Origin.Depth);
    }

    private static void AssertAsarOrigin(
        FileArtifact artifact,
        string container,
        string entry,
        int depth)
    {
        AssertOrigin(artifact, "asar", depth);
        Assert.Equal(container, artifact.Origin.Container);
        Assert.Equal(entry, artifact.Origin.Entry);
    }

    private static void AssertNoBangPaths(BlueprintDocument document) =>
        Assert.DoesNotContain(document.Files, artifact => artifact.RelativePath.Contains('!'));

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
