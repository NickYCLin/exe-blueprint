using System.Text.Json;
using System.Text.Json.Nodes;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class NativeDecompilationTests
{
    private static readonly NativeFunction Function = new() { Name = "worker", Address = "00401000" };
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static NativeDecompilation Evidence(string status = "success", string? code = "return 1;") => new()
    {
        InputSha256 = new string('a', 64), AnalyzerVersion = "12.1.4", Limits = new(),
        CandidateCount = 1, Complete = true, Truncated = status == "truncated",
        Functions = [new() { Address = Function.Address!, Status = status, Code = code }]
    };

    private static string Json(NativeDecompilation evidence) => JsonSerializer.Serialize(new { decompilation = evidence }, Options);

    [Theory]
    [InlineData("success", "return 1;")]
    [InlineData("truncated", "return")]
    [InlineData("failed", null)]
    [InlineData("timeout", null)]
    public void PreservesStatusesAndEvidence(string status, string? code)
    {
        var parsed = NativeDecompilationParser.Parse(Json(Evidence(status, code)), [Function]);
        Assert.Equal(status, Assert.Single(parsed!.Functions).Status);
        Assert.Equal(new string('a', 64), parsed.InputSha256);
        Assert.Equal("12.1.4", parsed.AnalyzerVersion);
    }

    [Fact]
    public void OldOutputHasNoPseudocode() => Assert.Null(NativeDecompilationParser.Parse("{}", []));

    [Fact]
    public void RetainsPartialCheckpoint()
    {
        var partial = Evidence() with { Complete = false, Functions = [] };
        Assert.False(NativeDecompilationParser.Parse(Json(partial), [Function])!.Complete);
    }

    [Theory]
    [InlineData("injected", "return 1;")]
    [InlineData("success", null)]
    [InlineData("failed", "return 1;")]
    public void RejectsInvalidStatusPayload(string status, string? code) =>
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(Json(Evidence(status, code)), [Function]));

    [Fact]
    public void RejectsBudgetsAndUnknownAddresses()
    {
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(Json(Evidence() with
        { Limits = new() { MaxTotalCharacters = 1 } }), [Function]));
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(Json(Evidence() with
        { Limits = new() { MaxFunctionCharacters = 1 } }), [Function]));
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(Json(Evidence()), []));
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(Json(Evidence() with
        { InputSha256 = "wrong" }), [Function]));
    }

    [Fact]
    public void RejectsMissingElapsedEvidence()
    {
        var json = Json(Evidence()).Replace(",\"elapsedMilliseconds\":0", string.Empty, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(json, [Function]));
    }

    [Fact]
    public void RejectsDuplicatesAndBrokenJson()
    {
        var json = Json(Evidence()).Replace("\"complete\":true", "\"complete\":true,\"complete\":false", StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(json, [Function]));
        Assert.ThrowsAny<JsonException>(() => NativeDecompilationParser.Parse("{", [Function]));
    }

    [Theory]
    [InlineData("functions", "[null]")]
    [InlineData("functions", "[1]")]
    [InlineData("functions", "[\"worker\"]")]
    [InlineData("functions", "null")]
    [InlineData("functions", "{}")]
    [InlineData("limits", "null")]
    [InlineData("limits", "[]")]
    public async Task RejectsNullAndWrongContainerTypesInParserAndAnalyzer(string field, string value)
    {
        var evidence = JsonNode.Parse(Json(Evidence()))!["decompilation"]!;
        evidence[field] = JsonNode.Parse(value);
        var json = new JsonObject { ["decompilation"] = evidence.DeepClone() }.ToJsonString();
        Assert.Throws<InvalidDataException>(() => NativeDecompilationParser.Parse(json, [Function]));
        var result = await ProbeAnalyzer(evidence, "matching", 0);
        Assert.Equal("none", result.Backend);
        Assert.Empty(result.Functions);
        Assert.Null(result.Decompilation);
        Assert.Contains("型別", result.Note);
    }

    [Theory]
    [InlineData("status", "17")]
    [InlineData("code", "{}")]
    [InlineData("elapsedMilliseconds", "\"slow\"")]
    public async Task RejectsWrongRecordTypesInParserAndAnalyzer(string field, string value)
    {
        var evidence = JsonNode.Parse(Json(Evidence()))!["decompilation"]!;
        evidence["functions"]![0]![field] = JsonNode.Parse(value);
        var json = new JsonObject { ["decompilation"] = evidence.DeepClone() }.ToJsonString();
        Assert.ThrowsAny<JsonException>(() => NativeDecompilationParser.Parse(json, [Function]));
        var result = await ProbeAnalyzer(evidence, "matching", 0);
        Assert.Equal("none", result.Backend);
        Assert.Empty(result.Functions);
        Assert.Contains("JSON", result.Note);
    }

    [Theory]
    [InlineData("missing", 1)]
    [InlineData("mismatch", 1)]
    [InlineData("mismatch", 0)]
    [InlineData("wrong_type", 1)]
    [InlineData("duplicate", 1)]
    public async Task RejectsUnverifiedBaselineRegardlessOfProcessDiagnostic(string checkpointHash, int exitCode)
    {
        var result = await ProbeAnalyzer(null, checkpointHash, exitCode);
        Assert.Equal("none", result.Backend);
        Assert.Empty(result.Functions);
        Assert.Null(result.CallGraph);
        Assert.Null(result.Decompilation);
        Assert.Contains("SHA256", result.Note);
        Assert.DoesNotContain("backend_partial", result.Note);
    }

    [Fact]
    public async Task PreservesOnlyHashVerifiedBaselineAfterBackendFailure()
    {
        var result = await ProbeAnalyzer(null, "matching", 1);
        Assert.Equal("ghidra", result.Backend);
        Assert.Single(result.Functions);
        Assert.Equal("backend_partial", result.Decompilation!.LimitReason);
        Assert.Equal("unavailable", result.Decompilation.AnalyzerVersion);
        Assert.False(result.Decompilation.Complete);
    }

    private static async Task<NativeCodeModel> ProbeAnalyzer(JsonNode? evidence, string checkpointHash, int exitCode)
    {
        var directory = Directory.CreateTempSubdirectory("native-provenance-test-").FullName;
        try
        {
            var support = Directory.CreateDirectory(Path.Combine(directory, "support")).FullName;
            var launcher = Path.Combine(support, OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
            await File.WriteAllTextAsync(launcher, string.Empty);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(launcher, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            var input = Path.Combine(directory, "synthetic.bin");
            await File.WriteAllBytesAsync(input, [1, 2, 3]);
            return await NativeAnalyzer.AnalyzeAsync(input, new()
            { GhidraInstallDir = directory, NativeDecompilation = new() }, async (request, cancellation) =>
            {
                using var config = JsonDocument.Parse(await File.ReadAllTextAsync(request.DecompilationConfigPath!, cancellation));
                var hash = config.RootElement.GetProperty("inputSha256").GetString()!;
                var payload = JsonNode.Parse("""
                    {"schemaVersion":3,"functionCount":1,"functions":[{"name":"worker","address":"00401000","signature":"int worker()","external":false}],"truncated":false,"callGraph":{"calls":[],"truncated":false}}
                    """)!;
                if (checkpointHash != "missing")
                    payload["inputSha256"] = checkpointHash == "wrong_type" ? JsonValue.Create(17)
                        : JsonValue.Create(checkpointHash == "mismatch" ? new string('b', 64) : hash);
                if (evidence is not null)
                {
                    payload["decompilation"] = evidence.DeepClone();
                    payload["decompilation"]!["inputSha256"] = hash;
                }
                var json = payload.ToJsonString();
                if (checkpointHash == "duplicate")
                    json = json.Insert(1, $"\"inputSha256\":\"{hash}\",");
                await File.WriteAllTextAsync(request.OutputPath, json, cancellation);
                return new GhidraRunResult(exitCode, string.Empty, "Imported program SHA256 differs from input evidence");
            }, CancellationToken.None);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task MissingBackendAndInvalidLimitsDoNotLaunch()
    {
        var options = new AnalysisOptions { GhidraInstallDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()), NativeDecompilation = new() };
        var result = await NativeAnalyzer.AnalyzeAsync("unused", options, CancellationToken.None);
        Assert.Equal("none", result.Backend);
        Assert.Null(result.Decompilation);
        result = await NativeAnalyzer.AnalyzeAsync("unused", options with
        { NativeDecompilation = new() { MaxFunctions = int.MaxValue } }, CancellationToken.None);
        Assert.Contains("限制", result.Note);
    }

    [Fact]
    public async Task CallerCancellationIsNotConvertedToEvidence()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NativeAnalyzer.AnalyzeAsync(
            "unused", new() { NativeDecompilation = new() }, cancellation.Token));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingBackendRetainsOnlyRequestedFailureEvidence(bool enabled)
    {
        var directory = Directory.CreateTempSubdirectory("native-missing-backend-").FullName;
        try
        {
            var input = Path.Combine(directory, "synthetic.bin");
            await File.WriteAllBytesAsync(input, [1, 2, 3]);
            var limits = new NativeDecompilationLimits { MaxFunctions = 7 };
            var result = await NativeAnalyzer.AnalyzeAsync(input, new()
            {
                GhidraInstallDir = Path.Combine(directory, "absent"),
                NativeDecompilation = enabled ? limits : null
            }, CancellationToken.None);
            Assert.Equal("none", result.Backend);
            Assert.Empty(result.Functions);
            Assert.Null(result.CallGraph);
            if (!enabled)
            {
                Assert.Null(result.Decompilation);
                return;
            }
            Assert.NotNull(result.Decompilation);
            Assert.Equal("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", result.Decompilation.InputSha256);
            Assert.Equal("unavailable", result.Decompilation.AnalyzerVersion);
            Assert.Equal("backend_unavailable", result.Decompilation.LimitReason);
            Assert.Equal(limits, result.Decompilation.Limits);
            Assert.False(result.Decompilation.Complete);
            Assert.False(result.Decompilation.Truncated);
            Assert.Empty(result.Decompilation.Functions);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData(0, false, null)]
    [InlineData(1, false, "backend_partial")]
    [InlineData(-1, true, "process_timeout")]
    public async Task AnalyzerValidatesEvidenceAndRetainsPartialGraphs(int exitCode, bool timedOut, string? reason)
    {
        var directory = Directory.CreateTempSubdirectory("native-evidence-test-").FullName;
        string? workspace = null;
        try
        {
            var support = Directory.CreateDirectory(Path.Combine(directory, "support")).FullName;
            var launcher = Path.Combine(support, OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
            await File.WriteAllTextAsync(launcher, string.Empty);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(launcher, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            var input = Path.Combine(directory, "synthetic.bin");
            await File.WriteAllBytesAsync(input, [1, 2, 3]);
            var result = await NativeAnalyzer.AnalyzeAsync(input, new()
            { GhidraInstallDir = directory, NativeDecompilation = new() }, async (request, cancellation) =>
            {
                workspace = request.WorkspacePath;
                Assert.NotNull(request.DecompilationConfigPath);
                using var config = JsonDocument.Parse(await File.ReadAllTextAsync(request.DecompilationConfigPath!, cancellation));
                var evidence = Evidence() with { InputSha256 = config.RootElement.GetProperty("inputSha256").GetString()! };
                var json = JsonSerializer.Serialize(new
                {
                    schemaVersion = 3, functionCount = 1,
                    inputSha256 = evidence.InputSha256,
                    functions = new[] { new { name = "worker", address = Function.Address, signature = "int worker()", external = false } },
                    truncated = false, callGraph = new { calls = Array.Empty<object>(), truncated = false },
                    decompilation = evidence
                }, Options);
                await File.WriteAllTextAsync(request.OutputPath, json, cancellation);
                return new GhidraRunResult(exitCode, string.Empty, string.Empty) { TimedOut = timedOut };
            }, CancellationToken.None);
            Assert.Equal("ghidra", result.Backend);
            Assert.NotNull(result.CallGraph);
            Assert.Equal(reason, result.Decompilation!.LimitReason);
            Assert.Equal(reason is null, result.Decompilation.Complete);
            Assert.Single(result.Decompilation.Functions);
            Assert.NotNull(workspace);
            Assert.False(Directory.Exists(workspace));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
