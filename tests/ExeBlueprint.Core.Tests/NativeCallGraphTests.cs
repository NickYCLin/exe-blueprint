using System.Text.Json;
using System.Text.Json.Nodes;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;
using ExeBlueprint.Reporting;

namespace ExeBlueprint.Core.Tests;

public sealed class NativeCallGraphTests
{
    internal const string OutputJson = """
        {
          "schemaVersion": 2, "functionCount": 3, "truncated": false,
          "functions": [
            {"name":"worker","address":"00401000","signature":"void worker()","external":false},
            {"name":"worker","address":"00402000","signature":"int worker(int)","external":false},
            {"name":"puts","address":"EXTERNAL:00000001","signature":"int puts(char*)","external":true}
          ],
          "callGraph": {"truncated":false,"calls":[
            {"callerAddress":"00401000","callSiteAddress":"00401004","targetAddress":"00402000","isIndirect":false},
            {"callerAddress":"00402000","callSiteAddress":"00402004","targetAddress":"00402000","isIndirect":false},
            {"callerAddress":"00401000","callSiteAddress":"00401008","targetAddress":"EXTERNAL:00000001","isIndirect":true},
            {"callerAddress":"00401000","callSiteAddress":"0040100c","targetAddress":null,"isIndirect":true},
            {"callerAddress":"00401000","callSiteAddress":"00401010","targetAddress":null,"isIndirect":false}
          ]}
        }
        """;

    [Fact]
    public void PreservesSameNamedFunctionsRecursionExternalAndUnresolvedCalls()
    {
        var parsed = GhidraOutputParser.Parse(OutputJson);
        Assert.True(parsed.IsValid, parsed.Error);
        var graph = Assert.IsType<NativeCallGraph>(parsed.CallGraph);
        Assert.False(graph.Truncated);
        Assert.False(graph.TailCallsAnalyzed);
        Assert.All(graph.Calls, call => Assert.False(call.IsTailCall));
        Assert.Equal(5, graph.Calls.Count);
        Assert.Equal(2, graph.UnresolvedCallCount);
        Assert.Equal("00401000", graph.Calls[0].CallerAddress);
        Assert.Equal("00402000", graph.Calls[0].TargetAddress);
        Assert.Equal(graph.Calls[1].CallerAddress, graph.Calls[1].TargetAddress);
        Assert.Equal("EXTERNAL:00000001", graph.Calls[2].TargetAddress);
        Assert.True(graph.Calls[2].IsIndirect);
        Assert.False(graph.Calls[4].IsIndirect);
    }

    internal static string TailOutputJson => CreateTailOutput().ToJsonString();

    private static JsonNode CreateTailOutput()
    {
        var root = JsonNode.Parse(OutputJson)!;
        root["schemaVersion"] = 3;
        foreach (var call in root["callGraph"]!["calls"]!.AsArray())
        {
            call!["isTailCall"] = false;
        }
        root["callGraph"]!["calls"]![0]!["isTailCall"] = true;
        return root;
    }

    [Fact]
    public void PreservesTailCallCoverageEvenWhenEmptyOrTruncated()
    {
        var root = CreateTailOutput();
        var parsed = GhidraOutputParser.Parse(root.ToJsonString());
        Assert.True(parsed.IsValid, parsed.Error);
        Assert.True(parsed.CallGraph!.TailCallsAnalyzed);
        Assert.True(parsed.CallGraph.Calls[0].IsTailCall);
        Assert.All(parsed.CallGraph.Calls.Skip(1), call => Assert.False(call.IsTailCall));

        var bounded = GhidraOutputParser.Parse(root.ToJsonString(), 32_000, 10, 100, maxCalls: 1);
        Assert.True(bounded.IsValid, bounded.Error);
        Assert.True(bounded.CallGraph!.TailCallsAnalyzed);
        Assert.True(bounded.CallGraph.Truncated);
        Assert.True(Assert.Single(bounded.CallGraph.Calls).IsTailCall);

        var functionsBounded = GhidraOutputParser.Parse(root.ToJsonString(), 32_000, 1, 100);
        Assert.True(functionsBounded.IsValid, functionsBounded.Error);
        Assert.True(functionsBounded.CallGraph!.Truncated);
        Assert.DoesNotContain(functionsBounded.CallGraph.Calls, call => call.IsTailCall);

        root["callGraph"]!["calls"] = new JsonArray();
        var empty = GhidraOutputParser.Parse(root.ToJsonString());
        Assert.True(empty.IsValid, empty.Error);
        Assert.True(empty.CallGraph!.TailCallsAnalyzed);
        Assert.False(empty.CallGraph.Truncated);
        Assert.Empty(empty.CallGraph.Calls);
    }

    [Theory]
    [InlineData("missing-flag")]
    [InlineData("invalid-flag")]
    [InlineData("null-flag")]
    [InlineData("indirect-tail")]
    [InlineData("unknown-tail")]
    [InlineData("recursive-tail")]
    [InlineData("multiple-tail-targets")]
    [InlineData("conflicting-site-kind")]
    [InlineData("conflicting-indirect-kind")]
    [InlineData("v2-with-tail-flag")]
    [InlineData("v2-with-false-tail-flag")]
    [InlineData("duplicate-flag")]
    [InlineData("invalid-after-limit")]
    public void RejectsInvalidTailCallEvidence(string mutation)
    {
        var root = CreateTailOutput();
        var calls = root["callGraph"]!["calls"]!.AsArray();
        var call = calls[0]!;
        switch (mutation)
        {
            case "missing-flag": call.AsObject().Remove("isTailCall"); break;
            case "invalid-flag": call["isTailCall"] = "true"; break;
            case "null-flag": call["isTailCall"] = null; break;
            case "indirect-tail": call["isIndirect"] = true; break;
            case "unknown-tail": call["targetAddress"] = null; break;
            case "recursive-tail": call["targetAddress"] = "00401000"; break;
            case "multiple-tail-targets":
                var secondTail = call.DeepClone();
                secondTail["targetAddress"] = "EXTERNAL:00000001";
                calls.Add(secondTail);
                break;
            case "conflicting-site-kind":
                var secondKind = call.DeepClone();
                secondKind["isTailCall"] = false;
                secondKind["targetAddress"] = "EXTERNAL:00000001";
                calls.Add(secondKind);
                break;
            case "conflicting-indirect-kind":
                var secondIndirect = calls[2]!.DeepClone();
                secondIndirect["isIndirect"] = false;
                secondIndirect["targetAddress"] = "00402000";
                calls.Add(secondIndirect);
                break;
            case "v2-with-tail-flag": root["schemaVersion"] = 2; break;
            case "v2-with-false-tail-flag": root["schemaVersion"] = 2; call["isTailCall"] = false; break;
            case "duplicate-flag": break;
            case "invalid-after-limit": calls[4]!.AsObject().Remove("isTailCall"); break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var json = root.ToJsonString();
        if (mutation == "duplicate-flag")
        {
            json = json.Replace("\"isTailCall\":true", "\"isTailCall\":false,\"isTailCall\":true", StringComparison.Ordinal);
        }
        var parsed = GhidraOutputParser.Parse(json, 32_000, 10, 100, maxCalls: 1);
        Assert.False(parsed.IsValid);
        Assert.Empty(parsed.Functions);
        Assert.Null(parsed.CallGraph);
    }

    [Fact]
    public async Task WritesTailCallFlagsAndCoverageToJsonAndReport()
    {
        await using var temp = new TemporaryDirectory();
        var parsed = GhidraOutputParser.Parse(TailOutputJson);
        Assert.True(parsed.IsValid, parsed.Error);
        var document = CreateDocument(new NativeCodeModel
        {
            Backend = "ghidra",
            FunctionCount = parsed.FunctionCount,
            Functions = parsed.Functions,
            CallGraph = parsed.CallGraph
        });
        var report = MarkdownReportWriter.Build(document);
        Assert.Contains("worker (00402000) | 直接 tail call |", report);
        Assert.Contains("未驗證呼叫慣例或堆疊狀態", report);
        Assert.Contains("間接與條件跳躍未納入", report);

        var output = Path.Combine(temp.Path, "blueprint.json");
        await BlueprintJsonWriter.WriteAsync(document, output);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(output));
        var graph = json.RootElement.GetProperty("files")[0].GetProperty("nativeCode").GetProperty("callGraph");
        Assert.True(graph.GetProperty("tailCallsAnalyzed").GetBoolean());
        Assert.True(graph.GetProperty("calls")[0].GetProperty("isTailCall").GetBoolean());
        Assert.False(graph.GetProperty("calls")[1].GetProperty("isTailCall").GetBoolean());
        Assert.Equal(2, graph.GetProperty("unresolvedCallCount").GetInt32());
    }

    [Fact]
    public void DistinguishesLegacyOutputFromAnEmptyScannedGraph()
    {
        var root = JsonNode.Parse(OutputJson)!;
        root["callGraph"]!["calls"] = new JsonArray();
        var empty = GhidraOutputParser.Parse(root.ToJsonString());
        Assert.True(empty.IsValid);
        Assert.Empty(empty.CallGraph!.Calls);
        Assert.False(empty.CallGraph.Truncated);

        root["schemaVersion"] = 1;
        root.AsObject().Remove("callGraph");
        var legacy = GhidraOutputParser.Parse(root.ToJsonString());
        Assert.True(legacy.IsValid);
        Assert.Null(legacy.CallGraph);
    }

    [Theory]
    [InlineData("missing-graph")]
    [InlineData("null-graph")]
    [InlineData("invalid-truncated")]
    [InlineData("invalid-calls")]
    [InlineData("unknown-caller")]
    [InlineData("external-caller")]
    [InlineData("unknown-target")]
    [InlineData("missing-target")]
    [InlineData("numeric-target")]
    [InlineData("blank-site")]
    [InlineData("oversized-site")]
    [InlineData("control-site")]
    [InlineData("invalid-indirect")]
    [InlineData("duplicate-function")]
    [InlineData("oversized-function-address")]
    [InlineData("duplicate-call")]
    [InlineData("invalid-call-after-limit")]
    [InlineData("legacy-with-graph")]
    public void RejectsInvalidGraphWithoutReturningPartialEdges(string mutation)
    {
        var root = JsonNode.Parse(OutputJson)!;
        var graph = root["callGraph"]!;
        var calls = graph["calls"]!.AsArray();
        var call = calls[0]!;
        switch (mutation)
        {
            case "missing-graph": root.AsObject().Remove("callGraph"); break;
            case "null-graph": root["callGraph"] = null; break;
            case "invalid-truncated": graph["truncated"] = "false"; break;
            case "invalid-calls": graph["calls"] = new JsonObject(); break;
            case "unknown-caller": call["callerAddress"] = "missing"; break;
            case "external-caller": call["callerAddress"] = "EXTERNAL:00000001"; break;
            case "unknown-target": call["targetAddress"] = "00402001"; break;
            case "missing-target": call.AsObject().Remove("targetAddress"); break;
            case "numeric-target": call["targetAddress"] = 123; break;
            case "blank-site": call["callSiteAddress"] = " "; break;
            case "oversized-site": call["callSiteAddress"] = new string('a', 257); break;
            case "control-site": call["callSiteAddress"] = "00401004\n"; break;
            case "invalid-indirect": call["isIndirect"] = 1; break;
            case "duplicate-function": root["functions"]![1]!["address"] = "00401000"; break;
            case "oversized-function-address": root["functions"]![1]!["address"] = new string('a', 257); break;
            case "duplicate-call": calls.Add(call.DeepClone()); break;
            case "invalid-call-after-limit": calls.Add(new JsonObject()); break;
            case "legacy-with-graph": root["schemaVersion"] = 1; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var parsed = GhidraOutputParser.Parse(root.ToJsonString(), 32_000, 10, 100, maxCalls: 1);
        Assert.False(parsed.IsValid);
        Assert.NotNull(parsed.Error);
        Assert.Empty(parsed.Functions);
        Assert.Null(parsed.CallGraph);
    }

    [Theory]
    [InlineData("\"schemaVersion\": 2", "\"schemaVersion\": 1, \"schemaVersion\": 2")]
    [InlineData("\"callerAddress\":\"00401000\"", "\"callerAddress\":\"bad\",\"callerAddress\":\"00401000\"")]
    [InlineData("\"name\":\"puts\"", "\"name\":\"wrong\",\"name\":\"puts\"")]
    [InlineData("\"truncated\":false,\"calls\"", "\"truncated\":true,\"truncated\":false,\"calls\"")]
    public void RejectsAmbiguousDuplicateProperties(string original, string replacement)
    {
        var parsed = GhidraOutputParser.Parse(OutputJson.Replace(original, replacement, StringComparison.Ordinal));
        Assert.False(parsed.IsValid);
        Assert.Null(parsed.CallGraph);
    }

    [Fact]
    public void BoundsCallsAndDropsReferencesToFunctionsNotRetained()
    {
        var bounded = GhidraOutputParser.Parse(OutputJson, 32_000, 10, 100, maxCalls: 2);
        Assert.True(bounded.IsValid);
        Assert.True(bounded.CallGraph!.Truncated);
        Assert.Equal(2, bounded.CallGraph.Calls.Count);
        Assert.Equal(0, bounded.CallGraph.UnresolvedCallCount);

        var functionsBounded = GhidraOutputParser.Parse(OutputJson, 32_000, 1, 4);
        Assert.True(functionsBounded.IsValid);
        Assert.True(functionsBounded.Truncated);
        Assert.Equal("00401000", Assert.Single(functionsBounded.Functions).Address);
        Assert.True(functionsBounded.CallGraph!.Truncated);
        Assert.Equal(2, functionsBounded.CallGraph.Calls.Count);
        Assert.All(functionsBounded.CallGraph.Calls, call => Assert.Null(call.TargetAddress));

        var exporterBounded = GhidraOutputParser.Parse(
            OutputJson.Replace("\"truncated\":false,\"calls\"", "\"truncated\":true,\"calls\"", StringComparison.Ordinal));
        Assert.True(exporterBounded.IsValid);
        Assert.False(exporterBounded.Truncated);
        Assert.True(exporterBounded.CallGraph!.Truncated);
    }

    [Fact]
    public async Task WritesCallGraphToJsonAndEscapedReportWithExplicitLimits()
    {
        await using var temp = new TemporaryDirectory();
        var parsed = GhidraOutputParser.Parse(OutputJson);
        var repeatedCalls = Enumerable.Range(0, 101)
            .Select(index => parsed.CallGraph!.Calls[0] with { CallSiteAddress = $"site-{index}" })
            .Append(parsed.CallGraph!.Calls[3]).ToArray();
        var native = new NativeCodeModel
        {
            Backend = "ghidra",
            FunctionCount = parsed.FunctionCount,
            Functions = parsed.Functions.Select(function => function with { Name = "worker|name" }).ToArray(),
            CallGraph = new NativeCallGraph { Calls = repeatedCalls, Truncated = true }
        };
        var document = CreateDocument(native);
        var report = MarkdownReportWriter.Build(document);
        Assert.Contains("保留 102 筆呼叫紀錄，其中 1 筆目標未解析", report);
        Assert.Contains("worker\\|name (00401000)", report);
        Assert.Contains("worker\\|name (00402000)", report);
        Assert.Contains("site-99", report);
        Assert.DoesNotContain("site-100", report);
        Assert.Contains("blueprint.json 也只保留部分紀錄", report);
        Assert.Contains("報告僅列出前 100 筆", report);

        var output = Path.Combine(temp.Path, "blueprint.json");
        await BlueprintJsonWriter.WriteAsync(document, output);
        using var json = JsonDocument.Parse(await File.ReadAllTextAsync(output));
        Assert.Equal("0.21", json.RootElement.GetProperty("schemaVersion").GetString());
        var graph = json.RootElement.GetProperty("files")[0].GetProperty("nativeCode").GetProperty("callGraph");
        Assert.Equal(102, graph.GetProperty("calls").GetArrayLength());
        Assert.False(graph.GetProperty("tailCallsAnalyzed").GetBoolean());
        Assert.Equal(1, graph.GetProperty("unresolvedCallCount").GetInt32());
        Assert.Equal(JsonValueKind.Null, graph.GetProperty("calls")[101].GetProperty("targetAddress").ValueKind);

        var ordinaryReport = MarkdownReportWriter.Build(CreateDocument(native with { CallGraph = parsed.CallGraph }));
        Assert.Contains("未解析 | 間接", ordinaryReport);
        Assert.Contains("未解析 | 直接", ordinaryReport);
        Assert.Contains("未分析 tail call", ordinaryReport);
        var legacyReport = MarkdownReportWriter.Build(CreateDocument(native with { CallGraph = null }));
        Assert.Contains("未提供原生呼叫圖", legacyReport);
    }

    private static BlueprintDocument CreateDocument(NativeCodeModel native) => new()
    {
        Input = new InputDescriptor { Name = "fixture.exe", Kind = "file", SourcePath = "fixture.exe", FileCount = 1, TotalBytes = 1 },
        Summary = new BlueprintSummary(),
        Files = [new FileArtifact
        {
            Id = "fixture.exe", RelativePath = "fixture.exe", FileName = "fixture.exe", Size = 1,
            Sha256 = new string('0', 64), Category = "executable", Format = "Native Portable Executable",
            NativeCode = native
        }]
    };

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("exe-blueprint-callgraph-test-").FullName;

        public ValueTask DisposeAsync()
        {
            Directory.Delete(Path, recursive: true);
            return ValueTask.CompletedTask;
        }
    }
}
