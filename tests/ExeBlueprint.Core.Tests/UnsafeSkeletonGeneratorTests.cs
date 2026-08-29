using System.Diagnostics;
using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class UnsafeSkeletonGeneratorTests
{
    private static readonly HashSet<string> FixtureTypeNames = new(StringComparer.Ordinal)
    {
        "ExeBlueprint.Core.Tests.FunctionPointerFixture",
        "ExeBlueprint.Core.Tests.UnsafeMemberFixture",
        "ExeBlueprint.Core.Tests.IUnsafeSignatureFixture",
        "ExeBlueprint.Core.Tests.UnsafeSignatureDelegateFixture",
        "ExeBlueprint.Core.Tests.UnsafePointerSourceFixture",
        "ExeBlueprint.Core.Tests.UnsafeBodyOnlyFixture",
        "ExeBlueprint.Core.Tests.SafeUnsafeNestedOwnerFixture",
        "ExeBlueprint.Core.Tests.SafeUnsafeNestedOwnerFixture.Child"
    };

    [Fact]
    public async Task EmitsScopedUnsafeContextsAndPerProjectCompilerSetting()
    {
        var fixtureDocument = await new BlueprintAnalyzer().AnalyzeAsync(typeof(UnsafeMemberFixture).Assembly.Location);
        var fixtureArtifact = Assert.Single(fixtureDocument.Files);
        var safeArtifact = fixtureArtifact with
        {
            Id = "safe",
            RelativePath = "Safe.dll",
            FileName = "Safe.dll",
            AssemblyName = "Safe",
            ManagedReferences = [],
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 5,
                Types =
                [
                    CreateType("SafeType"),
                    CreateType("OrphanNested") with
                    {
                        IsNested = true,
                        DeclaringType = "Tests.<GeneratedParent>",
                        Fields =
                        [
                            new FieldModel
                            {
                                Name = "Pointer",
                                Type = "byte*",
                                Accessibility = "internal"
                            }
                        ]
                    },
                    CreateType("StaticOwner") with
                    {
                        IsStatic = true,
                        Methods =
                        [
                            CreateMethod(
                                ".ctor",
                                parameters: [CreateParameter("pointer", "byte*")]) with
                            {
                                IsConstructor = true
                            }
                        ]
                    },
                    CreateType("EnumOwner", kind: "enum"),
                    CreateType("HiddenChild") with
                    {
                        FullName = "Tests.EnumOwner.HiddenChild",
                        IsNested = true,
                        DeclaringType = "Tests.EnumOwner",
                        Fields =
                        [
                            new FieldModel
                            {
                                Name = "Pointer",
                                Type = "byte*",
                                Accessibility = "internal"
                            }
                        ]
                    }
                ]
            }
        };
        var document = fixtureDocument with
        {
            Files = [fixtureArtifact, safeArtifact]
        };

        var files = CSharpSkeletonGenerator.Generate(document);
        var source = Assert.Single(
            files,
            file => file.RelativePath == "ExeBlueprint.Core.Tests/ExeBlueprint.Core.Tests.cs").Content;
        var unsafeProject = Assert.Single(
            files,
            file => file.RelativePath == "ExeBlueprint.Core.Tests/ExeBlueprint.Core.Tests.csproj").Content;
        var safeProject = Assert.Single(
            files,
            file => file.RelativePath == "Safe/Safe.csproj").Content;

        Assert.Contains("internal static unsafe class FunctionPointerFixture", source, StringComparison.Ordinal);
        Assert.Contains("internal sealed unsafe class UnsafeMemberFixture", source, StringComparison.Ordinal);
        Assert.Contains("internal static unsafe class UnsafeBodyOnlyFixture", source, StringComparison.Ordinal);
        Assert.Contains("internal unsafe interface IUnsafeSignatureFixture", source, StringComparison.Ordinal);
        Assert.Contains(
            "internal unsafe delegate int* UnsafeSignatureDelegateFixture(" +
            "byte* value, delegate* managed<void> callback);",
            source,
            StringComparison.Ordinal);
        Assert.Contains("internal static class SafeUnsafeNestedOwnerFixture", source, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "internal static unsafe class SafeUnsafeNestedOwnerFixture",
            source,
            StringComparison.Ordinal);
        Assert.Contains("    internal unsafe struct Child", source, StringComparison.Ordinal);
        Assert.Contains("internal int* PointerField = default!;", source, StringComparison.Ordinal);
        Assert.Contains(
            "internal byte* this[delegate* managed<void> callback]",
            source,
            StringComparison.Ordinal);
        Assert.Contains("<AllowUnsafeBlocks>true</AllowUnsafeBlocks>", unsafeProject, StringComparison.Ordinal);
        Assert.DoesNotContain("<AllowUnsafeBlocks>", safeProject, StringComparison.Ordinal);

        var bodyOnlyType = Assert.Single(
            fixtureArtifact.Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.UnsafeBodyOnlyFixture");
        var bodyOnlyMethod = Assert.Single(
            bodyOnlyType.Methods,
            method => method.Name == nameof(UnsafeBodyOnlyFixture.DiscardPointer));
        Assert.True(bodyOnlyMethod.BodyReconstructed);
        Assert.True(bodyOnlyMethod.RequiresUnsafeContext);

        var nestedOnlyArtifact = fixtureArtifact with
        {
            Id = "nested-only",
            RelativePath = "NestedOnly.dll",
            FileName = "NestedOnly.dll",
            AssemblyName = "NestedOnly",
            ManagedReferences = [],
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 2,
                Types =
                [
                    CreateType("Parent"),
                    CreateType("Child") with
                    {
                        FullName = "Tests.Parent.Child",
                        IsNested = true,
                        DeclaringType = "Tests.Parent",
                        Fields =
                        [
                            new FieldModel
                            {
                                Name = "Pointer",
                                Type = "byte*",
                                Accessibility = "internal"
                            }
                        ]
                    }
                ]
            }
        };
        var nestedOnlyFiles = CSharpSkeletonGenerator.Generate(
            fixtureDocument with { Files = [nestedOnlyArtifact] });
        var nestedOnlySource = Assert.Single(
            nestedOnlyFiles,
            file => file.RelativePath == "NestedOnly/Tests.cs").Content;
        var nestedOnlyProject = Assert.Single(
            nestedOnlyFiles,
            file => file.RelativePath == "NestedOnly/NestedOnly.csproj").Content;
        Assert.Contains("internal class Parent", nestedOnlySource, StringComparison.Ordinal);
        Assert.DoesNotContain("internal unsafe class Parent", nestedOnlySource, StringComparison.Ordinal);
        Assert.Contains("    internal unsafe class Child", nestedOnlySource, StringComparison.Ordinal);
        Assert.Contains("<AllowUnsafeBlocks>true</AllowUnsafeBlocks>", nestedOnlyProject, StringComparison.Ordinal);
    }

    [Fact]
    public void DetectsEveryEmittedUnsafeSignatureOwner()
    {
        var owners = new Dictionary<string, TypeModel>(StringComparer.Ordinal)
        {
            ["field"] = CreateType("FieldOwner") with
            {
                Fields =
                [
                    new FieldModel
                    {
                        Name = "Pointer",
                        Type = "byte*",
                        Accessibility = "internal"
                    }
                ]
            },
            ["property"] = CreateType("PropertyOwner") with
            {
                Properties =
                [
                    new PropertyModel
                    {
                        Name = "Pointer",
                        Type = "delegate* managed<void>",
                        Accessibility = "internal",
                        HasGetter = true
                    }
                ]
            },
            ["index parameter"] = CreateType("IndexerOwner") with
            {
                Properties =
                [
                    new PropertyModel
                    {
                        Name = "Item",
                        Type = "int",
                        Accessibility = "internal",
                        HasGetter = true,
                        Parameters = [CreateParameter("index", "byte*")]
                    }
                ]
            },
            ["event"] = CreateType("EventOwner") with
            {
                Events =
                [
                    new EventModel
                    {
                        Name = "Changed",
                        Type = "delegate* unmanaged<void>",
                        Accessibility = "internal"
                    }
                ]
            },
            ["method return"] = CreateType("MethodReturnOwner") with
            {
                Methods = [CreateMethod("Read", "byte*")]
            },
            ["method parameter"] = CreateType("MethodParameterOwner") with
            {
                Methods = [CreateMethod("Write", parameters: [CreateParameter("value", "byte*")])]
            },
            ["constructor parameter"] = CreateType("ConstructorOwner") with
            {
                Methods =
                [
                    CreateMethod(
                        ".ctor",
                        parameters: [CreateParameter("callback", "delegate* managed<void>")]) with
                    {
                        IsConstructor = true
                    }
                ]
            },
            ["reconstructed body"] = CreateType("BodyOwner") with
            {
                Methods =
                [
                    CreateMethod("CallPointerApi") with
                    {
                        BodyReconstructed = true,
                        Body = ["PointerApi.GetPointer();"],
                        RequiresUnsafeContext = true
                    }
                ]
            },
            ["delegate"] = CreateType("PointerDelegate", kind: "delegate") with
            {
                Methods =
                [
                    CreateMethod(
                        "Invoke",
                        "byte*",
                        [CreateParameter("callback", "delegate* unmanaged<void>")])
                ]
            }
        };

        foreach (var (shape, owner) in owners)
        {
            Assert.True(CSharpSkeletonGenerator.RequiresUnsafeContext(owner), shape);
        }

        var safeOwner = CreateType("SafeOwner") with
        {
            Fields =
            [
                new FieldModel
                {
                    Name = "Count",
                    Type = "int",
                    Accessibility = "private"
                }
            ],
            Methods =
            [
                CreateMethod("Multiply", parameters: [CreateParameter("value", "int")]) with
                {
                    BodyReconstructed = true,
                    Body = ["return (value * value);"]
                }
            ]
        };
        Assert.False(CSharpSkeletonGenerator.RequiresUnsafeContext(safeOwner));

        var staticOwnerWithSkippedConstructor = CreateType("StaticOwner") with
        {
            IsStatic = true,
            Methods =
            [
                CreateMethod(
                    ".ctor",
                    parameters: [CreateParameter("pointer", "byte*")]) with
                {
                    IsConstructor = true
                }
            ]
        };
        Assert.False(CSharpSkeletonGenerator.RequiresUnsafeContext(staticOwnerWithSkippedConstructor));
    }

    [Fact]
    public async Task GeneratedUnsafeSignatureSubsetBuildsInRelease()
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(UnsafeMemberFixture).Assembly.Location);
        var artifact = Assert.Single(analyzed.Files);
        var filteredTypes = artifact.Code!.Types
            .Where(type => FixtureTypeNames.Contains(type.FullName))
            .ToArray();
        Assert.Equal(FixtureTypeNames.Count, filteredTypes.Length);

        var filteredArtifact = artifact with
        {
            ManagedReferences = [],
            Code = artifact.Code with
            {
                NamespaceCount = 1,
                TypeCount = filteredTypes.Length,
                MethodCount = filteredTypes.Sum(type => type.Methods.Count),
                Types = filteredTypes
            }
        };
        var document = analyzed with { Files = [filteredArtifact] };
        var generatedFiles = CSharpSkeletonGenerator.Generate(document);

        await using var temp = new TemporaryDirectory();
        foreach (var file in generatedFiles)
        {
            var path = Path.Combine(temp.Path, file.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, file.Content);
        }

        var startInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = temp.Path,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add("build");
        startInfo.ArgumentList.Add("Reconstructed.slnx");
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add("Release");
        startInfo.ArgumentList.Add("--nologo");
        startInfo.ArgumentList.Add("-warnaserror");
        startInfo.Environment["DOTNET_CLI_HOME"] = Path.Combine(temp.Path, ".dotnet-home");
        startInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";

        using var process = Assert.IsType<Process>(Process.Start(startInfo));
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        var buildOutput = (await standardOutput) + (await standardError);
        Assert.True(process.ExitCode == 0, buildOutput);
    }

    private static TypeModel CreateType(string name, string kind = "class") => new()
    {
        FullName = $"Tests.{name}",
        Namespace = "Tests",
        Name = name,
        Kind = kind,
        Accessibility = "internal"
    };

    private static MethodModel CreateMethod(
        string name,
        string returnType = "void",
        IReadOnlyList<ParameterModel>? parameters = null) => new()
        {
            Name = name,
            Signature = $"{name}(...)",
            ReturnType = returnType,
            Accessibility = "internal",
            Parameters = parameters ?? []
        };

    private static ParameterModel CreateParameter(string name, string type) => new()
    {
        Name = name,
        Type = type
    };

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-csharp-unsafe-{Guid.NewGuid():N}");
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
