using System.Diagnostics;
using ExeBlueprint.Analysis;
using ExeBlueprint.Generation;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class CSharpSkeletonGeneratorTests
{
    [Fact]
    public async Task GeneratesReadableSkeletonFromManagedAssembly()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var files = CSharpSkeletonGenerator.Generate(document);

        Assert.Contains(files, file => file.RelativePath.EndsWith(".csproj", StringComparison.Ordinal));
        Assert.Contains(files, file => file.RelativePath == "README.md");

        var modelsFile = Assert.Single(
            files,
            file => file.RelativePath.EndsWith("ExeBlueprint.Models.cs", StringComparison.Ordinal));
        Assert.Contains("namespace ExeBlueprint.Models;", modelsFile.Content);
        Assert.Contains("class FileArtifact", modelsFile.Content);
        Assert.Contains("public override bool Equals(object? obj)", modelsFile.Content);
        Assert.Contains("public bool Equals(ExeBlueprint.Models.BlueprintDocument? other)", modelsFile.Content);
        Assert.Contains("throw new global::System.NotImplementedException();", modelsFile.Content);
    }

    [Fact]
    public async Task GeneratedTypeSignaturesAreCleanOfMetadataArtifacts()
    {
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);

        var sourceFiles = CSharpSkeletonGenerator.Generate(document)
            .Where(file => file.RelativePath.EndsWith(".cs", StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(sourceFiles);
        foreach (var file in sourceFiles)
        {
            // 註解裡的原始 IL 允許帶原始名稱；字串常值裡也可能剛好有反引號。
            // 這裡只檢查真正的 metadata 殘留：泛型 arity（`1）與運算子方法呼叫（.op_）。
            var codeLines = file.Content
                .Split('\n')
                .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));
            foreach (var line in codeLines)
            {
                Assert.DoesNotMatch(@"`\d", line);
                Assert.DoesNotContain(".op_", line, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void GenerateReturnsEmptyWhenNoManagedCode()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "sample",
                Kind = "file",
                SourcePath = "sample",
                FileCount = 0,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary()
        };

        Assert.Empty(CSharpSkeletonGenerator.Generate(document));
    }

    [Fact]
    public async Task EscapesKeywordParameterNamesInDelegatesAndConstructors()
    {
        var artifact = CreateManagedArtifact("KeywordIdentifiers", []) with
        {
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 2,
                MethodCount = 2,
                Types =
                [
                    new TypeModel
                    {
                        FullName = "KeywordIdentifiers.KeywordDelegate",
                        Namespace = "KeywordIdentifiers",
                        Name = "KeywordDelegate`1",
                        Kind = "delegate",
                        Accessibility = "public",
                        GenericParameters = ["TStruct"],
                        Methods =
                        [
                            new MethodModel
                            {
                                Name = "Invoke",
                                Signature = "void Invoke(ref !0 this)",
                                ReturnType = "void",
                                Accessibility = "public",
                                Parameters =
                                [
                                    new ParameterModel
                                    {
                                        Name = "this",
                                        Type = "ref !0"
                                    }
                                ]
                            }
                        ]
                    },
                    new TypeModel
                    {
                        FullName = "KeywordIdentifiers.RegexLike",
                        Namespace = "KeywordIdentifiers",
                        Name = "RegexLike",
                        Kind = "class",
                        Accessibility = "public",
                        IsSealed = true,
                        Methods =
                        [
                            new MethodModel
                            {
                                Name = ".ctor",
                                Signature = "void .ctor(string string)",
                                ReturnType = "void",
                                Accessibility = "public",
                                IsConstructor = true,
                                HasBody = true,
                                Parameters =
                                [
                                    new ParameterModel
                                    {
                                        Name = "string",
                                        Type = "string"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "keyword-identifiers",
                Kind = "file",
                SourcePath = "KeywordIdentifiers.dll",
                FileCount = 1,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files = [artifact]
        };

        var generated = CSharpSkeletonGenerator.Generate(document);
        var source = Assert.Single(
            generated,
            file => file.RelativePath == "KeywordIdentifiers/KeywordIdentifiers.cs").Content;

        Assert.Contains(
            "public delegate void KeywordDelegate<TStruct>(ref TStruct @this);",
            source,
            StringComparison.Ordinal);
        Assert.Contains("public RegexLike(string @string)", source, StringComparison.Ordinal);
        await AssertGeneratedSolutionBuildsAsync(generated);
    }

    [Fact]
    public async Task AttachesNestedTypeOnlyToExactGenericOwnerScope()
    {
        var artifact = CreateManagedArtifact("NestedOwnerScope", []) with
        {
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 3,
                Types =
                [
                    new TypeModel
                    {
                        FullName = "NestedOwnerScope.Owner",
                        Namespace = "NestedOwnerScope",
                        Name = "Owner",
                        Kind = "class",
                        Accessibility = "public"
                    },
                    new TypeModel
                    {
                        FullName = "NestedOwnerScope.Owner",
                        Namespace = "NestedOwnerScope",
                        Name = "Owner`1",
                        Kind = "class",
                        Accessibility = "public",
                        GenericParameters = ["T"]
                    },
                    new TypeModel
                    {
                        FullName = "NestedOwnerScope.Owner.Child",
                        Namespace = "NestedOwnerScope",
                        Name = "Child",
                        Kind = "class",
                        Accessibility = "public",
                        IsNested = true,
                        DeclaringType = "NestedOwnerScope.Owner",
                        InheritedGenericParameterCount = 1,
                        GenericParameters = ["T"],
                        Fields =
                        [
                            new FieldModel
                            {
                                Name = "Value",
                                Type = "!0",
                                Accessibility = "public"
                            }
                        ]
                    }
                ]
            }
        };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "nested-owner-scope",
                Kind = "file",
                SourcePath = "NestedOwnerScope.dll",
                FileCount = 1,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files = [artifact]
        };

        var generated = CSharpSkeletonGenerator.Generate(document);
        var source = Assert.Single(
            generated,
            file => file.RelativePath == "NestedOwnerScope/NestedOwnerScope.cs").Content;

        Assert.Equal(1, source.Split("class Child", StringSplitOptions.None).Length - 1);
        Assert.Contains(
            "public class Owner<T>\n{\n    public class Child\n    {\n        public T Value = default!;",
            source.ReplaceLineEndings("\n"),
            StringComparison.Ordinal);
        await AssertGeneratedSolutionBuildsAsync(generated);
    }

    [Fact]
    public void EmitsWhitelistedConstructorInitializersAndReconstructedBodies()
    {
        var artifact = CreateManagedArtifact("ConstructorCases", []) with
        {
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 1,
                Types =
                [
                    new TypeModel
                    {
                        FullName = "ConstructorCases.GenericOwner",
                        Namespace = "ConstructorCases",
                        Name = "GenericOwner",
                        Kind = "class",
                        Accessibility = "public",
                        GenericParameters = ["T"],
                        Methods =
                        [
                            new MethodModel
                            {
                                Name = ".ctor",
                                Signature = "void .ctor(!0 value)",
                                ReturnType = "void",
                                Accessibility = "public",
                                IsConstructor = true,
                                Parameters =
                                [
                                    new ParameterModel
                                    {
                                        Name = "value",
                                        Type = "!0"
                                    }
                                ],
                                ConstructorInitializer = new ConstructorInitializerModel
                                {
                                    Kind = "base",
                                    Arguments = ["value", "typeof(!0)", "\"!0\""]
                                },
                                BodyReconstructed = true,
                                Body = ["this.Value = value;", "var token = \"!0\";"]
                            },
                            new MethodModel
                            {
                                Name = ".ctor",
                                Signature = "void .ctor(int value)",
                                ReturnType = "void",
                                Accessibility = "protected",
                                IsConstructor = true,
                                Parameters =
                                [
                                    new ParameterModel
                                    {
                                        Name = "value",
                                        Type = "int"
                                    }
                                ],
                                ConstructorInitializer = new ConstructorInitializerModel
                                {
                                    Kind = "this",
                                    Arguments = ["default(!0)"]
                                },
                                Body = ["throw new global::System.Exception();"]
                            },
                            new MethodModel
                            {
                                Name = ".ctor",
                                Signature = "void .ctor(double value)",
                                ReturnType = "void",
                                Accessibility = "internal",
                                IsConstructor = true,
                                Parameters =
                                [
                                    new ParameterModel
                                    {
                                        Name = "value",
                                        Type = "double"
                                    }
                                ],
                                ConstructorInitializer = new ConstructorInitializerModel
                                {
                                    Kind = "global::System.Console.WriteLine",
                                    Arguments = ["value"]
                                },
                                BodyReconstructed = true
                            }
                        ]
                    }
                ]
            }
        };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "constructor-cases",
                Kind = "file",
                SourcePath = "ConstructorCases.dll",
                FileCount = 1,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files = [artifact]
        };

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath == "ConstructorCases/ConstructorCases.cs").Content.ReplaceLineEndings("\n");

        Assert.Contains(
            "public GenericOwner(T value) : base(value, typeof(T), \"!0\")\n" +
            "    {\n" +
            "        this.Value = value;\n" +
            "        var token = \"!0\";\n" +
            "    }",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "protected GenericOwner(int value) : this(default(T))\n" +
            "    {\n" +
            "    }",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal GenericOwner(double value)\n" +
            "    {\n" +
            "    }",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("throw new global::System.Exception();", source, StringComparison.Ordinal);
        Assert.DoesNotContain("global::System.Console.WriteLine", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PreservesMemberShapesInGeneratedCSharp()
    {
        var assemblyPath = typeof(MemberShapeFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("public const string Label = \"blueprint\";", source);
        Assert.Contains("protected internal static readonly int Counter = default!;", source);
        Assert.Contains("public virtual string Name { get; protected set; } = default!;", source);
        Assert.Contains("public System.Text.StringBuilder Builder { get; } = default!;", source);
        Assert.Contains("internal static event System.EventHandler Changed;", source);
        Assert.Contains("protected virtual event System.EventHandler Updated;", source);
        Assert.Equal(1, source.Split(" Changed;", StringSplitOptions.None).Length - 1);
        Assert.Equal(1, source.Split(" Updated;", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("add_Changed", source, StringComparison.Ordinal);
        Assert.DoesNotContain("remove_Changed", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsCompilableSetterOnlyPropertiesWithoutInventingGetters()
    {
        var artifact = CreateManagedArtifact("SetterOnly", []) with
        {
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = 6,
                Types =
                [
                    CreateSetterOnlyType(
                        "IWriteOnly",
                        kind: "interface",
                        isAbstract: true,
                        properties:
                        [
                            CreateSetterOnlyProperty(
                                "Value",
                                isAbstract: true,
                                isVirtual: true,
                                isNewSlot: true)
                        ]),
                    CreateSetterOnlyType(
                        "AbstractWriteOnly",
                        isAbstract: true,
                        properties:
                        [
                            CreateSetterOnlyProperty(
                                "Value",
                                isAbstract: true,
                                isVirtual: true,
                                isNewSlot: true)
                        ]),
                    CreateSetterOnlyType(
                        "StaticWriteOnly",
                        properties:
                        [
                            CreateSetterOnlyProperty("Value", isStatic: true),
                            CreateSetterOnlyProperty(
                                "InstanceValue",
                                isVirtual: true,
                                isNewSlot: true),
                            CreateSetterOnlyProperty(
                                "Item",
                                type: "string",
                                parameters:
                                [
                                    new ParameterModel
                                    {
                                        Name = "index",
                                        Type = "int"
                                    }
                                ]),
                            CreateSetterOnlyProperty("ProtectedValue", accessibility: "protected"),
                            CreateSetterOnlyProperty("MissingAccessors", type: "byte*", hasSetter: false),
                            CreateSetterOnlyProperty("ByRefSetter", type: "ref int"),
                            CreateSetterOnlyProperty("Callback", type: "delegate* managed<void>")
                        ],
                        methods:
                        [
                            CreateSetterMethod()
                        ]),
                    CreateSetterOnlyType(
                        "DerivedWriteOnly",
                        baseType: "SetterOnly.StaticWriteOnly",
                        properties:
                        [
                            CreateSetterOnlyProperty("InstanceValue", isVirtual: true, isFinal: true)
                        ]),
                    CreateSetterOnlyType(
                        "WriteOnlyStruct",
                        kind: "struct",
                        properties:
                        [
                            CreateSetterOnlyProperty("Value")
                        ]),
                    CreateSetterOnlyType(
                        "ExplicitWriteOnly",
                        interfaces: ["SetterOnly.IWriteOnly"],
                        properties:
                        [
                            CreateSetterOnlyProperty(
                                "SetterOnly.IWriteOnly.Value",
                                accessibility: "private",
                                isVirtual: true,
                                isFinal: true,
                                isNewSlot: true)
                        ])
                ]
            }
        };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "setter-only",
                Kind = "file",
                SourcePath = "SetterOnly.dll",
                FileCount = 1,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files = [artifact]
        };

        var generatedFiles = CSharpSkeletonGenerator.Generate(document);
        var source = Assert.Single(
            generatedFiles,
            file => file.RelativePath == "SetterOnly/SetterOnly.cs").Content.ReplaceLineEndings("\n");

        Assert.Contains("public interface IWriteOnly\n{\n    int Value { set; }\n}", source, StringComparison.Ordinal);
        Assert.Contains("public abstract int Value { set; }", source, StringComparison.Ordinal);
        Assert.Contains("public unsafe class StaticWriteOnly", source, StringComparison.Ordinal);
        Assert.Contains("public static int Value\n    {\n        set { }\n    }", source, StringComparison.Ordinal);
        Assert.Contains("public virtual int InstanceValue\n    {\n        set { }\n    }", source, StringComparison.Ordinal);
        Assert.Contains("public sealed override int InstanceValue\n    {\n        set { }\n    }", source, StringComparison.Ordinal);
        Assert.Contains("public string this[int index]\n    {\n        set { }\n    }", source, StringComparison.Ordinal);
        Assert.Contains("protected int ProtectedValue\n    {\n        set { }\n    }", source, StringComparison.Ordinal);
        Assert.Contains(
            "public delegate* managed<void> Callback\n    {\n        set { }\n    }",
            source,
            StringComparison.Ordinal);
        Assert.Contains("public struct WriteOnlyStruct\n{\n    public int Value\n    {\n        set { }\n    }\n}", source, StringComparison.Ordinal);
        Assert.Contains(
            "int SetterOnly.IWriteOnly.Value\n    {\n        set { }\n    }",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("get;", source, StringComparison.Ordinal);
        Assert.DoesNotContain("get =>", source, StringComparison.Ordinal);
        Assert.DoesNotContain("set_Value", source, StringComparison.Ordinal);
        Assert.DoesNotContain("MissingAccessors", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ByRefSetter", source, StringComparison.Ordinal);
        Assert.DoesNotContain("protected set", source, StringComparison.Ordinal);
        var project = Assert.Single(
            generatedFiles,
            file => file.RelativePath == "SetterOnly/SetterOnly.csproj").Content;
        Assert.Contains("<AllowUnsafeBlocks>true</AllowUnsafeBlocks>", project, StringComparison.Ordinal);
        Assert.False(CSharpSkeletonGenerator.RequiresUnsafeContext(
            new TypeModel
            {
                FullName = "SetterOnly.MalformedOnly",
                Namespace = "SetterOnly",
                Name = "MalformedOnly",
                Kind = "class",
                Accessibility = "public",
                Properties =
                [
                    new PropertyModel
                    {
                        Name = "MissingAccessors",
                        Type = "byte*",
                        Accessibility = "public"
                    }
                ]
            }));

        await AssertGeneratedSolutionBuildsAsync(generatedFiles);
    }

    [Fact]
    public async Task GeneratedCliStackCoercionSubsetBuildsInRelease()
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(CliStackCoercionFixture).Assembly.Location);
        var artifact = Assert.Single(analyzed.Files);
        var includedTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            typeof(CliStackCoercionFixture).FullName!,
            typeof(Int32StackCoercionEnum).FullName!
        };
        var types = artifact.Code!.Types
            .Where(type => includedTypes.Contains(type.FullName))
            .ToArray();
        Assert.Equal(includedTypes.Count, types.Length);
        var filteredArtifact = artifact with
        {
            ManagedReferences = [],
            Code = artifact.Code with
            {
                NamespaceCount = 1,
                TypeCount = types.Length,
                MethodCount = types.Sum(type => type.Methods.Count),
                Types = types
            }
        };
        var generatedFiles = CSharpSkeletonGenerator.Generate(analyzed with { Files = [filteredArtifact] });

        await AssertGeneratedSolutionBuildsAsync(generatedFiles);
    }

    [Fact]
    public async Task GeneratedConstructorReconstructionSubsetBuildsInRelease()
    {
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(typeof(ConstructorDerivedFixture).Assembly.Location);
        var artifact = Assert.Single(analyzed.Files);
        var includedTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            typeof(ConstructorModeFixture).FullName!,
            typeof(ConstructorBaseFixture).FullName!,
            typeof(ConstructorDerivedFixture).FullName!
        };
        var types = artifact.Code!.Types
            .Where(type => includedTypes.Contains(type.FullName))
            .ToArray();
        Assert.Equal(includedTypes.Count, types.Length);
        var filteredArtifact = artifact with
        {
            ManagedReferences = [],
            Code = artifact.Code with
            {
                NamespaceCount = 1,
                TypeCount = types.Length,
                MethodCount = types.Sum(type => type.Methods.Count),
                Types = types
            }
        };
        var generatedFiles = CSharpSkeletonGenerator.Generate(analyzed with { Files = [filteredArtifact] });

        await AssertGeneratedSolutionBuildsAsync(generatedFiles);
    }

    [Fact]
    public async Task PreservesGenericInterfacesWithoutEmittingCompilerGeneratedTypeSegments()
    {
        var assemblyPath = typeof(GenericInterfaceFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var types = document.Files[0].Code!.Types;
        var comparer = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericInterfaceFixture");
        var enumerator = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.GenericEnumeratorFixture");
        var explicitComparer = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExplicitGenericComparerFixture");
        var explicitEnumerator = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.ExplicitGenericEnumeratorFixture");
        var indexedCurrentDecoy = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.IndexedCurrentEnumeratorDecoyFixture");
        var nullableValueDecoy = Assert.Single(
            types,
            type => type.FullName == "ExeBlueprint.Core.Tests.NullableValueComparerDecoyFixture");
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains(
            "internal sealed class GenericInterfaceFixture<T> : System.Collections.Generic.IEqualityComparer<T>",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal sealed class GenericEnumeratorFixture<T> : System.Collections.Generic.IEnumerator<T>",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ExplicitGenericComparerFixture<T> : System.Collections.Generic.IEqualityComparer<T>",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "ExplicitGenericEnumeratorFixture<T> : System.Collections.Generic.IEnumerator<T>",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IndexedCurrentEnumeratorDecoyFixture<T> : System.Collections.Generic.IEnumerator<T>",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "NullableValueComparerDecoyFixture : System.Collections.Generic.IEqualityComparer<int>",
            source,
            StringComparison.Ordinal);
        Assert.True(CSharpSkeletonGenerator.ShouldEmitInterface(
            enumerator,
            "System.Collections.Generic.IEnumerator<!0>"));
        Assert.True(CSharpSkeletonGenerator.ShouldEmitInterface(
            comparer,
            "System.Collections.Generic.IEqualityComparer<!0>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            comparer,
            "System.Collections.Generic.ICollection<!0>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            explicitComparer,
            "System.Collections.Generic.IEqualityComparer<!0>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            explicitEnumerator,
            "System.Collections.Generic.IEnumerator<!0>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            indexedCurrentDecoy,
            "System.Collections.Generic.IEnumerator<!0>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            nullableValueDecoy,
            "System.Collections.Generic.IEqualityComparer<int>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            comparer,
            "System.Collections.Generic.IEqualityComparer<!0, string>"));
        Assert.False(CSharpSkeletonGenerator.ShouldEmitInterface(
            comparer,
            "System.Collections.Generic.IEqualityComparer<!0"));
        Assert.False(CSharpSkeletonGenerator.ContainsCompilerGeneratedTypeSegment(
            "System.Collections.Generic.IEnumerator<!0>"));
        Assert.True(CSharpSkeletonGenerator.ContainsCompilerGeneratedTypeSegment("Example.<State>d__1"));
        Assert.True(CSharpSkeletonGenerator.ContainsCompilerGeneratedTypeSegment(
            "System.Collections.Generic.IEnumerable<Example.<State>d__1>"));
        Assert.True(CSharpSkeletonGenerator.ContainsCompilerGeneratedTypeSegment(
            "System.Collections.Generic.IEnumerable<<State>d__1>"));
    }

    [Fact]
    public async Task EmitsOverrideSealedAndFinalInterfaceMethodModifiers()
    {
        var assemblyPath = typeof(DispatchDerivedFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("public abstract string Describe();", source);
        Assert.Contains("public virtual int Transform(int value)", source);
        Assert.Contains("public override string Describe()", source);
        Assert.Contains("public sealed override int Transform(int value)", source);
        Assert.Contains("public override int Value { get; }", source);
        Assert.Contains("public sealed override event System.EventHandler Dispatched;", source);
        Assert.Contains("public void Dispose()", source);
        Assert.DoesNotContain("virtual void Dispose()", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsNestedTypesWithOwnedGenericParameters()
    {
        var assemblyPath = typeof(NestedTypeFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal class NestedTypeFixture<T>", source);
        Assert.Contains("    public sealed class Child<U>", source);
        Assert.DoesNotContain("class Child<T, U>", source, StringComparison.Ordinal);
        Assert.Contains("        public T OuterValue { get; set; }", source);
        Assert.Contains("        public U InnerValue { get; set; }", source);
        Assert.Contains("        public enum State : byte", source);
        Assert.Contains("            Ready = 2,", source);
        Assert.Contains("        public struct Leaf", source);
        Assert.Contains("        public int Number { get; set; }", source);
        Assert.DoesNotContain("        public int Number { get; set; } = default!;", source, StringComparison.Ordinal);
        Assert.Contains(
            "public ExeBlueprint.Core.Tests.NestedTypeFixture<T>.Child<U>.Leaf Leaf { get; set; } = default!;",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "public ExeBlueprint.Core.Tests.NestedTypeFixture<T>.Child<U>.State State { get; set; } = default!;",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsVarianceAndSafeGenericConstraintClauses()
    {
        var assemblyPath = typeof(GenericConstraintFixture<,,,,,>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal))
            .Content
            .ReplaceLineEndings("\n");

        Assert.Contains("internal interface IGenericVarianceFixture<out TOut, in TIn>", source);
        Assert.Contains(
            "internal delegate TResult GenericVarianceDelegateFixture<out TResult, in TArgument>(TArgument value)\n" +
            "    where TResult : class?\n" +
            "    where TArgument : notnull;",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal class GenericConstraintFixture<TClass, TNullableClass, TStruct, TUnmanaged, TNotNull, TConstructed>\n" +
            "    where TClass : class\n" +
            "    where TNullableClass : class?\n" +
            "    where TStruct : struct\n" +
            "    where TUnmanaged : unmanaged\n" +
            "    where TNotNull : notnull\n" +
            "    where TConstructed : ExeBlueprint.Core.Tests.GenericConstraintBaseFixture, " +
            "ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture, new()",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    public static void Method<TMethodClass, TMethodNullable, TMethodNew, TMethodLink>()\n" +
            "        where TMethodClass : class\n" +
            "        where TMethodNullable : class?\n" +
            "        where TMethodNew : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture, new()\n" +
            "        where TMethodLink : TNotNull",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    internal class Nested<TNested>\n" +
            "        where TNested : TNotNull",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal sealed class OrderedConstraintFixture<TFirst, TSecond, TValue>\n" +
            "    where TFirst : ExeBlueprint.Core.Tests.GenericConstraintBaseFixture\n" +
            "    where TSecond : ExeBlueprint.Core.Tests.GenericConstraintBaseFixture\n" +
            "    where TValue : ExeBlueprint.Core.Tests.GenericConstraintBaseFixture, TFirst, TSecond, " +
            "ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal interface IAllowsRefStructFixture<T>\n" +
            "    where T : allows ref struct",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal sealed class NullableLocalConstraintFixture<TLocalBase, TLocalInterface, TParameter, TLinked>\n" +
            "    where TLocalBase : ExeBlueprint.Core.Tests.GenericConstraintBaseFixture?\n" +
            "    where TLocalInterface : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture?\n" +
            "    where TParameter : class?\n" +
            "    where TLinked : TParameter?",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    public static void Method<TMethod>()\n" +
            "        where TMethod : TParameter?",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    internal sealed class Nested<TNested>\n" +
            "        where TNested : TParameter?",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal sealed class KeywordGenericConstraintFixture<@class, @required, @record, @file, @scoped, @closed, @__arglist>\n" +
            "    where @class : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @required : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @record : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @file : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @scoped : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @closed : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture\n" +
            "    where @__arglist : ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    public static @class Echo<@struct>(@class value, @struct other)\n" +
            "        where @struct : @class",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "internal class NullableTypeConstraintFixture<TBase, TInterface, TConstructed>\n{",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("where TBase :", source, StringComparison.Ordinal);
        Assert.DoesNotContain("where TInterface :", source, StringComparison.Ordinal);

        var whereClauses = source
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.StartsWith("where ", StringComparison.Ordinal))
            .ToArray();
        Assert.DoesNotContain(whereClauses, line => line.Contains("System.ValueType", StringComparison.Ordinal));
        Assert.DoesNotContain(whereClauses, line => line is "where TStruct : struct, new()");
        Assert.DoesNotContain(whereClauses, line => line is "where TUnmanaged : unmanaged, new()");

        Assert.Contains(
            "    public abstract T Echo<T>(T value)\n" +
            "        where T : class;",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    public override T Echo<T>(T value)\n" +
            "    {",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "    T ExeBlueprint.Core.Tests.IGenericConstraintMethodFixture.Echo<T>(T value)\n" +
            "    {",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public void OmitsWholeOwnerClausesWhenGenericMetadataIsNotRepresentable()
    {
        static GenericParameterModel Parameter(
            string name,
            int position,
            IReadOnlyList<GenericTypeConstraintModel> constraints,
            bool valueType = false,
            bool defaultConstructor = false,
            bool allowsRefStruct = false,
            bool notNull = false,
            bool unmanaged = false) =>
            new()
            {
                Position = position,
                Name = name,
                RawAttributes = 0,
                Variance = "none",
                NotNullableValueTypeConstraint = valueType,
                NotNullConstraint = notNull,
                DefaultConstructorConstraint = defaultConstructor,
                AllowsRefStruct = allowsRefStruct,
                HasUnmanagedAttribute = unmanaged,
                Nullability = "oblivious",
                TypeConstraints = constraints,
                Complete = true
            };

        static GenericTypeConstraintModel Constraint(
            string type,
            string kind,
            IReadOnlyList<string>? requiredModifiers = null,
            string nullability = "oblivious") =>
            new()
            {
                Type = type,
                Kind = kind,
                Nullability = nullability,
                RequiredModifiers = requiredModifiers ?? [],
                Complete = true
            };

        static TypeModel Type(
            string name,
            IReadOnlyList<string> names,
            IReadOnlyList<GenericParameterModel> details) =>
            new()
            {
                FullName = $"Demo.{name}",
                Namespace = "Demo",
                Name = name,
                Kind = "class",
                Accessibility = "public",
                GenericParameters = names,
                GenericParameterDetails = details,
                GenericParametersComplete = true
            };

        var unsupportedModifier = Type(
            "UnsupportedModifier",
            ["TValid", "TUnsafe"],
            [
                Parameter("TValid", 0, [], defaultConstructor: true),
                Parameter(
                    "TUnsafe",
                    1,
                    [Constraint("Demo.IMarker", "interface", ["Demo.RequiredModifier"])])
            ]);
        var missingValueConstructor = Type(
            "MissingValueConstructor",
            ["T"],
            [Parameter("T", 0, [Constraint("System.ValueType", "value-type-marker")], valueType: true)]);
        var classAllowsRefStruct = Type(
            "ClassAllowsRefStruct",
            ["T"],
            [Parameter("T", 0, [Constraint("Demo.Base", "class")], allowsRefStruct: true)]);
        var unresolvedToken = Type(
            "UnresolvedToken",
            ["T"],
            [Parameter("T", 0, [Constraint("!10", "type-parameter")])]);
        var selfCycle = Type(
            "SelfCycle",
            ["T"],
            [Parameter("T", 0, [Constraint("!0", "type-parameter")])]);
        var mutualCycle = Type(
            "MutualCycle",
            ["T", "U"],
            [
                Parameter("T", 0, [Constraint("!1", "type-parameter")]),
                Parameter("U", 1, [Constraint("!0", "type-parameter")])
            ]);
        var valueTarget = Type(
            "ValueTarget",
            ["TValue", "TDependent"],
            [
                Parameter(
                    "TValue",
                    0,
                    [Constraint("System.ValueType", "value-type-marker")],
                    valueType: true,
                    defaultConstructor: true),
                Parameter(
                    "TDependent",
                    1,
                    [Constraint("!0", "type-parameter", nullability: "annotated")])
            ]);
        var duplicateNullableIdentity = Type(
            "DuplicateNullableIdentity",
            ["T"],
            [
                Parameter(
                    "T",
                    0,
                    [
                        Constraint("Demo.IMarker", "interface"),
                        Constraint("Demo.IMarker", "interface", nullability: "annotated")
                    ])
            ]);
        var conflictingTransitiveBases = Type(
            "ConflictingTransitiveBases",
            ["TFirst", "TSecond", "TValue"],
            [
                Parameter("TFirst", 0, [Constraint("Demo.FirstBase", "class")]),
                Parameter("TSecond", 1, [Constraint("Demo.SecondBase", "class")]),
                Parameter(
                    "TValue",
                    2,
                    [
                        Constraint("!0", "type-parameter"),
                        Constraint("!1", "type-parameter")
                    ])
            ]);
        var transitiveBaseAllowsRefStruct = Type(
            "TransitiveBaseAllowsRefStruct",
            ["TBase", "TValue"],
            [
                Parameter("TBase", 0, [Constraint("Demo.Base", "class")]),
                Parameter(
                    "TValue",
                    1,
                    [Constraint("!0", "type-parameter")],
                    allowsRefStruct: true)
            ]);
        var shadowingOuter = Type(
            "ShadowingOuter",
            ["T"],
            [Parameter("T", 0, [])]);
        var shadowingNested = Type(
            "Nested",
            ["T", "T", "U"],
            [
                Parameter("T", 0, []),
                Parameter("T", 1, []),
                Parameter(
                    "U",
                    2,
                    [Constraint("!0", "type-parameter")])
            ]) with
        {
            FullName = "Demo.ShadowingOuter.Nested",
            IsNested = true,
            DeclaringType = "Demo.ShadowingOuter",
            InheritedGenericParameterCount = 1
        };
        var shadowingMethodOwner = Type(
            "ShadowingMethodOwner",
            ["T"],
            [Parameter("T", 0, [])]) with
        {
            Methods =
            [
                new MethodModel
                {
                    Name = "Method",
                    Signature = "void Method<T, U>()",
                    ReturnType = "void",
                    Accessibility = "public",
                    GenericParameters = ["T", "U"],
                    GenericParameterDetails =
                    [
                        Parameter("T", 0, []),
                        Parameter(
                            "U",
                            1,
                            [Constraint("!0", "type-parameter", nullability: "annotated")])
                    ]
                }
            ]
        };
        var constructedConstraint = Type(
            "ConstructedConstraint",
            ["T"],
            [Parameter("T", 0, [Constraint("Demo.IRefOnly<int>", "interface")])]);
        var rawGenericDefinitionConstraint = Type(
            "RawGenericDefinitionConstraint",
            ["T"],
            [Parameter("T", 0, [Constraint("Demo.IRefOnly`1", "interface")])]);
        var ambiguousNotNullKeyword = Type(
            "AmbiguousNotNullKeyword",
            ["notnull"],
            [Parameter("notnull", 0, [], notNull: true)]);
        var ambiguousUnmanagedKeyword = Type(
            "AmbiguousUnmanagedKeyword",
            ["unmanaged"],
            [
                Parameter(
                    "unmanaged",
                    0,
                    [
                        Constraint(
                            "System.ValueType",
                            "value-type-marker",
                            ["System.Runtime.InteropServices.UnmanagedType"])
                    ],
                    valueType: true,
                    defaultConstructor: true,
                    unmanaged: true)
            ]);
        TypeModel[] types =
        [
            unsupportedModifier,
            missingValueConstructor,
            classAllowsRefStruct,
            unresolvedToken,
            selfCycle,
            mutualCycle,
            valueTarget,
            duplicateNullableIdentity,
            conflictingTransitiveBases,
            transitiveBaseAllowsRefStruct,
            shadowingOuter,
            shadowingNested,
            shadowingMethodOwner,
            constructedConstraint,
            rawGenericDefinitionConstraint,
            ambiguousNotNullKeyword,
            ambiguousUnmanagedKeyword
        ];
        var artifact = CreateManagedArtifact("Demo", []) with
        {
            Code = new CodeModel
            {
                Kind = "managed",
                NamespaceCount = 1,
                TypeCount = types.Length,
                Types = types
            }
        };
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "generic-metadata",
                Kind = "file",
                SourcePath = "Demo.dll",
                FileCount = 1,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files = [artifact]
        };

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath == "Demo/Demo.cs").Content.ReplaceLineEndings("\n");

        Assert.Contains("public class UnsupportedModifier<TValid, TUnsafe>\n{", source);
        Assert.Contains("public class MissingValueConstructor<T>\n{", source);
        Assert.Contains("public class ClassAllowsRefStruct<T>\n{", source);
        Assert.Contains("public class UnresolvedToken<T>\n{", source);
        Assert.Contains("public class SelfCycle<T>\n{", source);
        Assert.Contains("public class MutualCycle<T, U>\n{", source);
        Assert.Contains("public class ValueTarget<TValue, TDependent>\n{", source);
        Assert.Contains("public class DuplicateNullableIdentity<T>\n{", source);
        Assert.Contains("public class ConflictingTransitiveBases<TFirst, TSecond, TValue>\n{", source);
        Assert.Contains("public class TransitiveBaseAllowsRefStruct<TBase, TValue>\n{", source);
        Assert.Contains("public class ShadowingOuter<T>\n{", source);
        Assert.Contains("    public class Nested<T, U>\n    {", source);
        Assert.Contains("public class ShadowingMethodOwner<T>\n{", source);
        Assert.Contains("    public void Method<T, U>()\n    {", source);
        Assert.Contains("public class ConstructedConstraint<T>\n{", source);
        Assert.Contains("public class RawGenericDefinitionConstraint<T>\n{", source);
        Assert.Contains("public class AmbiguousNotNullKeyword<@notnull>\n{", source);
        Assert.Contains("public class AmbiguousUnmanagedKeyword<@unmanaged>\n{", source);
        Assert.DoesNotContain("Demo.IRefOnly<int>", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Demo.IRefOnly`1", source, StringComparison.Ordinal);
        Assert.DoesNotContain("where ", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GeneratedGenericConstraintSubsetBuildsInRelease()
    {
        var assemblyPath = typeof(GenericConstraintFixture<,,,,,>).Assembly.Location;
        var analyzed = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var artifact = Assert.Single(analyzed.Files);
        var includedTypes = new HashSet<string>(StringComparer.Ordinal)
        {
            "ExeBlueprint.Core.Tests.GenericConstraintBaseFixture",
            "ExeBlueprint.Core.Tests.IGenericConstraintInterfaceFixture",
            "ExeBlueprint.Core.Tests.GenericConstraintFixture",
            "ExeBlueprint.Core.Tests.GenericConstraintFixture.Nested",
            "ExeBlueprint.Core.Tests.IGenericVarianceFixture",
            "ExeBlueprint.Core.Tests.GenericVarianceDelegateFixture",
            "ExeBlueprint.Core.Tests.IAllowsRefStructFixture",
            "ExeBlueprint.Core.Tests.GenericConstraintOverrideBaseFixture",
            "ExeBlueprint.Core.Tests.GenericConstraintOverrideFixture",
            "ExeBlueprint.Core.Tests.IGenericConstraintMethodFixture",
            "ExeBlueprint.Core.Tests.ExplicitGenericConstraintMethodFixture",
            "ExeBlueprint.Core.Tests.OrderedConstraintFixture",
            "ExeBlueprint.Core.Tests.NullableLocalConstraintFixture",
            "ExeBlueprint.Core.Tests.NullableLocalConstraintFixture.Nested",
            "ExeBlueprint.Core.Tests.KeywordGenericConstraintFixture"
        };
        var filteredTypes = artifact.Code!.Types
            .Where(type => includedTypes.Contains(type.FullName))
            .ToArray();
        Assert.Equal(includedTypes.Count, filteredTypes.Length);
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

    [Fact]
    public async Task HumanizesGenericMetadataTokensInsideReconstructedBodies()
    {
        var assemblyPath = typeof(CSharpSkeletonGenericBodyFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.CSharpSkeletonGenericBodyFixture");

        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "TypeComparer").BodyReconstructed);
        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "MethodComparer").BodyReconstructed);
        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "EmptyTypeArray").BodyReconstructed);
        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "EmptyMethodArray").BodyReconstructed);
        var isKnownState = Assert.Single(fixture.Methods, method => method.Name == "IsKnownState");
        Assert.True(isKnownState.BodyReconstructed);
        Assert.Contains(
            isKnownState.Il,
            instruction => instruction.Contains(
                "System.Enum.IsDefined<ExeBlueprint.Core.Tests.GenericCallState>",
                StringComparison.Ordinal));
        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "MetadataLikeLiteral").BodyReconstructed);
        Assert.True(Assert.Single(fixture.Methods, method => method.Name == "EscapedMetadataLikeLiteral").BodyReconstructed);

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains(
            "return System.Collections.Generic.EqualityComparer<T>.Default;",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "return System.Collections.Generic.EqualityComparer<TMethod>.Default;",
            source,
            StringComparison.Ordinal);
        Assert.Contains("return System.Array.Empty<T>();", source, StringComparison.Ordinal);
        Assert.Contains("return System.Array.Empty<TMethod>();", source, StringComparison.Ordinal);
        Assert.Contains(
            "return System.Enum.IsDefined<ExeBlueprint.Core.Tests.GenericCallState>(unchecked((ExeBlueprint.Core.Tests.GenericCallState)0));",
            source,
            StringComparison.Ordinal);
        Assert.Contains("return \"!0 !!0\";", source, StringComparison.Ordinal);
        Assert.Contains("return \"\\\"!0\\\" \\\\\\\\ !!0\";", source, StringComparison.Ordinal);
        Assert.Empty(FindRawGenericTokensOutsideCommentsAndLiterals(source));
    }

    [Fact]
    public async Task PreservesMetadataDeclaringTypeForInstanceDispatch()
    {
        var assemblyPath = typeof(InterfaceDispatchFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.InterfaceDispatchFixture");

        Assert.True(Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(InterfaceDispatchFixture.EmptyEnumerator)).BodyReconstructed);
        Assert.True(Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(InterfaceDispatchFixture.CopyTo)).BodyReconstructed);
        Assert.True(Assert.Single(
            fixture.Methods,
            method => method.Name == nameof(InterfaceDispatchFixture.Read)).BodyReconstructed);

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains(
            "return ((System.Collections.Generic.IEnumerable<T>)System.Array.Empty<T>()).GetEnumerator();",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "((System.Collections.ICollection)items).CopyTo(array, index);",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "return ((ExeBlueprint.Core.Tests.DispatchContractFixture)value).Read();",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsExplicitInterfaceMembersWithoutAccessibilityOrAccessorMethods()
    {
        var assemblyPath = typeof(CSharpSkeletonExplicitInterfaceFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.CSharpSkeletonExplicitInterfaceFixture");
        var indexer = Assert.Single(fixture.Properties, property => property.Name.EndsWith(".Item", StringComparison.Ordinal));
        var indexParameter = Assert.Single(indexer.Parameters);
        Assert.Equal("index", indexParameter.Name);
        Assert.Equal("int", indexParameter.Type);

        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains(
            "string ExeBlueprint.Core.Tests.ICSharpSkeletonExplicitInterfaceFixture.Name { get; } = default!;",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "void ExeBlueprint.Core.Tests.ICSharpSkeletonExplicitInterfaceFixture.Execute()",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "string ExeBlueprint.Core.Tests.ICSharpSkeletonExplicitInterfaceFixture.this[int index]",
            source,
            StringComparison.Ordinal);
        Assert.Contains("public string this[string key]", source, StringComparison.Ordinal);
        Assert.Contains("    get => throw new global::System.NotImplementedException();", source, StringComparison.Ordinal);
        Assert.Contains("    set { }", source, StringComparison.Ordinal);
        Assert.DoesNotContain("this[string key] { get; set; }", source, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "private string ExeBlueprint.Core.Tests.ICSharpSkeletonExplicitInterfaceFixture.Name",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(".get_Name()", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".get_Item(", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".set_Item(", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task InitializesStructMembersWhenInstanceConstructorExists()
    {
        var assemblyPath = typeof(StructInitializerFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal struct StructInitializerFixture", source);
        Assert.Contains("public string Value { get; set; } = default!;", source);
        Assert.Contains("public StructInitializerFixture(string Value)", source);
    }

    [Fact]
    public async Task EmitsRefStructAndComputedRefLikePropertyStubs()
    {
        var assemblyPath = typeof(RefStructFixture).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal ref struct RefStructFixture", source);
        Assert.Contains("public System.Span<byte> Buffer", source);
        Assert.Contains("get => throw new global::System.NotImplementedException();", source);
        Assert.Contains("set { }", source);
        Assert.Contains("public System.ReadOnlySpan<byte> Header", source);
        Assert.DoesNotContain("System.ReadOnlySpan<byte> Header { get; }", source, StringComparison.Ordinal);
        Assert.Contains(
            "public ref int ValueRef\n    {\n        get => throw new global::System.NotImplementedException();\n    }",
            source.ReplaceLineEndings("\n"),
            StringComparison.Ordinal);
        Assert.DoesNotContain("public ref int ValueRef { get; }", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EmitsTopLevelAndNestedDelegateDeclarations()
    {
        var assemblyPath = typeof(GenericPredicateFixture<>).Assembly.Location;
        var document = await new BlueprintAnalyzer().AnalyzeAsync(assemblyPath);
        var source = Assert.Single(
            CSharpSkeletonGenerator.Generate(document),
            file => file.RelativePath.EndsWith("ExeBlueprint.Core.Tests.cs", StringComparison.Ordinal)).Content;

        Assert.Contains("internal delegate bool GenericPredicateFixture<T>(T value);", source);
        Assert.Contains("        public delegate T Projector(U value);", source);
        Assert.DoesNotContain("class GenericPredicateFixture", source, StringComparison.Ordinal);
    }

    [Fact]
    public void GeneratesSolutionAndReferencesForRelatedAssemblies()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "package",
                Kind = "directory",
                SourcePath = "package",
                FileCount = 2,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                CreateManagedArtifact("Demo.Core", []),
                CreateManagedArtifact("Demo.App", ["Demo.Core"])
            ]
        };

        var files = CSharpSkeletonGenerator.Generate(document);
        var solution = Assert.Single(files, file => file.RelativePath == "Reconstructed.slnx").Content;
        var appProject = Assert.Single(files, file => file.RelativePath == "Demo.App/Demo.App.csproj").Content;

        Assert.Contains("<Project Path=\"Demo.App/Demo.App.csproj\" />", solution);
        Assert.Contains("<Project Path=\"Demo.Core/Demo.Core.csproj\" />", solution);
        Assert.Contains("<ProjectReference Include=\"../Demo.Core/Demo.Core.csproj\" />", appProject);
    }

    [Fact]
    public void KeepsSanitizedProjectDirectoryNamesUnique()
    {
        var document = new BlueprintDocument
        {
            Input = new InputDescriptor
            {
                Name = "package",
                Kind = "directory",
                SourcePath = "package",
                FileCount = 2,
                TotalBytes = 0
            },
            Summary = new BlueprintSummary(),
            Files =
            [
                CreateManagedArtifact("Demo/App", []),
                CreateManagedArtifact("Demo:App", [])
            ]
        };

        var files = CSharpSkeletonGenerator.Generate(document);

        Assert.Contains(files, file => file.RelativePath == "Demo_App/Demo_App.csproj");
        Assert.Contains(files, file => file.RelativePath == "Demo_App_2/Demo_App_2.csproj");
        Assert.Equal(files.Count, files.Select(file => file.RelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    private static IReadOnlyList<string> FindRawGenericTokensOutsideCommentsAndLiterals(string source)
    {
        var matches = new List<string>();
        var inString = false;
        var inCharacter = false;
        var inLineComment = false;
        var inBlockComment = false;
        var escaped = false;
        var line = 1;

        for (var index = 0; index < source.Length; index++)
        {
            var current = source[index];
            var next = index + 1 < source.Length ? source[index + 1] : '\0';

            if (current == '\n')
            {
                line++;
                inLineComment = false;
            }

            if (inLineComment)
            {
                continue;
            }

            if (inBlockComment)
            {
                if (current == '*' && next == '/')
                {
                    inBlockComment = false;
                    index++;
                }

                continue;
            }

            if (inString || inCharacter)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (current == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (inString && current == '"')
                {
                    inString = false;
                }
                else if (inCharacter && current == '\'')
                {
                    inCharacter = false;
                }

                continue;
            }

            if (current == '/' && next == '/')
            {
                inLineComment = true;
                index++;
                continue;
            }

            if (current == '/' && next == '*')
            {
                inBlockComment = true;
                index++;
                continue;
            }

            if (current == '"')
            {
                inString = true;
                continue;
            }

            if (current == '\'')
            {
                inCharacter = true;
                continue;
            }

            if (current != '!')
            {
                continue;
            }

            var tokenEnd = index + 1;
            if (tokenEnd < source.Length && source[tokenEnd] == '!')
            {
                tokenEnd++;
            }

            var digitStart = tokenEnd;
            while (tokenEnd < source.Length && char.IsAsciiDigit(source[tokenEnd]))
            {
                tokenEnd++;
            }

            if (tokenEnd > digitStart)
            {
                matches.Add($"line {line}: {source[index..tokenEnd]}");
                index = tokenEnd - 1;
            }
        }

        return matches;
    }

    private static TypeModel CreateSetterOnlyType(
        string name,
        string kind = "class",
        bool isAbstract = false,
        string? baseType = null,
        IReadOnlyList<string>? interfaces = null,
        IReadOnlyList<PropertyModel>? properties = null,
        IReadOnlyList<MethodModel>? methods = null) =>
        new()
        {
            FullName = "SetterOnly." + name,
            Namespace = "SetterOnly",
            Name = name,
            Kind = kind,
            Accessibility = "public",
            IsAbstract = isAbstract,
            BaseType = baseType,
            Interfaces = interfaces ?? [],
            Properties = properties ?? [],
            Methods = methods ?? []
        };

    private static PropertyModel CreateSetterOnlyProperty(
        string name,
        string type = "int",
        string accessibility = "public",
        bool hasSetter = true,
        bool isStatic = false,
        bool isAbstract = false,
        bool isVirtual = false,
        bool isFinal = false,
        bool isNewSlot = false,
        IReadOnlyList<ParameterModel>? parameters = null) =>
        new()
        {
            Name = name,
            Type = type,
            Accessibility = accessibility,
            Parameters = parameters ?? [],
            SetterAccessibility = hasSetter ? accessibility : null,
            HasSetter = hasSetter,
            IsStatic = isStatic,
            IsAbstract = isAbstract,
            IsVirtual = isVirtual,
            IsFinal = isFinal,
            IsNewSlot = isNewSlot
        };

    private static MethodModel CreateSetterMethod() =>
        new()
        {
            Name = "set_Value",
            Signature = "void set_Value(int value)",
            ReturnType = "void",
            Accessibility = "public",
            IsStatic = true,
            Parameters =
            [
                new ParameterModel
                {
                    Name = "value",
                    Type = "int"
                }
            ]
        };

    private static FileArtifact CreateManagedArtifact(string assemblyName, IReadOnlyList<string> references) =>
        new()
        {
            Id = assemblyName,
            RelativePath = assemblyName + ".dll",
            FileName = assemblyName + ".dll",
            Size = 0,
            Sha256 = "",
            Category = "library",
            Format = "pe",
            IsManaged = true,
            AssemblyName = assemblyName,
            ManagedReferences = references,
            Code = new CodeModel
            {
                Kind = "managed",
                TypeCount = 1,
                Types =
                [
                    new TypeModel
                    {
                        FullName = assemblyName + ".Placeholder",
                        Namespace = assemblyName,
                        Name = "Placeholder",
                        Kind = "class",
                        Accessibility = "public"
                    }
                ]
            }
        };

    private static async Task AssertGeneratedSolutionBuildsAsync(IReadOnlyList<GeneratedFile> generatedFiles)
    {
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

    private sealed class TemporaryDirectory : IAsyncDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-csharp-generic-{Guid.NewGuid():N}");
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
