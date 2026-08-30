using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class EnumTypedTargetMetadataTests
{
    private static readonly byte[] SystemRuntimeToken =
        [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A];

    private static readonly byte[] NetstandardToken =
        [0xCC, 0x7B, 0x13, 0xFF, 0xCD, 0x2D, 0xDD, 0x51];

    private static readonly byte[] SystemPrivateCoreLibToken =
        [0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E];

    [Fact]
    public async Task AcceptsOnlyValueTypeEncodingForAValidLocalEnum()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                Methods =
                [
                    new MethodShape("FromValueType", ReturnEncoding.LocalValueType),
                    new MethodShape("FromClass", ReturnEncoding.LocalClass)
                ]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertReconstructedEnumReturn(methods["FromValueType"]);
        AssertRejected(methods["FromClass"]);
    }

    [Fact]
    public async Task RejectsExternalSameNameTypeReferenceWithoutPoisoningLocalEnum()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                AddExternalSameNameReference = true,
                Methods =
                [
                    new MethodShape("FromLocal", ReturnEncoding.LocalValueType),
                    new MethodShape("FromExternal", ReturnEncoding.ExternalValueType),
                    new MethodShape(
                        "LocalFromExternalArgument",
                        ReturnEncoding.LocalValueType,
                        ReturnEncoding.ExternalValueType),
                    new MethodShape(
                        "ExternalPassThrough",
                        ReturnEncoding.ExternalValueType,
                        ReturnEncoding.ExternalValueType)
                ]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertReconstructedEnumReturn(methods["FromLocal"]);
        AssertRejected(methods["FromExternal"]);
        AssertRejected(methods["LocalFromExternalArgument"]);
        Assert.True(methods["ExternalPassThrough"].BodyReconstructed);
        Assert.Equal(["return arg0;"], methods["ExternalPassThrough"].Body);
    }

    [Fact]
    public async Task RejectsGenericInstantiationAliasOfLocalEnum()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                Methods =
                [new MethodShape("FromGenericAlias", ReturnEncoding.GenericLocalValueType)]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertRejected(methods["FromGenericAlias"]);
    }

    [Fact]
    public async Task RejectsInstanceThisReturnedAsExternalValueType()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                AddExternalSameNameReference = true,
                Methods =
                [
                    new MethodShape(
                        "ReturnThisAsExternal",
                        ReturnEncoding.ExternalValueType,
                        IsInstance: true,
                        LoadThis: true)
                ]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertRejected(methods["ReturnThisAsExternal"]);
    }

    [Fact]
    public async Task RejectsMethodAttributeAndSignatureInstanceMismatch()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                Methods =
                [
                    new MethodShape(
                        "MismatchedInstanceHeader",
                        ReturnEncoding.LocalValueType,
                        SignatureIsInstance: true)
                ]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertRejected(methods["MismatchedInstanceHeader"]);
    }

    [Fact]
    public async Task RejectsLocalSystemEnumFromFakeCoreLibraryAssembly()
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                AssemblyName = "System.Private.CoreLib",
                // AssemblyDef 的 PublicKey 欄位不能只塞官方 token；此 fixture 未簽章，
                // 即使名稱與 8-byte token 看似正確，也不能把 local System.Enum 當框架型別。
                AssemblyPublicKeyOrToken = SystemPrivateCoreLibToken,
                UseLocalSystemEnumBase = true,
                Methods = [new MethodShape("FromFakeCoreLibrary", ReturnEncoding.LocalValueType)]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertRejected(methods["FromFakeCoreLibrary"]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TrustsOnlyTheOfficialNetstandardPublicKeyToken(bool useOfficialToken)
    {
        var token = useOfficialToken
            ? NetstandardToken
            : new byte[] { 0xCC, 0x7B, 0x13, 0xFF, 0xCD, 0x2D, 0xDD, 0x50 };
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                FrameworkAssemblyName = "netstandard",
                FrameworkPublicKeyToken = token,
                Methods = [new MethodShape("FromNetstandardEnum", ReturnEncoding.LocalValueType)]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        if (useOfficialToken)
        {
            AssertReconstructedEnumReturn(methods["FromNetstandardEnum"]);
        }
        else
        {
            AssertRejected(methods["FromNetstandardEnum"]);
        }
    }

    [Theory]
    [InlineData(LiteralShape.MissingDefault)]
    [InlineData(LiteralShape.PrimitiveSignature)]
    [InlineData(LiteralShape.WrongConstantType)]
    public async Task RejectsMalformedStaticEnumLiteral(LiteralShape literalShape)
    {
        using var fixture = CreateAssembly(
            new FixtureOptions
            {
                LiteralShape = literalShape,
                Methods = [new MethodShape("FromMalformedEnum", ReturnEncoding.LocalValueType)]
            });

        var methods = await AnalyzeMethodsAsync(fixture.Path);

        AssertRejected(methods["FromMalformedEnum"]);
    }

    private static async Task<IReadOnlyDictionary<string, MethodModel>> AnalyzeMethodsAsync(string path)
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(path);
        var host = Assert.Single(
            Assert.Single(document.Files).Code!.Types,
            type => type.FullName == "Tests.EnumTargets");
        return host.Methods.ToDictionary(method => method.Name, StringComparer.Ordinal);
    }

    private static void AssertReconstructedEnumReturn(MethodModel method)
    {
        Assert.True(method.BodyReconstructed);
        Assert.Equal(["return unchecked((Tests.State)1);"], method.Body);
    }

    private static void AssertRejected(MethodModel method)
    {
        Assert.False(method.BodyReconstructed);
        Assert.Empty(method.Body);
    }

    private static TemporaryAssembly CreateAssembly(FixtureOptions options)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString($"{options.AssemblyName}.dll"),
            mvid: metadata.GetOrAddGuid(Guid.NewGuid()),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString(options.AssemblyName),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: AddBlob(metadata, options.AssemblyPublicKeyOrToken),
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var frameworkAssembly = metadata.AddAssemblyReference(
            metadata.GetOrAddString(options.FrameworkAssemblyName),
            new Version(2, 0, 0, 0),
            culture: default,
            publicKeyOrToken: AddBlob(metadata, options.FrameworkPublicKeyToken),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            frameworkAssembly,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var externalEnumBase = metadata.AddTypeReference(
            frameworkAssembly,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Enum"));

        TypeReferenceHandle externalSameName = default;
        if (options.AddExternalSameNameReference)
        {
            var externalAssembly = metadata.AddAssemblyReference(
                metadata.GetOrAddString("External.Enums"),
                new Version(1, 0, 0, 0),
                culture: default,
                publicKeyOrToken: default,
                flags: (AssemblyFlags)0,
                hashValue: default);
            externalSameName = metadata.AddTypeReference(
                externalAssembly,
                metadata.GetOrAddString("Tests"),
                metadata.GetOrAddString("State"));
        }

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        TypeDefinitionHandle localSystemEnum = default;
        if (options.UseLocalSystemEnumBase)
        {
            localSystemEnum = metadata.AddTypeDefinition(
                TypeAttributes.Public | TypeAttributes.Abstract,
                metadata.GetOrAddString("System"),
                metadata.GetOrAddString("Enum"),
                objectType,
                MetadataTokens.FieldDefinitionHandle(1),
                MetadataTokens.MethodDefinitionHandle(1));
        }

        var enumType = metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Sealed,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("State"),
            options.UseLocalSystemEnumBase ? localSystemEnum : externalEnumBase,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("EnumTargets"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(3),
            MetadataTokens.MethodDefinitionHandle(1));

        metadata.AddFieldDefinition(
            FieldAttributes.Public | FieldAttributes.SpecialName | FieldAttributes.RTSpecialName,
            metadata.GetOrAddString("value__"),
            AddBlob(metadata, 0x06, 0x08)); // FIELD I4

        var literalAttributes = FieldAttributes.Public | FieldAttributes.Static | FieldAttributes.Literal;
        if (options.LiteralShape != LiteralShape.MissingDefault)
        {
            literalAttributes |= FieldAttributes.HasDefault;
        }

        var literalSignature = options.LiteralShape == LiteralShape.PrimitiveSignature
            ? AddBlob(metadata, 0x06, 0x08) // FIELD I4: enum 成員必須是 enum 自身型別。
            : AddFieldTypeSignature(metadata, enumType);
        var literal = metadata.AddFieldDefinition(
            literalAttributes,
            metadata.GetOrAddString("One"),
            literalSignature);
        if (options.LiteralShape != LiteralShape.MissingDefault)
        {
            metadata.AddConstant(
                literal,
                options.LiteralShape == LiteralShape.WrongConstantType ? "bad" : 1);
        }

        var ilStream = new BlobBuilder();
        var bodies = new MethodBodyStreamEncoder(ilStream);
        foreach (var method in options.Methods)
        {
            var instructions = new BlobBuilder();
            var encoder = new InstructionEncoder(instructions);
            if (method.LoadThis || method.ParameterEncoding.HasValue)
            {
                encoder.OpCode(ILOpCode.Ldarg_0);
            }
            else
            {
                encoder.LoadConstantI4(1);
            }

            encoder.OpCode(ILOpCode.Ret);
            var bodyOffset = bodies.AddMethodBody(encoder, maxStack: 1);
            metadata.AddMethodDefinition(
                MethodAttributes.Public |
                MethodAttributes.HideBySig |
                (method.IsInstance ? 0 : MethodAttributes.Static),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                metadata.GetOrAddString(method.Name),
                AddMethodSignature(
                    metadata,
                    method.ReturnEncoding,
                    method.ParameterEncoding,
                    method.SignatureIsInstance ?? method.IsInstance,
                    enumType,
                    externalSameName),
                bodyOffset,
                MetadataTokens.ParameterHandle(1));
        }

        var peBuilder = new ManagedPEBuilder(
            new PEHeaderBuilder(
                imageCharacteristics: Characteristics.ExecutableImage | Characteristics.Dll),
            new MetadataRootBuilder(metadata),
            ilStream,
            mappedFieldData: null,
            managedResources: null,
            nativeResources: null,
            debugDirectoryBuilder: null,
            strongNameSignatureSize: 0,
            entryPoint: default,
            flags: CorFlags.ILOnly);
        var peImage = new BlobBuilder();
        peBuilder.Serialize(peImage);

        var path = Path.Combine(Path.GetTempPath(), $"enum-typed-target-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(path, peImage.ToArray());
        return new TemporaryAssembly(path);
    }

    private static BlobHandle AddMethodSignature(
        MetadataBuilder metadata,
        ReturnEncoding returnEncoding,
        ReturnEncoding? parameterEncoding,
        bool isInstance,
        TypeDefinitionHandle enumType,
        TypeReferenceHandle externalSameName)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(isInstance ? (byte)0x20 : (byte)0x00); // HASTHIS | DEFAULT
        signature.WriteCompressedInteger(parameterEncoding.HasValue ? 1 : 0);
        WriteType(returnEncoding);
        if (parameterEncoding.HasValue)
        {
            WriteType(parameterEncoding.Value);
        }

        return metadata.GetOrAddBlob(signature);

        void WriteType(ReturnEncoding encoding)
        {
            switch (encoding)
            {
                case ReturnEncoding.LocalValueType:
                    WriteNamedType(signature, 0x11, enumType); // VALUETYPE
                    break;
                case ReturnEncoding.LocalClass:
                    WriteNamedType(signature, 0x12, enumType); // CLASS
                    break;
                case ReturnEncoding.ExternalValueType:
                    Assert.False(externalSameName.IsNil);
                    WriteNamedType(signature, 0x11, externalSameName); // VALUETYPE
                    break;
                case ReturnEncoding.GenericLocalValueType:
                    signature.WriteByte(0x15); // GENERICINST
                    WriteNamedType(signature, 0x11, enumType); // VALUETYPE
                    signature.WriteCompressedInteger(1);
                    signature.WriteByte(0x08); // I4
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(encoding));
            }
        }
    }

    private static BlobHandle AddFieldTypeSignature(
        MetadataBuilder metadata,
        TypeDefinitionHandle enumType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x06); // FIELD
        WriteNamedType(signature, 0x11, enumType); // VALUETYPE
        return metadata.GetOrAddBlob(signature);
    }

    private static void WriteNamedType(BlobBuilder signature, byte kind, EntityHandle type)
    {
        signature.WriteByte(kind);
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(type));
    }

    private static BlobHandle AddBlob(MetadataBuilder metadata, params byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return default;
        }

        var blob = new BlobBuilder(bytes.Length);
        blob.WriteBytes(bytes);
        return metadata.GetOrAddBlob(blob);
    }

    public enum LiteralShape
    {
        Valid,
        MissingDefault,
        PrimitiveSignature,
        WrongConstantType
    }

    private enum ReturnEncoding
    {
        LocalValueType,
        LocalClass,
        ExternalValueType,
        GenericLocalValueType
    }

    private sealed record MethodShape(
        string Name,
        ReturnEncoding ReturnEncoding,
        ReturnEncoding? ParameterEncoding = null,
        bool IsInstance = false,
        bool? SignatureIsInstance = null,
        bool LoadThis = false);

    private sealed class FixtureOptions
    {
        public string AssemblyName { get; init; } = "EnumMetadataFixture";

        public byte[] AssemblyPublicKeyOrToken { get; init; } = [];

        public string FrameworkAssemblyName { get; init; } = "System.Runtime";

        public byte[] FrameworkPublicKeyToken { get; init; } = SystemRuntimeToken;

        public bool UseLocalSystemEnumBase { get; init; }

        public bool AddExternalSameNameReference { get; init; }

        public LiteralShape LiteralShape { get; init; }

        public required IReadOnlyList<MethodShape> Methods { get; init; }
    }

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public void Dispose()
        {
            try
            {
                File.Delete(Path);
            }
            catch (IOException)
            {
                // 測試失敗時仍以主要 assertion 為準。
            }
            catch (UnauthorizedAccessException)
            {
                // 測試失敗時仍以主要 assertion 為準。
            }
        }
    }
}
