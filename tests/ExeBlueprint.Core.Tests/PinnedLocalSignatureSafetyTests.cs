using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class PinnedLocalSignatureSafetyTests
{
    [Fact]
    public async Task RejectsPinnedProductionLocalWithoutMarkingValidIlAsTruncated()
    {
        using var assembly = CreateAssembly();

        var code = await ManagedSymbolReader.TryReadAsync(
            assembly.Path,
            CancellationToken.None);

        Assert.NotNull(code);
        Assert.False(code.Truncated);
        var type = Assert.Single(code.Types, candidate => candidate.FullName == "Tests.PinnedLocalProbe");
        var normal = Assert.Single(type.Methods, method => method.Name == "Normal");
        var pinned = Assert.Single(type.Methods, method => method.Name == "Pinned");

        Assert.True(normal.BodyReconstructed);
        Assert.Equal(["int v0 = 1;", "return v0;"], normal.Body);
        Assert.False(normal.IlTruncated);

        Assert.False(pinned.BodyReconstructed);
        Assert.Empty(pinned.Body);
        Assert.False(pinned.IlTruncated);
        Assert.NotEmpty(pinned.Il);
    }

    [Fact]
    public void PropagatesPinnedQualifierWithoutDiscardingPrimitiveIdentity()
    {
        var provider = SignatureTypeNameProvider.Instance;
        var primitive = provider.GetPrimitiveType(PrimitiveTypeCode.Int32);
        var pinned = provider.GetPinnedType(primitive);

        Assert.True(pinned.HasPinnedQualifier);
        Assert.Equal(primitive.Text, pinned.Text);
        Assert.Equal(primitive.PrimitiveType, pinned.PrimitiveType);
        Assert.Equal(primitive.NominalHandle, pinned.NominalHandle);
        Assert.Equal(primitive.RawTypeKind, pinned.RawTypeKind);
        Assert.Equal(primitive.SignatureKind, pinned.SignatureKind);

        Assert.True(provider.GetSZArrayType(pinned).HasPinnedQualifier);
        Assert.True(provider.GetPointerType(pinned).HasPinnedQualifier);
        Assert.True(provider.GetGenericInstantiation("Tests.Box`1", [pinned]).HasPinnedQualifier);

        var functionPointer = provider.GetFunctionPointerType(FunctionPointer(
            SignatureCallingConvention.Default,
            "void",
            [pinned]));
        Assert.True(functionPointer.HasPinnedQualifier);

        var unsupportedFunctionPointer = provider.GetFunctionPointerType(FunctionPointer(
            SignatureCallingConvention.VarArgs,
            "void",
            [pinned]));
        Assert.Equal("nint", unsupportedFunctionPointer.Text);
        Assert.True(unsupportedFunctionPointer.HasPinnedQualifier);
    }

    private static TemporaryAssembly CreateAssembly()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("PinnedLocalSignatureSafetyTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("3c9e9514-5764-43bd-9bc9-f799872eb6de")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("PinnedLocalSignatureSafetyTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var systemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: metadata.GetOrAddBlob(
                ImmutableArray.Create<byte>(
                    0xB0,
                    0x3F,
                    0x5F,
                    0x7F,
                    0x11,
                    0xD5,
                    0x0A,
                    0x3A)),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("PinnedLocalProbe"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var normalLocal = AddLocalSignature(metadata, pinned: false);
        var pinnedLocal = AddLocalSignature(metadata, pinned: true);
        var ilStream = new BlobBuilder();
        var bodies = new MethodBodyStreamEncoder(ilStream);
        var normalBody = AddMethodBody(bodies, normalLocal);
        var pinnedBody = AddMethodBody(bodies, pinnedLocal);
        var methodSignature = AddMethodSignature(metadata);
        AddMethod("Normal", normalBody);
        AddMethod("Pinned", pinnedBody);

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
        var image = new BlobBuilder();
        peBuilder.Serialize(image);
        return TemporaryAssembly.Write(image.ToArray());

        void AddMethod(string name, int bodyOffset) =>
            metadata.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                metadata.GetOrAddString(name),
                methodSignature,
                bodyOffset,
                MetadataTokens.ParameterHandle(1));
    }

    private static StandaloneSignatureHandle AddLocalSignature(
        MetadataBuilder metadata,
        bool pinned)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x07); // LOCAL_SIG
        signature.WriteByte(0x01); // one local
        if (pinned)
        {
            signature.WriteByte(0x45); // PINNED
        }

        signature.WriteByte(0x08); // I4
        return metadata.AddStandaloneSignature(metadata.GetOrAddBlob(signature));
    }

    private static int AddMethodBody(
        MethodBodyStreamEncoder bodies,
        StandaloneSignatureHandle localSignature)
    {
        var instructions = new BlobBuilder();
        instructions.WriteByte(0x17); // ldc.i4.1
        instructions.WriteByte(0x0A); // stloc.0
        instructions.WriteByte(0x06); // ldloc.0
        instructions.WriteByte(0x2A); // ret
        return bodies.AddMethodBody(
            new InstructionEncoder(instructions),
            maxStack: 1,
            localVariablesSignature: localSignature,
            attributes: MethodBodyAttributes.InitLocals);
    }

    private static BlobHandle AddMethodSignature(MetadataBuilder metadata)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x00); // DEFAULT
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(0x08); // I4
        return metadata.GetOrAddBlob(signature);
    }

    private static MethodSignature<SignatureTypeName> FunctionPointer(
        SignatureCallingConvention callingConvention,
        SignatureTypeName returnType,
        ImmutableArray<SignatureTypeName> parameterTypes) =>
        new(
            new SignatureHeader(
                SignatureKind.Method,
                callingConvention,
                SignatureAttributes.None),
            returnType,
            parameterTypes.Length,
            genericParameterCount: 0,
            parameterTypes);

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public static TemporaryAssembly Write(byte[] image)
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-pinned-local-{Guid.NewGuid():N}.dll");
            File.WriteAllBytes(path, image);
            return new TemporaryAssembly(path);
        }

        public void Dispose()
        {
            try
            {
                File.Delete(Path);
            }
            catch (IOException)
            {
            }
        }
    }
}
