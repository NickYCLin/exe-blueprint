using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class InitLocalsSafetyTests
{
    [Fact]
    public void DirectHookDefaultsToInitializedAndFailsClosedOnlyWhenLocalsExist()
    {
        using var assembly = CreateAssembly();
        using var stream = File.OpenRead(assembly.Path);
        using var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();
        byte[] localBody =
        [
            0x17, // ldc.i4.1
            0x0A, // stloc.0
            0x28, 0x01, 0x00, 0x00, 0x06, // call Tests.InitLocalsProbe.Helper
            0x06, // ldloc.0
            0x2A // ret
        ];

        Assert.NotNull(ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            localBody,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"]));
        Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            localBody,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            localVariablesInitialized: false));
        Assert.Equal(
            ["return 1;"],
            ManagedSymbolReader.ReconstructBodyForTest(
                metadata,
                [0x17, 0x2A],
                isInstance: false,
                returnType: "int",
                localVariablesInitialized: false));
    }

    [Fact]
    public async Task HonorsInitLocalsWithoutDiscardingValidIlOrCallEvidence()
    {
        using var assembly = CreateAssembly();

        var code = await ManagedSymbolReader.TryReadAsync(
            assembly.Path,
            CancellationToken.None);

        Assert.NotNull(code);
        Assert.False(code.Truncated);
        var type = Assert.Single(
            code.Types,
            candidate => candidate.FullName == "Tests.InitLocalsProbe");
        var initialized = Assert.Single(
            type.Methods,
            method => method.Name == "InitializedLocal");
        var uninitialized = Assert.Single(
            type.Methods,
            method => method.Name == "UninitializedLocal");
        var noLocals = Assert.Single(
            type.Methods,
            method => method.Name == "UninitializedWithoutLocals");

        Assert.True(initialized.BodyReconstructed);
        Assert.Contains("int v0 = 1;", initialized.Body);
        Assert.False(initialized.IlTruncated);

        Assert.False(uninitialized.BodyReconstructed);
        Assert.Empty(uninitialized.Body);
        Assert.False(uninitialized.IlTruncated);
        Assert.NotEmpty(uninitialized.Il);
        Assert.Single(
            code.CallGraph,
            edge => edge.Caller == "Tests.InitLocalsProbe.UninitializedLocal"
                && edge.Callee == "Tests.InitLocalsProbe.Helper");

        Assert.True(noLocals.BodyReconstructed);
        Assert.Equal(["return 1;"], noLocals.Body);
        Assert.False(noLocals.IlTruncated);
        Assert.NotEmpty(noLocals.Il);
    }

    private static TemporaryAssembly CreateAssembly()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("InitLocalsSafetyTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("96281f9d-aae4-4843-bb7a-499fb5c40cf8")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("InitLocalsSafetyTests"),
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
            metadata.GetOrAddString("InitLocalsProbe"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var ilStream = new BlobBuilder();
        var bodies = new MethodBodyStreamEncoder(ilStream);
        var helperBody = AddHelperBody(bodies);
        var localSignature = AddLocalSignature(metadata);
        var initializedBody = AddLocalBody(
            bodies,
            localSignature,
            MethodBodyAttributes.InitLocals);
        var uninitializedBody = AddLocalBody(
            bodies,
            localSignature,
            MethodBodyAttributes.None);
        var noLocalsBody = AddNoLocalsBody(bodies);
        var voidSignature = AddMethodSignature(metadata, returnType: 0x01);
        var intSignature = AddMethodSignature(metadata, returnType: 0x08);

        AddMethod("Helper", helperBody, voidSignature);
        AddMethod("InitializedLocal", initializedBody, intSignature);
        AddMethod("UninitializedLocal", uninitializedBody, intSignature);
        AddMethod("UninitializedWithoutLocals", noLocalsBody, intSignature);

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

        void AddMethod(string name, int bodyOffset, BlobHandle signature) =>
            metadata.AddMethodDefinition(
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                metadata.GetOrAddString(name),
                signature,
                bodyOffset,
                MetadataTokens.ParameterHandle(1));
    }

    private static int AddHelperBody(MethodBodyStreamEncoder bodies)
    {
        var instructions = new BlobBuilder();
        instructions.WriteByte(0x2A); // ret
        return bodies.AddMethodBody(new InstructionEncoder(instructions), maxStack: 0);
    }

    private static int AddLocalBody(
        MethodBodyStreamEncoder bodies,
        StandaloneSignatureHandle localSignature,
        MethodBodyAttributes attributes)
    {
        var instructions = new BlobBuilder();
        instructions.WriteByte(0x17); // ldc.i4.1
        instructions.WriteByte(0x0A); // stloc.0
        instructions.WriteByte(0x28); // call
        instructions.WriteInt32(MetadataTokens.GetToken(MetadataTokens.MethodDefinitionHandle(1)));
        instructions.WriteByte(0x06); // ldloc.0
        instructions.WriteByte(0x2A); // ret
        return bodies.AddMethodBody(
            new InstructionEncoder(instructions),
            maxStack: 1,
            localVariablesSignature: localSignature,
            attributes: attributes);
    }

    private static int AddNoLocalsBody(MethodBodyStreamEncoder bodies)
    {
        var instructions = new BlobBuilder();
        instructions.WriteByte(0x17); // ldc.i4.1
        instructions.WriteByte(0x2A); // ret
        return bodies.AddMethodBody(
            new InstructionEncoder(instructions),
            maxStack: 1,
            attributes: MethodBodyAttributes.None);
    }

    private static StandaloneSignatureHandle AddLocalSignature(MetadataBuilder metadata)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x07); // LOCAL_SIG
        signature.WriteByte(0x01); // one local
        signature.WriteByte(0x08); // I4
        return metadata.AddStandaloneSignature(metadata.GetOrAddBlob(signature));
    }

    private static BlobHandle AddMethodSignature(MetadataBuilder metadata, byte returnType)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x00); // DEFAULT
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(returnType);
        return metadata.GetOrAddBlob(signature);
    }

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public static TemporaryAssembly Write(byte[] image)
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-init-locals-{Guid.NewGuid():N}.dll");
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
