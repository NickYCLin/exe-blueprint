using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class GenericArrayLocalSignatureSafetyTests
{
    [Fact]
    public async Task PreservesCallerGenericProvenanceForMultidimensionalArrayLocals()
    {
        using var assembly = CreateAssembly();

        var code = await ManagedSymbolReader.TryReadAsync(
            assembly.Path,
            CancellationToken.None);

        Assert.NotNull(code);
        Assert.False(code.Truncated);
        var type = Assert.Single(
            code.Types,
            candidate => candidate.FullName == "Tests.GenericArrayLocalProbe");

        var typeGeneric = Assert.Single(type.Methods, method => method.Name == "GetTypeLocal");
        Assert.True(typeGeneric.BodyReconstructed);
        Assert.Equal(
            ["!0[,] v0 = values;", "return v0[row, column];"],
            typeGeneric.Body);

        var methodGeneric = Assert.Single(type.Methods, method => method.Name == "GetMethodLocal");
        Assert.True(methodGeneric.BodyReconstructed);
        Assert.Equal(
            ["!!0[,] v0 = values;", "return v0[row, column];"],
            methodGeneric.Body);
    }

    private static TemporaryAssembly CreateAssembly()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("GenericArrayLocalSignatureSafetyTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("65a6805a-d1af-48b4-a1b7-c7fefbb53198")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("GenericArrayLocalSignatureSafetyTests"),
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
        var probeType = metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("GenericArrayLocalProbe`1"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var typeArray = AddArrayTypeSpecification(metadata, genericTypeCode: 0x13);
        var methodArray = AddArrayTypeSpecification(metadata, genericTypeCode: 0x1E);
        var typeGet = AddArrayGetMemberReference(metadata, typeArray, genericTypeCode: 0x13);
        var methodGet = AddArrayGetMemberReference(metadata, methodArray, genericTypeCode: 0x1E);
        var typeLocal = AddLocalSignature(metadata, genericTypeCode: 0x13);
        var methodLocal = AddLocalSignature(metadata, genericTypeCode: 0x1E);

        var ilStream = new BlobBuilder();
        var bodies = new MethodBodyStreamEncoder(ilStream);
        var typeBody = AddMethodBody(bodies, typeLocal, typeGet);
        var methodBody = AddMethodBody(bodies, methodLocal, methodGet);

        var typeParameterList = AddParameters(metadata, "values", "row", "column");
        var methodParameterList = AddParameters(metadata, "values", "row", "column");
        var typeMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("GetTypeLocal"),
            AddMethodSignature(metadata, genericTypeCode: 0x13, methodGeneric: false),
            typeBody,
            typeParameterList);
        var methodMethod = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("GetMethodLocal"),
            AddMethodSignature(metadata, genericTypeCode: 0x1E, methodGeneric: true),
            methodBody,
            methodParameterList);

        metadata.AddGenericParameter(
            probeType,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("T"),
            index: 0);
        metadata.AddGenericParameter(
            methodMethod,
            GenericParameterAttributes.None,
            metadata.GetOrAddString("U"),
            index: 0);

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
    }

    private static TypeSpecificationHandle AddArrayTypeSpecification(
        MetadataBuilder metadata,
        byte genericTypeCode)
    {
        var signature = new BlobBuilder();
        WriteGenericArrayType(signature, genericTypeCode);
        return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
    }

    private static MemberReferenceHandle AddArrayGetMemberReference(
        MetadataBuilder metadata,
        TypeSpecificationHandle arrayType,
        byte genericTypeCode)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x20); // HASTHIS | DEFAULT
        signature.WriteByte(0x02); // two parameters
        WriteGenericParameter(signature, genericTypeCode); // return element
        signature.WriteByte(0x08); // I4 row
        signature.WriteByte(0x08); // I4 column
        return metadata.AddMemberReference(
            arrayType,
            metadata.GetOrAddString("Get"),
            metadata.GetOrAddBlob(signature));
    }

    private static StandaloneSignatureHandle AddLocalSignature(
        MetadataBuilder metadata,
        byte genericTypeCode)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x07); // LOCAL_SIG
        signature.WriteByte(0x01); // one local
        WriteGenericArrayType(signature, genericTypeCode);
        return metadata.AddStandaloneSignature(metadata.GetOrAddBlob(signature));
    }

    private static BlobHandle AddMethodSignature(
        MetadataBuilder metadata,
        byte genericTypeCode,
        bool methodGeneric)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(methodGeneric ? (byte)0x10 : (byte)0x00); // GENERIC | DEFAULT
        if (methodGeneric)
        {
            signature.WriteByte(0x01); // one generic method parameter
        }

        signature.WriteByte(0x03); // three parameters
        WriteGenericParameter(signature, genericTypeCode); // return element
        WriteGenericArrayType(signature, genericTypeCode);
        signature.WriteByte(0x08); // I4 row
        signature.WriteByte(0x08); // I4 column
        return metadata.GetOrAddBlob(signature);
    }

    private static void WriteGenericArrayType(BlobBuilder signature, byte genericTypeCode)
    {
        signature.WriteByte(0x14); // ARRAY
        WriteGenericParameter(signature, genericTypeCode);
        signature.WriteByte(0x02); // rank two
        signature.WriteByte(0x00); // no sizes
        signature.WriteByte(0x00); // no lower bounds
    }

    private static void WriteGenericParameter(BlobBuilder signature, byte genericTypeCode)
    {
        signature.WriteByte(genericTypeCode); // VAR or MVAR
        signature.WriteByte(0x00); // slot zero
    }

    private static ParameterHandle AddParameters(MetadataBuilder metadata, params string[] names)
    {
        ParameterHandle first = default;
        for (var index = 0; index < names.Length; index++)
        {
            var handle = metadata.AddParameter(
                ParameterAttributes.None,
                metadata.GetOrAddString(names[index]),
                index + 1);
            if (index == 0)
            {
                first = handle;
            }
        }

        return first;
    }

    private static int AddMethodBody(
        MethodBodyStreamEncoder bodies,
        StandaloneSignatureHandle localSignature,
        MemberReferenceHandle arrayGet)
    {
        var instructions = new BlobBuilder();
        instructions.WriteByte(0x02); // ldarg.0
        instructions.WriteByte(0x0A); // stloc.0
        instructions.WriteByte(0x06); // ldloc.0
        instructions.WriteByte(0x03); // ldarg.1
        instructions.WriteByte(0x04); // ldarg.2
        instructions.WriteByte(0x28); // call
        instructions.WriteInt32(MetadataTokens.GetToken(arrayGet));
        instructions.WriteByte(0x2A); // ret
        return bodies.AddMethodBody(
            new InstructionEncoder(instructions),
            maxStack: 3,
            localVariablesSignature: localSignature,
            attributes: MethodBodyAttributes.InitLocals);
    }

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public static TemporaryAssembly Write(byte[] image)
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-generic-array-local-{Guid.NewGuid():N}.dll");
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
