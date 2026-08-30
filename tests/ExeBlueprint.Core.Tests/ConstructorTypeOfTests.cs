using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorTypeOfTests
{
    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    [InlineData(129, 128)]
    public void AcceptsCanonicalGenericTypeOfConstructorArgument(
        int genericArity,
        int typeParameterSlot)
    {
        using var fixture = CreateFixture(
            Mutation.None,
            genericArity,
            typeParameterSlot);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal([$"typeof(!{typeParameterSlot})"], result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.NonTypeSpecificationToken)]
    [InlineData(Mutation.InvalidTypeSpecificationToken)]
    [InlineData(Mutation.MethodGenericParameter)]
    [InlineData(Mutation.OutOfRangeTypeParameter)]
    [InlineData(Mutation.NonCanonicalTypeParameterIndex)]
    [InlineData(Mutation.ModifiedTypeParameter)]
    [InlineData(Mutation.TruncatedTypeSpecification)]
    [InlineData(Mutation.TrailingTypeSpecificationData)]
    [InlineData(Mutation.OversizedTypeSpecification)]
    [InlineData(Mutation.NonGenericOwner)]
    [InlineData(Mutation.OwnerArityMismatch)]
    [InlineData(Mutation.OwnerPositionMismatch)]
    [InlineData(Mutation.InterposedNop)]
    [InlineData(Mutation.CallvirtHelper)]
    [InlineData(Mutation.NewobjHelper)]
    [InlineData(Mutation.NonMemberReferenceHelper)]
    [InlineData(Mutation.WrongHelperName)]
    [InlineData(Mutation.WrongHelperParent)]
    [InlineData(Mutation.LocalHelperParentSpoof)]
    [InlineData(Mutation.ShadowRuntimeAssembly)]
    [InlineData(Mutation.WrongAssemblyToken)]
    [InlineData(Mutation.AssemblyCulture)]
    [InlineData(Mutation.RetargetableAssembly)]
    [InlineData(Mutation.WindowsRuntimeAssembly)]
    [InlineData(Mutation.DifferentRuntimeAssembly)]
    [InlineData(Mutation.WrongSystemTypeNamespace)]
    [InlineData(Mutation.WrongRuntimeTypeNamespace)]
    [InlineData(Mutation.InstanceHelper)]
    [InlineData(Mutation.GenericHelper)]
    [InlineData(Mutation.VarArgHelper)]
    [InlineData(Mutation.TwoHelperParameters)]
    [InlineData(Mutation.WrongReturnType)]
    [InlineData(Mutation.WrongReturnKind)]
    [InlineData(Mutation.DifferentReturnTypeHandle)]
    [InlineData(Mutation.NonCanonicalReturnTypeHandle)]
    [InlineData(Mutation.ModifiedReturnType)]
    [InlineData(Mutation.WrongRuntimeType)]
    [InlineData(Mutation.WrongRuntimeTypeKind)]
    [InlineData(Mutation.NonCanonicalRuntimeTypeHandle)]
    [InlineData(Mutation.TruncatedHelperSignature)]
    [InlineData(Mutation.TrailingHelperSignatureData)]
    [InlineData(Mutation.TargetTypeMismatch)]
    [InlineData(Mutation.ThisConstructor)]
    public void RejectsUnprovenGenericTypeOfConstructorArgument(Mutation mutation)
    {
        using var fixture = CreateFixture(mutation);

        Assert.Null(Reconstruct(fixture));
    }

    private static ManagedSymbolReader.ConstructorReconstructionTestResult? Reconstruct(
        MetadataFixture fixture) =>
        ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Reader,
            fixture.Il,
            fixture.CurrentConstructor,
            requireBaseInitializer: false);

    private static MetadataFixture CreateFixture(
        Mutation mutation,
        int genericArity = 1,
        int typeParameterSlot = 0)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstructorTypeOfTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("8f61bc76-1bba-4b43-bf2f-2031980cce07")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorTypeOfTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var trustedToken = ImmutableArray.Create<byte>(
            0xB0,
            0x3F,
            0x5F,
            0x7F,
            0x11,
            0xD5,
            0x0A,
            0x3A);
        var systemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString(
                mutation == Mutation.ShadowRuntimeAssembly
                    ? "Shadow.Runtime"
                    : "System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: mutation == Mutation.AssemblyCulture
                ? metadata.GetOrAddString("en-US")
                : default,
            publicKeyOrToken: metadata.GetOrAddBlob(
                mutation == Mutation.WrongAssemblyToken
                    ? ImmutableArray.Create<byte>(0, 0, 0, 0, 0, 0, 0, 0)
                    : trustedToken),
            flags: mutation switch
            {
                Mutation.RetargetableAssembly => AssemblyFlags.Retargetable,
                Mutation.WindowsRuntimeAssembly => AssemblyFlags.WindowsRuntime,
                _ => (AssemblyFlags)0
            },
            hashValue: default);
        var secondSystemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: metadata.GetOrAddBlob(trustedToken),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var systemType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString(
                mutation == Mutation.WrongSystemTypeNamespace
                    ? "Shadow.System"
                    : "System"),
            metadata.GetOrAddString("Type"));
        var duplicateSystemType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Type"));
        var runtimeTypeHandle = metadata.AddTypeReference(
            mutation == Mutation.DifferentRuntimeAssembly
                ? secondSystemRuntime
                : systemRuntime,
            metadata.GetOrAddString(
                mutation == Mutation.WrongRuntimeTypeNamespace
                    ? "Shadow.System"
                    : "System"),
            metadata.GetOrAddString("RuntimeTypeHandle"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var localSystemType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Type"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var baseType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Base"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var derivedType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString(mutation switch
            {
                Mutation.NonGenericOwner => "Derived",
                Mutation.OwnerArityMismatch => "Derived`2",
                _ => $"Derived`{genericArity}"
            }),
            baseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        if (mutation != Mutation.NonGenericOwner)
        {
            var parameterCount = mutation == Mutation.OwnerArityMismatch
                ? 1
                : genericArity;
            for (var index = 0; index < parameterCount; index++)
            {
                metadata.AddGenericParameter(
                    derivedType,
                    GenericParameterAttributes.None,
                    metadata.GetOrAddString($"T{index}"),
                    index: mutation == Mutation.OwnerPositionMismatch ? index + 1 : index);
            }
        }

        var typeParameterSpecification = AddTypeParameterSpecification();
        var helperSignature = new BlobBuilder();
        helperSignature.WriteByte(mutation switch
        {
            Mutation.InstanceHelper => 0x20, // HASTHIS | DEFAULT
            Mutation.GenericHelper => 0x10, // GENERIC | DEFAULT
            Mutation.VarArgHelper => 0x05, // VARARG
            _ => 0x00 // static DEFAULT
        });
        if (mutation == Mutation.GenericHelper)
        {
            helperSignature.WriteByte(0x01); // one method generic parameter
        }

        helperSignature.WriteByte(
            mutation == Mutation.TwoHelperParameters
                ? (byte)0x02
                : (byte)0x01);
        if (mutation == Mutation.TruncatedHelperSignature)
        {
            helperSignature.WriteByte(0x12); // truncated CLASS return
        }
        else
        {
            if (mutation == Mutation.ModifiedReturnType)
            {
                helperSignature.WriteByte(0x20); // CMOD_OPT
                helperSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(objectType));
            }

            helperSignature.WriteByte(
                mutation == Mutation.WrongReturnKind
                    ? (byte)0x11 // VALUETYPE
                    : (byte)0x12); // CLASS
            var helperReturn = mutation switch
            {
                Mutation.WrongHelperParent or Mutation.WrongReturnType => (EntityHandle)objectType,
                Mutation.DifferentReturnTypeHandle => duplicateSystemType,
                _ => systemType
            };
            WriteTypeHandle(helperReturn, mutation == Mutation.NonCanonicalReturnTypeHandle);
            helperSignature.WriteByte(
                mutation == Mutation.WrongRuntimeTypeKind
                    ? (byte)0x12 // CLASS
                    : (byte)0x11); // VALUETYPE
            WriteTypeHandle(
                mutation == Mutation.WrongRuntimeType
                    ? objectType
                    : runtimeTypeHandle,
                mutation == Mutation.NonCanonicalRuntimeTypeHandle);
            if (mutation == Mutation.TrailingHelperSignatureData)
            {
                helperSignature.WriteByte(0x00);
            }
        }

        var helperParent = mutation switch
        {
            Mutation.WrongHelperParent => (EntityHandle)objectType,
            Mutation.LocalHelperParentSpoof => localSystemType,
            _ => systemType
        };
        var helper = metadata.AddMemberReference(
            helperParent,
            metadata.GetOrAddString(
                mutation == Mutation.WrongHelperName
                    ? "GetTypeFromToken"
                    : "GetTypeFromHandle"),
            metadata.GetOrAddBlob(helperSignature));

        var targetType = mutation == Mutation.TargetTypeMismatch
            ? duplicateSystemType
            : systemType;
        var targetSignature = new BlobBuilder();
        targetSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        targetSignature.WriteByte(0x01);
        targetSignature.WriteByte(0x01); // VOID
        targetSignature.WriteByte(0x12); // CLASS
        targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(targetType));
        var baseConstructor = metadata.AddMemberReference(
            baseType,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(targetSignature));
        var thisConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(targetSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteByte(0x00);
        currentSignature.WriteByte(0x01); // VOID
        var currentConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            metadata.GetOrAddBlob(currentSignature),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(
            metadataImage.ToImmutableArray());
        var typeToken = mutation switch
        {
            Mutation.NonTypeSpecificationToken => MetadataTokens.GetToken(systemType),
            Mutation.InvalidTypeSpecificationToken => unchecked((int)0x1B00FFFF),
            _ => MetadataTokens.GetToken(typeParameterSpecification)
        };
        var helperToken = mutation == Mutation.NonMemberReferenceHelper
            ? MetadataTokens.GetToken(baseType)
            : MetadataTokens.GetToken(helper);
        var constructorToken = MetadataTokens.GetToken(
            mutation == Mutation.ThisConstructor
                ? thisConstructor
                : baseConstructor);
        return new MetadataFixture(
            provider,
            currentConstructor,
            BuildIl(mutation, typeToken, helperToken, constructorToken));

        void WriteTypeHandle(EntityHandle handle, bool nonCanonical)
        {
            var codedIndex = CodedIndex.TypeDefOrRef(handle);
            if (nonCanonical)
            {
                Assert.InRange(codedIndex, 0, 0x7F);
                helperSignature.WriteByte(0x80);
                helperSignature.WriteByte((byte)codedIndex);
            }
            else
            {
                helperSignature.WriteCompressedInteger(codedIndex);
            }
        }

        TypeSpecificationHandle AddTypeParameterSpecification()
        {
            var signature = new BlobBuilder();
            switch (mutation)
            {
                case Mutation.MethodGenericParameter:
                    signature.WriteByte(0x1E); // MVAR
                    signature.WriteByte(0x00);
                    break;
                case Mutation.OutOfRangeTypeParameter:
                    signature.WriteByte(0x13); // VAR
                    signature.WriteByte(0x01);
                    break;
                case Mutation.NonCanonicalTypeParameterIndex:
                    signature.WriteByte(0x13); // VAR
                    signature.WriteByte(0x80);
                    signature.WriteByte(0x00);
                    break;
                case Mutation.ModifiedTypeParameter:
                    signature.WriteByte(0x20); // CMOD_OPT
                    signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(objectType));
                    signature.WriteByte(0x13); // VAR
                    signature.WriteByte(0x00);
                    break;
                case Mutation.TruncatedTypeSpecification:
                    signature.WriteByte(0x13); // truncated VAR
                    break;
                default:
                    signature.WriteByte(0x13); // VAR
                    signature.WriteCompressedInteger(typeParameterSlot);
                    break;
            }

            if (mutation == Mutation.TrailingTypeSpecificationData)
            {
                signature.WriteByte(0x00);
            }
            else if (mutation == Mutation.OversizedTypeSpecification)
            {
                for (var index = 0; index < 70; index++)
                {
                    signature.WriteByte(0x00);
                }
            }

            return metadata.AddTypeSpecification(metadata.GetOrAddBlob(signature));
        }
    }

    private static byte[] BuildIl(
        Mutation mutation,
        int typeToken,
        int helperToken,
        int constructorToken)
    {
        var il = new List<byte> { 0x02, 0xD0 }; // ldarg.0; ldtoken
        WriteToken(typeToken);
        if (mutation == Mutation.InterposedNop)
        {
            il.Add(0x00); // nop
        }

        il.Add(mutation switch
        {
            Mutation.CallvirtHelper => (byte)0x6F,
            Mutation.NewobjHelper => (byte)0x73,
            _ => (byte)0x28 // call
        });
        WriteToken(helperToken);
        il.Add(0x28); // call base/this constructor
        WriteToken(constructorToken);
        il.Add(0x2A); // ret
        return [.. il];

        void WriteToken(int token)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(bytes, token);
            foreach (var value in bytes)
            {
                il.Add(value);
            }
        }
    }

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    public enum Mutation
    {
        None,
        NonTypeSpecificationToken,
        InvalidTypeSpecificationToken,
        MethodGenericParameter,
        OutOfRangeTypeParameter,
        NonCanonicalTypeParameterIndex,
        ModifiedTypeParameter,
        TruncatedTypeSpecification,
        TrailingTypeSpecificationData,
        OversizedTypeSpecification,
        NonGenericOwner,
        OwnerArityMismatch,
        OwnerPositionMismatch,
        InterposedNop,
        CallvirtHelper,
        NewobjHelper,
        NonMemberReferenceHelper,
        WrongHelperName,
        WrongHelperParent,
        LocalHelperParentSpoof,
        ShadowRuntimeAssembly,
        WrongAssemblyToken,
        AssemblyCulture,
        RetargetableAssembly,
        WindowsRuntimeAssembly,
        DifferentRuntimeAssembly,
        WrongSystemTypeNamespace,
        WrongRuntimeTypeNamespace,
        InstanceHelper,
        GenericHelper,
        VarArgHelper,
        TwoHelperParameters,
        WrongReturnType,
        WrongReturnKind,
        DifferentReturnTypeHandle,
        NonCanonicalReturnTypeHandle,
        ModifiedReturnType,
        WrongRuntimeType,
        WrongRuntimeTypeKind,
        NonCanonicalRuntimeTypeHandle,
        TruncatedHelperSignature,
        TrailingHelperSignatureData,
        TargetTypeMismatch,
        ThisConstructor
    }

    private sealed class MetadataFixture(
        MetadataReaderProvider provider,
        MethodDefinitionHandle currentConstructor,
        byte[] il) : IDisposable
    {
        public MetadataReader Reader { get; } = provider.GetMetadataReader();

        public MethodDefinitionHandle CurrentConstructor { get; } = currentConstructor;

        public byte[] Il { get; } = il;

        public void Dispose() => provider.Dispose();
    }
}
