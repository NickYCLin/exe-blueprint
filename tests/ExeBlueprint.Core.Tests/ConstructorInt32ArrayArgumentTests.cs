using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorInt32ArrayArgumentTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(32)]
    public void AcceptsBoundedTrustedInt32ArrayForDirectBase(int length)
    {
        using var fixture = CreateFixture(Mutation.None, length);

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal([$"new int[{length}]"], result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(Mutation.NegativeLength)]
    [InlineData(Mutation.OversizedLength)]
    [InlineData(Mutation.ParameterLength)]
    [InlineData(Mutation.Int64Length)]
    [InlineData(Mutation.ShadowRuntimeAssembly)]
    [InlineData(Mutation.WrongAssemblyToken)]
    [InlineData(Mutation.EmptyAssemblyToken)]
    [InlineData(Mutation.AssemblyCulture)]
    [InlineData(Mutation.RetargetableAssembly)]
    [InlineData(Mutation.WindowsRuntimeAssembly)]
    [InlineData(Mutation.PublicKeyFlagWithToken)]
    [InlineData(Mutation.WrongNamespace)]
    [InlineData(Mutation.WrongName)]
    [InlineData(Mutation.NestedTypeReference)]
    [InlineData(Mutation.LocalTypeDefinition)]
    [InlineData(Mutation.TypeSpecificationToken)]
    [InlineData(Mutation.InvalidTypeReferenceToken)]
    [InlineData(Mutation.TargetStringArray)]
    [InlineData(Mutation.TargetOptionalModifier)]
    [InlineData(Mutation.TargetRequiredModifier)]
    [InlineData(Mutation.TargetModifiedElement)]
    [InlineData(Mutation.TargetByRefArray)]
    [InlineData(Mutation.TargetMultidimensionalArray)]
    [InlineData(Mutation.ThisConstructor)]
    public void RejectsUnprovenInt32ArrayArgument(Mutation mutation)
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

    private static MetadataFixture CreateFixture(Mutation mutation, int length = 2)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstructorInt32ArrayArgumentTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("5d78c848-2218-4e95-8a4f-b4ef95e20535")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorInt32ArrayArgumentTests"),
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
        var primaryRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString(
                mutation == Mutation.ShadowRuntimeAssembly
                    ? "Shadow.Runtime"
                    : "System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: mutation == Mutation.AssemblyCulture
                ? metadata.GetOrAddString("en-US")
                : default,
            publicKeyOrToken: mutation switch
            {
                Mutation.EmptyAssemblyToken => default,
                Mutation.WrongAssemblyToken => metadata.GetOrAddBlob(
                    ImmutableArray.Create<byte>(0, 0, 0, 0, 0, 0, 0, 0)),
                _ => metadata.GetOrAddBlob(trustedToken)
            },
            flags: mutation switch
            {
                Mutation.RetargetableAssembly => AssemblyFlags.Retargetable,
                Mutation.WindowsRuntimeAssembly => AssemblyFlags.WindowsRuntime,
                Mutation.PublicKeyFlagWithToken => AssemblyFlags.PublicKey,
                _ => (AssemblyFlags)0
            },
            hashValue: default);
        var trustedRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: metadata.GetOrAddBlob(trustedToken),
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            trustedRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var modifierType = metadata.AddTypeReference(
            trustedRuntime,
            metadata.GetOrAddString("System.Runtime.CompilerServices"),
            metadata.GetOrAddString("IsConst"));
        var nestedScope = metadata.AddTypeReference(
            primaryRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Nested"));
        var int32Reference = metadata.AddTypeReference(
            mutation == Mutation.NestedTypeReference
                ? nestedScope
                : primaryRuntime,
            metadata.GetOrAddString(
                mutation == Mutation.WrongNamespace
                    ? "Shadow.System"
                    : "System"),
            metadata.GetOrAddString(
                mutation == Mutation.WrongName
                    ? "UInt32"
                    : "Int32"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var localInt32 = metadata.AddTypeDefinition(
            TypeAttributes.Public | TypeAttributes.Sealed,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString(
                mutation == Mutation.LocalTypeDefinition
                    ? "Int32"
                    : "OtherInt32"),
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

        var int32ArraySpecification = new BlobBuilder();
        int32ArraySpecification.WriteByte(0x1D); // SZARRAY
        int32ArraySpecification.WriteByte(0x08); // I4
        var int32ArrayType = metadata.AddTypeSpecification(
            metadata.GetOrAddBlob(int32ArraySpecification));

        var targetSignature = new BlobBuilder();
        targetSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        targetSignature.WriteByte(0x01);
        targetSignature.WriteByte(0x01); // VOID
        if (mutation is Mutation.TargetOptionalModifier or Mutation.TargetRequiredModifier)
        {
            targetSignature.WriteByte(
                mutation == Mutation.TargetRequiredModifier
                    ? (byte)0x1F // CMOD_REQD
                    : (byte)0x20); // CMOD_OPT
            targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
        }

        if (mutation == Mutation.TargetByRefArray)
        {
            targetSignature.WriteByte(0x10); // BYREF
        }

        if (mutation == Mutation.TargetMultidimensionalArray)
        {
            targetSignature.WriteByte(0x14); // ARRAY
            targetSignature.WriteByte(0x08); // I4
            targetSignature.WriteByte(0x01); // rank
            targetSignature.WriteByte(0x00); // no sizes
            targetSignature.WriteByte(0x00); // no lower bounds
        }
        else
        {
            targetSignature.WriteByte(0x1D); // SZARRAY
            if (mutation == Mutation.TargetModifiedElement)
            {
                targetSignature.WriteByte(0x20); // CMOD_OPT
                targetSignature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(modifierType));
            }

            targetSignature.WriteByte(
                mutation == Mutation.TargetStringArray
                    ? (byte)0x0E // STRING
                    : (byte)0x08); // I4
        }

        var targetSignatureHandle = metadata.GetOrAddBlob(targetSignature);
        var baseConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            targetSignatureHandle,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Owner"),
            baseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(2));
        var thisConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            targetSignatureHandle,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var currentSignature = new BlobBuilder();
        currentSignature.WriteByte(0x20); // HASTHIS | DEFAULT
        currentSignature.WriteByte(
            mutation == Mutation.ParameterLength
                ? (byte)0x01
                : (byte)0x00);
        currentSignature.WriteByte(0x01); // VOID
        if (mutation == Mutation.ParameterLength)
        {
            currentSignature.WriteByte(0x08); // I4
        }

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
        var arrayTypeToken = mutation switch
        {
            Mutation.LocalTypeDefinition => MetadataTokens.GetToken(localInt32),
            Mutation.TypeSpecificationToken => MetadataTokens.GetToken(int32ArrayType),
            Mutation.InvalidTypeReferenceToken => unchecked((int)0x0100FFFF),
            _ => MetadataTokens.GetToken(int32Reference)
        };
        return new MetadataFixture(
            provider,
            currentConstructor,
            BuildIl(
                mutation,
                length,
                arrayTypeToken,
                MetadataTokens.GetToken(
                    mutation == Mutation.ThisConstructor
                        ? thisConstructor
                        : baseConstructor)));
    }

    private static byte[] BuildIl(
        Mutation mutation,
        int length,
        int arrayTypeToken,
        int constructorToken)
    {
        var il = new List<byte> { 0x02 }; // ldarg.0
        switch (mutation)
        {
            case Mutation.NegativeLength:
                il.Add(0x15); // ldc.i4.m1
                break;
            case Mutation.OversizedLength:
                il.Add(0x1F); // ldc.i4.s
                il.Add(33);
                break;
            case Mutation.ParameterLength:
                il.Add(0x03); // ldarg.1
                break;
            case Mutation.Int64Length:
                il.Add(0x21); // ldc.i8
                AppendInt64(il, 2);
                break;
            default:
                AppendInt32Constant(il, length);
                break;
        }

        il.Add(0x8D); // newarr
        AppendInt32(il, arrayTypeToken);
        il.Add(0x28); // call
        AppendInt32(il, constructorToken);
        il.Add(0x2A); // ret
        return [.. il];
    }

    private static void AppendInt32Constant(List<byte> il, int value)
    {
        if (value is >= 0 and <= 8)
        {
            il.Add((byte)(0x16 + value)); // ldc.i4.0 ... ldc.i4.8
            return;
        }

        il.Add(0x1F); // ldc.i4.s
        il.Add(unchecked((byte)(sbyte)value));
    }

    private static void AppendInt32(List<byte> bytes, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    private static void AppendInt64(List<byte> bytes, long value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    public enum Mutation
    {
        None,
        NegativeLength,
        OversizedLength,
        ParameterLength,
        Int64Length,
        ShadowRuntimeAssembly,
        WrongAssemblyToken,
        EmptyAssemblyToken,
        AssemblyCulture,
        RetargetableAssembly,
        WindowsRuntimeAssembly,
        PublicKeyFlagWithToken,
        WrongNamespace,
        WrongName,
        NestedTypeReference,
        LocalTypeDefinition,
        TypeSpecificationToken,
        InvalidTypeReferenceToken,
        TargetStringArray,
        TargetOptionalModifier,
        TargetRequiredModifier,
        TargetModifiedElement,
        TargetByRefArray,
        TargetMultidimensionalArray,
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
