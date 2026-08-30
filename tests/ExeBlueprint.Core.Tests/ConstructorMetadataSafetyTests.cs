using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorMetadataSafetyTests
{
    [Fact]
    public void AcceptsCanonicalLocalConstructorDefinitionControl()
    {
        using var fixture = CreateFixture();

        var result = Reconstruct(fixture);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Empty(result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);
    }

    [Theory]
    [InlineData(ConstructorMethodRole.Caller, ConstructorDefinitionFlagMutation.Static)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorDefinitionFlagMutation.Abstract)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorDefinitionFlagMutation.MissingSpecialName)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorDefinitionFlagMutation.MissingRuntimeSpecialName)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorDefinitionFlagMutation.Static)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorDefinitionFlagMutation.Abstract)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorDefinitionFlagMutation.MissingSpecialName)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorDefinitionFlagMutation.MissingRuntimeSpecialName)]
    public void RejectsNonCanonicalCallerAndLocalCalleeDefinitionFlags(
        ConstructorMethodRole role,
        ConstructorDefinitionFlagMutation mutation)
    {
        using var fixture = CreateFixture(
            new FixtureOptions
            {
                FlagMutationRole = role,
                FlagMutation = mutation
            });

        Assert.Null(Reconstruct(fixture));
    }

    [Theory]
    [InlineData(ConstructorMethodRole.Caller, ConstructorSignatureMutation.VarArg)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorSignatureMutation.GenericHeader)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorSignatureMutation.GenericParameterDefinition)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorSignatureMutation.NamedVoidReturn)]
    [InlineData(ConstructorMethodRole.Caller, ConstructorSignatureMutation.NamedIntParameter)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorSignatureMutation.VarArg)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorSignatureMutation.GenericHeader)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorSignatureMutation.GenericParameterDefinition)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorSignatureMutation.NamedVoidReturn)]
    [InlineData(ConstructorMethodRole.LocalCallee, ConstructorSignatureMutation.NamedIntParameter)]
    public void RejectsNonCanonicalCallingConventionGenericAndPrimitiveAliasSignatures(
        ConstructorMethodRole role,
        ConstructorSignatureMutation mutation)
    {
        using var fixture = CreateFixture(
            new FixtureOptions
            {
                SignatureMutationRole = role,
                SignatureMutation = mutation
            });

        Assert.Null(Reconstruct(fixture));
    }

    [Theory]
    [InlineData(ConstructorTargetMutation.TypeSpecificationBase)]
    [InlineData(ConstructorTargetMutation.UnrelatedLocalDefinition)]
    [InlineData(ConstructorTargetMutation.SameNameWrongTypeReferenceHandle)]
    public void RejectsTypeSpecificationBaseAndExactOwnerHandleMismatches(
        ConstructorTargetMutation mutation)
    {
        using var fixture = CreateFixture(
            new FixtureOptions
            {
                TargetMutation = mutation
            });

        Assert.Null(Reconstruct(fixture));
    }

    private static ManagedSymbolReader.ConstructorReconstructionTestResult? Reconstruct(
        MetadataFixture fixture) =>
        ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Reader,
            fixture.Il,
            fixture.CurrentConstructor);

    private static MetadataFixture CreateFixture(FixtureOptions? options = null)
    {
        options ??= new FixtureOptions();
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("ConstructorMetadataSafetyTests.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("27b162d8-3e70-4fc5-84d0-ec5538ab795b")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("ConstructorMetadataSafetyTests"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);

        var systemRuntime = metadata.AddAssemblyReference(
            metadata.GetOrAddString("System.Runtime"),
            new Version(10, 0, 0, 0),
            culture: default,
            publicKeyOrToken: default,
            flags: (AssemblyFlags)0,
            hashValue: default);
        var objectType = metadata.AddTypeReference(
            systemRuntime,
            metadata.GetOrAddString("System"),
            metadata.GetOrAddString("Object"));
        var namedVoid = metadata.AddTypeReference(
            systemRuntime,
            @namespace: default,
            metadata.GetOrAddString("void"));
        var namedInt = metadata.AddTypeReference(
            systemRuntime,
            @namespace: default,
            metadata.GetOrAddString("int"));

        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        var baseType = metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Base"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        EntityHandle derivedBaseType = baseType;
        TypeSpecificationHandle typeSpecificationBase = default;
        if (options.TargetMutation == ConstructorTargetMutation.TypeSpecificationBase)
        {
            var typeSpecification = new BlobBuilder();
            WriteNamedType(typeSpecification, 0x12, baseType); // CLASS Tests.Base
            typeSpecificationBase = metadata.AddTypeSpecification(
                metadata.GetOrAddBlob(typeSpecification));
            derivedBaseType = typeSpecificationBase;
        }

        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Derived"),
            derivedBaseType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(2));
        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Unrelated"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(3));

        var baseSignatureShape = SignatureShape.Canonical;
        var currentSignatureShape = SignatureShape.Canonical;
        if (options.SignatureMutation is not null)
        {
            var mutatedShape = ToSignatureShape(options.SignatureMutation.Value);
            if (options.SignatureMutationRole == ConstructorMethodRole.Caller)
            {
                currentSignatureShape = mutatedShape;
                if (mutatedShape == SignatureShape.NamedIntParameter)
                {
                    baseSignatureShape = SignatureShape.PrimitiveIntParameter;
                }
            }
            else
            {
                baseSignatureShape = mutatedShape;
                if (mutatedShape == SignatureShape.NamedIntParameter)
                {
                    currentSignatureShape = SignatureShape.PrimitiveIntParameter;
                }
            }
        }

        var baseAttributes = MutateAttributes(
            CanonicalConstructorAttributes,
            options.FlagMutationRole == ConstructorMethodRole.LocalCallee
                ? options.FlagMutation
                : null);
        var currentAttributes = MutateAttributes(
            CanonicalConstructorAttributes,
            options.FlagMutationRole == ConstructorMethodRole.Caller
                ? options.FlagMutation
                : null);
        var baseConstructor = metadata.AddMethodDefinition(
            baseAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            AddConstructorSignature(metadata, baseSignatureShape, namedVoid, namedInt),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var currentConstructor = metadata.AddMethodDefinition(
            currentAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            AddConstructorSignature(metadata, currentSignatureShape, namedVoid, namedInt),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var unrelatedConstructor = metadata.AddMethodDefinition(
            CanonicalConstructorAttributes,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString(".ctor"),
            AddConstructorSignature(metadata, SignatureShape.Canonical, namedVoid, namedInt),
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        if (options.SignatureMutation == ConstructorSignatureMutation.GenericParameterDefinition)
        {
            metadata.AddGenericParameter(
                options.SignatureMutationRole == ConstructorMethodRole.Caller
                    ? currentConstructor
                    : baseConstructor,
                GenericParameterAttributes.None,
                metadata.GetOrAddString("T"),
                index: 0);
        }

        EntityHandle target = options.TargetMutation switch
        {
            ConstructorTargetMutation.UnrelatedLocalDefinition => unrelatedConstructor,
            ConstructorTargetMutation.TypeSpecificationBase => metadata.AddMemberReference(
                typeSpecificationBase,
                metadata.GetOrAddString(".ctor"),
                AddConstructorSignature(
                    metadata,
                    SignatureShape.Canonical,
                    namedVoid,
                    namedInt)),
            ConstructorTargetMutation.SameNameWrongTypeReferenceHandle =>
                AddSameNameWrongHandleConstructorReference(metadata),
            _ => baseConstructor
        };

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        var parameterCount = currentSignatureShape is
            SignatureShape.PrimitiveIntParameter or
            SignatureShape.NamedIntParameter
            ? 1
            : 0;
        return new MetadataFixture(
            provider,
            currentConstructor,
            BuildConstructorIl(MetadataTokens.GetToken(target), parameterCount));

        EntityHandle AddSameNameWrongHandleConstructorReference(MetadataBuilder builder)
        {
            var externalAssembly = builder.AddAssemblyReference(
                builder.GetOrAddString("External.Base"),
                new Version(1, 0, 0, 0),
                culture: default,
                publicKeyOrToken: default,
                flags: (AssemblyFlags)0,
                hashValue: default);
            var wrongBaseHandle = builder.AddTypeReference(
                externalAssembly,
                builder.GetOrAddString("Tests"),
                builder.GetOrAddString("Base"));
            return builder.AddMemberReference(
                wrongBaseHandle,
                builder.GetOrAddString(".ctor"),
                AddConstructorSignature(
                    builder,
                    SignatureShape.Canonical,
                    namedVoid,
                    namedInt));
        }
    }

    private static BlobHandle AddConstructorSignature(
        MetadataBuilder metadata,
        SignatureShape shape,
        TypeReferenceHandle namedVoid,
        TypeReferenceHandle namedInt)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(shape switch
        {
            SignatureShape.VarArg => 0x25, // HASTHIS | VARARG
            SignatureShape.GenericHeader => 0x30, // HASTHIS | GENERIC | DEFAULT
            _ => 0x20 // HASTHIS | DEFAULT
        });
        if (shape == SignatureShape.GenericHeader)
        {
            signature.WriteCompressedInteger(1);
        }

        var hasParameter = shape is
            SignatureShape.PrimitiveIntParameter or
            SignatureShape.NamedIntParameter;
        signature.WriteCompressedInteger(hasParameter ? 1 : 0);
        if (shape == SignatureShape.NamedVoidReturn)
        {
            WriteNamedType(signature, 0x12, namedVoid); // CLASS void，不能冒充 ELEMENT_TYPE_VOID。
        }
        else
        {
            signature.WriteByte(0x01); // VOID
        }

        if (shape == SignatureShape.PrimitiveIntParameter)
        {
            signature.WriteByte(0x08); // I4
        }
        else if (shape == SignatureShape.NamedIntParameter)
        {
            WriteNamedType(signature, 0x12, namedInt); // CLASS int，不能冒充 ELEMENT_TYPE_I4。
        }

        return metadata.GetOrAddBlob(signature);
    }

    private static void WriteNamedType(BlobBuilder signature, byte kind, EntityHandle type)
    {
        signature.WriteByte(kind);
        signature.WriteCompressedInteger(CodedIndex.TypeDefOrRef(type));
    }

    private static byte[] BuildConstructorIl(int constructorToken, int parameterCount)
    {
        var il = new byte[parameterCount == 0 ? 7 : 8];
        var index = 0;
        il[index++] = 0x02; // ldarg.0
        if (parameterCount == 1)
        {
            il[index++] = 0x03; // ldarg.1
        }

        il[index++] = 0x28; // call
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(index, 4), constructorToken);
        index += 4;
        il[index] = 0x2A; // ret
        return il;
    }

    private static MethodAttributes MutateAttributes(
        MethodAttributes attributes,
        ConstructorDefinitionFlagMutation? mutation) =>
        mutation switch
        {
            ConstructorDefinitionFlagMutation.Static => attributes | MethodAttributes.Static,
            ConstructorDefinitionFlagMutation.Abstract => attributes | MethodAttributes.Abstract,
            ConstructorDefinitionFlagMutation.MissingSpecialName =>
                attributes & ~MethodAttributes.SpecialName,
            ConstructorDefinitionFlagMutation.MissingRuntimeSpecialName =>
                attributes & ~MethodAttributes.RTSpecialName,
            _ => attributes
        };

    private static SignatureShape ToSignatureShape(ConstructorSignatureMutation mutation) =>
        mutation switch
        {
            ConstructorSignatureMutation.VarArg => SignatureShape.VarArg,
            ConstructorSignatureMutation.GenericHeader => SignatureShape.GenericHeader,
            ConstructorSignatureMutation.NamedVoidReturn => SignatureShape.NamedVoidReturn,
            ConstructorSignatureMutation.NamedIntParameter => SignatureShape.NamedIntParameter,
            _ => SignatureShape.Canonical
        };

    private const MethodAttributes CanonicalConstructorAttributes =
        MethodAttributes.Public |
        MethodAttributes.HideBySig |
        MethodAttributes.SpecialName |
        MethodAttributes.RTSpecialName;

    public enum ConstructorMethodRole
    {
        Caller,
        LocalCallee
    }

    public enum ConstructorDefinitionFlagMutation
    {
        Static,
        Abstract,
        MissingSpecialName,
        MissingRuntimeSpecialName
    }

    public enum ConstructorSignatureMutation
    {
        VarArg,
        GenericHeader,
        GenericParameterDefinition,
        NamedVoidReturn,
        NamedIntParameter
    }

    public enum ConstructorTargetMutation
    {
        Canonical,
        TypeSpecificationBase,
        UnrelatedLocalDefinition,
        SameNameWrongTypeReferenceHandle
    }

    private enum SignatureShape
    {
        Canonical,
        VarArg,
        GenericHeader,
        NamedVoidReturn,
        PrimitiveIntParameter,
        NamedIntParameter
    }

    private sealed class FixtureOptions
    {
        public ConstructorMethodRole? FlagMutationRole { get; init; }

        public ConstructorDefinitionFlagMutation? FlagMutation { get; init; }

        public ConstructorMethodRole? SignatureMutationRole { get; init; }

        public ConstructorSignatureMutation? SignatureMutation { get; init; }

        public ConstructorTargetMutation TargetMutation { get; init; }
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
