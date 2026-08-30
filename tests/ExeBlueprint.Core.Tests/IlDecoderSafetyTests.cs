using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class IlDecoderSafetyTests
{
    [Fact]
    public void AcceptsCanonicalOperandWidthsAndInstructionBudgetBoundary()
    {
        byte[] canonical =
        [
            0x00,                         // nop
            0x1F, 0x7F,                   // ldc.i4.s 127
            0xFE, 0x09, 0x00, 0x00,       // ldarg 0
            0x20, 0x01, 0x00, 0x00, 0x00, // ldc.i4 1
            0x21, 0x01, 0x00, 0x00, 0x00, // ldc.i8 1
            0x00, 0x00, 0x00, 0x00,
            0x22, 0x00, 0x00, 0x80, 0x3F, // ldc.r4 1
            0x23, 0x00, 0x00, 0x00, 0x00, // ldc.r8 1
            0x00, 0x00, 0xF0, 0x3F,
            0xFE, 0x01,                   // ceq
            0x2A                          // ret
        ];

        var decoded = ManagedSymbolReader.DecodeIlForTest(canonical);

        Assert.Equal("Complete", decoded.Status);
        Assert.Equal(9, decoded.InstructionCount);
        Assert.Equal(canonical.Length, decoded.ConsumedOffset);

        var exactlyFourHundred = Enumerable.Repeat((byte)0x00, 399)
            .Append((byte)0x2A)
            .ToArray();
        decoded = ManagedSymbolReader.DecodeIlForTest(exactlyFourHundred);
        Assert.Equal("Complete", decoded.Status);
        Assert.Equal(400, decoded.InstructionCount);
        Assert.Equal(exactlyFourHundred.Length, decoded.ConsumedOffset);

        var fourHundredAndOne = Enumerable.Repeat((byte)0x00, 400)
            .Append((byte)0x2A)
            .ToArray();
        decoded = ManagedSymbolReader.DecodeIlForTest(fourHundredAndOne);
        Assert.Equal("BudgetExceeded", decoded.Status);
        Assert.Equal(400, decoded.InstructionCount);
        Assert.Equal(400, decoded.ConsumedOffset);
    }

    [Theory]
    [MemberData(nameof(MalformedOpcodes))]
    public void RejectsUnknownReservedAndTruncatedOpcodes(byte[] il)
    {
        var decoded = ManagedSymbolReader.DecodeIlForTest(il);

        Assert.Equal("Malformed", decoded.Status);
        Assert.Equal(0, decoded.InstructionCount);
        Assert.Equal(0, decoded.ConsumedOffset);
    }

    public static TheoryData<byte[]> MalformedOpcodes => new()
    {
        new byte[] { 0xA6 },                         // unknown one-byte opcode
        new byte[] { 0xFE, 0x08 },                   // unknown two-byte opcode
        new byte[] { 0xFE },                         // dangling two-byte prefix
        new byte[] { 0xF8 },                         // reserved prefix7
        new byte[] { 0xF9 },                         // reserved prefix6
        new byte[] { 0xFA },                         // reserved prefix5
        new byte[] { 0xFB },                         // reserved prefix4
        new byte[] { 0xFC },                         // reserved prefix3
        new byte[] { 0xFD },                         // reserved prefix2
        new byte[] { 0xFF },                         // reserved prefixref
        new byte[] { 0x1F },                         // truncated ShortInlineI
        new byte[] { 0x0E },                         // truncated ShortInlineVar
        new byte[] { 0xFE, 0x09, 0x00 },             // truncated InlineVar
        new byte[] { 0x20, 0x00, 0x00, 0x00 },       // truncated InlineI
        new byte[] { 0x28, 0x01, 0x00, 0x00 },       // truncated InlineMethod
        new byte[] { 0x2B },                         // truncated short branch
        new byte[] { 0x38, 0x00, 0x00, 0x00 },       // truncated long branch
        new byte[] { 0x21, 0, 0, 0, 0, 0, 0, 0 },   // truncated InlineI8
        new byte[] { 0x22, 0x00, 0x00, 0x00 },       // truncated ShortInlineR
        new byte[] { 0x23, 0, 0, 0, 0, 0, 0, 0 },    // truncated InlineR
        new byte[] { 0x45, 0x00, 0x00, 0x00 },       // truncated switch count
        new byte[] { 0x45, 0xFF, 0xFF, 0xFF, 0xFF }, // negative switch count
        new byte[] { 0x45, 0x01, 0x00, 0x00, 0x00 }  // truncated switch table
    };

    [Fact]
    public void EnforcesAggregateSwitchTargetBudget()
    {
        var exactBudget = BuildSwitchBody(2_048, 2_048);
        var decoded = ManagedSymbolReader.DecodeIlForTest(exactBudget);

        Assert.Equal("Complete", decoded.Status);
        Assert.Equal(3, decoded.InstructionCount);
        Assert.Equal(exactBudget.Length, decoded.ConsumedOffset);

        var overBudget = BuildSwitchBody(2_048, 2_049);
        decoded = ManagedSymbolReader.DecodeIlForTest(overBudget);

        Assert.Equal("BudgetExceeded", decoded.Status);
        Assert.Equal(1, decoded.InstructionCount);
        Assert.Equal(1 + 4 + (2_048 * 4), decoded.ConsumedOffset);
    }

    [Fact]
    public void ValidatesEveryBranchTargetAsAnInstructionBoundary()
    {
        Assert.Equal(
            "Complete",
            ManagedSymbolReader.DecodeIlForTest([0x2B, 0x00, 0x2A]).Status);
        Assert.Equal(
            "Complete",
            ManagedSymbolReader.DecodeIlForTest([0x38, 0, 0, 0, 0, 0x2A]).Status);
        Assert.Equal(
            "Complete",
            ManagedSymbolReader.DecodeIlForTest([0x2B, 0xFE]).Status);
        Assert.Equal(
            "Complete",
            ManagedSymbolReader.DecodeIlForTest(BuildSwitchBody(0)).Status);

        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest([0x2B, 0xFF, 0x2A]).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest([0x2B, 0x01, 0x2A]).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(
                [0x2B, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x2A]).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(
                [0x38, 0xFF, 0xFF, 0xFF, 0x7F, 0x2A]).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(
                [0x38, 0xFC, 0xFF, 0xFF, 0xFF, 0x2A]).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(BuildSwitchWithTarget(2)).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(BuildSwitchWithTarget(10)).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(BuildSwitchWithTarget(100)).Status);
        Assert.Equal(
            "Malformed",
            ManagedSymbolReader.DecodeIlForTest(BuildSwitchWithTarget(-1)).Status);
    }

    [Fact]
    public void RejectsMalformedSuffixAndUnsupportedNormalFallthrough()
    {
        using var fixture = OpenCurrentAssembly();
        byte[] malformedSuffix = [0x17, 0x2A, 0xA6];

        var decoded = ManagedSymbolReader.DecodeIlForTest(malformedSuffix);
        Assert.Equal("Malformed", decoded.Status);
        Assert.Equal(2, decoded.InstructionCount);
        Assert.Equal(2, decoded.ConsumedOffset);
        Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
            fixture.Metadata,
            malformedSuffix,
            isInstance: false,
            returnType: "int"));

        Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
            fixture.Metadata,
            [0x00],
            isInstance: false,
            returnType: "void"));
        Assert.Equal(
            ["throw null;"],
            ManagedSymbolReader.ReconstructBodyForTest(
                fixture.Metadata,
                [0x14, 0x7A],
                isInstance: false,
                returnType: "void"));
    }

    [Fact]
    public async Task ProductionReadCommitsOnlyCompleteMethodEvidence()
    {
        const int targetToken = 0x06000001;
        var validCall = BuildCall(targetToken, includeRet: true, malformedSuffix: false);
        using (var assembly = CreateProbeAssembly(validCall))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.False(code!.Truncated);
            Assert.False(probe.IlTruncated);
            Assert.True(probe.BodyReconstructed);
            Assert.Single(code.CallGraph, edge => edge.Caller == "Tests.Probe.Probe");
        }

        var noRet = BuildCall(targetToken, includeRet: false, malformedSuffix: false);
        using (var assembly = CreateProbeAssembly(noRet))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.False(code!.Truncated);
            Assert.False(probe.IlTruncated);
            Assert.False(probe.BodyReconstructed);
            Assert.Single(code.CallGraph, edge => edge.Caller == "Tests.Probe.Probe");
        }

        var exactInstructionBudget = BuildCall(
            targetToken,
            includeRet: true,
            malformedSuffix: false,
            nopCount: 398);
        using (var assembly = CreateProbeAssembly(exactInstructionBudget))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.False(code!.Truncated);
            Assert.False(probe.IlTruncated);
            Assert.True(probe.BodyReconstructed);
            Assert.Equal(400, probe.Il.Count);
            Assert.Single(code.CallGraph, edge => edge.Caller == "Tests.Probe.Probe");
        }

        var overInstructionBudget = BuildCall(
            targetToken,
            includeRet: true,
            malformedSuffix: false,
            nopCount: 399);
        using (var assembly = CreateProbeAssembly(overInstructionBudget))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.True(code!.Truncated);
            Assert.True(probe.IlTruncated);
            Assert.False(probe.BodyReconstructed);
            Assert.Equal(400, probe.Il.Count);
            Assert.DoesNotContain(
                code.CallGraph,
                edge => edge.Caller == "Tests.Probe.Probe");
        }

        var malformed = BuildCall(targetToken, includeRet: true, malformedSuffix: true);
        using (var assembly = CreateProbeAssembly(malformed))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.True(code!.Truncated);
            Assert.True(probe.IlTruncated);
            Assert.False(probe.BodyReconstructed);
            Assert.DoesNotContain(
                code.CallGraph,
                edge => edge.Caller == "Tests.Probe.Probe");
            Assert.Equal(2, probe.Il.Count);
        }

        using (var assembly = CreateProbeAssembly([]))
        {
            var code = await ManagedSymbolReader.TryReadAsync(
                assembly.Path,
                CancellationToken.None);
            var probe = GetProbe(code);

            Assert.True(code!.Truncated);
            Assert.True(probe.IlTruncated);
            Assert.False(probe.BodyReconstructed);
            Assert.Empty(probe.Il);
        }
    }

    private static MethodModel GetProbe(CodeModel? code)
    {
        Assert.NotNull(code);
        var type = Assert.Single(code.Types, type => type.FullName == "Tests.Probe");
        return Assert.Single(type.Methods, method => method.Name == "Probe");
    }

    private static byte[] BuildSwitchBody(params int[] targetCounts)
    {
        var bytes = new List<byte>();
        var switchBases = new List<(int DeltaStart, int Count, int BaseOffset)>();
        foreach (var count in targetCounts)
        {
            bytes.Add(0x45); // switch
            AppendInt32(bytes, count);
            var deltaStart = bytes.Count;
            for (var index = 0; index < count; index++)
            {
                AppendInt32(bytes, 0);
            }

            switchBases.Add((deltaStart, count, bytes.Count));
        }

        var returnOffset = bytes.Count;
        bytes.Add(0x2A); // ret
        foreach (var (deltaStart, count, baseOffset) in switchBases)
        {
            var delta = returnOffset - baseOffset;
            for (var index = 0; index < count; index++)
            {
                WriteInt32(bytes, deltaStart + (index * 4), delta);
            }
        }

        return [.. bytes];
    }

    private static byte[] BuildSwitchWithTarget(int target)
    {
        var bytes = new List<byte> { 0x45 }; // switch
        AppendInt32(bytes, 1);
        var baseOffset = bytes.Count + 4;
        AppendInt32(bytes, target - baseOffset);
        bytes.Add(0x2A); // ret
        return [.. bytes];
    }

    private static byte[] BuildCall(
        int targetToken,
        bool includeRet,
        bool malformedSuffix,
        int nopCount = 0)
    {
        var bytes = new List<byte> { 0x28 }; // call
        AppendInt32(bytes, targetToken);
        bytes.AddRange(Enumerable.Repeat((byte)0x00, nopCount));
        if (includeRet)
        {
            bytes.Add(0x2A); // ret
        }

        if (malformedSuffix)
        {
            bytes.Add(0xA6); // unknown opcode
        }

        return [.. bytes];
    }

    private static TemporaryAssembly CreateProbeAssembly(byte[] probeIl)
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("IlDecoderProbe.dll"),
            mvid: metadata.GetOrAddGuid(Guid.NewGuid()),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("IlDecoderProbe"),
            new Version(1, 0, 0, 0),
            culture: default,
            publicKey: default,
            flags: (AssemblyFlags)0,
            hashAlgorithm: AssemblyHashAlgorithm.None);
        var runtime = metadata.AddAssemblyReference(
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
            runtime,
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
            metadata.GetOrAddString("Probe"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var ilStream = new BlobBuilder();
        var bodies = new MethodBodyStreamEncoder(ilStream);
        var targetInstructions = new BlobBuilder();
        var targetEncoder = new InstructionEncoder(targetInstructions);
        targetEncoder.OpCode(ILOpCode.Ret);
        var targetBody = bodies.AddMethodBody(targetEncoder, maxStack: 1);

        var probeInstructions = new BlobBuilder();
        probeInstructions.WriteBytes(probeIl);
        var probeBody = bodies.AddMethodBody(
            new InstructionEncoder(probeInstructions),
            maxStack: 8);
        var signature = new BlobBuilder();
        signature.WriteByte(0x00); // DEFAULT
        signature.WriteByte(0x00); // zero parameters
        signature.WriteByte(0x01); // VOID
        var signatureHandle = metadata.GetOrAddBlob(signature);
        metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("Target"),
            signatureHandle,
            targetBody,
            MetadataTokens.ParameterHandle(1));
        metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("Probe"),
            signatureHandle,
            probeBody,
            MetadataTokens.ParameterHandle(1));

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

        var path = Path.Combine(
            Path.GetTempPath(),
            $"il-decoder-probe-{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(path, peImage.ToArray());
        return new TemporaryAssembly(path);
    }

    private static MetadataFixture OpenCurrentAssembly()
    {
        var stream = File.OpenRead(typeof(IlDecoderSafetyTests).Assembly.Location);
        var peReader = new PEReader(stream);
        return new MetadataFixture(stream, peReader);
    }

    private static void AppendInt32(List<byte> bytes, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        bytes.AddRange(buffer);
    }

    private static void WriteInt32(List<byte> bytes, int offset, int value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        for (var index = 0; index < buffer.Length; index++)
        {
            bytes[offset + index] = buffer[index];
        }
    }

    private sealed class MetadataFixture(Stream stream, PEReader peReader) : IDisposable
    {
        public MetadataReader Metadata { get; } = peReader.GetMetadataReader();

        public void Dispose()
        {
            peReader.Dispose();
            stream.Dispose();
        }
    }

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public void Dispose()
        {
            File.Delete(Path);
        }
    }
}
