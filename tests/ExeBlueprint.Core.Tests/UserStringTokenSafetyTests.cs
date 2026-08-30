using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class UserStringTokenSafetyTests
{
    [Fact]
    public void ReadsCanonicalEmptyEscapedAndCompressedLengthEntries()
    {
        var escaped = UserStringTokenFixture.EscapedValue;
        var twoByteLength = new string('A', 64);
        var heap = BuildHeap(string.Empty, escaped, twoByteLength);

        AssertRead(heap, 0, string.Empty);
        AssertRead(heap, 1, escaped);
        AssertRead(heap, 2, twoByteLength);
        Assert.Equal(0x80, heap.Bytes[heap.Offsets[2]] & 0xC0);

        var twoByteBoundaryHeap = BuildHeap(new string('C', 8_191), string.Empty);
        Assert.Equal(0xBF, twoByteBoundaryHeap.Bytes[twoByteBoundaryHeap.Offsets[0]]);
        Assert.Equal(0xFF, twoByteBoundaryHeap.Bytes[twoByteBoundaryHeap.Offsets[0] + 1]);
        AssertRead(twoByteBoundaryHeap, 1, string.Empty);

        var fourByteLength = new string('B', 8_192);
        var fourByteHeap = BuildHeap(fourByteLength, string.Empty);
        Assert.Equal(0xC0, fourByteHeap.Bytes[fourByteHeap.Offsets[0]] & 0xE0);
        AssertRead(fourByteHeap, 1, string.Empty);

        static void AssertRead(RawHeap heap, int index, string expected)
        {
            var result = ManagedSymbolReader.ReadUserStringForTest(
                heap.Bytes,
                UserStringToken(heap.Offsets[index]));

            Assert.True(result.Success);
            Assert.Equal(expected, result.Value);
            Assert.False(result.Truncated);
        }
    }

    [Fact]
    public void EnforcesDecodedCharacterBudgetAtExactBoundary()
    {
        var heap = BuildHeap(new string('A', 4_096), new string('B', 4_097));

        var exact = ManagedSymbolReader.ReadUserStringForTest(
            heap.Bytes,
            UserStringToken(heap.Offsets[0]));
        Assert.True(exact.Success);
        Assert.Equal(4_096, exact.Value.Length);
        Assert.False(exact.Truncated);

        var over = ManagedSymbolReader.ReadUserStringForTest(
            heap.Bytes,
            UserStringToken(heap.Offsets[1]));
        Assert.False(over.Success);
        Assert.True(over.Truncated);
    }

    [Fact]
    public void RejectsWrongTableNilAndNonEntryOffsets()
    {
        var heap = BuildHeap("A");
        var offset = heap.Offsets[0];
        int[] invalidTokens =
        [
            offset,
            0x0100_0000 | offset,
            0x0600_0000 | offset,
            0x6F00_0000 | offset,
            0x7100_0000 | offset,
            unchecked((int)0xFF00_0000) | offset,
            UserStringToken(0),
            UserStringToken(offset + 1),
            UserStringToken(offset + 2),
            UserStringToken(offset + 3),
            UserStringToken(heap.Bytes.Length - 1),
            UserStringToken(heap.Bytes.Length),
            unchecked((int)0x70FF_FFFF)
        ];

        foreach (var token in invalidTokens)
        {
            var result = ManagedSymbolReader.ReadUserStringForTest(heap.Bytes, token);

            Assert.False(result.Success);
            Assert.Equal(string.Empty, result.Value);
            Assert.False(result.Truncated);
        }
    }

    [Theory]
    [MemberData(nameof(MalformedHeaps))]
    public void RejectsMalformedHeapFromFirstEntry(byte[] heap)
    {
        var result = ManagedSymbolReader.ReadUserStringForTest(
            heap,
            UserStringToken(1));

        Assert.False(result.Success);
        Assert.True(result.Truncated);
    }

    public static TheoryData<byte[]> MalformedHeaps => new()
    {
        new byte[] { 0x01 },                         // reserved byte is not zero
        new byte[] { 0x00, 0x80 },                   // truncated two-byte length
        new byte[] { 0x00, 0xC0, 0x00, 0x40 },       // truncated four-byte length
        new byte[] { 0x00, 0xE0 },                   // reserved compressed prefix
        new byte[] { 0x00, 0xFF },                   // reserved compressed prefix
        new byte[] { 0x00, 0x80, 0x01, 0x00 },       // overlong encoding of length 1
        new byte[] { 0x00, 0xC0, 0x00, 0x00, 0x01 }, // overlong encoding of length 1
        new byte[] { 0x00, 0x05, 0x41, 0x00, 0x00 }, // declared payload past heap
        new byte[] { 0x00, 0x02, 0x41, 0x00 },       // even payload length
        new byte[] { 0x00, 0x01, 0x02 },             // terminal byte is not 0/1
        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00 }, // more than three padding bytes
        new byte[] { 0x00, 0x00, 0x00, 0x01 }        // non-zero padding
    };

    [Fact]
    public void AcceptsEitherDefinedTerminalFlagWithoutChangingPayload()
    {
        var zeroForSpecialCharacter = ManagedSymbolReader.ReadUserStringForTest(
            [0x00, 0x03, 0x85, 0x00, 0x00],
            UserStringToken(1));
        var oneForOrdinaryCharacter = ManagedSymbolReader.ReadUserStringForTest(
            [0x00, 0x03, 0x41, 0x00, 0x01],
            UserStringToken(1));

        Assert.True(zeroForSpecialCharacter.Success);
        Assert.Equal("\u0085", zeroForSpecialCharacter.Value);
        Assert.False(zeroForSpecialCharacter.Truncated);
        Assert.True(oneForOrdinaryCharacter.Success);
        Assert.Equal("A", oneForOrdinaryCharacter.Value);
        Assert.False(oneForOrdinaryCharacter.Truncated);
    }

    [Fact]
    public void PreservesValidatedPrefixButRejectsMalformedSuffix()
    {
        byte[] heap = [0x00, 0x03, 0x41, 0x00, 0x00, 0xE0];

        var prefix = ManagedSymbolReader.ReadUserStringForTest(
            heap,
            UserStringToken(1));
        var suffix = ManagedSymbolReader.ReadUserStringForTest(
            heap,
            UserStringToken(5));

        Assert.True(prefix.Success);
        Assert.Equal("A", prefix.Value);
        Assert.True(prefix.Truncated);
        Assert.False(suffix.Success);
        Assert.True(suffix.Truncated);
    }

    [Fact]
    public void ReconstructsOnlyCanonicalUserStringTokensInBodiesAndConstructors()
    {
        using var fixture = OpenAssembly();
        var escapedToken = ReadUserStringToken(
            fixture,
            typeof(UserStringTokenFixture).GetMethod(
                nameof(UserStringTokenFixture.ReturnEscaped))!);
        var emptyToken = ReadUserStringToken(
            fixture,
            typeof(UserStringTokenFixture).GetMethod(
                nameof(UserStringTokenFixture.ReturnEmpty))!);
        var currentConstructor = typeof(UserStringConstructorDerivedFixture).GetConstructor(
            Type.EmptyTypes)!;
        var baseConstructor = typeof(UserStringConstructorBaseFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(string)],
            modifiers: null)!;
        var currentConstructorHandle = MethodHandle(currentConstructor);

        var escapedBody = ManagedSymbolReader.ReconstructBodyForTest(
            fixture.Metadata,
            BuildLdstrReturn(escapedToken),
            isInstance: false,
            returnType: "string",
            peReader: fixture.Reader);
        AssertEscaped(Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<string>>(escapedBody)));

        Assert.Equal(
            ["return \"\";"],
            ManagedSymbolReader.ReconstructBodyForTest(
                fixture.Metadata,
                BuildLdstrReturn(emptyToken),
                isInstance: false,
                returnType: "string",
                peReader: fixture.Reader));

        var validConstructor = ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            BuildStringConstructorIl(escapedToken, baseConstructor.MetadataToken),
            currentConstructorHandle,
            peReader: fixture.Reader);
        Assert.NotNull(validConstructor);
        Assert.Equal("base", validConstructor.Initializer.Kind);
        AssertEscaped(Assert.Single(validConstructor.Initializer.Arguments));

        var heapSize = fixture.Metadata.GetHeapSize(HeapIndex.UserString);
        int[] invalidTokens =
        [
            0x7100_0000 | (escapedToken & 0x00FF_FFFF),
            0x0600_0000 | (escapedToken & 0x00FF_FFFF),
            UserStringToken(0),
            UserStringToken((escapedToken & 0x00FF_FFFF) + 1),
            heapSize <= 0x00FF_FFFF
                ? UserStringToken(heapSize)
                : unchecked((int)0x70FF_FFFF),
            unchecked((int)0x70FF_FFFF)
        ];

        foreach (var invalidToken in invalidTokens)
        {
            Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
                fixture.Metadata,
                BuildLdstrReturn(invalidToken),
                isInstance: false,
                returnType: "string",
                peReader: fixture.Reader));
            Assert.Null(ManagedSymbolReader.ReconstructConstructorForTest(
                fixture.Metadata,
                BuildStringConstructorIl(invalidToken, baseConstructor.MetadataToken),
                currentConstructorHandle,
                peReader: fixture.Reader));
        }
    }

    [Fact]
    public async Task InvalidTokenKeepsRawDisassemblyAndCommitsNoMethodEvidence()
    {
        var method = typeof(UserStringTokenFixture).GetMethod(
            nameof(UserStringTokenFixture.ReturnEscaped))!;
        var originalPath = typeof(UserStringTokenFixture).Assembly.Location;
        var valid = await ManagedSymbolReader.TryReadAsync(
            originalPath,
            CancellationToken.None);
        var caller = $"{typeof(UserStringTokenFixture).FullName}.{method.Name}";
        var callee = $"{typeof(UserStringTokenFixture).FullName}.{nameof(UserStringTokenFixture.Touch)}";
        Assert.Contains(
            valid!.CallGraph,
            edge => edge.Caller == caller && edge.Callee == callee);
        var validMethod = GetMethod(valid, method.Name);
        Assert.True(validMethod.BodyReconstructed);
        Assert.False(validMethod.IlTruncated);

        using var fixture = OpenAssembly();
        var validToken = ReadUserStringToken(fixture, method);
        var invalidToken = 0x7100_0000 | (validToken & 0x00FF_FFFF);
        using var patched = PatchMethodUserStringToken(method, invalidToken);

        var code = await ManagedSymbolReader.TryReadAsync(
            patched.Path,
            CancellationToken.None);
        var invalidMethod = GetMethod(code!, method.Name);

        Assert.True(code!.Truncated);
        Assert.True(invalidMethod.IlTruncated);
        Assert.False(invalidMethod.BodyReconstructed);
        Assert.Contains(
            invalidMethod.Il,
            instruction => instruction.Contains(
                $"str(0x{invalidToken:X8})",
                StringComparison.Ordinal));
        Assert.DoesNotContain(code.CallGraph, edge => edge.Caller == caller);
    }

    [Fact]
    public async Task MalformedHeapFailsClosedAcrossProductionBodyAndConstructor()
    {
        var method = typeof(UserStringTokenFixture).GetMethod(
            nameof(UserStringTokenFixture.ReturnMalformed))!;
        var currentConstructor = typeof(UserStringConstructorDerivedFixture).GetConstructor(
            Type.EmptyTypes)!;
        var validCode = await ManagedSymbolReader.TryReadAsync(
            typeof(UserStringTokenFixture).Assembly.Location,
            CancellationToken.None);
        var validConstructorType = Assert.Single(
            validCode!.Types,
            type => type.FullName == typeof(UserStringConstructorDerivedFixture).FullName);
        var validConstructor = Assert.Single(
            validConstructorType.Methods,
            candidate => candidate.Name == ".ctor");

        Assert.False(validConstructor.IlTruncated);
        Assert.NotNull(validConstructor.ConstructorInitializer);
        Assert.Equal("base", validConstructor.ConstructorInitializer.Kind);
        Assert.True(validConstructor.BodyReconstructed);

        using var original = OpenAssembly();
        var token = ReadUserStringToken(original, method);
        using var patched = PatchUserStringHeader(token, 0xE0);

        var code = await ManagedSymbolReader.TryReadAsync(
            patched.Path,
            CancellationToken.None);
        var model = GetMethod(code!, method.Name);
        var caller = $"{typeof(UserStringTokenFixture).FullName}.{method.Name}";

        Assert.True(code!.Truncated);
        Assert.True(model.IlTruncated);
        Assert.False(model.BodyReconstructed);
        Assert.Contains(
            model.Il,
            instruction => instruction.Contains(
                $"str(0x{token:X8})",
                StringComparison.Ordinal));
        Assert.DoesNotContain(code.CallGraph, edge => edge.Caller == caller);

        using var malformed = OpenAssembly(patched.Path);
        Assert.Null(ManagedSymbolReader.ReconstructBodyForTest(
            malformed.Metadata,
            BuildLdstrReturn(token),
            isInstance: false,
            returnType: "string",
            peReader: malformed.Reader));

        var baseConstructor = typeof(UserStringConstructorBaseFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(string)],
            modifiers: null)!;
        Assert.Null(ManagedSymbolReader.ReconstructConstructorForTest(
            malformed.Metadata,
            BuildStringConstructorIl(token, baseConstructor.MetadataToken),
            MethodHandle(currentConstructor),
            peReader: malformed.Reader));

        using var constructorOriginal = OpenAssembly();
        var constructorToken = ReadUserStringToken(
            constructorOriginal,
            currentConstructor);
        using var constructorPatched = PatchUserStringHeader(
            constructorToken,
            0xE0);
        var constructorCode = await ManagedSymbolReader.TryReadAsync(
            constructorPatched.Path,
            CancellationToken.None);
        var constructorType = Assert.Single(
            constructorCode!.Types,
            type => type.FullName == typeof(UserStringConstructorDerivedFixture).FullName);
        var constructorModel = Assert.Single(
            constructorType.Methods,
            method => method.Name == ".ctor");

        Assert.True(constructorCode.Truncated);
        Assert.True(constructorModel.IlTruncated);
        Assert.Null(constructorModel.ConstructorInitializer);
        Assert.False(constructorModel.BodyReconstructed);
        Assert.Contains(
            constructorModel.Il,
            instruction => instruction.Contains(
                $"str(0x{constructorToken:X8})",
                StringComparison.Ordinal));
    }

    private static void AssertEscaped(string value)
    {
        Assert.Contains("US_ESCAPED_A9", value, StringComparison.Ordinal);
        Assert.Contains("\\\\", value, StringComparison.Ordinal);
        Assert.Contains("\\\"", value, StringComparison.Ordinal);
        Assert.Contains("\\0", value, StringComparison.Ordinal);
        Assert.Contains("\\a", value, StringComparison.Ordinal);
        Assert.Contains("\\b", value, StringComparison.Ordinal);
        Assert.Contains("\\f", value, StringComparison.Ordinal);
        Assert.Contains("\\v", value, StringComparison.Ordinal);
        Assert.Contains("\\r\\n\\t", value, StringComparison.Ordinal);
        Assert.Contains("\\u0085", value, StringComparison.Ordinal);
        Assert.Contains("\\u2028", value, StringComparison.Ordinal);
        Assert.Contains("\\u2029", value, StringComparison.Ordinal);
        Assert.Contains("\\uD800", value, StringComparison.Ordinal);
        Assert.Contains("\\uDC00", value, StringComparison.Ordinal);
        Assert.DoesNotContain('\0', value);
        Assert.DoesNotContain('\r', value);
        Assert.DoesNotContain('\n', value);
        Assert.DoesNotContain('\t', value);
    }

    private static ExeBlueprint.Models.MethodModel GetMethod(
        ExeBlueprint.Models.CodeModel code,
        string methodName)
    {
        var type = Assert.Single(
            code.Types,
            type => type.FullName == typeof(UserStringTokenFixture).FullName);
        return Assert.Single(type.Methods, method => method.Name == methodName);
    }

    private static byte[] BuildLdstrReturn(int token)
    {
        var il = new byte[6];
        il[0] = 0x72;
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(1, 4), token);
        il[5] = 0x2A;
        return il;
    }

    private static byte[] BuildStringConstructorIl(int stringToken, int constructorToken)
    {
        var il = new byte[12];
        il[0] = 0x02;
        il[1] = 0x72;
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(2, 4), stringToken);
        il[6] = 0x28;
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(7, 4), constructorToken);
        il[11] = 0x2A;
        return il;
    }

    private static int ReadUserStringToken(AssemblyFixture fixture, MethodBase method)
    {
        var definition = fixture.Metadata.GetMethodDefinition(MethodHandle(method));
        var il = fixture.Reader.GetMethodBody(definition.RelativeVirtualAddress).GetILBytes() ??
                 throw new InvalidOperationException("Fixture method has no IL body.");
        var operandOffset = FindUserStringOperandOffset(il);
        var token = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(operandOffset, 4));
        Assert.Equal(0x70u, (uint)token >> 24);
        Assert.NotEqual(0, token & 0x00FF_FFFF);
        return token;
    }

    private static int FindUserStringOperandOffset(byte[] il)
    {
        for (var offset = 0; offset <= il.Length - 5; offset++)
        {
            if (il[offset] != 0x72)
            {
                continue;
            }

            var token = BinaryPrimitives.ReadInt32LittleEndian(il.AsSpan(offset + 1, 4));
            if ((uint)token >> 24 == 0x70)
            {
                return offset + 1;
            }
        }

        throw new InvalidOperationException("Fixture method does not contain a canonical ldstr token.");
    }

    private static TemporaryAssembly PatchMethodUserStringToken(
        MethodInfo method,
        int replacementToken)
    {
        var image = File.ReadAllBytes(typeof(UserStringTokenFixture).Assembly.Location);
        using var stream = new MemoryStream(image, writable: false);
        using var reader = new PEReader(stream);
        var metadata = reader.GetMetadataReader();
        var definition = metadata.GetMethodDefinition(MethodHandle(method));
        var il = reader.GetMethodBody(definition.RelativeVirtualAddress).GetILBytes() ??
                 throw new InvalidOperationException("Fixture method has no IL body.");
        var operandOffset = FindUserStringOperandOffset(il);
        var bodyOffset = RvaToFileOffset(reader.PEHeaders, definition.RelativeVirtualAddress);
        var codeOffset = GetMethodCodeOffset(image, bodyOffset);
        BinaryPrimitives.WriteInt32LittleEndian(
            image.AsSpan(codeOffset + operandOffset, 4),
            replacementToken);
        return TemporaryAssembly.Write(image);
    }

    private static TemporaryAssembly PatchUserStringHeader(int token, byte replacement)
    {
        var image = File.ReadAllBytes(typeof(UserStringTokenFixture).Assembly.Location);
        using var stream = new MemoryStream(image, writable: false);
        using var reader = new PEReader(stream);
        var metadata = reader.GetMetadataReader();
        var heapOffset = token & 0x00FF_FFFF;
        var fileOffset = reader.PEHeaders.MetadataStartOffset +
                         metadata.GetHeapMetadataOffset(HeapIndex.UserString) +
                         heapOffset;
        Assert.InRange(fileOffset, 0, image.Length - 1);
        Assert.NotEqual(replacement, image[fileOffset]);
        image[fileOffset] = replacement;
        return TemporaryAssembly.Write(image);
    }

    private static int GetMethodCodeOffset(byte[] image, int bodyOffset)
    {
        var format = image[bodyOffset] & 0x03;
        if (format == 0x02)
        {
            return bodyOffset + 1;
        }

        Assert.Equal(0x03, format);
        var flagsAndSize = BinaryPrimitives.ReadUInt16LittleEndian(
            image.AsSpan(bodyOffset, 2));
        var headerSize = (flagsAndSize >> 12) * 4;
        Assert.InRange(headerSize, 12, 60);
        return bodyOffset + headerSize;
    }

    private static int RvaToFileOffset(PEHeaders headers, int rva)
    {
        foreach (var section in headers.SectionHeaders)
        {
            var size = Math.Max(section.VirtualSize, section.SizeOfRawData);
            if (rva >= section.VirtualAddress &&
                rva - section.VirtualAddress < size)
            {
                return section.PointerToRawData + (rva - section.VirtualAddress);
            }
        }

        throw new InvalidOperationException($"RVA 0x{rva:X8} is outside all PE sections.");
    }

    private static MethodDefinitionHandle MethodHandle(MethodBase method) =>
        MetadataTokens.MethodDefinitionHandle(method.MetadataToken & 0x00FF_FFFF);

    private static AssemblyFixture OpenAssembly(string? path = null)
    {
        var stream = File.OpenRead(path ?? typeof(UserStringTokenFixture).Assembly.Location);
        var reader = new PEReader(stream);
        return new AssemblyFixture(stream, reader, reader.GetMetadataReader());
    }

    private static int UserStringToken(int offset) => 0x7000_0000 | offset;

    private static RawHeap BuildHeap(params string[] values)
    {
        var bytes = new List<byte> { 0x00 };
        var offsets = new List<int>();
        foreach (var value in values)
        {
            offsets.Add(bytes.Count);
            var payloadLength = checked((value.Length * 2) + 1);
            WriteCompressedUnsigned(bytes, payloadLength);
            foreach (var character in value)
            {
                bytes.Add((byte)character);
                bytes.Add((byte)(character >> 8));
            }

            bytes.Add(GetTerminalFlag(value));
        }

        while ((bytes.Count & 3) != 0)
        {
            bytes.Add(0x00);
        }

        return new RawHeap([.. bytes], [.. offsets]);
    }

    private static void WriteCompressedUnsigned(List<byte> bytes, int value)
    {
        if (value <= 0x7F)
        {
            bytes.Add((byte)value);
            return;
        }

        if (value <= 0x3FFF)
        {
            bytes.Add((byte)(0x80 | (value >> 8)));
            bytes.Add((byte)value);
            return;
        }

        Assert.InRange(value, 0x4000, 0x1FFF_FFFF);
        bytes.Add((byte)(0xC0 | (value >> 24)));
        bytes.Add((byte)(value >> 16));
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }

    private static byte GetTerminalFlag(string value)
    {
        foreach (var character in value)
        {
            if (character >= 0x7F ||
                character is >= '\u0001' and <= '\u0008' or
                    >= '\u000E' and <= '\u001F' or '\u0027' or '\u002D')
            {
                return 1;
            }
        }

        return 0;
    }

    private sealed record RawHeap(byte[] Bytes, int[] Offsets);

    private sealed class AssemblyFixture(
        FileStream stream,
        PEReader reader,
        MetadataReader metadata) : IDisposable
    {
        public PEReader Reader { get; } = reader;

        public MetadataReader Metadata { get; } = metadata;

        public void Dispose()
        {
            Reader.Dispose();
            stream.Dispose();
        }
    }

    private sealed class TemporaryAssembly(string path) : IDisposable
    {
        public string Path { get; } = path;

        public static TemporaryAssembly Write(byte[] image)
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"exe-blueprint-user-string-{Guid.NewGuid():N}.dll");
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

internal static class UserStringTokenFixture
{
    public const string EscapedValue =
        "US_ESCAPED_A9\\\"\0\a\b\f\v\r\n\t\u0085\u2028\u2029\uD800X\uDC00";

    public const string MalformedValue = "US_MALFORMED_6F32A9";

    public static void Touch()
    {
    }

    public static string ReturnEscaped()
    {
        Touch();
        return EscapedValue;
    }

    public static string ReturnMalformed()
    {
        Touch();
        return MalformedValue;
    }

    public static string ReturnEmpty() => "";
}

internal class UserStringConstructorBaseFixture
{
    protected UserStringConstructorBaseFixture(string value)
    {
        _ = value;
    }
}

internal sealed class UserStringConstructorDerivedFixture : UserStringConstructorBaseFixture
{
    private const string ConstructorValue = "US_CTOR_MALFORMED_4D117B";

    public UserStringConstructorDerivedFixture()
        : base(ConstructorValue)
    {
    }
}
