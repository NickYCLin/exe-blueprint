using System.Buffers.Binary;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

public sealed class ConstructorInitializerSafetyTests
{
    [Fact]
    public void ValidatesLongConstructorChainsWithoutRecursionAndRejectsBrokenGraphs()
    {
        const int chainLength = 25_000;
        var longChain = Enumerable.Range(1, chainLength).ToDictionary(
            row => row,
            row => row == chainLength ? (int?)null : row + 1);

        var valid = ManagedSymbolReader.ValidateConstructorChainsForTest(longChain);

        Assert.Equal(chainLength, valid.Count);
        Assert.True(valid[1]);
        Assert.True(valid[chainLength / 2]);
        Assert.True(valid[chainLength]);

        var cycle = ManagedSymbolReader.ValidateConstructorChainsForTest(
            new Dictionary<int, int?>
            {
                [1] = 2,
                [2] = 3,
                [3] = 1
            });
        Assert.All(cycle.Values, Assert.False);

        var missingTarget = ManagedSymbolReader.ValidateConstructorChainsForTest(
            new Dictionary<int, int?>
            {
                [1] = 2
            });
        Assert.False(missingTarget[1]);
    }

    [Fact]
    public void AcceptsOnlyCanonicalDirectBaseConstructorPrologues()
    {
        using var fixture = OpenFixture();
        var valid = BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A]);

        var result = ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            valid,
            fixture.CurrentConstructor);

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Equal(
            ["unchecked((ExeBlueprint.Core.Tests.ConstructorModeFixture)1)", "true"],
            result.Initializer.Arguments);
        Assert.NotNull(result.Body);
        Assert.Empty(result.Body);

        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x03, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x6F,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02],
            0x28,
            fixture.UnrelatedConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x03],
            0x28,
            fixture.CurrentConstructorToken,
            [0x2A])));
    }

    [Fact]
    public void RejectsUnsafeConstructorArgumentsAndControlFlow()
    {
        using var fixture = OpenFixture();

        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x18],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x02, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x2B, 0x00],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A])));
        Assert.Null(Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [])));

        var branchIntoPrefix = BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2B, 0xF6, 0x2A]);
        Assert.Null(Reconstruct(fixture, branchIntoPrefix));

        var branchPastMethodEnd = BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2B, 0x0A, 0x2A]);
        Assert.Null(Reconstruct(fixture, branchPastMethodEnd));

        var branchIntoOperand = BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2B, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x26, 0x2A]);
        Assert.Null(Reconstruct(fixture, branchIntoOperand));

        var protectedPrefix = BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x2A]);
        Assert.Null(ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            protectedPrefix,
            fixture.CurrentConstructor,
            [
                new ManagedSymbolReader.ExceptionRegionInfo(
                    ExceptionRegionKind.Finally,
                    TryOffset: 0,
                    TryLength: 8,
                    HandlerOffset: 8,
                    HandlerLength: 1)
            ]));

        Assert.Null(ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            protectedPrefix,
            fixture.CurrentConstructor,
            [
                new ManagedSymbolReader.ExceptionRegionInfo(
                    ExceptionRegionKind.Finally,
                    TryOffset: 8,
                    TryLength: 2,
                    HandlerOffset: 8,
                    HandlerLength: 1)
            ]));

        Assert.Null(ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            protectedPrefix,
            fixture.CurrentConstructor,
            [
                new ManagedSymbolReader.ExceptionRegionInfo(
                    ExceptionRegionKind.Finally,
                    TryOffset: 8,
                    TryLength: 1,
                    HandlerOffset: 8,
                    HandlerLength: 2)
            ]));
    }

    [Fact]
    public void KeepsVerifiedInitializerWhenTailIsOutsideCanonicalAssignmentSubset()
    {
        using var fixture = OpenFixture();
        var result = Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            [0x03, 0x17, 0xFE, 0x01, 0x26, 0x2A]));

        Assert.NotNull(result);
        Assert.Equal("base", result.Initializer.Kind);
        Assert.Null(result.Body);
    }

    [Fact]
    public void ReconstructsOnlyCurrentInstanceFieldDefinitionConstructorTails()
    {
        using var fixture = OpenFieldFixture();

        var valid = Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            BuildFieldStoreTail(0x03, fixture.CurrentInstanceFieldToken)));
        Assert.NotNull(valid);
        Assert.Equal(["this._value = value;"], valid.Body);

        AssertInitializerOnly(fixture, fixture.CurrentStaticFieldToken);
        AssertInitializerOnly(fixture, fixture.UnrelatedInstanceFieldToken);
        AssertInitializerOnly(fixture, fixture.FieldMemberReferenceToken);

        var invalidUserString = Reconstruct(fixture, BuildConstructorIl(
            [0x02, 0x17, 0x17],
            0x28,
            fixture.BaseConstructorToken,
            BuildInvalidUserStringFieldStoreTail(
                fixture.CurrentInstanceFieldToken,
                unchecked((int)0x70FF_FFFF))));
        Assert.NotNull(invalidUserString);
        Assert.Equal("base", invalidUserString.Initializer.Kind);
        Assert.Null(invalidUserString.Body);

        void AssertInitializerOnly(ConstructorFixtureMetadata metadata, int fieldToken)
        {
            var result = Reconstruct(metadata, BuildConstructorIl(
                [0x02, 0x17, 0x17],
                0x28,
                metadata.BaseConstructorToken,
                BuildFieldStoreTail(0x03, fieldToken)));

            Assert.NotNull(result);
            Assert.Equal("base", result.Initializer.Kind);
            Assert.Null(result.Body);
        }
    }

    private static ManagedSymbolReader.ConstructorReconstructionTestResult? Reconstruct(
        ConstructorFixtureMetadata fixture,
        byte[] il) =>
        ManagedSymbolReader.ReconstructConstructorForTest(
            fixture.Metadata,
            il,
            fixture.CurrentConstructor);

    private static byte[] BuildConstructorIl(
        byte[] prefix,
        byte callOpcode,
        int constructorToken,
        byte[] tail)
    {
        var il = new byte[prefix.Length + 5 + tail.Length];
        prefix.CopyTo(il, 0);
        il[prefix.Length] = callOpcode;
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(prefix.Length + 1, 4), constructorToken);
        tail.CopyTo(il, prefix.Length + 5);
        return il;
    }

    private static byte[] BuildFieldStoreTail(byte valueOpcode, int fieldToken)
    {
        var tail = new byte[8];
        tail[0] = 0x02;
        tail[1] = valueOpcode;
        tail[2] = 0x7D;
        BinaryPrimitives.WriteInt32LittleEndian(tail.AsSpan(3, 4), fieldToken);
        tail[7] = 0x2A;
        return tail;
    }

    private static byte[] BuildInvalidUserStringFieldStoreTail(int fieldToken, int userStringToken)
    {
        var tail = new byte[12];
        tail[0] = 0x02;
        tail[1] = 0x72;
        BinaryPrimitives.WriteInt32LittleEndian(tail.AsSpan(2, 4), userStringToken);
        tail[6] = 0x7D;
        BinaryPrimitives.WriteInt32LittleEndian(tail.AsSpan(7, 4), fieldToken);
        tail[11] = 0x2A;
        return tail;
    }

    private static ConstructorFixtureMetadata OpenFixture()
    {
        var assemblyPath = typeof(ConstructorDerivedFixture).Assembly.Location;
        var stream = File.OpenRead(assemblyPath);
        var peReader = new PEReader(stream);
        var current = typeof(ConstructorDerivedFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            [typeof(int)],
            modifiers: null)!;
        var baseConstructor = typeof(ConstructorBaseFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(ConstructorModeFixture), typeof(bool)],
            modifiers: null)!;
        var unrelated = typeof(StackCoercionClass).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            Type.EmptyTypes,
            modifiers: null)!;
        return new ConstructorFixtureMetadata(
            stream,
            peReader,
            peReader.GetMetadataReader(),
            (MethodDefinitionHandle)MetadataTokens.EntityHandle(current.MetadataToken),
            current.MetadataToken,
            baseConstructor.MetadataToken,
            unrelated.MetadataToken,
            0,
            0,
            0,
            0);
    }

    private static ConstructorFixtureMetadata OpenFieldFixture()
    {
        var assemblyPath = typeof(ConstructorFieldSafetyFixture).Assembly.Location;
        var stream = File.OpenRead(assemblyPath);
        var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();
        var current = typeof(ConstructorFieldSafetyFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            [typeof(int)],
            modifiers: null)!;
        var baseConstructor = typeof(ConstructorBaseFixture).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic,
            binder: null,
            [typeof(ConstructorModeFixture), typeof(bool)],
            modifiers: null)!;
        var unrelated = typeof(StackCoercionClass).GetConstructor(
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            Type.EmptyTypes,
            modifiers: null)!;
        var currentInstanceField = typeof(ConstructorFieldSafetyFixture).GetField(
            "_value",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var currentStaticField = typeof(ConstructorFieldSafetyFixture).GetField(
            "s_staticValue",
            BindingFlags.Static | BindingFlags.NonPublic)!;
        var unrelatedInstanceField = typeof(ConstructorDerivedFixture).GetField(
            "_value",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        var fieldMemberReference = Enumerable.Range(
                1,
                metadata.GetTableRowCount(TableIndex.MemberRef))
            .Select(MetadataTokens.MemberReferenceHandle)
            .First(handle => metadata.GetMemberReference(handle).GetKind() == MemberReferenceKind.Field);
        return new ConstructorFixtureMetadata(
            stream,
            peReader,
            metadata,
            (MethodDefinitionHandle)MetadataTokens.EntityHandle(current.MetadataToken),
            current.MetadataToken,
            baseConstructor.MetadataToken,
            unrelated.MetadataToken,
            currentInstanceField.MetadataToken,
            currentStaticField.MetadataToken,
            unrelatedInstanceField.MetadataToken,
            MetadataTokens.GetToken(fieldMemberReference));
    }

    private sealed class ConstructorFixtureMetadata(
        Stream stream,
        PEReader peReader,
        MetadataReader metadata,
        MethodDefinitionHandle currentConstructor,
        int currentConstructorToken,
        int baseConstructorToken,
        int unrelatedConstructorToken,
        int currentInstanceFieldToken,
        int currentStaticFieldToken,
        int unrelatedInstanceFieldToken,
        int fieldMemberReferenceToken) : IDisposable
    {
        public MetadataReader Metadata { get; } = metadata;

        public MethodDefinitionHandle CurrentConstructor { get; } = currentConstructor;

        public int CurrentConstructorToken { get; } = currentConstructorToken;

        public int BaseConstructorToken { get; } = baseConstructorToken;

        public int UnrelatedConstructorToken { get; } = unrelatedConstructorToken;

        public int CurrentInstanceFieldToken { get; } = currentInstanceFieldToken;

        public int CurrentStaticFieldToken { get; } = currentStaticFieldToken;

        public int UnrelatedInstanceFieldToken { get; } = unrelatedInstanceFieldToken;

        public int FieldMemberReferenceToken { get; } = fieldMemberReferenceToken;

        public void Dispose()
        {
            peReader.Dispose();
            stream.Dispose();
        }
    }
}

internal sealed class ConstructorFieldSafetyFixture : ConstructorBaseFixture
{
    private readonly int _value;
    private static int s_staticValue;

    public ConstructorFieldSafetyFixture(int value)
        : base(ConstructorModeFixture.Enabled, true)
    {
        _value = value;
    }

    internal int ReadValue() => _value;

    internal static int ReadStaticValue() => s_staticValue;

    internal static void WriteStaticValue(int value) => s_staticValue = value;
}
