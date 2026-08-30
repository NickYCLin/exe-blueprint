using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;
using ExeBlueprint.Models;

namespace ExeBlueprint.Core.Tests;

public sealed class BaseDispatchReconstructionTests
{
    [Fact]
    public async Task PreservesBaseAndOrdinaryInstanceDispatchFromCompiledIl()
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(
            typeof(BaseDispatchDerivedFixture).Assembly.Location);
        var fixture = Assert.Single(
            document.Files[0].Code!.Types,
            type => type.FullName == "ExeBlueprint.Core.Tests.BaseDispatchDerivedFixture");

        var transform = FindMethod(fixture, nameof(BaseDispatchDerivedFixture.Transform));
        var getter = FindMethod(fixture, "get_Number");
        var setter = FindMethod(fixture, "set_Number");
        var sameTypeCall = FindMethod(fixture, nameof(BaseDispatchDerivedFixture.CallSameType));
        var virtualCall = FindMethod(fixture, nameof(BaseDispatchDerivedFixture.CallVirtual));

        Assert.Multiple(
            () => AssertCallOpcode(transform, "call"),
            () => Assert.Equal(["return base.Transform(value);"], transform.Body),
            () => AssertCallOpcode(getter, "call"),
            () => Assert.Equal(["return base.Number;"], getter.Body),
            () => AssertCallOpcode(setter, "call"),
            () => Assert.Equal(["base.Number = value;"], setter.Body),
            () => AssertCallOpcode(sameTypeCall, "call"),
            () => Assert.Equal(["return this.Increment(value);"], sameTypeCall.Body),
            () => AssertCallOpcode(virtualCall, "callvirt"),
            () => Assert.Equal(["return target.Transform(value);"], virtualCall.Body));
    }

    [Fact]
    public void RejectsDirectCallToGrandparentAcrossIntermediateOverride()
    {
        var currentMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.Transform));
        var grandparentMethod = GetRequiredMethod(
            typeof(BaseDispatchGrandparentFixture),
            nameof(BaseDispatchGrandparentFixture.Transform));

        // Derived 的直接 base 是 BaseDispatchParentFixture；跳過中間 override 呼叫 grandparent
        // 無法用 C# 的 base 語法等價表示，必須 fail closed。
        Assert.Null(Reconstruct(
            currentMethod,
            BuildInstanceCall(
                receiverOpcode: 0x02, // ldarg.0 (this)
                argumentOpcode: 0x03, // ldarg.1 (value)
                callOpcode: 0x28,     // call
                grandparentMethod.MetadataToken)));
    }

    [Fact]
    public void RejectsNonVirtualCallToVirtualMethodOnNonThisReceiver()
    {
        var currentMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.CallVirtual));
        var virtualMethod = GetRequiredMethod(
            typeof(BaseDispatchParentFixture),
            nameof(BaseDispatchParentFixture.Transform));

        // call（非 callvirt）對任意 receiver 會刻意略過 virtual dispatch 與 null check；
        // 輸出 target.Transform(value) 會改變語意，因此不可重建。
        Assert.Null(Reconstruct(
            currentMethod,
            BuildInstanceCall(
                receiverOpcode: 0x03, // ldarg.1 (target)
                argumentOpcode: 0x04, // ldarg.2 (value)
                callOpcode: 0x28,     // call
                virtualMethod.MetadataToken)));
    }

    [Fact]
    public void RejectsDirectCallToNonVirtualMethodOnNonThisReceiver()
    {
        var currentMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.CallVirtual));
        var nonVirtualMethod = GetRequiredMethod(
            typeof(BaseDispatchParentFixture),
            nameof(BaseDispatchParentFixture.NonVirtualIdentity));

        // 即使 target method 不是 virtual，IL call 對任意 receiver 仍不會執行
        // C# instance call 的 null check，不能安全輸出 target.NonVirtualIdentity(value)。
        Assert.Null(Reconstruct(
            currentMethod,
            BuildInstanceCall(
                receiverOpcode: 0x03, // ldarg.1 (target)
                argumentOpcode: 0x04, // ldarg.2 (value)
                callOpcode: 0x28,     // call
                nonVirtualMethod.MetadataToken)));
    }

    [Fact]
    public void RejectsCallvirtOpcodeWithStaticTarget()
    {
        var currentMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.Transform));
        var staticMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.StaticIdentity));

        byte[] il =
        [
            0x03,                   // ldarg.1 (value)
            0x6F, 0, 0, 0, 0,      // callvirt static int StaticIdentity(int)
            0x2A                    // ret
        ];
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(2, sizeof(int)), staticMethod.MetadataToken);

        Assert.Null(Reconstruct(currentMethod, il));
    }

    [Fact]
    public void RejectsDirectCallToOpenGenericBaseMethodDefinition()
    {
        var currentMethod = GetRequiredMethod(
            typeof(BaseDispatchDerivedFixture),
            nameof(BaseDispatchDerivedFixture.Transform));
        var openGenericMethod = GetRequiredMethod(
            typeof(BaseDispatchParentFixture),
            nameof(BaseDispatchParentFixture.GenericIdentity));
        Assert.True(openGenericMethod.IsGenericMethodDefinition);

        // 未經 MethodSpec 實化的 generic MethodDef 含有 !!0，不能把當前 int stack
        // 擅自套入並輸出 base.GenericIdentity(value)。
        Assert.Null(Reconstruct(
            currentMethod,
            BuildInstanceCall(
                receiverOpcode: 0x02, // ldarg.0 (this)
                argumentOpcode: 0x03, // ldarg.1 (value)
                callOpcode: 0x28,     // call
                openGenericMethod.MetadataToken)));
    }

    [Fact]
    public void RejectsDirectCallToAbstractFinalSameTypeMethodDefinition()
    {
        var metadata = new MetadataBuilder();
        metadata.AddModule(
            generation: 0,
            moduleName: metadata.GetOrAddString("AbstractFinalDispatch.dll"),
            mvid: metadata.GetOrAddGuid(new Guid("c05af610-83a5-429a-89f2-c7c7a1e2f87f")),
            encId: default,
            encBaseId: default);
        metadata.AddAssembly(
            metadata.GetOrAddString("AbstractFinalDispatch"),
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
        metadata.AddTypeDefinition(
            TypeAttributes.NotPublic,
            @namespace: default,
            metadata.GetOrAddString("<Module>"),
            baseType: default,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));
        metadata.AddTypeDefinition(
            TypeAttributes.Public,
            metadata.GetOrAddString("Tests"),
            metadata.GetOrAddString("Current"),
            objectType,
            MetadataTokens.FieldDefinitionHandle(1),
            MetadataTokens.MethodDefinitionHandle(1));

        var signature = AddInstanceInt32Signature(metadata);
        var caller = metadata.AddMethodDefinition(
            MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("Caller"),
            signature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));
        var target = metadata.AddMethodDefinition(
            MethodAttributes.Public |
            MethodAttributes.HideBySig |
            MethodAttributes.Abstract |
            MethodAttributes.Virtual |
            MethodAttributes.Final,
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            metadata.GetOrAddString("Target"),
            signature,
            bodyOffset: 0,
            parameterList: MetadataTokens.ParameterHandle(1));

        var metadataImage = new BlobBuilder();
        new MetadataRootBuilder(metadata).Serialize(
            metadataImage,
            methodBodyStreamRva: 0,
            mappedFieldDataStreamRva: 0);
        using var provider = MetadataReaderProvider.FromMetadataImage(metadataImage.ToImmutableArray());
        var il = BuildInstanceCall(
            receiverOpcode: 0x02, // ldarg.0 (this)
            argumentOpcode: 0x03, // ldarg.1 (value)
            callOpcode: 0x28,     // call
            MetadataTokens.GetToken(target));

        Assert.Null(ManagedSymbolReader.ReconstructMethodForTest(
            provider.GetMetadataReader(),
            il,
            caller));
    }

    [Fact]
    public async Task ReconstructsSystemConsoleUnixBaseDispatchWithoutSelfRecursion()
    {
        var document = await new BlueprintAnalyzer().AnalyzeAsync(typeof(Console).Assembly.Location);
        var unixConsoleStream = document.Files[0].Code!.Types.SingleOrDefault(
            type => type.FullName == "System.ConsolePal.UnixConsoleStream");

        // Windows 的 runtime implementation 不一定包含 UnixConsoleStream；有該型別的平台必須驗證。
        if (unixConsoleStream is null)
        {
            return;
        }

        var dispose = FindMethod(unixConsoleStream, "Dispose");
        var flush = FindMethod(unixConsoleStream, "Flush");
        Assert.Multiple(
            () => Assert.Contains("base.Dispose(disposing);", dispose.Body),
            () => Assert.DoesNotContain("this.Dispose(disposing);", dispose.Body),
            () => Assert.Contains("base.Flush();", flush.Body),
            () => Assert.DoesNotContain("this.Flush();", flush.Body));
    }

    private static MethodModel FindMethod(TypeModel fixture, string name)
    {
        var method = Assert.Single(fixture.Methods, candidate => candidate.Name == name);
        Assert.True(method.BodyReconstructed, $"{name} 未成功還原：{string.Join(Environment.NewLine, method.Il)}");
        return method;
    }

    private static void AssertCallOpcode(MethodModel method, string expectedOpcode)
    {
        var call = Assert.Single(
            method.Il,
            instruction => instruction.Contains("call", StringComparison.Ordinal));
        Assert.Contains($": {expectedOpcode} ", call, StringComparison.Ordinal);
    }

    private static IReadOnlyList<string>? Reconstruct(MethodInfo currentMethod, byte[] il)
    {
        using var peReader = new PEReader(File.OpenRead(currentMethod.DeclaringType!.Assembly.Location));
        var metadata = peReader.GetMetadataReader();
        return ManagedSymbolReader.ReconstructMethodForTest(
            metadata,
            il,
            (MethodDefinitionHandle)MetadataTokens.EntityHandle(currentMethod.MetadataToken));
    }

    private static MethodInfo GetRequiredMethod(Type type, string name) =>
        Assert.IsAssignableFrom<MethodInfo>(type.GetMethod(
            name,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static));

    private static byte[] BuildInstanceCall(
        byte receiverOpcode,
        byte argumentOpcode,
        byte callOpcode,
        int targetToken)
    {
        byte[] il =
        [
            receiverOpcode,
            argumentOpcode,
            callOpcode, 0, 0, 0, 0,
            0x2A // ret
        ];
        BinaryPrimitives.WriteInt32LittleEndian(il.AsSpan(3, sizeof(int)), targetToken);
        return il;
    }

    private static BlobHandle AddInstanceInt32Signature(MetadataBuilder metadata)
    {
        var signature = new BlobBuilder();
        signature.WriteByte(0x20); // HASTHIS | DEFAULT
        signature.WriteCompressedInteger(1);
        signature.WriteByte(0x08); // I4 return
        signature.WriteByte(0x08); // I4 parameter
        return metadata.GetOrAddBlob(signature);
    }
}

internal class BaseDispatchGrandparentFixture
{
    public virtual int Transform(int value) => value;
}

internal class BaseDispatchParentFixture : BaseDispatchGrandparentFixture
{
    public virtual int Number { get; set; }

    public override int Transform(int value) => base.Transform(value) + 1;

    public virtual T GenericIdentity<T>(T value) => value;

    public int NonVirtualIdentity(int value) => value;
}

internal sealed class BaseDispatchDerivedFixture : BaseDispatchParentFixture
{
    public override int Number
    {
        get => base.Number;
        set => base.Number = value;
    }

    public override int Transform(int value) => base.Transform(value);

    public int CallSameType(int value) => Increment(value);

    public int CallVirtual(BaseDispatchParentFixture target, int value) => target.Transform(value);

    public static int StaticIdentity(int value) => value;

    private int Increment(int value) => value + 1;
}
