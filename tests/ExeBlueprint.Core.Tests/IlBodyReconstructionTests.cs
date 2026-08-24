using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using ExeBlueprint.Analysis;

namespace ExeBlueprint.Core.Tests;

// 用手工組出的 IL bytes 驗證控制流程還原，不依賴自我組件剛好有對應形狀。
// 這些 IL 只用區域變數、參數、算式與分支，不碰任何 metadata token。
public sealed class IlBodyReconstructionTests
{
    [Fact]
    public void ReconstructsWhileLoop()
    {
        // static int M(int n) { int i = 0; while (i < n) { i = i + 1; } return i; }
        byte[] il =
        [
            0x16,             // ldc.i4.0
            0x0A,             // stloc.0
            0x2B, 0x04,       // br.s COND (+4 -> IL_0008)
            0x06,             // IL_0004 BODY: ldloc.0
            0x17,             // ldc.i4.1
            0x58,             // add
            0x0A,             // stloc.0
            0x06,             // IL_0008 COND: ldloc.0
            0x02,             // ldarg.0
            0x32, 0xF8,       // blt.s BODY (-8 -> IL_0004)
            0x06,             // ldloc.0
            0x2A              // ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            ["var v0 = 0;", "while (v0 < arg0)", "{", "    v0 = (v0 + 1);", "}", "return v0;"],
            body);
    }

    [Fact]
    public void ReconstructsDoWhileLoop()
    {
        // static int M(int n) { int i = 0; do { i = i + 1; } while (i < n); return i; }
        byte[] il =
        [
            0x16,       // ldc.i4.0
            0x0A,       // stloc.0
            0x06,       // IL_0002 BODY: ldloc.0
            0x17,       // ldc.i4.1
            0x58,       // add
            0x0A,       // stloc.0
            0x06,       // ldloc.0
            0x02,       // ldarg.0
            0x32, 0xF8, // blt.s BODY (-8 -> IL_0002)
            0x06,       // ldloc.0
            0x2A        // ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            ["var v0 = 0;", "do", "{", "    v0 = (v0 + 1);", "} while (v0 < arg0);", "return v0;"],
            body);
    }

    [Fact]
    public void IgnoresBranchToImmediatelyFollowingInstruction()
    {
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x0A,       // IL_0001 stloc.0
            0x2B, 0x00, // IL_0002 br.s IL_0004
            0x06,       // IL_0004 ldloc.0
            0x2A        // IL_0005 ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.Equal(["var v0 = arg0;", "return v0;"], body);
    }

    [Fact]
    public void ReconstructsIf()
    {
        // static int M(int n) { if (n == 5) { return 1; } return 2; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x1B,       // IL_0001 ldc.i4.5
            0x33, 0x02, // IL_0002 bne.un.s IL_0006 (+2)
            0x17,       // IL_0004 ldc.i4.1
            0x2A,       // IL_0005 ret
            0x18,       // IL_0006 ldc.i4.2
            0x2A        // IL_0007 ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            ["if (arg0 == 5)", "{", "    return 1;", "}", "return 2;"],
            body);
    }

    [Fact]
    public void ReconstructsTypedTruthinessConditions()
    {
        // static bool M(T value) { if (value) return true; return false; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x2C, 0x02, // IL_0001 brfalse.s IL_0005
            0x17,       // IL_0003 ldc.i4.1
            0x2A,       // IL_0004 ret
            0x16,       // IL_0005 ldc.i4.0
            0x2A        // IL_0006 ret
        ];

        var booleanBody = Reconstruct(
            il,
            isInstance: false,
            returnType: "bool",
            parameterTypes: ["bool"]);
        Assert.Equal(["if (arg0)", "{", "    return true;", "}", "return false;"], booleanBody);

        var integerBody = Reconstruct(
            il,
            isInstance: false,
            returnType: "bool",
            parameterTypes: ["int"]);
        Assert.Equal(
            [
                "if (!(System.Collections.Generic.EqualityComparer<int>.Default.Equals(arg0, default)))",
                "{",
                "    return true;",
                "}",
                "return false;"
            ],
            integerBody);
    }

    [Fact]
    public void ReconstructsTerminalSwitchCases()
    {
        // static int M(int n) => n switch { 0 => 10, 1 => 20, 2 => 30, _ => 99 };
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x03, 0x00, 0x00, 0x00, // IL_0001 switch (3 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x05, 0x00, 0x00, 0x00,       // case 1 -> IL_0017
            0x08, 0x00, 0x00, 0x00,       // case 2 -> IL_001A
            0x2B, 0x09,                   // IL_0012 br.s default (IL_001D)
            0x1F, 0x0A, 0x2A,             // IL_0014 ldc.i4.s 10; ret
            0x1F, 0x14, 0x2A,             // IL_0017 ldc.i4.s 20; ret
            0x1F, 0x1E, 0x2A,             // IL_001A ldc.i4.s 30; ret
            0x1F, 0x63, 0x2A              // IL_001D ldc.i4.s 99; ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            [
                "switch (arg0)",
                "{",
                "    case 0:",
                "        return 10;",
                "    case 1:",
                "        return 20;",
                "    case 2:",
                "        return 30;",
                "    default:",
                "        return 99;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsEnumMaskAndSwitchCases()
    {
        // static int M(FieldAttributes value) => (value & (FieldAttributes)7) - 1 switch { 0 => 10, 1 => 20, _ => 99 };
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x1D,                         // IL_0001 ldc.i4.7
            0x5F,                         // IL_0002 and
            0x17,                         // IL_0003 ldc.i4.1
            0x59,                         // IL_0004 sub
            0x45, 0x02, 0x00, 0x00, 0x00, // IL_0005 switch (2 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x05, 0x00, 0x00, 0x00,       // case 1 -> IL_0017
            0x2B, 0x06,                   // IL_0012 br.s default (IL_001A)
            0x1F, 0x0A, 0x2A,             // IL_0014 ldc.i4.s 10; ret
            0x1F, 0x14, 0x2A,             // IL_0017 ldc.i4.s 20; ret
            0x1F, 0x63, 0x2A              // IL_001A ldc.i4.s 99; ret
        ];

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            parameterTypes: ["System.Reflection.FieldAttributes"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "switch (((arg0 & unchecked((System.Reflection.FieldAttributes)7)) - 1))",
                "{",
                "    case unchecked((System.Reflection.FieldAttributes)0):",
                "        return 10;",
                "    case unchecked((System.Reflection.FieldAttributes)1):",
                "        return 20;",
                "    default:",
                "        return 99;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsGroupedCasesAndFallThroughDefault()
    {
        // case 0 與 case 1 共用同一個 target；default 直接接在 switch 後面，沒有額外 br。
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x02, 0x00, 0x00, 0x00, // IL_0001 switch (2 targets)
            0x03, 0x00, 0x00, 0x00,       // case 0 -> IL_0011
            0x03, 0x00, 0x00, 0x00,       // case 1 -> IL_0011
            0x1F, 0x63, 0x2A,             // IL_000E default: ldc.i4.s 99; ret
            0x1F, 0x0A, 0x2A              // IL_0011 cases: ldc.i4.s 10; ret
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int");

        Assert.NotNull(body);
        Assert.Equal(
            [
                "switch (arg0)",
                "{",
                "    default:",
                "        return 99;",
                "    case 0:",
                "    case 1:",
                "        return 10;",
                "}"
            ],
            body);
    }

    [Fact]
    public void ReconstructsSwitchWithSharedJoin()
    {
        // 每個 case 指派 result 後跳到共同 return；default 直接落到 join。
        byte[] il =
        [
            0x02,                         // IL_0000 ldarg.0
            0x45, 0x03, 0x00, 0x00, 0x00, // IL_0001 switch (3 targets)
            0x02, 0x00, 0x00, 0x00,       // case 0 -> IL_0014
            0x07, 0x00, 0x00, 0x00,       // case 1 -> IL_0019
            0x0C, 0x00, 0x00, 0x00,       // case 2 -> IL_001E
            0x2B, 0x0F,                   // IL_0012 br.s default (IL_0023)
            0x1F, 0x0A, 0x0A, 0x2B, 0x0D, // IL_0014 result = 10; br.s join
            0x1F, 0x14, 0x0A, 0x2B, 0x08, // IL_0019 result = 20; br.s join
            0x1F, 0x1E, 0x0A, 0x2B, 0x03, // IL_001E result = 30; br.s join
            0x1F, 0x63, 0x0A,             // IL_0023 default: result = 99
            0x06, 0x2A                    // IL_0026 join: return result
        ];

        var body = Reconstruct(il, isInstance: false, returnType: "int", localTypes: ["int"]);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "switch (arg0)",
                "{",
                "    case 0:",
                "        v0 = 10;",
                "        break;",
                "    case 1:",
                "        v0 = 20;",
                "        break;",
                "    case 2:",
                "        v0 = 30;",
                "        break;",
                "    default:",
                "        v0 = 99;",
                "        break;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsTryFinallyFromExceptionRegion()
    {
        // static int M(int n) { try { result = n + 1; } finally { result += 10; } return result; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x06, // IL_0004 leave.s IL_000C
            0x06,       // IL_0006 ldloc.0
            0x1F, 0x0A, // IL_0007 ldc.i4.s 10
            0x58,       // IL_0009 add
            0x0A,       // IL_000A stloc.0
            0xDC,       // IL_000B endfinally
            0x06,       // IL_000C ldloc.0
            0x2A        // IL_000D ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Finally,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "finally",
                "{",
                "    v0 = (v0 + 10);",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsFaultAsCatchAndRethrow()
    {
        // CLR fault 只在例外路徑執行；C# 沒有 fault，等價輸出為 catch { cleanup; throw; }。
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x06, // IL_0004 leave.s IL_000C
            0x06,       // IL_0006 ldloc.0
            0x1F, 0x0A, // IL_0007 ldc.i4.s 10
            0x58,       // IL_0009 add
            0x0A,       // IL_000A stloc.0
            0xDC,       // IL_000B endfinally
            0x06,       // IL_000C ldloc.0
            0x2A        // IL_000D ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "catch",
                "{",
                "    v0 = (v0 + 10);",
                "    throw;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsTerminalTryWithFault()
    {
        byte[] il =
        [
            0x14,       // IL_0000 ldnull
            0x7A,       // IL_0001 throw
            0x02,       // IL_0002 ldarg.0
            0x17,       // IL_0003 ldc.i4.1
            0x58,       // IL_0004 add
            0x10, 0x00, // IL_0005 starg.s 0
            0xDC        // IL_0007 endfinally
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 2,
                HandlerOffset: 2,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "try",
                "{",
                "    throw null;",
                "}",
                "catch",
                "{",
                "    arg0 = (arg0 + 1);",
                "    throw;",
                "}"
            ],
            body);
    }

    [Fact]
    public void BailsOnFaultWithoutEndFinally()
    {
        byte[] il =
        [
            0x00,       // IL_0000 nop
            0xDE, 0x01, // IL_0001 leave.s IL_0004
            0x2A,       // IL_0003 ret（fault handler 不可用 ret 收尾）
            0x2A        // IL_0004 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Fault,
                TryOffset: 0,
                TryLength: 3,
                HandlerOffset: 3,
                HandlerLength: 1)
        };

        Assert.Null(Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions));
    }

    [Fact]
    public void ReconstructsCatchFromExceptionRegion()
    {
        // static int M(int n) { try { return n + 1; } catch (InvalidOperationException) { return -1; } }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x05, // IL_0004 leave.s IL_000B
            0x26,       // IL_0006 pop
            0x15,       // IL_0007 ldc.i4.m1
            0x0A,       // IL_0008 stloc.0
            0xDE, 0x00, // IL_0009 leave.s IL_000B
            0x06,       // IL_000B ldloc.0
            0x2A        // IL_000C ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Catch,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 5,
                CatchType: "System.InvalidOperationException")
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    v0 = (arg0 + 1);",
                "}",
                "catch (System.InvalidOperationException)",
                "{",
                "    v0 = -1;",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void ReconstructsCombinedCatchAndFinallyFromNestedExceptionRegions()
    {
        // static int M(int n) { try { result = n + 1; } catch (Exception) { result = -1; }
        // finally { result += 10; } return result; }
        byte[] il =
        [
            0x02,       // IL_0000 ldarg.0
            0x17,       // IL_0001 ldc.i4.1
            0x58,       // IL_0002 add
            0x0A,       // IL_0003 stloc.0
            0xDE, 0x05, // IL_0004 leave.s IL_000B
            0x26,       // IL_0006 pop
            0x15,       // IL_0007 ldc.i4.m1
            0x0A,       // IL_0008 stloc.0
            0xDE, 0x00, // IL_0009 leave.s IL_000B
            0xDE, 0x06, // IL_000B leave.s IL_0013
            0x06,       // IL_000D ldloc.0
            0x1F, 0x0A, // IL_000E ldc.i4.s 10
            0x58,       // IL_0010 add
            0x0A,       // IL_0011 stloc.0
            0xDC,       // IL_0012 endfinally
            0x06,       // IL_0013 ldloc.0
            0x2A        // IL_0014 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Catch,
                TryOffset: 0,
                TryLength: 6,
                HandlerOffset: 6,
                HandlerLength: 5,
                CatchType: "System.Exception"),
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Finally,
                TryOffset: 0,
                TryLength: 13,
                HandlerOffset: 13,
                HandlerLength: 6)
        };

        var body = Reconstruct(
            il,
            isInstance: false,
            returnType: "int",
            localTypes: ["int"],
            exceptionRegions: regions);

        Assert.NotNull(body);
        Assert.Equal(
            [
                "int v0 = default;",
                "try",
                "{",
                "    try",
                "    {",
                "        v0 = (arg0 + 1);",
                "    }",
                "    catch (System.Exception)",
                "    {",
                "        v0 = -1;",
                "    }",
                "}",
                "finally",
                "{",
                "    v0 = (v0 + 10);",
                "}",
                "return v0;"
            ],
            body);
    }

    [Fact]
    public void BailsOnMalformedFilterRegion()
    {
        byte[] il =
        [
            0x00,       // IL_0000 nop
            0xDE, 0x03, // IL_0001 leave.s IL_0006
            0x26,       // IL_0003 pop
            0xDE, 0x00, // IL_0004 leave.s IL_0006
            0x2A        // IL_0006 ret
        ];
        var regions = new[]
        {
            new ManagedSymbolReader.ExceptionRegionInfo(
                ExceptionRegionKind.Filter,
                TryOffset: 0,
                TryLength: 3,
                HandlerOffset: 3,
                HandlerLength: 3,
                FilterOffset: 3)
        };

        Assert.Null(Reconstruct(
            il,
            isInstance: false,
            returnType: "void",
            exceptionRegions: regions));
    }

    [Fact]
    public void BailsOnBackwardInfiniteLoop()
    {
        // BODY: nop; br.s BODY  -> while(true), 目前不支援，應放棄。
        byte[] il =
        [
            0x00,             // IL_0000 nop
            0x2B, 0xFD        // br.s -3 -> IL_0000
        ];

        Assert.Null(Reconstruct(il, isInstance: false, returnType: "void"));
    }

    private static IReadOnlyList<string>? Reconstruct(
        byte[] il,
        bool isInstance,
        string returnType,
        IReadOnlyList<string>? localTypes = null,
        IReadOnlyList<ManagedSymbolReader.ExceptionRegionInfo>? exceptionRegions = null,
        IReadOnlyList<string>? parameterTypes = null)
    {
        // 隨便挑一個現成組件當 MetadataReader；這些 IL 不含 token，不會真的用到它。
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        using var peReader = new PEReader(File.OpenRead(assemblyPath));
        var metadata = peReader.GetMetadataReader();
        return ManagedSymbolReader.ReconstructBodyForTest(
            metadata,
            il,
            isInstance,
            returnType,
            localTypes,
            exceptionRegions,
            parameterTypes);
    }
}

internal static class SwitchFixture
{
    public static int TerminalCases(int value)
    {
        switch (value)
        {
            case 0:
                return 10;
            case 1:
                return 20;
            case 2:
                return 30;
            default:
                return 99;
        }
    }

    public static int JoinedCases(int value)
    {
        int result;
        switch (value)
        {
            case 0:
                result = 10;
                break;
            case 1:
                result = 20;
                break;
            case 2:
                result = 30;
                break;
            default:
                result = 99;
                break;
        }

        return result;
    }
}
