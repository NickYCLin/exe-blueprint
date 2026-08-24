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

    private static IReadOnlyList<string>? Reconstruct(byte[] il, bool isInstance, string returnType)
    {
        // 隨便挑一個現成組件當 MetadataReader；這些 IL 不含 token，不會真的用到它。
        var assemblyPath = typeof(BlueprintAnalyzer).Assembly.Location;
        using var peReader = new PEReader(File.OpenRead(assemblyPath));
        var metadata = peReader.GetMetadataReader();
        return ManagedSymbolReader.ReconstructBodyForTest(metadata, il, isInstance, returnType);
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
}
