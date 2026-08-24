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
