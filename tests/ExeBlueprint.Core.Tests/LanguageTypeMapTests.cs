using ExeBlueprint.Generation;

namespace ExeBlueprint.Core.Tests;

// 型別對應是粗略近似，但不能悄悄輸出錯的型別或不存在的語法：可為 null 註記與 ref／out 要剝掉，
// 指標要保留指標性，多維陣列不能被切成殘缺的字串，巢狀泛型的擁有者不能被誤取成外層型別。
public sealed class LanguageTypeMapTests
{
    [Theory]
    [InlineData("string?", "String")]
    [InlineData("string[]?", "Vec<String>")]
    [InlineData("ref int", "i32")]
    [InlineData("out long", "i64")]
    [InlineData("in double", "f64")]
    [InlineData("ref readonly byte", "u8")]
    [InlineData("byte*", "*mut u8")]
    [InlineData("void*", "*mut std::ffi::c_void")]
    [InlineData("int[,]", "Vec<Vec<i32>>")]
    [InlineData("int[,,]", "Vec<Vec<Vec<i32>>>")]
    [InlineData("Ns.Outer<int>.Inner", "Inner")]
    [InlineData("System.Collections.Generic.List<int>", "List")]
    [InlineData("delegate* unmanaged[Cdecl]<int, void>", "*const ()")]
    public void MapsToRustWithoutLosingShape(string csharpType, string expected)
    {
        Assert.Equal(expected, LanguageTypeMap.ToRust(csharpType));
    }

    [Theory]
    [InlineData("string?", "string")]
    [InlineData("int*", "*int32")]
    [InlineData("void*", "unsafe.Pointer")]
    [InlineData("int[,]", "[][]int32")]
    [InlineData("ref int", "int32")]
    [InlineData("delegate* unmanaged[Cdecl]<int, void>", "unsafe.Pointer")]
    public void MapsToGoWithoutLosingShape(string csharpType, string expected)
    {
        Assert.Equal(expected, LanguageTypeMap.ToGo(csharpType));
    }

    [Theory]
    [InlineData("byte*", "uint8_t*")]
    [InlineData("int*", "int32_t*")]
    [InlineData("void*", "void*")]
    [InlineData("ref int", "int32_t")]
    [InlineData("string?", "std::string")]
    [InlineData("int[,]", "std::vector<std::vector<int32_t>>")]
    [InlineData("delegate* unmanaged[Cdecl]<int, void>", "void*")]
    public void MapsToCppWithoutLosingShape(string csharpType, string expected)
    {
        Assert.Equal(expected, LanguageTypeMap.ToCpp(csharpType));
    }
}
