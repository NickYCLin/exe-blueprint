namespace ExeBlueprint.Generation;

// 把 .NET 型別名稱粗略對應到各目標語言。只處理常見基本型別與陣列，
// 其餘取簡單名稱原樣帶過（骨架用途，不保證型別完全正確）。
internal static class LanguageTypeMap
{
    public static string ToRust(string csharpType) => Map(csharpType, RustPrimitives, "()", element => $"Vec<{element}>");

    public static string ToGo(string csharpType) => Map(csharpType, GoPrimitives, "any", element => $"[]{element}");

    public static string ToCpp(string csharpType) => Map(csharpType, CppPrimitives, "void", element => $"std::vector<{element}>");

    private static string Map(
        string csharpType,
        IReadOnlyDictionary<string, string> primitives,
        string voidType,
        Func<string, string> arrayOf)
    {
        var type = csharpType.Trim();
        if (type.EndsWith("[]", StringComparison.Ordinal))
        {
            return arrayOf(Map(type[..^2], primitives, voidType, arrayOf));
        }

        if (type is "void")
        {
            return voidType;
        }

        if (primitives.TryGetValue(type, out var mapped))
        {
            return mapped;
        }

        return SkeletonSupport.SimpleName(type);
    }

    private static readonly IReadOnlyDictionary<string, string> RustPrimitives = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["bool"] = "bool",
        ["byte"] = "u8",
        ["sbyte"] = "i8",
        ["short"] = "i16",
        ["ushort"] = "u16",
        ["int"] = "i32",
        ["uint"] = "u32",
        ["long"] = "i64",
        ["ulong"] = "u64",
        ["float"] = "f32",
        ["double"] = "f64",
        ["char"] = "char",
        ["string"] = "String",
        ["object"] = "Box<dyn std::any::Any>",
        ["nint"] = "isize",
        ["nuint"] = "usize"
    };

    private static readonly IReadOnlyDictionary<string, string> GoPrimitives = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["bool"] = "bool",
        ["byte"] = "byte",
        ["sbyte"] = "int8",
        ["short"] = "int16",
        ["ushort"] = "uint16",
        ["int"] = "int32",
        ["uint"] = "uint32",
        ["long"] = "int64",
        ["ulong"] = "uint64",
        ["float"] = "float32",
        ["double"] = "float64",
        ["char"] = "rune",
        ["string"] = "string",
        ["object"] = "any",
        ["nint"] = "int",
        ["nuint"] = "uint"
    };

    private static readonly IReadOnlyDictionary<string, string> CppPrimitives = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["bool"] = "bool",
        ["byte"] = "uint8_t",
        ["sbyte"] = "int8_t",
        ["short"] = "int16_t",
        ["ushort"] = "uint16_t",
        ["int"] = "int32_t",
        ["uint"] = "uint32_t",
        ["long"] = "int64_t",
        ["ulong"] = "uint64_t",
        ["float"] = "float",
        ["double"] = "double",
        ["char"] = "char16_t",
        ["string"] = "std::string",
        ["object"] = "void*",
        ["nint"] = "intptr_t",
        ["nuint"] = "uintptr_t"
    };
}
