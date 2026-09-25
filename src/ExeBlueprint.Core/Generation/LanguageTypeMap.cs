namespace ExeBlueprint.Generation;

// 把 .NET 型別名稱粗略對應到各目標語言。只處理常見基本型別與陣列，
// 其餘取簡單名稱原樣帶過（骨架用途，不保證型別完全正確）。
internal static class LanguageTypeMap
{
    public static string ToRust(string csharpType) => Map(
        csharpType,
        new Language(
            RustPrimitives,
            VoidType: "()",
            ArrayOf: element => $"Vec<{element}>",
            PointerTo: pointee => pointee == "()" ? "*mut std::ffi::c_void" : $"*mut {pointee}",
            FunctionPointer: "*const ()"));

    public static string ToGo(string csharpType) => Map(
        csharpType,
        new Language(
            GoPrimitives,
            VoidType: "any",
            ArrayOf: element => $"[]{element}",
            PointerTo: pointee => pointee == "any" ? "unsafe.Pointer" : $"*{pointee}",
            FunctionPointer: "unsafe.Pointer"));

    public static string ToCpp(string csharpType) => Map(
        csharpType,
        new Language(
            CppPrimitives,
            VoidType: "void",
            ArrayOf: element => $"std::vector<{element}>",
            PointerTo: pointee => $"{pointee}*",
            FunctionPointer: "void*"));

    private sealed record Language(
        IReadOnlyDictionary<string, string> Primitives,
        string VoidType,
        Func<string, string> ArrayOf,
        Func<string, string> PointerTo,
        string FunctionPointer);

    private static readonly string[] ByReferencePrefixes = ["ref readonly ", "ref ", "out ", "in "];

    private static string Map(string csharpType, Language language)
    {
        var type = csharpType.Trim();

        // 可為 null 註記（string?）與 ref／in／out 修飾對目標語言的型別對應沒有意義，先剝掉；
        // 先前 string? 會原樣落地，ref int 也直接輸出成不存在的語法。
        if (type.EndsWith('?'))
        {
            type = type[..^1].TrimEnd();
        }

        foreach (var prefix in ByReferencePrefixes)
        {
            if (type.StartsWith(prefix, StringComparison.Ordinal))
            {
                type = type[prefix.Length..].TrimStart();
                break;
            }
        }

        // delegate* unmanaged[...]<...> 這類函式指標無法逐字對應，統一用不透明指標表示，
        // 不再輸出被切斷的片段。
        if (type.StartsWith("delegate*", StringComparison.Ordinal))
        {
            return language.FunctionPointer;
        }

        // 指標要保留指標性：先前 SimpleName 會把結尾的 * 剪掉，byte* 在 C++ 變成不存在的 byte，
        // int* 也悄悄失去指標。
        if (type.EndsWith('*'))
        {
            return language.PointerTo(Map(type[..^1].TrimEnd(), language));
        }

        // int[] 與多維的 int[,]、int[,,]：多維以巢狀陣列近似，先前 [,] 會被切成 int[,。
        if (type.EndsWith(']'))
        {
            var open = type.LastIndexOf('[');
            if (open > 0 && type[(open + 1)..^1].All(character => character == ','))
            {
                var mapped = Map(type[..open], language);
                var rank = type.Length - open - 1;
                for (var dimension = 0; dimension < rank; dimension++)
                {
                    mapped = language.ArrayOf(mapped);
                }

                return mapped;
            }
        }

        if (type is "void")
        {
            return language.VoidType;
        }

        if (language.Primitives.TryGetValue(type, out var primitive))
        {
            return primitive;
        }

        // 先去掉所有平衡的 <...> 泛型引數再取最後一段，讓 Ns.Outer<int>.Inner 得到 Inner，
        // 而不是被切在第一個 < 變成錯的 Outer。
        return SkeletonSupport.SimpleName(StripGenericArguments(type));
    }

    private static string StripGenericArguments(string type)
    {
        var builder = new System.Text.StringBuilder(type.Length);
        var depth = 0;
        foreach (var character in type)
        {
            if (character == '<')
            {
                depth++;
            }
            else if (character == '>' && depth > 0)
            {
                depth--;
            }
            else if (depth == 0)
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
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
