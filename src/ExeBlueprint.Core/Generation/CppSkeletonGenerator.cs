using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 從 CodeModel 產生 C++ 標頭骨架（class／enum class／抽象介面與方法簽章），方法體為擲例外或空。
// 只還原結構，型別對應粗略，僅供轉語言起點，不保證能編譯。
public static class CppSkeletonGenerator
{
    public static IReadOnlyList<GeneratedFile> Generate(BlueprintDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var files = new List<GeneratedFile>();
        var usedStems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (_, assemblyName, types) in SkeletonSupport.Assemblies(document))
        {
            files.Add(new GeneratedFile
            {
                RelativePath = $"{SkeletonSupport.UniqueFileStem(usedStems, SkeletonSupport.SanitizeFileStem(assemblyName, "Reconstructed"))}.hpp",
                Content = BuildFile(types)
            });
        }

        if (files.Count > 0)
        {
            files.Add(new GeneratedFile { RelativePath = "README.md", Content = Readme() });
        }

        return files;
    }

    private static string BuildFile(IReadOnlyList<TypeModel> types)
    {
        var builder = new StringBuilder();
        builder.AppendLine("// 由 ExeBlueprint 從 .NET 中介模型產生的 C++ 骨架，僅還原結構，不保證可編譯。");
        builder.AppendLine("#pragma once");
        builder.AppendLine("#include <cstdint>");
        builder.AppendLine("#include <string>");
        builder.AppendLine("#include <vector>");
        builder.AppendLine("#include <stdexcept>");
        builder.AppendLine();

        // 所有命名空間攤平到同一個檔案，A.Foo 與 B.Foo 會變成兩個 Foo；型別名在檔案內保證唯一。
        var usedTypeNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var type in types.OrderBy(type => type.Name, StringComparer.Ordinal))
        {
            AppendType(builder, type, usedTypeNames);
            builder.AppendLine();
        }

        return builder.ToString();
    }

    private static void AppendType(StringBuilder builder, TypeModel type, HashSet<string> usedTypeNames)
    {
        var name = SkeletonSupport.UniqueName(usedTypeNames, Identifier(SkeletonSupport.SimpleName(type.Name), "Type"));
        if (type.Kind == "enum")
        {
            var underlyingType = LanguageTypeMap.ToCpp(SkeletonSupport.EnumUnderlyingType(type));
            builder.AppendLine($"enum class {name} : {underlyingType} {{");
            builder.AppendLine(string.Join(",\n", SkeletonSupport.EnumMembers(type).Select(member =>
            {
                var assignment = SkeletonSupport.IntegralEnumValue(member.ConstantValue) is { } value ? $" = {value}" : "";
                return $"    {Identifier(member.Name, "Member")}{assignment}";
            })));
            builder.AppendLine("};");
            return;
        }

        var isInterface = type.Kind == "interface";
        builder.AppendLine($"class {name} {{");
        builder.AppendLine("public:");
        if (isInterface)
        {
            builder.AppendLine($"    virtual ~{name}() = default;");
        }

        foreach (var (memberName, memberType) in SkeletonSupport.DataMembers(type))
        {
            builder.AppendLine($"    {LanguageTypeMap.ToCpp(memberType)} {Identifier(memberName, "field")};");
        }

        foreach (var method in SkeletonSupport.EmittableMethods(type))
        {
            builder.AppendLine($"    {Method(method, isInterface)}");
        }

        builder.AppendLine("};");
    }

    private static string Method(MethodModel method, bool isInterface)
    {
        var returns = method.ReturnType == "void" ? "void" : LanguageTypeMap.ToCpp(method.ReturnType);
        // 同名參數是重複宣告；依序加序號。
        var usedParameters = new HashSet<string>(StringComparer.Ordinal);
        var parameters = string.Join(", ", method.Parameters.Select((parameter, index) =>
            $"{LanguageTypeMap.ToCpp(parameter.Type)} {SkeletonSupport.UniqueName(usedParameters, ParameterName(parameter.Name, index))}"));
        var prefix = method.IsStatic ? "static " : "";
        var header = $"{prefix}{returns} {Identifier(method.Name, "method")}({parameters})";

        // 介面的靜態成員不能是純虛擬：virtual static 不是合法 C++。靜態成員照一般方法給個實作。
        if (isInterface && !method.IsStatic)
        {
            return $"virtual {header} = 0;";
        }

        var body = returns == "void" ? "{ }" : "{ throw std::runtime_error(\"not implemented\"); }";
        return $"{header} {body}";
    }

    private static string ParameterName(string name, int index)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        if (string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]))
        {
            return $"arg{index}";
        }

        return Keywords.Contains(sanitized) ? $"{sanitized}_" : sanitized;
    }

    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case",
        "catch", "char", "char8_t", "char16_t", "char32_t", "class", "compl", "concept", "const", "consteval",
        "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
        "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern",
        "false", "float", "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new",
        "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private", "protected", "public",
        "register", "reinterpret_cast", "requires", "return", "short", "signed", "sizeof", "static",
        "static_assert", "static_cast", "struct", "switch", "template", "this", "thread_local", "throw",
        "true", "try", "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void",
        "volatile", "wchar_t", "while", "xor", "xor_eq"
    };

    // C++ 沒有原始識別字語法，撞到關鍵字只能加底線改名；空名稱與開頭數字由 IdentifierStem 處理。
    private static string Identifier(string name, string fallback)
    {
        var stem = SkeletonSupport.IdentifierStem(name, fallback);
        return Keywords.Contains(stem) ? $"{stem}_" : stem;
    }

    private static string Readme() =>
        """
        # 重建的 C++ 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是擲例外或空實作。型別對應為粗略近似，用來當轉 C++ 的起點，不保證能直接編譯。

        """;
}
