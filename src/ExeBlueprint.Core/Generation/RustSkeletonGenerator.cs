using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 從 CodeModel 產生 Rust 型別骨架（struct／trait／enum 與方法簽章），方法體為 unimplemented!()。
// 只還原結構，不翻譯方法內容；型別對應是粗略的，僅供轉語言起點，不保證能編譯。
public static class RustSkeletonGenerator
{
    public static IReadOnlyList<GeneratedFile> Generate(BlueprintDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var files = new List<GeneratedFile>();
        var assemblies = SkeletonSupport.Assemblies(document);
        var usedStems = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (_, assemblyName, types) in assemblies)
        {
            files.Add(new GeneratedFile
            {
                RelativePath = $"{SkeletonSupport.UniqueFileStem(usedStems, SkeletonSupport.SanitizeFileStem(assemblyName, "Reconstructed"))}.rs",
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
        builder.AppendLine("// 由 ExeBlueprint 從 .NET 中介模型產生的 Rust 骨架，僅還原結構，不保證可編譯。");
        builder.AppendLine("#![allow(non_snake_case, non_camel_case_types, dead_code, unused_variables)]");
        builder.AppendLine();

        foreach (var type in types.OrderBy(type => type.Name, StringComparer.Ordinal))
        {
            AppendType(builder, type);
            builder.AppendLine();
        }

        return builder.ToString();
    }

    private static void AppendType(StringBuilder builder, TypeModel type)
    {
        var name = Identifier(SkeletonSupport.SimpleName(type.Name), "Type");
        switch (type.Kind)
        {
            case "enum":
                var enumMembers = SkeletonSupport.EnumMembers(type);
                if (enumMembers.Count == 0)
                {
                    // 零變體的列舉不能帶 #[repr]（E0084），只能輸出空的 enum。
                    builder.AppendLine($"pub enum {name} {{}}");
                    return;
                }

                builder.AppendLine($"#[repr({LanguageTypeMap.ToRust(SkeletonSupport.EnumUnderlyingType(type))})]");
                builder.AppendLine($"pub enum {name} {{");
                var firstVariantByValue = new Dictionary<string, string>(StringComparer.Ordinal);
                var aliases = new List<(string Alias, string Target)>();
                foreach (var member in enumMembers)
                {
                    var variant = Identifier(member.Name, "Member");
                    var value = SkeletonSupport.IntegralEnumValue(member.ConstantValue);
                    if (value is not null && firstVariantByValue.TryGetValue(value, out var target))
                    {
                        // Rust 不允許兩個變體有相同判別值（E0081）；.NET 常見的別名成員改成關聯常數。
                        aliases.Add((variant, target));
                        continue;
                    }

                    if (value is not null)
                    {
                        firstVariantByValue[value] = variant;
                    }

                    builder.AppendLine($"    {variant}{(value is null ? "" : $" = {value}")},");
                }

                builder.AppendLine("}");
                if (aliases.Count > 0)
                {
                    builder.AppendLine();
                    builder.AppendLine($"impl {name} {{");
                    foreach (var (alias, target) in aliases)
                    {
                        builder.AppendLine($"    pub const {alias}: Self = Self::{target};");
                    }

                    builder.AppendLine("}");
                }

                return;

            case "interface":
                builder.AppendLine($"pub trait {name} {{");
                var usedTraitMethods = new HashSet<string>(StringComparer.Ordinal);
                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    var traitMethod = SkeletonSupport.UniqueName(usedTraitMethods, Identifier(method.Name, "method"));
                    builder.AppendLine($"    {Signature(method, traitMethod, includeBody: false, visibility: "")};");
                }

                builder.AppendLine("}");
                return;

            default:
                builder.AppendLine($"pub struct {name} {{");
                var usedFields = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (memberName, memberType) in SkeletonSupport.DataMembers(type))
                {
                    var field = SkeletonSupport.UniqueName(usedFields, Identifier(memberName, "field"));
                    builder.AppendLine($"    pub {field}: {LanguageTypeMap.ToRust(memberType)},");
                }

                builder.AppendLine("}");

                var methods = SkeletonSupport.EmittableMethods(type);
                if (methods.Count > 0)
                {
                    builder.AppendLine();
                    builder.AppendLine($"impl {name} {{");
                    // .NET 的多載在 Rust 是重複定義（E0592）；同名方法依序加序號。
                    var usedMethods = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var method in methods)
                    {
                        var methodName = SkeletonSupport.UniqueName(usedMethods, Identifier(method.Name, "method"));
                        builder.AppendLine($"    {Signature(method, methodName, includeBody: true, visibility: "pub ")}");
                    }

                    builder.AppendLine("}");
                }

                return;
        }
    }

    // trait 裡的方法不能帶 pub（E0449），impl 裡的才需要；由呼叫端決定可見性前綴。
    private static string Signature(MethodModel method, string methodName, bool includeBody, string visibility)
    {
        var parameters = new List<string>();
        if (!method.IsStatic)
        {
            parameters.Add("&self");
        }

        parameters.AddRange(method.Parameters.Select(parameter =>
            $"{ParameterName(parameter.Name)}: {LanguageTypeMap.ToRust(parameter.Type)}"));

        var returns = method.ReturnType == "void" ? "" : $" -> {LanguageTypeMap.ToRust(method.ReturnType)}";
        var header = $"{visibility}fn {methodName}({string.Join(", ", parameters)}){returns}";
        return includeBody ? $"{header} {{ unimplemented!() }}" : header;
    }

    private static string ParameterName(string name)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        if (string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]))
        {
            return $"arg_{sanitized}";
        }

        // self 會和接收者參數撞名，其他關鍵字可用 r# 原始識別字。
        return EscapeKeyword(sanitized);
    }

    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "as", "async", "await", "break", "const", "continue", "dyn", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
        "static", "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "abstract", "become",
        "box", "do", "final", "macro", "override", "priv", "try", "typeof", "unsized", "virtual", "yield", "gen"
    };

    // 這幾個不能寫成 r# 原始識別字，只能改名。
    private static readonly HashSet<string> NonRawable = new(StringComparer.Ordinal)
    {
        "self", "super", "crate", "Self"
    };

    private static string EscapeKeyword(string stem) =>
        NonRawable.Contains(stem) ? $"{stem}_"
        : Keywords.Contains(stem) ? $"r#{stem}"
        : stem;

    // 名稱直接來自 metadata：空名稱與開頭數字由 IdentifierStem 處理，單獨一個 _ 不能當欄位名，
    // 關鍵字用 r#，self／super／crate／Self 沒有原始識別字語法就加底線。
    private static string Identifier(string name, string fallback)
    {
        var stem = SkeletonSupport.IdentifierStem(name, fallback);
        return EscapeKeyword(stem == "_" ? fallback : stem);
    }

    private static string Readme() =>
        """
        # 重建的 Rust 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是 `unimplemented!()`。型別對應為粗略近似，用來當轉 Rust 的起點，不保證能直接編譯。

        """;
}
