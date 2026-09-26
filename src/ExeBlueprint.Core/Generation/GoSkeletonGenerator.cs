using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 從 CodeModel 產生 Go 型別骨架（struct／interface／const 列舉與方法簽章），方法體為 panic。
// 只還原結構，型別對應粗略，僅供轉語言起點，不保證能編譯。
public static class GoSkeletonGenerator
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
                RelativePath = $"{SkeletonSupport.UniqueFileStem(usedStems, SkeletonSupport.SanitizeFileStem(assemblyName, "Reconstructed"))}.go",
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
        builder.AppendLine("// 由 ExeBlueprint 從 .NET 中介模型產生的 Go 骨架，僅還原結構，不保證可編譯。");
        builder.AppendLine("package reconstructed");
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
        switch (type.Kind)
        {
            case "enum":
                builder.AppendLine($"type {name} {LanguageTypeMap.ToGo(SkeletonSupport.EnumUnderlyingType(type))}");
                var members = SkeletonSupport.EnumMembers(type);
                if (members.Count > 0)
                {
                    builder.AppendLine("const (");
                    foreach (var member in members)
                    {
                        var value = SkeletonSupport.IntegralEnumValue(member.ConstantValue) ?? "iota";
                        builder.AppendLine($"    {name}{SkeletonSupport.IdentifierStem(member.Name, "Member")} {name} = {value}");
                    }

                    builder.AppendLine(")");
                }

                return;

            case "interface":
                builder.AppendLine($"type {name} interface {{");
                var usedInterfaceMethods = new HashSet<string>(StringComparer.Ordinal);
                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    var interfaceMethod = SkeletonSupport.UniqueName(usedInterfaceMethods, Identifier(method.Name, "Method"));
                    builder.AppendLine($"    {interfaceMethod}({Parameters(method)}){ReturnSuffix(method)}");
                }

                builder.AppendLine("}");
                return;

            default:
                builder.AppendLine($"type {name} struct {{");
                // Go 的欄位與方法共用同一個名稱空間，同名會是 "field and method with the same name"；
                // .NET 的多載在這裡也是重複宣告。整個型別共用一個集合，撞名依序加序號。
                var usedMembers = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (memberName, memberType) in SkeletonSupport.DataMembers(type))
                {
                    var field = SkeletonSupport.UniqueName(usedMembers, Identifier(memberName, "Field"));
                    builder.AppendLine($"    {field} {LanguageTypeMap.ToGo(memberType)}");
                }

                builder.AppendLine("}");

                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    builder.AppendLine();
                    if (method.IsStatic)
                    {
                        var staticName = SkeletonSupport.UniqueName(usedMembers, $"{name}_{SkeletonSupport.IdentifierStem(method.Name, "Method")}");
                        builder.AppendLine($"func {staticName}({Parameters(method)}){ReturnSuffix(method)} {{");
                    }
                    else
                    {
                        var methodName = SkeletonSupport.UniqueName(usedMembers, Identifier(method.Name, "Method"));
                        builder.AppendLine($"func (r *{name}) {methodName}({Parameters(method)}){ReturnSuffix(method)} {{");
                    }

                    builder.AppendLine("    panic(\"not implemented\")");
                    builder.AppendLine("}");
                }

                return;
        }
    }

    private static string Parameters(MethodModel method)
    {
        // 同名參數是 duplicate argument；依序加序號。
        var usedParameters = new HashSet<string>(StringComparer.Ordinal);
        return string.Join(", ", method.Parameters.Select((parameter, index) =>
            $"{SkeletonSupport.UniqueName(usedParameters, ParameterName(parameter.Name, index))} {LanguageTypeMap.ToGo(parameter.Type)}"));
    }

    private static string ReturnSuffix(MethodModel method) =>
        method.ReturnType == "void" ? "" : $" {LanguageTypeMap.ToGo(method.ReturnType)}";

    private static string ParameterName(string name, int index)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        if (string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]))
        {
            return $"arg{index}";
        }

        // r 是 receiver 的名字，參數同名會是 duplicate argument；關鍵字沒有原始識別字語法，只能改名。
        return sanitized == "r" || Keywords.Contains(sanitized) ? $"{sanitized}_" : sanitized;
    }

    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough", "for",
        "func", "go", "goto", "if", "import", "interface", "map", "package", "range", "return", "select",
        "struct", "switch", "type", "var"
    };

    // Go 沒有原始識別字語法，撞到關鍵字只能加底線改名；空名稱與開頭數字由 IdentifierStem 處理。
    private static string Identifier(string name, string fallback)
    {
        var stem = SkeletonSupport.IdentifierStem(name, fallback);
        return Keywords.Contains(stem) ? $"{stem}_" : stem;
    }

    private static string Readme() =>
        """
        # 重建的 Go 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是 `panic("not implemented")`。型別對應為粗略近似，用來當轉 Go 的起點，不保證能直接編譯。

        """;
}
