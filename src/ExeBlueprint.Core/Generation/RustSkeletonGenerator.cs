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
        foreach (var (_, assemblyName, types) in assemblies)
        {
            files.Add(new GeneratedFile
            {
                RelativePath = $"{SkeletonSupport.Sanitize(assemblyName)}.rs",
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
        var name = SkeletonSupport.SimpleName(type.Name);
        switch (type.Kind)
        {
            case "enum":
                builder.AppendLine($"#[repr({LanguageTypeMap.ToRust(SkeletonSupport.EnumUnderlyingType(type))})]");
                builder.AppendLine($"pub enum {name} {{");
                foreach (var member in SkeletonSupport.EnumMembers(type))
                {
                    var assignment = member.ConstantValue?.Value is string value ? $" = {value}" : "";
                    builder.AppendLine($"    {SkeletonSupport.Sanitize(member.Name)}{assignment},");
                }

                builder.AppendLine("}");
                return;

            case "interface":
                builder.AppendLine($"pub trait {name} {{");
                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    builder.AppendLine($"    {Signature(method, includeBody: false)};");
                }

                builder.AppendLine("}");
                return;

            default:
                builder.AppendLine($"pub struct {name} {{");
                foreach (var (memberName, memberType) in SkeletonSupport.DataMembers(type))
                {
                    builder.AppendLine($"    pub {SkeletonSupport.Sanitize(memberName)}: {LanguageTypeMap.ToRust(memberType)},");
                }

                builder.AppendLine("}");

                var methods = SkeletonSupport.EmittableMethods(type);
                if (methods.Count > 0)
                {
                    builder.AppendLine();
                    builder.AppendLine($"impl {name} {{");
                    foreach (var method in methods)
                    {
                        builder.AppendLine($"    {Signature(method, includeBody: true)}");
                    }

                    builder.AppendLine("}");
                }

                return;
        }
    }

    private static string Signature(MethodModel method, bool includeBody)
    {
        var parameters = new List<string>();
        if (!method.IsStatic)
        {
            parameters.Add("&self");
        }

        parameters.AddRange(method.Parameters.Select(parameter =>
            $"{ParameterName(parameter.Name)}: {LanguageTypeMap.ToRust(parameter.Type)}"));

        var returns = method.ReturnType == "void" ? "" : $" -> {LanguageTypeMap.ToRust(method.ReturnType)}";
        var header = $"pub fn {SkeletonSupport.Sanitize(method.Name)}({string.Join(", ", parameters)}){returns}";
        return includeBody ? $"{header} {{ unimplemented!() }}" : header;
    }

    private static string ParameterName(string name)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        return string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]) ? $"arg_{sanitized}" : sanitized;
    }

    private static string Readme() =>
        """
        # 重建的 Rust 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是 `unimplemented!()`。型別對應為粗略近似，用來當轉 Rust 的起點，不保證能直接編譯。

        """;
}
