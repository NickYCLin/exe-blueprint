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
        foreach (var (_, assemblyName, types) in SkeletonSupport.Assemblies(document))
        {
            files.Add(new GeneratedFile
            {
                RelativePath = $"{SkeletonSupport.Sanitize(assemblyName)}.go",
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
                builder.AppendLine($"type {name} int");
                var members = SkeletonSupport.EnumMembers(type);
                if (members.Count > 0)
                {
                    builder.AppendLine("const (");
                    for (var index = 0; index < members.Count; index++)
                    {
                        builder.AppendLine(index == 0
                            ? $"    {name}{members[index]} {name} = iota"
                            : $"    {name}{members[index]}");
                    }

                    builder.AppendLine(")");
                }

                return;

            case "interface":
                builder.AppendLine($"type {name} interface {{");
                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    builder.AppendLine($"    {SkeletonSupport.Sanitize(method.Name)}({Parameters(method)}){ReturnSuffix(method)}");
                }

                builder.AppendLine("}");
                return;

            default:
                builder.AppendLine($"type {name} struct {{");
                foreach (var (memberName, memberType) in SkeletonSupport.DataMembers(type))
                {
                    builder.AppendLine($"    {SkeletonSupport.Sanitize(memberName)} {LanguageTypeMap.ToGo(memberType)}");
                }

                builder.AppendLine("}");

                foreach (var method in SkeletonSupport.EmittableMethods(type))
                {
                    builder.AppendLine();
                    if (method.IsStatic)
                    {
                        builder.AppendLine($"func {name}_{SkeletonSupport.Sanitize(method.Name)}({Parameters(method)}){ReturnSuffix(method)} {{");
                    }
                    else
                    {
                        builder.AppendLine($"func (r *{name}) {SkeletonSupport.Sanitize(method.Name)}({Parameters(method)}){ReturnSuffix(method)} {{");
                    }

                    builder.AppendLine("    panic(\"not implemented\")");
                    builder.AppendLine("}");
                }

                return;
        }
    }

    private static string Parameters(MethodModel method) =>
        string.Join(", ", method.Parameters.Select((parameter, index) =>
            $"{ParameterName(parameter.Name, index)} {LanguageTypeMap.ToGo(parameter.Type)}"));

    private static string ReturnSuffix(MethodModel method) =>
        method.ReturnType == "void" ? "" : $" {LanguageTypeMap.ToGo(method.ReturnType)}";

    private static string ParameterName(string name, int index)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        return string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]) ? $"arg{index}" : sanitized;
    }

    private static string Readme() =>
        """
        # 重建的 Go 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是 `panic("not implemented")`。型別對應為粗略近似，用來當轉 Go 的起點，不保證能直接編譯。

        """;
}
