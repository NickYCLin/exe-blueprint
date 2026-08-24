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
        foreach (var (_, assemblyName, types) in SkeletonSupport.Assemblies(document))
        {
            files.Add(new GeneratedFile
            {
                RelativePath = $"{SkeletonSupport.Sanitize(assemblyName)}.hpp",
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
        if (type.Kind == "enum")
        {
            var underlyingType = LanguageTypeMap.ToCpp(SkeletonSupport.EnumUnderlyingType(type));
            builder.AppendLine($"enum class {name} : {underlyingType} {{");
            builder.AppendLine(string.Join(",\n", SkeletonSupport.EnumMembers(type).Select(member =>
            {
                var assignment = member.ConstantValue?.Value is string value ? $" = {value}" : "";
                return $"    {SkeletonSupport.Sanitize(member.Name)}{assignment}";
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
            builder.AppendLine($"    {LanguageTypeMap.ToCpp(memberType)} {SkeletonSupport.Sanitize(memberName)};");
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
        var parameters = string.Join(", ", method.Parameters.Select((parameter, index) =>
            $"{LanguageTypeMap.ToCpp(parameter.Type)} {ParameterName(parameter.Name, index)}"));
        var prefix = method.IsStatic ? "static " : "";
        var header = $"{prefix}{returns} {SkeletonSupport.Sanitize(method.Name)}({parameters})";

        if (isInterface)
        {
            return $"virtual {header} = 0;";
        }

        var body = returns == "void" ? "{ }" : "{ throw std::runtime_error(\"not implemented\"); }";
        return $"{header} {body}";
    }

    private static string ParameterName(string name, int index)
    {
        var sanitized = SkeletonSupport.Sanitize(name);
        return string.IsNullOrEmpty(sanitized) || char.IsDigit(sanitized[0]) ? $"arg{index}" : sanitized;
    }

    private static string Readme() =>
        """
        # 重建的 C++ 骨架

        這份程式碼由 ExeBlueprint 從 .NET 組件的中介模型產生，只還原型別、欄位與方法簽章，
        方法體是擲例外或空實作。型別對應為粗略近似，用來當轉 C++ 的起點，不保證能直接編譯。

        """;
}
