using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 把 CodeModel 轉成可閱讀的 C# 骨架。
// 這是「轉語言」鏈路的第一步：還原型別與成員的形狀，方法體先放 NotImplementedException。
// 產出的程式碼用來對照與接手改寫，不保證能直接編譯（泛型、巢狀型別、事件等尚未完整還原）。
public static class CSharpSkeletonGenerator
{
    private const int MaxIlLinesInBody = 40;

    public static IReadOnlyList<GeneratedFile> Generate(BlueprintDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var files = new List<GeneratedFile>();
        var assemblies = document.Files
            .Where(file => file.Code is { TypeCount: > 0 })
            .ToArray();

        if (assemblies.Length == 0)
        {
            return files;
        }

        foreach (var artifact in assemblies)
        {
            var assemblyName = string.IsNullOrWhiteSpace(artifact.AssemblyName)
                ? Path.GetFileNameWithoutExtension(artifact.FileName)
                : artifact.AssemblyName!;
            var projectDirectory = Sanitize(assemblyName);

            var emittableTypes = artifact.Code!.Types
                .Where(type => !type.IsNested && !IsCompilerGenerated(type.Name) && type.Kind != "delegate")
                .ToArray();

            foreach (var namespaceGroup in emittableTypes.GroupBy(type => type.Namespace).OrderBy(group => group.Key, StringComparer.Ordinal))
            {
                var fileName = string.IsNullOrEmpty(namespaceGroup.Key) ? "_GlobalNamespace" : namespaceGroup.Key;
                files.Add(new GeneratedFile
                {
                    RelativePath = $"{projectDirectory}/{fileName}.cs",
                    Content = BuildNamespaceFile(namespaceGroup.Key, namespaceGroup)
                });
            }

            files.Add(new GeneratedFile
            {
                RelativePath = $"{projectDirectory}/{projectDirectory}.csproj",
                Content = BuildProjectFile()
            });
        }

        files.Add(new GeneratedFile
        {
            RelativePath = "README.md",
            Content = BuildReadme(assemblies.Length)
        });

        return files;
    }

    private static string BuildNamespaceFile(string namespaceName, IEnumerable<TypeModel> types)
    {
        var builder = new StringBuilder();
        builder.AppendLine("// 由 ExeBlueprint 自動產生的 C# 骨架，供對照與接手改寫，不保證可直接編譯。");
        builder.AppendLine();

        var indent = "";
        if (!string.IsNullOrEmpty(namespaceName))
        {
            builder.AppendLine($"namespace {namespaceName};");
            builder.AppendLine();
        }

        var ordered = types.OrderBy(type => type.Name, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < ordered.Length; index++)
        {
            AppendType(builder, ordered[index], indent);
            if (index < ordered.Length - 1)
            {
                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static void AppendType(StringBuilder builder, TypeModel type, string indent)
    {
        var declaration = BuildTypeDeclaration(type);
        builder.AppendLine($"{indent}{declaration}");
        builder.AppendLine($"{indent}{{");
        var body = indent + "    ";

        if (type.Kind == "enum")
        {
            AppendEnumMembers(builder, type, body);
            builder.AppendLine($"{indent}}}");
            return;
        }

        var wroteMember = false;
        foreach (var field in type.Fields.Where(field => !IsCompilerGenerated(field.Name) && field.Name != "value__"))
        {
            var modifiers = field.IsConstant ? "const" : field.IsStatic ? "static" : null;
            var prefix = modifiers is null ? "" : $"{modifiers} ";
            builder.AppendLine($"{body}{field.Accessibility} {prefix}{Humanize(field.Type, type.GenericParameters, [])} {SafeName(field.Name)};");
            wroteMember = true;
        }

        if (wroteMember && type.Properties.Count > 0)
        {
            builder.AppendLine();
        }

        foreach (var property in type.Properties.Where(property => !IsCompilerGenerated(property.Name)))
        {
            var accessors = new StringBuilder("{ ");
            if (property.HasGetter)
            {
                accessors.Append("get; ");
            }

            if (property.HasSetter)
            {
                accessors.Append("set; ");
            }

            accessors.Append('}');
            builder.AppendLine($"{body}public {Humanize(property.Type, type.GenericParameters, [])} {SafeName(property.Name)} {accessors}");
            wroteMember = true;
        }

        var methods = type.Methods
            .Where(method => !ShouldSkipMethod(method))
            .ToArray();
        if (wroteMember && methods.Length > 0)
        {
            builder.AppendLine();
        }

        for (var index = 0; index < methods.Length; index++)
        {
            AppendMethod(builder, type, methods[index], body);
            if (index < methods.Length - 1)
            {
                builder.AppendLine();
            }
        }

        builder.AppendLine($"{indent}}}");
    }

    private static void AppendEnumMembers(StringBuilder builder, TypeModel type, string body)
    {
        var members = type.Fields
            .Where(field => field.IsConstant && field.Name != "value__")
            .ToArray();
        foreach (var member in members)
        {
            var assignment = member.ConstantValue?.Value is string value ? $" = {value}" : "";
            builder.AppendLine($"{body}{SafeName(member.Name)}{assignment},");
        }
    }

    private static void AppendMethod(StringBuilder builder, TypeModel type, MethodModel method, string body)
    {
        var parameters = string.Join(", ", method.Parameters.Select(parameter =>
            $"{Humanize(parameter.Type, type.GenericParameters, method.GenericParameters)} {SafeName(parameter.Name)}"));

        if (method.IsConstructor)
        {
            if (type.IsStatic)
            {
                return;
            }

            builder.AppendLine($"{body}{method.Accessibility} {CleanName(type.Name)}({parameters})");
            builder.AppendLine($"{body}{{");
            builder.AppendLine($"{body}}}");
            return;
        }

        var modifiers = BuildMethodModifiers(type, method);
        var generics = method.GenericParameters.Count == 0
            ? ""
            : $"<{string.Join(", ", method.GenericParameters)}>";
        var returnType = Humanize(method.ReturnType, type.GenericParameters, method.GenericParameters);
        var header = $"{body}{modifiers}{returnType} {SafeName(method.Name)}{generics}({parameters})";

        var noBody = type.Kind == "interface" || method.IsAbstract;
        if (noBody)
        {
            builder.AppendLine($"{header};");
            return;
        }

        builder.AppendLine(header);
        builder.AppendLine($"{body}{{");

        if (method.BodyReconstructed)
        {
            foreach (var statement in method.Body)
            {
                builder.AppendLine($"{body}    {statement}");
            }
        }
        else
        {
            AppendIlComment(builder, method, body + "    ");
            builder.AppendLine($"{body}    // TODO：以上 IL 尚未還原成 C#，暫時擲出例外。");
            builder.AppendLine($"{body}    throw new global::System.NotImplementedException();");
        }

        builder.AppendLine($"{body}}}");
    }

    private static void AppendIlComment(StringBuilder builder, MethodModel method, string indent)
    {
        if (method.Il.Count == 0)
        {
            return;
        }

        builder.AppendLine($"{indent}// 原始 IL（供還原方法體參考）：");
        foreach (var instruction in method.Il.Take(MaxIlLinesInBody))
        {
            builder.AppendLine($"{indent}// {instruction}");
        }

        if (method.Il.Count > MaxIlLinesInBody || method.IlTruncated)
        {
            builder.AppendLine($"{indent}// …其餘 IL 請看 blueprint.json。");
        }
    }

    private static string BuildMethodModifiers(TypeModel type, MethodModel method)
    {
        if (type.Kind == "interface")
        {
            return "";
        }

        var parts = new List<string> { method.Accessibility };
        if (method.IsStatic)
        {
            parts.Add("static");
        }
        else if (method.IsAbstract)
        {
            parts.Add("abstract");
        }
        else if (method.IsVirtual)
        {
            parts.Add("virtual");
        }

        return string.Join(" ", parts) + " ";
    }

    private static string BuildTypeDeclaration(TypeModel type)
    {
        var parts = new List<string> { type.Accessibility };
        if (type.Kind == "class")
        {
            if (type.IsStatic)
            {
                parts.Add("static");
            }
            else if (type.IsAbstract)
            {
                parts.Add("abstract");
            }
            else if (type.IsSealed)
            {
                parts.Add("sealed");
            }
        }

        parts.Add(type.Kind);

        var name = CleanName(type.Name);
        if (type.GenericParameters.Count > 0)
        {
            name += $"<{string.Join(", ", type.GenericParameters)}>";
        }

        parts.Add(name);

        var bases = new List<string>();
        if (type.Kind is "class" && !string.IsNullOrEmpty(type.BaseType) && type.BaseType != "System.Object")
        {
            bases.Add(Humanize(type.BaseType!, type.GenericParameters, []));
        }

        bases.AddRange(type.Interfaces
            .Where(name => !IsCompilerGenerated(name))
            .Select(name => Humanize(name, type.GenericParameters, [])));

        var declaration = string.Join(" ", parts);
        if (type.Kind == "enum")
        {
            var underlyingType = SkeletonSupport.EnumUnderlyingType(type);
            return underlyingType == "int" ? declaration : $"{declaration} : {underlyingType}";
        }

        return bases.Count == 0 ? declaration : $"{declaration} : {string.Join(", ", bases)}";
    }

    private static bool ShouldSkipMethod(MethodModel method)
    {
        if (method.Name is ".cctor")
        {
            return true;
        }

        return method.Name.StartsWith("get_", StringComparison.Ordinal)
            || method.Name.StartsWith("set_", StringComparison.Ordinal)
            || method.Name.StartsWith("add_", StringComparison.Ordinal)
            || method.Name.StartsWith("remove_", StringComparison.Ordinal)
            || method.Name.StartsWith("op_", StringComparison.Ordinal)
            || IsCompilerGenerated(method.Name);
    }

    private static string Humanize(string typeText, IReadOnlyList<string> typeGenerics, IReadOnlyList<string> methodGenerics)
    {
        var text = typeText;
        for (var index = methodGenerics.Count - 1; index >= 0; index--)
        {
            text = text.Replace($"!!{index}", methodGenerics[index], StringComparison.Ordinal);
        }

        for (var index = typeGenerics.Count - 1; index >= 0; index--)
        {
            text = text.Replace($"!{index}", typeGenerics[index], StringComparison.Ordinal);
        }

        return text;
    }

    private static string CleanName(string name)
    {
        var backtick = name.IndexOf('`', StringComparison.Ordinal);
        return backtick < 0 ? name : name[..backtick];
    }

    private static string SafeName(string name) => IsCompilerGenerated(name) ? $"@{name.Replace('<', '_').Replace('>', '_')}" : name;

    private static bool IsCompilerGenerated(string name) =>
        name.Contains('<', StringComparison.Ordinal) || name.Contains('>', StringComparison.Ordinal);

    private static string Sanitize(string value)
    {
        var characters = value.Select(character =>
            char.IsLetterOrDigit(character) || character is '.' or '_' or '-' ? character : '_');
        return new string(characters.ToArray());
    }

    private static string BuildProjectFile() =>
        """
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <TargetFramework>net10.0</TargetFramework>
            <Nullable>enable</Nullable>
            <ImplicitUsings>enable</ImplicitUsings>
          </PropertyGroup>
        </Project>

        """;

    private static string BuildReadme(int assemblyCount) =>
        $"""
        # 重建的 C# 骨架

        這份程式碼由 ExeBlueprint 從 {assemblyCount} 個 .NET 組件的中介模型自動產生。

        目前只還原型別、欄位、屬性、方法簽章與繼承關係。方法體是 `NotImplementedException`，
        需要對照原程式的 IL 或反組譯結果補回實作。

        用途是拿來對照結構、接手改寫或轉成其他語言的起點，不保證能直接編譯：
        泛型限制、巢狀型別、事件、運算子多載與 P/Invoke 等尚未完整處理。

        """;
}
