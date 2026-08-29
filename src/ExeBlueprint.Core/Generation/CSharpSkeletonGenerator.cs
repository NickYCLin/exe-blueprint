using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 把 CodeModel 轉成可閱讀的 C# 骨架。
// 這是「轉語言」鏈路的第一步：還原型別與成員的形狀，能安全結構化的方法也帶回方法體。
// 產出的程式碼用來對照與接手改寫，不保證能直接編譯（泛型限制、外部依賴等尚未完整還原）。
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

        var projectDirectories = CreateProjectDescriptors(assemblies);
        var projectsByAssembly = projectDirectories
            .GroupBy(project => project.AssemblyName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().ProjectDirectory, StringComparer.OrdinalIgnoreCase);

        foreach (var project in projectDirectories)
        {
            var artifact = project.Artifact;
            var projectDirectory = project.ProjectDirectory;

            var emittableTypes = artifact.Code!.Types
                .Where(type => !IsCompilerGenerated(type.Name) && type.Kind != "delegate")
                .ToArray();
            var nestedTypesByDeclaringType = emittableTypes
                .Where(type => type.IsNested && !string.IsNullOrEmpty(type.DeclaringType))
                .GroupBy(type => type.DeclaringType!, StringComparer.Ordinal)
                .ToDictionary(
                    group => group.Key,
                    group => group.OrderBy(type => type.Name, StringComparer.Ordinal).ToArray(),
                    StringComparer.Ordinal);
            var topLevelTypes = emittableTypes
                .Where(type => !type.IsNested)
                .ToArray();
            var refLikeTypes = artifact.Code.Types
                .Where(type => type.IsRefLike)
                .Select(type => type.FullName)
                .ToHashSet(StringComparer.Ordinal);

            foreach (var namespaceGroup in topLevelTypes.GroupBy(type => type.Namespace).OrderBy(group => group.Key, StringComparer.Ordinal))
            {
                var fileName = string.IsNullOrEmpty(namespaceGroup.Key) ? "_GlobalNamespace" : namespaceGroup.Key;
                files.Add(new GeneratedFile
                {
                    RelativePath = $"{projectDirectory}/{fileName}.cs",
                    Content = BuildNamespaceFile(
                        namespaceGroup.Key,
                        namespaceGroup,
                        nestedTypesByDeclaringType,
                        refLikeTypes)
                });
            }

            files.Add(new GeneratedFile
            {
                RelativePath = $"{projectDirectory}/{projectDirectory}.csproj",
                Content = BuildProjectFile(
                    artifact.ManagedReferences
                        .Where(reference => projectsByAssembly.ContainsKey(reference))
                        .Select(reference => projectsByAssembly[reference])
                        .Where(reference => reference != projectDirectory)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase))
            });
        }

        files.Add(new GeneratedFile
        {
            RelativePath = "Reconstructed.slnx",
            Content = BuildSolution(
                projectDirectories
                    .Select(project => project.ProjectDirectory)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(directory => directory, StringComparer.OrdinalIgnoreCase))
        });

        files.Add(new GeneratedFile
        {
            RelativePath = "README.md",
            Content = BuildReadme(assemblies.Length)
        });

        return files;
    }

    private static string BuildNamespaceFile(
        string namespaceName,
        IEnumerable<TypeModel> types,
        IReadOnlyDictionary<string, TypeModel[]> nestedTypesByDeclaringType,
        IReadOnlySet<string> refLikeTypes)
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
            AppendType(builder, ordered[index], indent, nestedTypesByDeclaringType, refLikeTypes);
            if (index < ordered.Length - 1)
            {
                builder.AppendLine();
            }
        }

        return builder.ToString();
    }

    private static void AppendType(
        StringBuilder builder,
        TypeModel type,
        string indent,
        IReadOnlyDictionary<string, TypeModel[]> nestedTypesByDeclaringType,
        IReadOnlySet<string> refLikeTypes)
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
        var eventNames = type.Events.Select(@event => @event.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var field in type.Fields.Where(field =>
                     !IsCompilerGenerated(field.Name) &&
                     field.Name != "value__" &&
                     !eventNames.Contains(field.Name)))
        {
            var modifiers = new List<string> { field.Accessibility };
            if (field.IsConstant)
            {
                modifiers.Add("const");
            }
            else
            {
                if (field.IsStatic)
                {
                    modifiers.Add("static");
                }

                if (field.IsReadOnly)
                {
                    modifiers.Add("readonly");
                }
            }

            var initializer = field.IsConstant
                ? $" = {FormatConstant(field.ConstantValue)}"
                : ShouldInitializeSkeletonMember(type)
                    ? " = default!"
                    : "";
            builder.AppendLine($"{body}{string.Join(" ", modifiers)} {Humanize(field.Type, type.GenericParameters, [])} {SafeName(field.Name)}{initializer};");
            wroteMember = true;
        }

        if (wroteMember && type.Properties.Count > 0)
        {
            builder.AppendLine();
        }

        foreach (var property in type.Properties.Where(property => !IsCompilerGenerated(property.Name)))
        {
            var propertyType = Humanize(property.Type, type.GenericParameters, []);
            var accessors = new StringBuilder("{ ");
            if (property.HasGetter)
            {
                AppendAccessorAccessibility(accessors, property.GetterAccessibility, property.Accessibility, property.HasSetter);
                accessors.Append("get; ");
            }

            if (property.HasSetter)
            {
                AppendAccessorAccessibility(accessors, property.SetterAccessibility, property.Accessibility, property.HasGetter);
                accessors.Append("set; ");
            }

            accessors.Append('}');
            var modifiers = BuildMemberModifiers(
                type,
                property.Accessibility,
                property.IsStatic,
                property.IsAbstract,
                property.IsVirtual,
                property.IsFinal,
                property.IsNewSlot);
            if (type.Kind != "interface" &&
                !property.IsAbstract &&
                IsRefLikeType(propertyType, refLikeTypes))
            {
                builder.AppendLine($"{body}{modifiers}{propertyType} {SafeName(property.Name)}");
                builder.AppendLine($"{body}{{");
                if (property.HasGetter)
                {
                    var getterAccessibility = new StringBuilder();
                    AppendAccessorAccessibility(
                        getterAccessibility,
                        property.GetterAccessibility,
                        property.Accessibility,
                        property.HasSetter);
                    builder.AppendLine($"{body}    {getterAccessibility}get => throw new global::System.NotImplementedException();");
                }

                if (property.HasSetter)
                {
                    var setterAccessibility = new StringBuilder();
                    AppendAccessorAccessibility(
                        setterAccessibility,
                        property.SetterAccessibility,
                        property.Accessibility,
                        property.HasGetter);
                    builder.AppendLine($"{body}    {setterAccessibility}set {{ }}");
                }

                builder.AppendLine($"{body}}}");
            }
            else
            {
                var initializer = ShouldInitializeSkeletonMember(type) && !property.IsAbstract
                    ? " = default!;"
                    : "";
                builder.AppendLine($"{body}{modifiers}{propertyType} {SafeName(property.Name)} {accessors}{initializer}");
            }

            wroteMember = true;
        }

        if (wroteMember && type.Events.Count > 0)
        {
            builder.AppendLine();
        }

        foreach (var @event in type.Events.Where(@event => !IsCompilerGenerated(@event.Name)))
        {
            var modifiers = BuildMemberModifiers(
                type,
                @event.Accessibility,
                @event.IsStatic,
                @event.IsAbstract,
                @event.IsVirtual,
                @event.IsFinal,
                @event.IsNewSlot);
            builder.AppendLine($"{body}{modifiers}event {Humanize(@event.Type, type.GenericParameters, [])} {SafeName(@event.Name)};");
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

        var nestedTypes = nestedTypesByDeclaringType.TryGetValue(type.FullName, out var children)
            ? children
            : [];
        if ((wroteMember || methods.Length > 0) && nestedTypes.Length > 0)
        {
            builder.AppendLine();
        }

        for (var index = 0; index < nestedTypes.Length; index++)
        {
            AppendType(builder, nestedTypes[index], body, nestedTypesByDeclaringType, refLikeTypes);
            if (index < nestedTypes.Length - 1)
            {
                builder.AppendLine();
            }
        }

        builder.AppendLine($"{indent}}}");
    }

    // 方法重建不了時 constructor 會留空；class 與原本就有 instance constructor 的 struct
    // 先用 default! 明確表達 skeleton 佔位值。沒有 constructor 的 struct 不能帶 instance initializer。
    private static bool ShouldInitializeSkeletonMember(TypeModel type) =>
        type.Kind == "class" ||
        (type.Kind == "struct" && type.Methods.Any(method => method.IsConstructor && !method.IsStatic));

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
                var humanized = HumanizeBodyStatement(
                    statement,
                    type.GenericParameters,
                    method.GenericParameters);
                builder.AppendLine($"{body}    {humanized}");
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
        else
        {
            AppendDispatchModifiers(
                parts,
                method.IsAbstract,
                method.IsVirtual,
                method.IsFinal,
                method.IsNewSlot);
        }

        return string.Join(" ", parts) + " ";
    }

    private static string BuildMemberModifiers(
        TypeModel type,
        string accessibility,
        bool isStatic,
        bool isAbstract,
        bool isVirtual,
        bool isFinal,
        bool isNewSlot)
    {
        if (type.Kind == "interface")
        {
            return "";
        }

        var parts = new List<string> { accessibility };
        if (isStatic)
        {
            parts.Add("static");
        }
        else
        {
            AppendDispatchModifiers(parts, isAbstract, isVirtual, isFinal, isNewSlot);
        }

        return string.Join(" ", parts) + " ";
    }

    private static void AppendDispatchModifiers(
        List<string> parts,
        bool isAbstract,
        bool isVirtual,
        bool isFinal,
        bool isNewSlot)
    {
        if (!isVirtual)
        {
            return;
        }

        if (!isNewSlot)
        {
            if (isFinal)
            {
                parts.Add("sealed");
            }

            if (isAbstract)
            {
                parts.Add("abstract");
            }

            parts.Add("override");
            return;
        }

        if (isAbstract)
        {
            parts.Add("abstract");
        }
        else if (!isFinal)
        {
            parts.Add("virtual");
        }
    }

    private static void AppendAccessorAccessibility(
        StringBuilder builder,
        string? accessorAccessibility,
        string propertyAccessibility,
        bool hasOtherAccessor)
    {
        if (hasOtherAccessor &&
            accessorAccessibility is not null &&
            accessorAccessibility != propertyAccessibility)
        {
            builder.Append(accessorAccessibility).Append(' ');
        }
    }

    private static string FormatConstant(ConstantValueModel? constant)
    {
        if (constant?.Value is null)
        {
            return "null";
        }

        return constant.Type switch
        {
            "string" => $"\"{EscapeString(constant.Value)}\"",
            "char" => $"'{EscapeChar(constant.Value[0])}'",
            "float" => constant.Value + "F",
            _ => constant.Value
        };
    }

    private static string EscapeString(string value) => value
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal)
        .Replace("\r", "\\r", StringComparison.Ordinal)
        .Replace("\n", "\\n", StringComparison.Ordinal)
        .Replace("\t", "\\t", StringComparison.Ordinal);

    private static string EscapeChar(char value) => value switch
    {
        '\\' => "\\\\",
        '\'' => "\\'",
        '\r' => "\\r",
        '\n' => "\\n",
        '\t' => "\\t",
        _ => value.ToString()
    };

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

        if (type.Kind == "struct" && type.IsRefLike)
        {
            parts.Add("ref");
        }

        parts.Add(type.Kind);

        var name = CleanName(type.Name);
        var declaredGenericParameters = type.GenericParameters
            .Skip(type.InheritedGenericParameterCount)
            .ToArray();
        if (declaredGenericParameters.Length > 0)
        {
            name += $"<{string.Join(", ", declaredGenericParameters)}>";
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

    private static bool IsRefLikeType(string typeName, IReadOnlySet<string> refLikeTypes)
    {
        var genericStart = typeName.IndexOf('<', StringComparison.Ordinal);
        var definitionName = genericStart < 0 ? typeName : typeName[..genericStart];
        return definitionName is
            "System.Span" or
            "System.ReadOnlySpan" or
            "System.TypedReference" or
            "System.ArgIterator" or
            "System.RuntimeArgumentHandle" ||
            refLikeTypes.Contains(definitionName);
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

    // Method body 來自 metadata 型別文字，可能仍含 !0／!!0。只轉換程式碼 token，
    // 保留使用者原始 string／char literal 中恰好相同的內容。
    private static string HumanizeBodyStatement(
        string statement,
        IReadOnlyList<string> typeGenerics,
        IReadOnlyList<string> methodGenerics)
    {
        var builder = new StringBuilder(statement.Length);
        var position = 0;
        while (position < statement.Length)
        {
            if (statement[position] is '"' or '\'')
            {
                AppendQuotedLiteral(builder, statement, ref position);
                continue;
            }

            if (statement[position] != '!')
            {
                builder.Append(statement[position++]);
                continue;
            }

            var isMethodParameter = position + 1 < statement.Length && statement[position + 1] == '!';
            var digitStart = position + (isMethodParameter ? 2 : 1);
            var digitEnd = digitStart;
            var parameterIndex = 0;
            var overflow = false;
            while (digitEnd < statement.Length && statement[digitEnd] is >= '0' and <= '9')
            {
                var digit = statement[digitEnd] - '0';
                if (parameterIndex > (int.MaxValue - digit) / 10)
                {
                    overflow = true;
                }
                else if (!overflow)
                {
                    parameterIndex = (parameterIndex * 10) + digit;
                }

                digitEnd++;
            }

            var isCompleteToken = digitEnd > digitStart
                && (digitEnd == statement.Length
                    || !(char.IsLetterOrDigit(statement[digitEnd]) || statement[digitEnd] == '_'));
            var parameters = isMethodParameter ? methodGenerics : typeGenerics;
            if (!overflow && isCompleteToken && parameterIndex < parameters.Count)
            {
                builder.Append(parameters[parameterIndex]);
                position = digitEnd;
                continue;
            }

            if (digitEnd > digitStart)
            {
                builder.Append(statement, position, digitEnd - position);
                position = digitEnd;
                continue;
            }

            builder.Append(statement[position++]);
        }

        return builder.ToString();
    }

    private static void AppendQuotedLiteral(StringBuilder builder, string statement, ref int position)
    {
        var quote = statement[position++];
        builder.Append(quote);
        while (position < statement.Length)
        {
            var current = statement[position++];
            builder.Append(current);
            if (current == '\\' && position < statement.Length)
            {
                builder.Append(statement[position++]);
            }
            else if (current == quote)
            {
                break;
            }
        }
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

    private static string AssemblyName(FileArtifact artifact) =>
        string.IsNullOrWhiteSpace(artifact.AssemblyName)
            ? Path.GetFileNameWithoutExtension(artifact.FileName)
            : artifact.AssemblyName!;

    private static IReadOnlyList<ProjectDescriptor> CreateProjectDescriptors(IEnumerable<FileArtifact> assemblies)
    {
        var descriptors = new List<ProjectDescriptor>();
        var usedDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var artifact in assemblies)
        {
            var assemblyName = AssemblyName(artifact);
            var baseDirectory = Sanitize(assemblyName);
            if (string.IsNullOrWhiteSpace(baseDirectory))
            {
                baseDirectory = "ReconstructedProject";
            }

            var projectDirectory = baseDirectory;
            var suffix = 2;
            while (!usedDirectories.Add(projectDirectory))
            {
                projectDirectory = $"{baseDirectory}_{suffix++}";
            }

            descriptors.Add(new ProjectDescriptor(artifact, assemblyName, projectDirectory));
        }

        return descriptors;
    }

    private static string BuildProjectFile(IEnumerable<string> projectReferences)
    {
        var references = projectReferences.ToArray();
        var builder = new StringBuilder();
        builder.AppendLine("<Project Sdk=\"Microsoft.NET.Sdk\">");
        builder.AppendLine("  <PropertyGroup>");
        builder.AppendLine("    <TargetFramework>net10.0</TargetFramework>");
        builder.AppendLine("    <Nullable>enable</Nullable>");
        builder.AppendLine("    <ImplicitUsings>enable</ImplicitUsings>");
        builder.AppendLine("  </PropertyGroup>");
        if (references.Length > 0)
        {
            builder.AppendLine("  <ItemGroup>");
            foreach (var reference in references)
            {
                builder.AppendLine($"    <ProjectReference Include=\"../{reference}/{reference}.csproj\" />");
            }

            builder.AppendLine("  </ItemGroup>");
        }

        builder.AppendLine("</Project>");
        return builder.ToString();
    }

    private static string BuildSolution(IEnumerable<string> projectDirectories)
    {
        var builder = new StringBuilder();
        builder.AppendLine("<Solution>");
        foreach (var directory in projectDirectories)
        {
            builder.AppendLine($"  <Project Path=\"{directory}/{directory}.csproj\" />");
        }

        builder.AppendLine("</Solution>");
        return builder.ToString();
    }

    private static string BuildReadme(int assemblyCount) =>
        $"""
        # 重建的 C# 骨架

        這份程式碼由 ExeBlueprint 從 {assemblyCount} 個 .NET 組件的中介模型自動產生。

        `Reconstructed.slnx` 會收錄所有產生的專案；輸入套件內可對上的 assembly reference
        會轉成專案間的 `ProjectReference`。

        目前會還原型別、欄位、屬性、事件、方法簽章與繼承關係；可安全結構化的方法也會帶回方法體，
        其餘方法會保留 IL 並使用 `NotImplementedException`，
        需要對照原程式的 IL 或反組譯結果補回實作。

        用途是拿來對照結構、接手改寫或轉成其他語言的起點，不保證能直接編譯：
        泛型限制、套件外依賴、運算子多載與 P/Invoke 等尚未完整處理。

        """;

    private sealed record ProjectDescriptor(
        FileArtifact Artifact,
        string AssemblyName,
        string ProjectDirectory);
}
