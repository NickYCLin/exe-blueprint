using System.Text;
using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 把 CodeModel 轉成可閱讀的 C# 骨架。
// 這是「轉語言」鏈路的第一步：還原型別與成員的形狀，能安全結構化的方法也帶回方法體。
// 產出的程式碼用來對照與接手改寫，不保證能直接編譯（外部依賴等尚未完整還原）。
public static class CSharpSkeletonGenerator
{
    private const int MaxIlLinesInBody = 40;
    private const int MaxGenericConstraintDependencyDepth = 64;
    private static readonly HashSet<string> CSharpReservedKeywords = new(StringComparer.Ordinal)
    {
        "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
        "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else", "enum",
        "event", "explicit", "extern", "false", "finally", "fixed", "float", "for", "foreach", "goto",
        "if", "implicit", "in", "int", "interface", "internal", "is", "lock", "long", "namespace", "new",
        "null", "object", "operator", "out", "override", "params", "private", "protected", "public",
        "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static",
        "string", "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong",
        "unchecked", "unsafe", "ushort", "using", "virtual", "void", "volatile", "while",

        // Contextual keywords are escaped too. Several of them become grammar tokens specifically in
        // generic declarations or constraints (for example required, record, notnull and unmanaged).
        "_", "add", "alias", "allows", "and", "ascending", "assembly", "async", "await", "by", "closed",
        "descending", "dynamic", "equals", "extension", "field", "file", "from", "get", "global", "group", "init",
        "into", "join", "let", "managed", "method", "module", "nameof", "nint", "not", "notnull", "nuint",
        "on", "or", "orderby", "param", "partial", "property", "record", "remove", "required", "safe", "scoped",
        "select", "set", "type", "typevar", "union", "unmanaged", "value", "var", "when", "where", "with", "yield",
        "__arglist", "__makeref", "__reftype", "__refvalue"
    };

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
                .Where(type => !IsCompilerGenerated(type.Name))
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
            var requiresUnsafeBlocks = topLevelTypes.Any(type => RequiresUnsafeContextInTree(
                type,
                nestedTypesByDeclaringType,
                new HashSet<string>(StringComparer.Ordinal)));

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
                        .OrderBy(reference => reference, StringComparer.OrdinalIgnoreCase),
                    requiresUnsafeBlocks)
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
        if (type.Kind == "delegate")
        {
            AppendDelegate(builder, type, indent);
            return;
        }

        var declaration = BuildTypeDeclaration(type);
        AppendConstrainedDeclaration(
            builder,
            $"{indent}{declaration}",
            indent + "    ",
            BuildTypeConstraintClauses(type),
            terminator: "");
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
            var isExplicitInterfaceMember = IsExplicitInterfaceMember(property.Name);
            var isIndexer = property.Parameters.Count > 0;
            var propertyType = Humanize(property.Type, type.GenericParameters, []);
            var propertyName = isIndexer
                ? FormatIndexerName(property, type.GenericParameters)
                : SafeName(property.Name);
            var accessors = new StringBuilder("{ ");
            if (property.HasGetter)
            {
                if (!isExplicitInterfaceMember)
                {
                    AppendAccessorAccessibility(accessors, property.GetterAccessibility, property.Accessibility, property.HasSetter);
                }

                accessors.Append("get; ");
            }

            if (property.HasSetter)
            {
                if (!isExplicitInterfaceMember)
                {
                    AppendAccessorAccessibility(accessors, property.SetterAccessibility, property.Accessibility, property.HasGetter);
                }

                accessors.Append("set; ");
            }

            accessors.Append('}');
            var modifiers = isExplicitInterfaceMember
                ? string.Empty
                : BuildMemberModifiers(
                    type,
                    property.Accessibility,
                    property.IsStatic,
                    property.IsAbstract,
                    property.IsVirtual,
                    property.IsFinal,
                    property.IsNewSlot);
            if (type.Kind != "interface" &&
                !property.IsAbstract &&
                (isIndexer || IsByRefType(propertyType) || IsRefLikeType(propertyType, refLikeTypes)))
            {
                builder.AppendLine($"{body}{modifiers}{propertyType} {propertyName}");
                builder.AppendLine($"{body}{{");
                if (property.HasGetter)
                {
                    var getterAccessibility = new StringBuilder();
                    if (!isExplicitInterfaceMember)
                    {
                        AppendAccessorAccessibility(
                            getterAccessibility,
                            property.GetterAccessibility,
                            property.Accessibility,
                            property.HasSetter);
                    }

                    builder.AppendLine($"{body}    {getterAccessibility}get => throw new global::System.NotImplementedException();");
                }

                if (property.HasSetter)
                {
                    var setterAccessibility = new StringBuilder();
                    if (!isExplicitInterfaceMember)
                    {
                        AppendAccessorAccessibility(
                            setterAccessibility,
                            property.SetterAccessibility,
                            property.Accessibility,
                            property.HasGetter);
                    }

                    builder.AppendLine($"{body}    {setterAccessibility}set {{ }}");
                }

                builder.AppendLine($"{body}}}");
            }
            else
            {
                var initializer = ShouldInitializeSkeletonMember(type) && !property.IsAbstract
                    ? " = default!;"
                    : "";
                builder.AppendLine($"{body}{modifiers}{propertyType} {propertyName} {accessors}{initializer}");
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

    private static void AppendDelegate(StringBuilder builder, TypeModel type, string indent)
    {
        var invoke = type.Methods.FirstOrDefault(method => method.Name == "Invoke");
        var name = CleanName(type.Name);
        var declaredGenericParameters = type.GenericParameters
            .Skip(type.InheritedGenericParameterCount)
            .ToArray();
        if (declaredGenericParameters.Length > 0)
        {
            name += $"<{string.Join(", ", FormatDeclaredTypeParameters(type))}>";
        }

        var returnType = invoke is null
            ? "void"
            : Humanize(invoke.ReturnType, type.GenericParameters, invoke.GenericParameters);
        var parameters = invoke is null
            ? ""
            : string.Join(", ", invoke.Parameters.Select(parameter =>
                $"{Humanize(parameter.Type, type.GenericParameters, invoke.GenericParameters)} {SafeName(parameter.Name)}"));
        AppendConstrainedDeclaration(
            builder,
            $"{indent}{type.Accessibility}{(RequiresUnsafeContext(type) ? " unsafe" : "")} delegate " +
            $"{returnType} {name}({parameters})",
            indent + "    ",
            BuildTypeConstraintClauses(type),
            terminator: ";");
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
            : $"<{string.Join(", ", method.GenericParameters.Select(FormatGenericParameterIdentifier))}>";
        var returnType = Humanize(method.ReturnType, type.GenericParameters, method.GenericParameters);
        var header = $"{body}{modifiers}{returnType} {SafeName(method.Name)}{generics}({parameters})";
        var constraintClauses = BuildMethodConstraintClauses(type, method);

        var noBody = type.Kind == "interface" || method.IsAbstract;
        if (noBody)
        {
            AppendConstrainedDeclaration(
                builder,
                header,
                body + "    ",
                constraintClauses,
                terminator: ";");
            return;
        }

        AppendConstrainedDeclaration(
            builder,
            header,
            body + "    ",
            constraintClauses,
            terminator: "");
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
        if (type.Kind == "interface" || IsExplicitInterfaceMember(method.Name))
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

        if (RequiresUnsafeContext(type))
        {
            parts.Add("unsafe");
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
            name += $"<{string.Join(", ", FormatDeclaredTypeParameters(type))}>";
        }

        parts.Add(name);

        var bases = new List<string>();
        if (type.Kind is "class" && !string.IsNullOrEmpty(type.BaseType) && type.BaseType != "System.Object")
        {
            bases.Add(Humanize(type.BaseType!, type.GenericParameters, []));
        }

        bases.AddRange(type.Interfaces
            .Where(name => ShouldEmitInterface(type, name))
            .Select(name => Humanize(name, type.GenericParameters, [])));

        var declaration = string.Join(" ", parts);
        if (type.Kind == "enum")
        {
            var underlyingType = SkeletonSupport.EnumUnderlyingType(type);
            return underlyingType == "int" ? declaration : $"{declaration} : {underlyingType}";
        }

        return bases.Count == 0 ? declaration : $"{declaration} : {string.Join(", ", bases)}";
    }

    internal static bool RequiresUnsafeContext(TypeModel type)
    {
        if (type.Kind == "enum")
        {
            return false;
        }

        if (type.Kind == "delegate")
        {
            var invoke = type.Methods.FirstOrDefault(method => method.Name == "Invoke");
            return invoke is not null && RequiresUnsafeContext(invoke);
        }

        var eventNames = type.Events.Select(@event => @event.Name).ToHashSet(StringComparer.Ordinal);
        return type.Fields.Any(field =>
                   !IsCompilerGenerated(field.Name) &&
                   field.Name != "value__" &&
                   !eventNames.Contains(field.Name) &&
                   RequiresUnsafeContext(field.Type)) ||
               type.Properties.Any(property =>
                   !IsCompilerGenerated(property.Name) &&
                   (RequiresUnsafeContext(property.Type) ||
                    property.Parameters.Any(parameter => RequiresUnsafeContext(parameter.Type)))) ||
               type.Events.Any(@event =>
                   !IsCompilerGenerated(@event.Name) &&
                   RequiresUnsafeContext(@event.Type)) ||
               type.Methods.Any(method =>
                   !ShouldSkipMethod(method) &&
                   !(type.IsStatic && method.IsConstructor) &&
                   RequiresUnsafeContext(method));
    }

    private static bool RequiresUnsafeContextInTree(
        TypeModel type,
        IReadOnlyDictionary<string, TypeModel[]> nestedTypesByDeclaringType,
        HashSet<string> activeTypes)
    {
        if (!activeTypes.Add(type.FullName))
        {
            return false;
        }

        try
        {
            if (RequiresUnsafeContext(type))
            {
                return true;
            }

            if (type.Kind is "delegate" or "enum")
            {
                return false;
            }

            return nestedTypesByDeclaringType.TryGetValue(type.FullName, out var children) &&
                children.Any(child => RequiresUnsafeContextInTree(
                    child,
                    nestedTypesByDeclaringType,
                    activeTypes));
        }
        finally
        {
            activeTypes.Remove(type.FullName);
        }
    }

    private static bool RequiresUnsafeContext(MethodModel method) =>
        method.RequiresUnsafeContext ||
        RequiresUnsafeContext(method.ReturnType) ||
        method.Parameters.Any(parameter => RequiresUnsafeContext(parameter.Type));

    private static bool RequiresUnsafeContext(string typeName) => typeName.Contains('*');

    private static void AppendConstrainedDeclaration(
        StringBuilder builder,
        string declaration,
        string constraintIndent,
        IReadOnlyList<string> constraintClauses,
        string terminator)
    {
        if (constraintClauses.Count == 0)
        {
            builder.AppendLine(declaration + terminator);
            return;
        }

        builder.AppendLine(declaration);
        for (var index = 0; index < constraintClauses.Count; index++)
        {
            builder.Append(constraintIndent).Append(constraintClauses[index]);
            if (index == constraintClauses.Count - 1)
            {
                builder.Append(terminator);
            }

            builder.AppendLine();
        }
    }

    private static IReadOnlyList<string> FormatDeclaredTypeParameters(TypeModel type)
    {
        if (type.InheritedGenericParameterCount < 0 ||
            type.InheritedGenericParameterCount > type.GenericParameters.Count)
        {
            return type.GenericParameters;
        }

        var names = type.GenericParameters
            .Skip(type.InheritedGenericParameterCount)
            .Select(FormatGenericParameterIdentifier)
            .ToArray();
        if (type.Kind is not ("interface" or "delegate") ||
            !TryGetCompleteGenericParameterDetails(
                type.GenericParameters,
                type.GenericParameterDetails,
                type.GenericParametersComplete,
                out var details))
        {
            return names;
        }

        return details
            .Skip(type.InheritedGenericParameterCount)
            .Select(parameter => parameter.Variance switch
            {
                "out" => $"out {FormatGenericParameterIdentifier(parameter.Name)}",
                "in" => $"in {FormatGenericParameterIdentifier(parameter.Name)}",
                _ => FormatGenericParameterIdentifier(parameter.Name)
            })
            .ToArray();
    }

    private static IReadOnlyList<string> BuildTypeConstraintClauses(TypeModel type)
    {
        if (type.InheritedGenericParameterCount < 0 ||
            type.InheritedGenericParameterCount > type.GenericParameters.Count ||
            !TryGetCompleteGenericParameterDetails(
                type.GenericParameters,
                type.GenericParameterDetails,
                type.GenericParametersComplete,
                out var details))
        {
            return [];
        }

        return TryBuildConstraintClauses(
            details.Skip(type.InheritedGenericParameterCount),
            ownerUsesMethodParameters: false,
            new GenericConstraintEmissionContext(type.GenericParameters, details, [], []),
            out var clauses)
            ? clauses
            : [];
    }

    private static IReadOnlyList<string> BuildMethodConstraintClauses(TypeModel type, MethodModel method)
    {
        // Override 與 explicit interface implementation 會從原宣告繼承 constraints；
        // C# 不允許在實作端完整重複，否則會產生 CS0460。
        if (IsExplicitInterfaceMember(method.Name) ||
            method.IsVirtual && !method.IsNewSlot ||
            !TryGetCompleteGenericParameterDetails(
                method.GenericParameters,
                method.GenericParameterDetails,
                method.GenericParametersComplete,
                out var details))
        {
            return [];
        }

        IReadOnlyList<GenericParameterModel>? typeDetails = null;
        if (TryGetCompleteGenericParameterDetails(
                type.GenericParameters,
                type.GenericParameterDetails,
                type.GenericParametersComplete,
                out var completeTypeDetails))
        {
            typeDetails = completeTypeDetails;
        }

        return TryBuildConstraintClauses(
            details,
            ownerUsesMethodParameters: true,
            new GenericConstraintEmissionContext(
                type.GenericParameters,
                typeDetails,
                method.GenericParameters,
                details),
            out var clauses)
            ? clauses
            : [];
    }

    private static bool TryGetCompleteGenericParameterDetails(
        IReadOnlyList<string> names,
        IReadOnlyList<GenericParameterModel> details,
        bool ownerComplete,
        out IReadOnlyList<GenericParameterModel> completeDetails)
    {
        completeDetails = details;
        if (!ownerComplete || names.Count != details.Count)
        {
            return false;
        }

        for (var index = 0; index < details.Count; index++)
        {
            var parameter = details[index];
            if (!parameter.Complete ||
                parameter.Position != index ||
                parameter.Name != names[index] ||
                parameter.Variance is not ("none" or "out" or "in") ||
                parameter.TypeConstraints.Any(constraint => !constraint.Complete))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryBuildConstraintClauses(
        IEnumerable<GenericParameterModel> parameters,
        bool ownerUsesMethodParameters,
        GenericConstraintEmissionContext context,
        out IReadOnlyList<string> clauses)
    {
        var ownerParameters = parameters.ToArray();
        if (!HasAcyclicOwnerConstraints(ownerParameters, ownerUsesMethodParameters))
        {
            clauses = [];
            return false;
        }

        var result = new List<string>();
        var traitCache = new Dictionary<GenericParameterReference, GenericParameterTraits>();
        foreach (var parameter in ownerParameters)
        {
            if (!TryBuildConstraintValues(
                    parameter,
                    ownerUsesMethodParameters,
                    context,
                    traitCache,
                    out var constraints))
            {
                clauses = [];
                return false;
            }

            if (constraints.Count > 0)
            {
                result.Add(
                    $"where {FormatGenericParameterIdentifier(parameter.Name)} : " +
                    string.Join(", ", constraints));
            }
        }

        clauses = result;
        return true;
    }

    private static bool TryBuildConstraintValues(
        GenericParameterModel parameter,
        bool isMethodParameter,
        GenericConstraintEmissionContext context,
        Dictionary<GenericParameterReference, GenericParameterTraits> traitCache,
        out IReadOnlyList<string> values)
    {
        values = [];
        var parameterReference = new GenericParameterReference(
            isMethodParameter,
            parameter.Position);
        if (!TryGetGenericParameterTraits(
                parameterReference,
                context,
                traitCache,
                [],
                out _))
        {
            return false;
        }

        var result = new List<string>();
        if (parameter.NotNullableValueTypeConstraint)
        {
            result.Add(parameter.HasUnmanagedAttribute ? "unmanaged" : "struct");
        }
        else if (parameter.ReferenceTypeConstraint)
        {
            switch (parameter.Nullability)
            {
                case "annotated":
                    result.Add("class?");
                    break;
                case "oblivious":
                case "not-annotated":
                    result.Add("class");
                    break;
                default:
                    return false;
            }
        }
        else if (parameter.NotNullConstraint)
        {
            result.Add("notnull");
        }

        var ordinaryConstraints = new List<(GenericTypeConstraintModel Constraint, int Index)>();
        var valueTypeMarkers = 0;
        for (var index = 0; index < parameter.TypeConstraints.Count; index++)
        {
            var constraint = parameter.TypeConstraints[index];
            if (!constraint.Complete)
            {
                return false;
            }

            if (constraint.Kind == "value-type-marker")
            {
                valueTypeMarkers++;
                if (!IsRepresentedValueTypeMarker(parameter, constraint))
                {
                    return false;
                }

                continue;
            }

            if (constraint.Kind is not ("class" or "type-parameter" or "interface") ||
                constraint.RequiredModifiers.Count > 0 ||
                constraint.OptionalModifiers.Count > 0)
            {
                return false;
            }

            ordinaryConstraints.Add((constraint, index));
        }

        if (valueTypeMarkers != (parameter.NotNullableValueTypeConstraint ? 1 : 0))
        {
            return false;
        }

        var renderedConstraints = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in ordinaryConstraints
                     .OrderBy(item => ConstraintKindOrder(item.Constraint.Kind))
                     .ThenBy(item => item.Index))
        {
            if (!TryRenderTypeConstraint(
                    item.Constraint,
                    context,
                    out var rendered,
                    out var identity,
                    out _) ||
                !renderedConstraints.Add(identity))
            {
                return false;
            }

            result.Add(rendered);
        }

        if (parameter.DefaultConstructorConstraint &&
            !parameter.NotNullableValueTypeConstraint)
        {
            result.Add("new()");
        }

        if (parameter.AllowsRefStruct)
        {
            result.Add("allows ref struct");
        }

        values = result;
        return true;
    }

    private static bool IsRepresentedValueTypeMarker(
        GenericParameterModel parameter,
        GenericTypeConstraintModel constraint)
    {
        if (constraint.Type != "System.ValueType" ||
            constraint.OptionalModifiers.Count > 0 ||
            constraint.Nullability == "annotated")
        {
            return false;
        }

        return parameter.HasUnmanagedAttribute
            ? constraint.RequiredModifiers.SequenceEqual(
                ["System.Runtime.InteropServices.UnmanagedType"],
                StringComparer.Ordinal)
            : constraint.RequiredModifiers.Count == 0;
    }

    private static int ConstraintKindOrder(string kind) => kind switch
    {
        "class" => 0,
        "type-parameter" => 1,
        _ => 2
    };

    private static bool TryRenderTypeConstraint(
        GenericTypeConstraintModel constraint,
        GenericConstraintEmissionContext context,
        out string rendered,
        out string identity,
        out GenericParameterReference? referencedParameter)
    {
        rendered = string.Empty;
        identity = string.Empty;
        referencedParameter = null;
        if (constraint.NullableFlags.Count > 1 ||
            constraint.NullableFlags.Any(flag => flag > 2) ||
            constraint.Kind is "class" or "interface" &&
            (constraint.Type.Contains('<', StringComparison.Ordinal) ||
             constraint.Type.Contains('`', StringComparison.Ordinal)) ||
            !HasUnshadowedGenericParameterReferences(constraint.Type, context) ||
            !TryHumanize(constraint.Type, context.TypeNames, context.MethodNames, out rendered))
        {
            return false;
        }

        if (constraint.Kind == "type-parameter")
        {
            if (!TryParseGenericParameterReference(constraint.Type, out var reference) ||
                !TryResolveGenericParameter(reference, context, out _))
            {
                return false;
            }

            referencedParameter = reference;
        }

        identity = rendered.EndsWith("?", StringComparison.Ordinal)
            ? rendered[..^1]
            : rendered;

        switch (constraint.Nullability)
        {
            case "annotated":
                if (!rendered.EndsWith("?", StringComparison.Ordinal))
                {
                    rendered += "?";
                }

                break;
            case "oblivious":
            case "not-annotated":
                break;
            default:
                return false;
        }

        return constraint.Kind != "class" ||
               identity is not ("System.Object" or "System.Array" or "System.ValueType");
    }

    private static bool HasUnshadowedGenericParameterReferences(
        string type,
        GenericConstraintEmissionContext context)
    {
        var position = 0;
        while (position < type.Length)
        {
            if (type[position] != '!')
            {
                position++;
                continue;
            }

            var isMethodParameter = position + 1 < type.Length && type[position + 1] == '!';
            var digitStart = position + (isMethodParameter ? 2 : 1);
            var digitEnd = digitStart;
            var parameterIndex = 0;
            var overflow = false;
            while (digitEnd < type.Length && type[digitEnd] is >= '0' and <= '9')
            {
                var digit = type[digitEnd] - '0';
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

            if (digitEnd == digitStart ||
                digitEnd < type.Length &&
                (char.IsLetterOrDigit(type[digitEnd]) || type[digitEnd] == '_'))
            {
                return false;
            }

            var names = isMethodParameter ? context.MethodNames : context.TypeNames;
            if (overflow || parameterIndex >= names.Count)
            {
                return false;
            }

            var parameterName = names[parameterIndex];
            if (names.Skip(parameterIndex + 1).Contains(parameterName, StringComparer.Ordinal) ||
                !isMethodParameter && context.MethodNames.Contains(parameterName, StringComparer.Ordinal))
            {
                return false;
            }

            position = digitEnd;
        }

        return true;
    }

    private static bool HasAcyclicOwnerConstraints(
        IReadOnlyList<GenericParameterModel> parameters,
        bool ownerUsesMethodParameters)
    {
        var parametersByPosition = new Dictionary<int, GenericParameterModel>();
        foreach (var parameter in parameters)
        {
            if (!parametersByPosition.TryAdd(parameter.Position, parameter))
            {
                return false;
            }
        }

        var states = new Dictionary<int, byte>();
        foreach (var position in parametersByPosition.Keys)
        {
            if (!Visit(position, 0))
            {
                return false;
            }
        }

        return true;

        bool Visit(int position, int depth)
        {
            if (depth > MaxGenericConstraintDependencyDepth)
            {
                return false;
            }

            if (states.TryGetValue(position, out var state))
            {
                return state == 2;
            }

            states[position] = 1;
            foreach (var constraint in parametersByPosition[position].TypeConstraints)
            {
                if (constraint.Kind != "type-parameter")
                {
                    continue;
                }

                if (!TryParseGenericParameterReference(constraint.Type, out var reference))
                {
                    return false;
                }

                if (reference.IsMethodParameter != ownerUsesMethodParameters ||
                    !parametersByPosition.ContainsKey(reference.Position))
                {
                    continue;
                }

                if (states.TryGetValue(reference.Position, out var targetState) && targetState == 1 ||
                    !Visit(reference.Position, depth + 1))
                {
                    return false;
                }
            }

            states[position] = 2;
            return true;
        }
    }

    private static bool TryParseGenericParameterReference(
        string type,
        out GenericParameterReference reference)
    {
        reference = default;
        if (type.Length < 2 || type[0] != '!')
        {
            return false;
        }

        var isMethodParameter = type.Length > 1 && type[1] == '!';
        var digitStart = isMethodParameter ? 2 : 1;
        if (digitStart == type.Length)
        {
            return false;
        }

        var position = 0;
        for (var index = digitStart; index < type.Length; index++)
        {
            if (type[index] is not (>= '0' and <= '9'))
            {
                return false;
            }

            var digit = type[index] - '0';
            if (position > (int.MaxValue - digit) / 10)
            {
                return false;
            }

            position = (position * 10) + digit;
        }

        reference = new GenericParameterReference(isMethodParameter, position);
        return true;
    }

    private static bool TryResolveGenericParameter(
        GenericParameterReference reference,
        GenericConstraintEmissionContext context,
        out GenericParameterModel parameter)
    {
        parameter = null!;
        var names = reference.IsMethodParameter ? context.MethodNames : context.TypeNames;
        var details = reference.IsMethodParameter ? context.MethodDetails : context.TypeDetails;
        if (details is null ||
            details.Count != names.Count ||
            reference.Position < 0 ||
            reference.Position >= details.Count)
        {
            return false;
        }

        parameter = details[reference.Position];
        return parameter.Complete &&
               parameter.Position == reference.Position &&
               parameter.Name == names[reference.Position] &&
               parameter.TypeConstraints.All(constraint => constraint.Complete);
    }

    private static bool TryGetGenericParameterTraits(
        GenericParameterReference reference,
        GenericConstraintEmissionContext context,
        Dictionary<GenericParameterReference, GenericParameterTraits> cache,
        HashSet<GenericParameterReference> active,
        out GenericParameterTraits traits)
    {
        if (cache.TryGetValue(reference, out var cachedTraits))
        {
            traits = cachedTraits;
            return true;
        }

        traits = null!;
        if (!TryResolveGenericParameter(reference, context, out var parameter) ||
            !HasRepresentablePrimaryConstraintShape(parameter))
        {
            return false;
        }

        if (active.Count >= MaxGenericConstraintDependencyDepth || !active.Add(reference))
        {
            return false;
        }

        try
        {
            var concreteBaseTypes = new HashSet<string>(StringComparer.Ordinal);
            var requiresReferenceType = parameter.ReferenceTypeConstraint;
            var directClassConstraints = 0;
            var valueTypeMarkers = 0;
            foreach (var constraint in parameter.TypeConstraints)
            {
                if (!constraint.Complete)
                {
                    return false;
                }

                if (constraint.Kind == "value-type-marker")
                {
                    valueTypeMarkers++;
                    if (!IsRepresentedValueTypeMarker(parameter, constraint))
                    {
                        return false;
                    }

                    continue;
                }

                if (constraint.Kind is not ("class" or "type-parameter" or "interface") ||
                    constraint.RequiredModifiers.Count > 0 ||
                    constraint.OptionalModifiers.Count > 0 ||
                    !TryRenderTypeConstraint(
                        constraint,
                        context,
                        out _,
                        out var identity,
                        out var targetReference))
                {
                    return false;
                }

                if (constraint.Kind == "class")
                {
                    directClassConstraints++;
                    if (!concreteBaseTypes.Add(identity))
                    {
                        return false;
                    }

                    if (identity != "System.Enum")
                    {
                        requiresReferenceType = true;
                    }

                    continue;
                }

                if (constraint.Kind != "type-parameter")
                {
                    continue;
                }

                if (targetReference is not { } target ||
                    !TryGetGenericParameterTraits(target, context, cache, active, out var targetTraits) ||
                    targetTraits.HasValueTypeConstraint)
                {
                    return false;
                }

                if (parameter.NotNullableValueTypeConstraint && targetTraits.RequiresReferenceType)
                {
                    return false;
                }

                requiresReferenceType |= targetTraits.RequiresReferenceType;
                concreteBaseTypes.UnionWith(targetTraits.ConcreteBaseTypes);
            }

            if (valueTypeMarkers != (parameter.NotNullableValueTypeConstraint ? 1 : 0) ||
                directClassConstraints > 1 ||
                concreteBaseTypes.Count > 1 ||
                parameter.ReferenceTypeConstraint && directClassConstraints > 0 ||
                parameter.ReferenceTypeConstraint && concreteBaseTypes.Contains("System.Enum") ||
                parameter.NotNullableValueTypeConstraint && requiresReferenceType ||
                parameter.AllowsRefStruct &&
                (parameter.ReferenceTypeConstraint ||
                 concreteBaseTypes.Any(type => type != "System.Enum")))
            {
                return false;
            }

            traits = new GenericParameterTraits(
                parameter.NotNullableValueTypeConstraint,
                requiresReferenceType,
                concreteBaseTypes);
            cache[reference] = traits;
            return true;
        }
        finally
        {
            active.Remove(reference);
        }
    }

    private static bool HasRepresentablePrimaryConstraintShape(GenericParameterModel parameter) =>
        parameter.Complete &&
        !(parameter.ReferenceTypeConstraint && parameter.NotNullableValueTypeConstraint) &&
        !(parameter.NotNullConstraint &&
          (parameter.ReferenceTypeConstraint || parameter.NotNullableValueTypeConstraint)) &&
        !(parameter.HasUnmanagedAttribute && !parameter.NotNullableValueTypeConstraint) &&
        !(parameter.NotNullableValueTypeConstraint && !parameter.DefaultConstructorConstraint) &&
        !(parameter.NotNullConstraint && parameter.Name == "notnull") &&
        !(parameter.HasUnmanagedAttribute && parameter.Name == "unmanaged");

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

    private static bool IsByRefType(string typeName) =>
        typeName.StartsWith("ref ", StringComparison.Ordinal);

    private static bool ShouldSkipMethod(MethodModel method)
    {
        if (method.Name is ".cctor")
        {
            return true;
        }

        var unqualifiedName = method.Name[(method.Name.LastIndexOf('.') + 1)..];
        return unqualifiedName.StartsWith("get_", StringComparison.Ordinal)
            || unqualifiedName.StartsWith("set_", StringComparison.Ordinal)
            || unqualifiedName.StartsWith("add_", StringComparison.Ordinal)
            || unqualifiedName.StartsWith("remove_", StringComparison.Ordinal)
            || unqualifiedName.StartsWith("op_", StringComparison.Ordinal)
            || IsCompilerGenerated(method.Name);
    }

    private static bool IsExplicitInterfaceMember(string name) =>
        name.Contains('.', StringComparison.Ordinal);

    private static string FormatIndexerName(PropertyModel property, IReadOnlyList<string> typeGenerics)
    {
        var parameters = string.Join(", ", property.Parameters.Select(parameter =>
            $"{Humanize(parameter.Type, typeGenerics, [])} {SafeName(parameter.Name)}"));
        var separator = property.Name.LastIndexOf('.');
        if (separator < 0)
        {
            return $"this[{parameters}]";
        }

        var qualifier = Humanize(property.Name[..separator], typeGenerics, []);
        return $"{qualifier}.this[{parameters}]";
    }

    private static string Humanize(
        string typeText,
        IReadOnlyList<string> typeGenerics,
        IReadOnlyList<string> methodGenerics)
    {
        TryHumanize(typeText, typeGenerics, methodGenerics, out var humanized);
        return humanized;
    }

    private static bool TryHumanize(
        string typeText,
        IReadOnlyList<string> typeGenerics,
        IReadOnlyList<string> methodGenerics,
        out string humanized)
    {
        var builder = new StringBuilder(typeText.Length);
        var complete = true;
        var position = 0;
        while (position < typeText.Length)
        {
            if (typeText[position] != '!')
            {
                builder.Append(typeText[position++]);
                continue;
            }

            var isMethodParameter = position + 1 < typeText.Length && typeText[position + 1] == '!';
            var digitStart = position + (isMethodParameter ? 2 : 1);
            var digitEnd = digitStart;
            var parameterIndex = 0;
            var overflow = false;
            while (digitEnd < typeText.Length && typeText[digitEnd] is >= '0' and <= '9')
            {
                var digit = typeText[digitEnd] - '0';
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

            var isCompleteToken = digitEnd > digitStart &&
                                  (digitEnd == typeText.Length ||
                                   !(char.IsLetterOrDigit(typeText[digitEnd]) || typeText[digitEnd] == '_'));
            if (!isCompleteToken)
            {
                builder.Append(typeText[position++]);
                continue;
            }

            var parameters = isMethodParameter ? methodGenerics : typeGenerics;
            if (!overflow && parameterIndex < parameters.Count)
            {
                builder.Append(FormatGenericParameterIdentifier(parameters[parameterIndex]));
            }
            else
            {
                builder.Append(typeText, position, digitEnd - position);
                complete = false;
            }

            position = digitEnd;
        }

        humanized = builder.ToString();
        return complete;
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
                builder.Append(FormatGenericParameterIdentifier(parameters[parameterIndex]));
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

    private static string FormatGenericParameterIdentifier(string name) =>
        CSharpReservedKeywords.Contains(name) ? $"@{name}" : name;

    private static bool IsCompilerGenerated(string name) =>
        name.Contains('<', StringComparison.Ordinal) || name.Contains('>', StringComparison.Ordinal);

    internal static bool ContainsCompilerGeneratedTypeSegment(string name)
    {
        for (var index = name.IndexOf('<', StringComparison.Ordinal);
             index >= 0;
             index = name.IndexOf('<', index + 1))
        {
            if (index == 0 || name[index - 1] is '.' or '<')
            {
                return true;
            }

            var previous = index - 1;
            while (previous >= 0 && char.IsWhiteSpace(name[previous]))
            {
                previous--;
            }

            if (previous >= 0 && name[previous] == ',')
            {
                return true;
            }
        }

        return false;
    }

    internal static bool ShouldEmitInterface(TypeModel type, string name)
    {
        if (ContainsCompilerGeneratedTypeSegment(name))
        {
            return false;
        }

        var genericStart = name.IndexOf('<', StringComparison.Ordinal);
        if (genericStart < 0)
        {
            return true;
        }

        if (!TryGetSingleGenericArgument(name, genericStart, out var argument))
        {
            return false;
        }

        // collection 類泛型介面的 explicit accessor／out 參數契約仍待完整支援。
        // 只有目前 member generator 確定會輸出完整公開契約時才保留介面，避免合法輸入產生 CS0535。
        return name[..genericStart] switch
        {
            "System.Collections.Generic.IEnumerator" => type.Properties.Any(property =>
                property.Name == "Current" &&
                property.Accessibility == "public" &&
                (property.GetterAccessibility ?? property.Accessibility) == "public" &&
                property.HasGetter &&
                !property.IsStatic &&
                property.Parameters.Count == 0 &&
                SameContractType(property.Type, argument)),
            "System.Collections.Generic.IEqualityComparer" =>
                HasPublicInstanceMethod(type, "Equals", "bool", [argument, argument]) &&
                HasPublicInstanceMethod(type, "GetHashCode", "int", [argument]),
            _ => false
        };
    }

    private static bool TryGetSingleGenericArgument(string name, int genericStart, out string argument)
    {
        argument = string.Empty;
        if (genericStart <= 0 || genericStart >= name.Length - 2 || name[^1] != '>')
        {
            return false;
        }

        var depth = 0;
        for (var index = genericStart; index < name.Length; index++)
        {
            switch (name[index])
            {
                case '<':
                    depth++;
                    break;
                case '>':
                    depth--;
                    if (depth < 0 || (depth == 0 && index != name.Length - 1))
                    {
                        return false;
                    }

                    break;
                case ',' when depth == 1:
                    return false;
            }
        }

        if (depth != 0)
        {
            return false;
        }

        argument = name[(genericStart + 1)..^1].Trim();
        return argument.Length > 0;
    }

    private static bool HasPublicInstanceMethod(
        TypeModel type,
        string name,
        string returnType,
        IReadOnlyList<string> parameterTypes) =>
        type.Methods.Any(method =>
            method.Name == name &&
            method.Accessibility == "public" &&
            !method.IsStatic &&
            !method.IsConstructor &&
            method.GenericParameters.Count == 0 &&
            SameContractType(method.ReturnType, returnType) &&
            method.Parameters.Select(parameter => NormalizeContractType(parameter.Type)).SequenceEqual(
                parameterTypes.Select(NormalizeContractType),
                StringComparer.Ordinal));

    private static bool SameContractType(string left, string right) =>
        string.Equals(
            NormalizeContractType(left),
            NormalizeContractType(right),
            StringComparison.Ordinal);

    private static string NormalizeContractType(string typeName)
    {
        var normalized = typeName.Trim();
        if (!normalized.EndsWith('?'))
        {
            return normalized;
        }

        var withoutAnnotation = normalized[..^1].TrimEnd();
        var digitStart = withoutAnnotation.StartsWith("!!", StringComparison.Ordinal) ? 2 : 1;
        return withoutAnnotation.StartsWith('!') &&
               digitStart < withoutAnnotation.Length &&
               withoutAnnotation[digitStart..].All(character => character is >= '0' and <= '9')
            ? withoutAnnotation
            : normalized;
    }

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

    private static string BuildProjectFile(
        IEnumerable<string> projectReferences,
        bool allowUnsafeBlocks)
    {
        var references = projectReferences.ToArray();
        var builder = new StringBuilder();
        builder.AppendLine("<Project Sdk=\"Microsoft.NET.Sdk\">");
        builder.AppendLine("  <PropertyGroup>");
        builder.AppendLine("    <TargetFramework>net10.0</TargetFramework>");
        builder.AppendLine("    <Nullable>enable</Nullable>");
        builder.AppendLine("    <ImplicitUsings>enable</ImplicitUsings>");
        if (allowUnsafeBlocks)
        {
            builder.AppendLine("    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>");
        }

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

        目前會還原型別、泛型 variance 與可安全表示的 where constraints、欄位、屬性、事件、方法簽章與繼承關係；pointer owner 會取得 scoped unsafe context，可安全結構化的方法也會帶回方法體，
        其餘方法會保留 IL 並使用 `NotImplementedException`，
        需要對照原程式的 IL 或反組譯結果補回實作。

        用途是拿來對照結構、接手改寫或轉成其他語言的起點，不保證能直接編譯：
        套件外依賴、運算子多載與 P/Invoke 等尚未完整處理。

        """;

    private sealed record ProjectDescriptor(
        FileArtifact Artifact,
        string AssemblyName,
        string ProjectDirectory);

    private readonly record struct GenericConstraintEmissionContext(
        IReadOnlyList<string> TypeNames,
        IReadOnlyList<GenericParameterModel>? TypeDetails,
        IReadOnlyList<string> MethodNames,
        IReadOnlyList<GenericParameterModel>? MethodDetails);

    private readonly record struct GenericParameterReference(
        bool IsMethodParameter,
        int Position);

    private sealed record GenericParameterTraits(
        bool HasValueTypeConstraint,
        bool RequiresReferenceType,
        IReadOnlySet<string> ConcreteBaseTypes);
}
