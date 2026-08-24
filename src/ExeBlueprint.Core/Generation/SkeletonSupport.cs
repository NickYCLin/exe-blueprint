using ExeBlueprint.Models;

namespace ExeBlueprint.Generation;

// 多語言骨架產生器共用的挑選與命名工具。
internal static class SkeletonSupport
{
    public static IReadOnlyList<(FileArtifact Artifact, string AssemblyName, IReadOnlyList<TypeModel> Types)> Assemblies(BlueprintDocument document)
    {
        var result = new List<(FileArtifact, string, IReadOnlyList<TypeModel>)>();
        foreach (var artifact in document.Files.Where(file => file.Code is { TypeCount: > 0 }))
        {
            var assemblyName = string.IsNullOrWhiteSpace(artifact.AssemblyName)
                ? Path.GetFileNameWithoutExtension(artifact.FileName)
                : artifact.AssemblyName!;
            var types = artifact.Code!.Types
                .Where(type => !type.IsNested && !IsGenerated(type.Name) && type.Kind != "delegate")
                .ToArray();
            if (types.Length > 0)
            {
                result.Add((artifact, assemblyName, types));
            }
        }

        return result;
    }

    public static bool IsGenerated(string name) =>
        name.Contains('<', StringComparison.Ordinal) || name.Contains('>', StringComparison.Ordinal);

    // 去掉泛型 arity（`1）與泛型參數，取最後一段當簡單型別名。
    public static string SimpleName(string name)
    {
        var text = name;
        var generic = text.IndexOf('`', StringComparison.Ordinal);
        if (generic >= 0)
        {
            text = text[..generic];
        }

        var angle = text.IndexOf('<', StringComparison.Ordinal);
        if (angle >= 0)
        {
            text = text[..angle];
        }

        var dot = text.LastIndexOf('.');
        if (dot >= 0)
        {
            text = text[(dot + 1)..];
        }

        return text.Trim('[', ']', '*', ' ');
    }

    public static string Sanitize(string value)
    {
        var characters = value.Select(character =>
            char.IsLetterOrDigit(character) || character is '_' ? character : '_');
        return new string(characters.ToArray());
    }

    public static IReadOnlyList<MethodModel> EmittableMethods(TypeModel type) =>
        type.Methods
            .Where(method => !method.IsConstructor
                && !IsGenerated(method.Name)
                && !method.Name.StartsWith("get_", StringComparison.Ordinal)
                && !method.Name.StartsWith("set_", StringComparison.Ordinal)
                && !method.Name.StartsWith("add_", StringComparison.Ordinal)
                && !method.Name.StartsWith("remove_", StringComparison.Ordinal)
                && !method.Name.StartsWith("op_", StringComparison.Ordinal))
            .ToArray();

    // 資料成員＝非編譯器產生的欄位＋屬性（record 的狀態都在屬性上）。
    public static IReadOnlyList<(string Name, string Type)> DataMembers(TypeModel type)
    {
        var members = new List<(string, string)>();
        members.AddRange(type.Fields
            .Where(field => !IsGenerated(field.Name))
            .Select(field => (field.Name, field.Type)));
        members.AddRange(type.Properties
            .Where(property => !IsGenerated(property.Name))
            .Select(property => (property.Name, property.Type)));
        return members;
    }

    public static string EnumUnderlyingType(TypeModel type) =>
        type.Fields.FirstOrDefault(field => field.Name == "value__")?.Type ?? "int";

    public static IReadOnlyList<(string Name, ConstantValueModel? ConstantValue)> EnumMembers(TypeModel type) =>
        type.Fields
            .Where(field => field.IsConstant && field.Name != "value__" && !IsGenerated(field.Name))
            .Select(field => (field.Name, field.ConstantValue))
            .ToArray();
}
