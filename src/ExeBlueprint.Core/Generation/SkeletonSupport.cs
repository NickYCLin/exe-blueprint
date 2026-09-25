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

    private static readonly HashSet<string> ReservedFileStems = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$"
    };

    // 產生保證能落地的檔名主幹（單一路徑片段，不含副檔名）：非英數與底線一律換底線，空字串用
    // fallback，撞到 Windows 保留裝置名就前綴底線。組件名可能取自不受信任的輸入 EXE，若直接當檔名，
    // 像 CON、COM1 這類名稱會被 GeneratedProjectWriter 的路徑檢查擋下而讓整包匯出失敗。
    public static string SanitizeFileStem(string value, string fallback) =>
        EnsureWritableSegment(Sanitize(value), fallback);

    // 把已成形的路徑片段（可能含點，例如命名空間或帶點的組件名）整理成 writer 接受的樣子：去掉結尾
    // 的點與空白；空、`.`、`..` 改用 fallback；片段開頭的裝置名前綴底線。不更動片段內部的點，保留
    // 「My.Namespace.cs」這種可讀檔名。
    public static string EnsureWritableSegment(string segment, string fallback)
    {
        var trimmed = segment.TrimEnd('.', ' ');
        if (trimmed.Length == 0 || trimmed is "." or "..")
        {
            return fallback;
        }

        var dot = trimmed.IndexOf('.', StringComparison.Ordinal);
        var stem = dot < 0 ? trimmed : trimmed[..dot];
        return IsReservedFileStem(stem) ? $"_{trimmed}" : trimmed;
    }

    private static bool IsReservedFileStem(string stem) =>
        ReservedFileStems.Contains(stem) ||
        stem.Length == 4 &&
        stem[3] is >= '1' and <= '9' &&
        (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
         stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase));

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

    // 列舉成員的值只接受整數常數，而且字面必須真的是整數。constant 的型別與內容都取自不受信任
    // 的組件 metadata：若照字面寫進原始碼，一個型別為 string 的常數就能在骨架裡塞進任意程式碼
    // （例如 Go 的 func init()），使用者一建置執行就中招。不是整數就不寫值，交由各語言的預設值。
    public static string? IntegralEnumValue(ConstantValueModel? constant) =>
        constant?.Value is { } value &&
        constant.Type is "sbyte" or "byte" or "short" or "ushort" or "int" or "uint" or "long" or "ulong" &&
        IsIntegerLiteral(value)
            ? value
            : null;

    private static bool IsIntegerLiteral(string value)
    {
        var start = value.Length > 0 && value[0] == '-' ? 1 : 0;
        var digits = value.Length - start;
        if (digits is < 1 or > 20)
        {
            return false;
        }

        for (var index = start; index < value.Length; index++)
        {
            if (value[index] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    // 把可能含路徑分隔或檔名非法字元的文字整理成單一片段：/ \ : * ? " < > | 與控制字元換成底線，
    // 內部的點保留。命名空間直接來自 metadata，含 / 會悄悄變成子目錄、含 : 或 * 則讓 writer 拒收。
    public static string SanitizePathSegment(string value)
    {
        var characters = value.Select(character =>
            character is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' || char.IsControl(character)
                ? '_'
                : character);
        return new string(characters.ToArray());
    }

    // 同一個輸出目錄裡的檔名主幹不分大小寫必須唯一：組件名相同（例如各 RID 一份）、A.B 與 A_B
    // 都會整理成同一個主幹，writer 會把重複路徑當成錯誤而讓整包匯出失敗。撞名就加序號。
    public static string UniqueFileStem(HashSet<string> used, string stem)
    {
        var candidate = stem;
        var suffix = 2;
        while (!used.Add(candidate))
        {
            candidate = $"{stem}_{suffix++}";
        }

        return candidate;
    }

    // 把 Sanitize 後的名稱整理成各語言都能接受的識別字骨架：空字串用 fallback、開頭是數字就補底線。
    // 名稱直接來自 metadata，混淆過的組件常有空名稱或以數字開頭的成員。各語言的關鍵字另由呼叫端
    // 處理（Rust 可用 r#，Go 與 C++ 沒有原始識別字語法只能改名）。
    public static string IdentifierStem(string value, string fallback)
    {
        var sanitized = Sanitize(value);
        if (sanitized.Length == 0)
        {
            return fallback;
        }

        return char.IsDigit(sanitized[0]) ? $"_{sanitized}" : sanitized;
    }
}
