namespace ExeBlueprint.Analysis;

internal static class FileClassifier
{
    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".cab", ".jar", ".nupkg", ".appx", ".msix", ".asar"
    };

    private static readonly HashSet<string> ConfigurationExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".config", ".json", ".xml", ".ini", ".yaml", ".yml", ".toml", ".properties", ".manifest"
    };

    private static readonly HashSet<string> ResourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".wav", ".mp3", ".ogg",
        ".ttf", ".otf", ".resx", ".resources", ".dfm", ".pak", ".pck", ".dat"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd", ".py", ".pyc", ".js", ".mjs", ".cjs", ".ts", ".lua", ".ahk", ".au3"
    };

    public static (string Category, string Format) Classify(string path, ReadOnlySpan<byte> header)
    {
        var extension = Path.GetExtension(path);
        if (IsZip(header))
        {
            var format = extension.Equals(".jar", StringComparison.OrdinalIgnoreCase) ? "Java archive" : "ZIP archive";
            return ("archive", format);
        }

        if (ArchiveExtensions.Contains(extension))
        {
            return ("archive", extension.TrimStart('.').ToUpperInvariant() + " archive");
        }

        if (extension.Equals(".msi", StringComparison.OrdinalIgnoreCase) && IsOleCompoundFile(header))
        {
            return ("archive", "Windows Installer package");
        }

        if (extension.Equals(".pdb", StringComparison.OrdinalIgnoreCase))
        {
            return ("debug-symbol", "Program Database");
        }

        if (extension.Equals(".db", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".sqlite", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".sqlite3", StringComparison.OrdinalIgnoreCase) ||
            header.StartsWith("SQLite format 3\0"u8))
        {
            return ("database", "SQLite/database file");
        }

        if (ConfigurationExtensions.Contains(extension))
        {
            return ("configuration", extension.TrimStart('.').ToUpperInvariant() + " configuration");
        }

        if (ResourceExtensions.Contains(extension))
        {
            return ("resource", extension.TrimStart('.').ToUpperInvariant() + " resource");
        }

        if (ScriptExtensions.Contains(extension))
        {
            return ("script", extension.TrimStart('.').ToUpperInvariant() + " script");
        }

        return ("unknown", string.IsNullOrWhiteSpace(extension) ? "Unknown" : extension.TrimStart('.').ToUpperInvariant());
    }

    private static bool IsZip(ReadOnlySpan<byte> header) =>
        header.Length >= 4 &&
        header[0] == 0x50 &&
        header[1] == 0x4B &&
        header[2] is 0x03 or 0x05 or 0x07 &&
        header[3] is 0x04 or 0x06 or 0x08;

    private static bool IsOleCompoundFile(ReadOnlySpan<byte> header) =>
        header.Length >= 8 &&
        header[..8].SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
}
