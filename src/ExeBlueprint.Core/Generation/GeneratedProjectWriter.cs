using System.Text;

namespace ExeBlueprint.Generation;

public static class GeneratedProjectWriter
{
    public static async Task WriteAsync(
        IReadOnlyList<GeneratedFile> files,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);

        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var target = Path.Combine(outputDirectory, file.RelativePath.Replace('/', Path.DirectorySeparatorChar));
            var directory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(target, file.Content, encoding, cancellationToken).ConfigureAwait(false);
        }
    }
}
