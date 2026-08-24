using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text;

namespace ExeBlueprint.Analysis;

internal sealed record PeAnalysis
{
    public required bool IsExecutable { get; init; }

    public required bool IsLibrary { get; init; }

    public required bool IsManaged { get; init; }

    public required string Architecture { get; init; }

    public required string Subsystem { get; init; }

    public string? AssemblyName { get; init; }

    public string? AssemblyVersion { get; init; }

    public string? CorFlags { get; init; }

    public bool HasAuthenticodeSignature { get; init; }

    public IReadOnlyList<string> Sections { get; init; } = [];

    public IReadOnlyList<string> ImportedModules { get; init; } = [];

    public IReadOnlyList<string> ManagedReferences { get; init; } = [];
}

internal static class PeAnalyzer
{
    private const int ImportDescriptorSize = 20;
    private const int MaxImportDescriptors = 4096;
    private const int MaxImportNameBytes = 512;

    public static async Task<PeAnalysis?> TryAnalyzeAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            useAsync: true);

        if (!await HasPeSignatureAsync(stream, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        stream.Position = 0;
        using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var headers = peReader.PEHeaders;
        var peHeader = headers.PEHeader ?? throw new BadImageFormatException("PE optional header 不存在。");
        var isLibrary = headers.CoffHeader.Characteristics.HasFlag(Characteristics.Dll) ||
                        peReader.HasMetadata && headers.CorHeader?.EntryPointTokenOrRelativeVirtualAddress == 0;
        var isExecutable = headers.CoffHeader.Characteristics.HasFlag(Characteristics.ExecutableImage) && !isLibrary;
        var managedReferences = new List<string>();
        string? assemblyName = null;
        string? assemblyVersion = null;

        if (peReader.HasMetadata)
        {
            var metadata = peReader.GetMetadataReader();
            if (metadata.IsAssembly)
            {
                var definition = metadata.GetAssemblyDefinition();
                assemblyName = metadata.GetString(definition.Name);
                assemblyVersion = definition.Version.ToString();
            }

            foreach (var handle in metadata.AssemblyReferences)
            {
                var reference = metadata.GetAssemblyReference(handle);
                managedReferences.Add(metadata.GetString(reference.Name));
            }
        }

        var importedModules = ReadImportedModules(stream, headers);
        return new PeAnalysis
        {
            IsExecutable = isExecutable,
            IsLibrary = isLibrary,
            IsManaged = peReader.HasMetadata,
            Architecture = GetArchitecture(headers.CoffHeader.Machine),
            Subsystem = peHeader.Subsystem.ToString(),
            AssemblyName = assemblyName,
            AssemblyVersion = assemblyVersion,
            CorFlags = headers.CorHeader?.Flags.ToString(),
            HasAuthenticodeSignature = peHeader.CertificateTableDirectory.Size > 0,
            Sections = headers.SectionHeaders
                .Select(section => section.Name)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
            ImportedModules = importedModules,
            ManagedReferences = managedReferences
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray()
        };
    }

    private static async Task<bool> HasPeSignatureAsync(FileStream stream, CancellationToken cancellationToken)
    {
        if (stream.Length < 64)
        {
            return false;
        }

        var dosHeader = new byte[64];
        await stream.ReadExactlyAsync(dosHeader, cancellationToken).ConfigureAwait(false);
        if (dosHeader[0] != (byte)'M' || dosHeader[1] != (byte)'Z')
        {
            return false;
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader.AsSpan(0x3C, 4));
        if (peOffset < 64 || peOffset > stream.Length - 4)
        {
            return false;
        }

        stream.Position = peOffset;
        var signature = new byte[4];
        await stream.ReadExactlyAsync(signature, cancellationToken).ConfigureAwait(false);
        return signature.AsSpan().SequenceEqual("PE\0\0"u8);
    }

    private static IReadOnlyList<string> ReadImportedModules(FileStream stream, PEHeaders headers)
    {
        var directory = headers.PEHeader?.ImportTableDirectory ?? default;
        if (directory.RelativeVirtualAddress == 0 || directory.Size == 0)
        {
            return [];
        }

        if (!TryRvaToOffset(headers, directory.RelativeVirtualAddress, out var descriptorOffset))
        {
            return [];
        }

        var modules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Span<byte> descriptor = stackalloc byte[ImportDescriptorSize];

        for (var index = 0; index < MaxImportDescriptors; index++)
        {
            var offset = descriptorOffset + (long)index * ImportDescriptorSize;
            if (offset < 0 || offset > stream.Length - ImportDescriptorSize)
            {
                break;
            }

            stream.Position = offset;
            stream.ReadExactly(descriptor);
            if (descriptor.IndexOfAnyExcept((byte)0) < 0)
            {
                break;
            }

            var nameRva = BinaryPrimitives.ReadInt32LittleEndian(descriptor.Slice(12, 4));
            if (nameRva <= 0 || !TryRvaToOffset(headers, nameRva, out var nameOffset))
            {
                continue;
            }

            var module = ReadNullTerminatedAscii(stream, nameOffset);
            if (!string.IsNullOrWhiteSpace(module))
            {
                modules.Add(module);
            }
        }

        return modules.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool TryRvaToOffset(PEHeaders headers, int rva, out long offset)
    {
        var peHeader = headers.PEHeader;
        if (peHeader is not null && rva >= 0 && rva < peHeader.SizeOfHeaders)
        {
            offset = rva;
            return true;
        }

        foreach (var section in headers.SectionHeaders)
        {
            var sectionSize = Math.Max(section.VirtualSize, section.SizeOfRawData);
            var sectionEnd = (long)section.VirtualAddress + sectionSize;
            if (rva < section.VirtualAddress || rva >= sectionEnd)
            {
                continue;
            }

            offset = (long)section.PointerToRawData + (rva - section.VirtualAddress);
            return true;
        }

        offset = 0;
        return false;
    }

    private static string ReadNullTerminatedAscii(FileStream stream, long offset)
    {
        if (offset < 0 || offset >= stream.Length)
        {
            return string.Empty;
        }

        stream.Position = offset;
        var bytes = new List<byte>();
        for (var index = 0; index < MaxImportNameBytes; index++)
        {
            var value = stream.ReadByte();
            if (value <= 0)
            {
                break;
            }

            bytes.Add((byte)value);
        }

        return Encoding.ASCII.GetString(bytes.ToArray());
    }

    private static string GetArchitecture(Machine machine) => machine switch
    {
        Machine.I386 => "x86",
        Machine.Amd64 => "x64",
        Machine.Arm => "ARM",
        Machine.ArmThumb2 => "ARM Thumb-2",
        Machine.Arm64 => "ARM64",
        Machine.IA64 => "Itanium",
        _ => machine.ToString()
    };
}
