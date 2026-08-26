# ExeBlueprint

[繁體中文](README.md) | [English](README.en.md)

[![CI](https://github.com/NickYCLin/exe-blueprint/actions/workflows/ci.yml/badge.svg)](https://github.com/NickYCLin/exe-blueprint/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/NickYCLin/exe-blueprint)](https://github.com/NickYCLin/exe-blueprint/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ExeBlueprint is a cross-platform static analyzer for Windows EXE, DLL, folder, and ZIP application packages. It inspects PE files, .NET metadata and IL, dependencies, embedded resources, and WPF BAML, then exports a machine-readable software blueprint plus a readable Markdown report.

It includes an Avalonia desktop app for Windows, macOS, and Linux, as well as a command-line interface. Analysis is static by default: ExeBlueprint does not run the input application.

## When to use it

- Inventory an unfamiliar or legacy Windows application before running or migrating it
- Inspect PE imports, .NET assembly references, frameworks, resources, and package-local dependencies
- Review .NET types, IL instructions, method call graphs, and WPF BAML structure
- Produce structured JSON for scripts, CI pipelines, large language models, or application-modernization workflows
- Generate C#, C++, Rust, or Go skeletons as a starting point for code reconstruction

ExeBlueprint is not a dynamic malware sandbox or a complete source-code decompiler. Native function discovery is available through optional Ghidra integration; the most detailed code reconstruction currently targets .NET assemblies.

## Download

Download a self-contained desktop package from the [latest GitHub Release](https://github.com/NickYCLin/exe-blueprint/releases/latest). Packages are available for:

- Windows 10/11 x64
- macOS Apple Silicon and Intel
- Linux x64

Each archive also includes the `exe-blueprint-cli` command-line tool and checksum information. Windows and macOS builds are currently unsigned, and macOS builds are not notarized. Follow the included `README.txt` when the operating system shows a first-launch warning.

## What it analyzes

- Individual EXE or DLL files, folders, and ZIP application packages
- PE architecture, subsystem, sections, signature metadata, and imports
- .NET assembly references, namespaces, types, fields, properties, events, methods, enum values, and inheritance
- IL instructions, method-level call graphs, and reconstructable C# control flow
- Embedded manifest resources and safe decoding of standard `.resources` values
- WPF `.baml` header versions and record-type summaries without loading WPF types
- Common runtime, framework, language, installer, and toolchain fingerprints
- Optional Ghidra headless results for native PE functions

Recognized technologies include .NET, WPF, Windows Forms, Avalonia, Visual Basic 6, Delphi/C++Builder, Microsoft Visual C++, Go, Rust, Python, PyInstaller, Java/JVM, Qt, Tauri, Electron, Unity, Inno Setup, and NSIS. Detection results include evidence and confidence; a detected language or framework is not treated as proof of the original source language.

## Output

The analyzer creates:

```text
exe-blueprint-output/<input-name>-<timestamp>/
├─ blueprint.json
└─ REPORT.md
```

`blueprint.json` is intended for further automation and reconstruction workflows. `REPORT.md` is a Traditional Chinese summary for human review.

Optional generators can also create structural starting points under:

```text
reconstructed-csharp/
reconstructed-cpp/
reconstructed-rust/
reconstructed-go/
```

Generated projects are reference material and are not guaranteed to compile without manual work.

## Run from source

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then start the desktop app:

```powershell
dotnet run --project .\src\ExeBlueprint.Desktop
```

Analyze an application with the CLI:

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\MyApplication
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\MyApplication.zip
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe -o .\report
```

Generate code skeletons:

```powershell
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\App.exe --emit-csharp --emit-rust --emit-go --emit-cpp
```

Enable native PE function discovery with Ghidra:

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.0"
dotnet run --project .\src\ExeBlueprint.Cli -- analyze .\Native.exe --native
```

If Ghidra is unavailable, the rest of the analysis continues and the report records that native function discovery was skipped.

## Safety and limitations

- Analyze only software that you own or are authorized to inspect.
- Do not commit customer binaries, credentials, private configuration, or analysis output to the repository.
- ZIP extraction rejects path traversal and symbolic links and enforces file-count and size limits.
- Custom `.resources` types are not deserialized, and WPF objects are not instantiated during BAML inspection.
- Detection and reconstructed code must be reviewed by an engineer before use.

See the [architecture notes](docs/architecture.md), [contribution guide](CONTRIBUTING.md), and [security policy](SECURITY.md) for more details.

## License

ExeBlueprint is available under the [MIT License](LICENSE).
