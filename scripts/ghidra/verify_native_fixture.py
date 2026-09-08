"""Build a small Windows DLL and verify the real CLI/Ghidra pipeline without executing it."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]


def run(arguments, cwd, environment, log_path):
    with log_path.open("w", encoding="utf-8") as log:
        result = subprocess.run(arguments, cwd=cwd, env=environment, stdout=log,
                                stderr=subprocess.STDOUT, timeout=300, check=False)
    if result.returncode:
        raise RuntimeError(f"Command failed with exit {result.returncode}; see {log_path}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--compiler", type=Path, help="MSVC Hostx64/x64/cl.exe; otherwise found with vswhere")
    args = parser.parse_args()
    require(os.name == "nt", "This fixture requires Windows and MSVC x64.")
    ghidra = args.ghidra.resolve()
    java_home = args.java_home.resolve()
    require((ghidra / "support/analyzeHeadless.bat").is_file(), "Ghidra headless launcher not found.")
    require((java_home / "bin/java.exe").is_file(), "JDK java.exe not found.")

    compiler = args.compiler
    if compiler is None:
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        found = subprocess.check_output([
            str(vswhere), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-find",
            r"VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
        ], text=True, encoding="utf-8", timeout=30).strip().splitlines()
        require(bool(found), "MSVC x64 compiler not found.")
        compiler = Path(found[-1])
    compiler = compiler.resolve()
    require(compiler.is_file(), "MSVC cl.exe not found.")

    artifacts = REPO / "artifacts"
    artifacts.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="native-acceptance-", dir=artifacts))
    environment = os.environ.copy()
    environment["JAVA_HOME"] = str(java_home)
    environment["PATH"] = str(compiler.parent) + os.pathsep + str(java_home / "bin") + os.pathsep + environment.get("PATH", "")
    fixture = work / "native_calls.dll"
    run([str(compiler), "/nologo", "/LD", "/O2", "/GS-", "/Zl",
         str(REPO / "tests/ghidra/fixtures/native_calls.c"), "/link", "/NODEFAULTLIB",
         "/NOENTRY", "/INCREMENTAL:NO", "/MACHINE:X64", "/OUT:" + str(fixture)], work, environment, work / "compile.log")
    run(["dotnet", "build", str(REPO / "src/ExeBlueprint.Cli"), "-c", "Release", "--nologo"],
        REPO, environment, work / "build.log")
    output = work / "report"
    run(["dotnet", str(REPO / "src/ExeBlueprint.Cli/bin/Release/net10.0/exe-blueprint.dll"),
         "analyze", str(fixture), "--native", "--ghidra", str(ghidra), "--output", str(output)],
        REPO, environment, work / "analyze.log")

    document = json.loads((output / "blueprint.json").read_text(encoding="utf-8-sig"))
    native = document["files"][0]["nativeCode"]
    require(native["backend"] == "ghidra", f"Native analysis did not succeed: {native.get('note')}")
    graph = native["callGraph"]
    require(graph is not None and graph["tailCallsAnalyzed"], "Tail-call analysis was not supplied.")
    require(not native["functionsTruncated"] and not graph["truncated"], "Fixture output was truncated.")
    functions = {}
    for name in ("target", "tail", "ordinary", "loop", "indirect"):
        matches = [item for item in native["functions"] if item["name"] == name]
        require(len(matches) == 1, f"Expected exactly one exported function named {name}.")
        functions[name] = matches[0]["address"]
    calls = graph["calls"]
    tail_calls = [call for call in calls if call["callerAddress"] == functions["tail"]]
    require(len(tail_calls) == 1 and tail_calls[0]["isTailCall"]
            and not tail_calls[0]["isIndirect"] and tail_calls[0]["targetAddress"] == functions["target"],
            "Direct tail call did not resolve to the exported target.")
    ordinary_calls = [call for call in calls if call["callerAddress"] == functions["ordinary"]]
    require(len(ordinary_calls) == 1 and not ordinary_calls[0]["isTailCall"]
            and ordinary_calls[0]["targetAddress"] == functions["target"], "Ordinary CALL was not preserved.")
    require(not any(call["isTailCall"] and call["callerAddress"] in (functions["loop"], functions["indirect"])
                    for call in calls), "A local loop or computed jump was misclassified as a tail call.")
    report = (output / "REPORT.md").read_text(encoding="utf-8-sig")
    require("直接 tail call" in report, "Markdown report omitted the tail-call classification.")

    properties = (ghidra / "Ghidra/application.properties").read_text(encoding="utf-8")
    version = next(line.split("=", 1)[1].strip() for line in properties.splitlines()
                   if line.startswith("application.version="))
    summary = {
        "ghidraVersion": version,
        "schemaVersion": document["schemaVersion"],
        "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
        "functionCount": native["functionCount"],
        "callCount": len(calls),
        "tailCallCount": sum(call["isTailCall"] for call in calls),
        "unresolvedCallCount": graph["unresolvedCallCount"],
        "truncated": graph["truncated"],
        "checks": ["direct tail call", "ordinary CALL", "local loop exclusion", "computed jump exclusion", "Markdown output"],
    }
    (work / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Evidence: {work}")


if __name__ == "__main__":
    main()
