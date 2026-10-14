import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description="靜態驗證自有 native_pseudocode.c fixture；不執行 DLL。")
    parser.add_argument("--ghidra", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    arguments.output.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256(arguments.fixture.read_bytes()).hexdigest()
    limits = dict(maxFunctions=256, maxFunctionCharacters=65536, maxTotalCharacters=1048576,
                  functionTimeoutSeconds=10, totalTimeoutSeconds=60)
    headless = arguments.ghidra / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")

    def analyze(label, settings=None):
        output = (arguments.output / (label + ".json")).resolve()
        command = [str(headless.resolve())]
        with tempfile.TemporaryDirectory(prefix="pseudocode-verification-") as project:
            command.extend([project, label, "-import", str(arguments.fixture.resolve()),
                            "-scriptPath", str(root / "scripts" / "ghidra"),
                            "-postScript", "ExportFunctions.py", str(output)])
            if settings is not None:
                config = arguments.output / (label + ".config.json")
                config.write_text(json.dumps(dict(inputSha256=digest, limits=settings)), encoding="utf-8")
                command.append(str(config.resolve()))
            command.append("-deleteProject")
            with (arguments.output / (label + ".log")).open("w", encoding="utf-8") as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180, check=True)
        return json.loads(output.read_text(encoding="utf-8"))

    baseline = analyze("baseline")
    enabled = analyze("enabled", limits)
    reduced = analyze("reduced", dict(limits, maxFunctions=2, maxFunctionCharacters=80, maxTotalCharacters=120))
    for result in (enabled, reduced):
        for key in ("schemaVersion", "functionCount", "functions", "truncated", "callGraph"):
            assert baseline[key] == result[key], key
        assert result["decompilation"]["inputSha256"] == digest
    evidence = enabled["decompilation"]
    assert evidence["complete"] and not evidence["truncated"]
    functions = {function["name"]: function["address"] for function in enabled["functions"]}
    bodies = {function["address"]: function for function in evidence["functions"]}
    assert all(function["status"] == "success" for function in bodies.values())
    code = {name: bodies[functions[name]]["code"] for name in ("branch", "loop", "choice", "caller")}
    assert re.search(r"\bif\s*\(", code["branch"])
    assert re.search(r"\b(for|while|do)\b", code["loop"])
    assert re.search(r"\bswitch\s*\(", code["choice"])
    assert all(re.search(r"\b" + target + r"\s*\(", code["caller"]) for target in ("branch", "loop", "choice"))
    edges = enabled["callGraph"]["calls"]
    assert all(any(edge["callerAddress"] == functions["caller"] and edge["targetAddress"] == functions[target]
                   for edge in edges) for target in ("branch", "loop", "choice"))
    partial = reduced["decompilation"]
    assert not partial["complete"] and partial["truncated"]
    assert len(partial["functions"]) == 2 and partial["limitReason"] == "function_count"
    sizes = [len(function["code"].encode("utf-16-le")) // 2 for function in partial["functions"]]
    assert sizes == [80, 40]
    summary = dict(inputSha256=digest, analyzerVersion=evidence["analyzerVersion"],
                   functions=functions, statuses={name: bodies[address]["status"] for name, address in functions.items()},
                   callCount=len(edges), graphCompatible=True, reducedCharacters=sizes,
                   reducedReason=partial["limitReason"])
    (arguments.output / "acceptance.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
