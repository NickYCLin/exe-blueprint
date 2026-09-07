"""Execute the shipped exporter with a small Ghidra API fixture, without Java."""

import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ghidra/ExportFunctions.py"


def flow(call=True, indirect=False):
    return SimpleNamespace(isCall=lambda: call, isComputed=lambda: indirect)


def instruction(address, call=True, indirect=False):
    return SimpleNamespace(getAddress=lambda: address, getFlowType=lambda: flow(call, indirect))


def reference(target, call=True):
    return SimpleNamespace(getToAddress=lambda: target, getReferenceType=lambda: flow(call))


def function(address, name="worker", external=False, instructions=()):
    return SimpleNamespace(
        getEntryPoint=lambda: address,
        getName=lambda: name,
        getPrototypeString=lambda *_: "void worker()",
        isExternal=lambda: external,
        getBody=lambda: instructions,
    )


class ExportFunctionsTests(unittest.TestCase):
    def fixture(self):
        functions = [
            function("00401000", instructions=[
                instruction("00401004"),
                instruction("00401008", indirect=True),
                instruction("0040100c", indirect=True),
                instruction("00401010"),
                instruction("00401014", call=False),
            ]),
            function("00402000", instructions=[instruction("00402004")]),
            function("EXTERNAL:00000001", name="puts", external=True),
        ]
        refs = {
            "00401004": [reference("00402000"), reference("00402000"), reference("data", call=False)],
            "00401008": [reference("EXTERNAL:00000001")],
            "0040100c": [reference("data", call=False)],
            "00401010": [reference("00402001")],  # interior address is not a function entry
            "00401014": [reference("00402000", call=False)],  # a jump is not a call
            "00402004": [reference("00402000")],
        }
        return functions, refs

    def export(self, functions=None, refs=None, limits=None, check_cancelled=lambda: None):
        if functions is None:
            functions, refs = self.fixture()
        refs = refs or {}
        by_address = {f.getEntryPoint(): f for f in functions}
        manager = SimpleNamespace(
            getFunctions=lambda _: (f for f in functions if not f.isExternal()),
            getExternalFunctions=lambda: (f for f in functions if f.isExternal()),
            getFunctionCount=lambda: len(functions),
            getFunctionAt=lambda address: by_address.get(address),
        )
        reference_manager = SimpleNamespace(
            getReferenceCountFrom=lambda address: len(refs.get(address, [])),
            getReferencesFrom=lambda address: refs.get(address, []),
        )
        program = SimpleNamespace(
            getFunctionManager=lambda: manager,
            getListing=lambda: SimpleNamespace(getInstructions=lambda body, _: iter(body)),
            getReferenceManager=lambda: reference_manager,
        )
        source = SCRIPT.read_text(encoding="utf-8")
        for key, value in (limits or {}).items():
            source, count = re.subn(r"^" + re.escape(key) + r" = .+$", key + " = " + str(value), source, flags=re.M)
            self.assertEqual(1, count, key)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "functions.json"
            environment = {
                "getScriptArgs": lambda: [str(output)],
                "currentProgram": program,
                "monitor": SimpleNamespace(checkCancelled=check_cancelled),
            }
            exec(compile(source, str(SCRIPT), "exec"), environment)
            raw = output.read_bytes()
            return json.loads(raw), len(raw)

    def test_exports_direct_external_recursive_and_unresolved_calls(self):
        result, _ = self.export()
        self.assertEqual(2, result["schemaVersion"])
        self.assertEqual(3, result["functionCount"])
        self.assertFalse(result["truncated"])
        graph = result["callGraph"]
        self.assertFalse(graph["truncated"])
        self.assertEqual([
            ("00401000", "00401004", "00402000", False),
            ("00401000", "00401008", "EXTERNAL:00000001", True),
            ("00401000", "0040100c", None, True),
            ("00401000", "00401010", None, False),
            ("00402000", "00402004", "00402000", False),
        ], [(c["callerAddress"], c["callSiteAddress"], c["targetAddress"], c["isIndirect"]) for c in graph["calls"]])

    def test_no_functions_is_an_empty_scanned_graph(self):
        result, _ = self.export(functions=[])
        self.assertEqual({"calls": [], "truncated": False}, result["callGraph"])

    def test_preserves_multiple_targets_at_one_call_site(self):
        functions, refs = self.fixture()
        refs["00401008"].extend([reference("00402000"), reference("unknown")])
        result, _ = self.export(functions, refs)
        calls = [c for c in result["callGraph"]["calls"] if c["callSiteAddress"] == "00401008"]
        self.assertEqual(["EXTERNAL:00000001", "00402000", None], [c["targetAddress"] for c in calls])
        self.assertTrue(all(c["isIndirect"] for c in calls))

    def test_bounds_calls_instructions_and_references(self):
        for limits, retained in [
            ({"max_calls": 2}, 2),
            ({"max_instructions": 1}, 1),
            ({"max_references": 0}, 0),
            ({"max_references_per_instruction": 2}, 0),
        ]:
            with self.subTest(limits=limits):
                result, _ = self.export(limits=limits)
                self.assertTrue(result["callGraph"]["truncated"])
                self.assertFalse(result["truncated"])
                self.assertEqual(retained, len(result["callGraph"]["calls"]))

    def test_function_limit_does_not_create_dangling_edges(self):
        result, _ = self.export(limits={"max_functions": 1})
        self.assertTrue(result["truncated"])
        self.assertTrue(result["callGraph"]["truncated"])
        self.assertEqual(1, len(result["functions"]))
        self.assertTrue(all(c["targetAddress"] is None for c in result["callGraph"]["calls"]))

    def test_json_budget_covers_functions_and_calls_together(self):
        result, size = self.export(limits={"max_json_chars": 1000})
        self.assertLessEqual(size, 1000)
        self.assertTrue(result["callGraph"]["truncated"])
        self.assertLess(len(result["callGraph"]["calls"]), 5)

    def test_function_text_truncation_does_not_change_address_identity(self):
        result, _ = self.export(limits={"max_string_chars": 4})
        self.assertTrue(result["truncated"])
        self.assertEqual("work", result["functions"][0]["name"])
        self.assertEqual("00401000", result["functions"][0]["address"])
        self.assertEqual("00402000", result["callGraph"]["calls"][0]["targetAddress"])

    def test_oversized_addresses_are_rejected_instead_of_shortened(self):
        with self.assertRaises(ValueError):
            self.export(functions=[function("a" * 257)])

    def test_cancellation_is_not_swallowed(self):
        def cancelled():
            raise RuntimeError("cancelled")
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.export(check_cancelled=cancelled)


if __name__ == "__main__":
    unittest.main()
