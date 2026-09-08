"""Execute the shipped exporter with a small Ghidra API fixture, without Java."""

import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/ghidra/ExportFunctions.py"


def flow(call=True, indirect=False, jump=False, conditional=False):
    return SimpleNamespace(isCall=lambda: call, isComputed=lambda: indirect,
                           isJump=lambda: jump, isConditional=lambda: conditional)


def instruction(address, call=True, indirect=False, jump=False, conditional=False, fallthrough=None):
    return SimpleNamespace(getAddress=lambda: address,
                           getFlowType=lambda: flow(call, indirect, jump, conditional),
                           getFallThrough=lambda: fallthrough)


def reference(target, call=True, indirect=False, jump=False, conditional=False):
    return SimpleNamespace(getToAddress=lambda: target,
                           getReferenceType=lambda: flow(call, indirect, jump, conditional))


def function(address, name="worker", external=False, instructions=(), body_addresses=()):
    addresses = {address, *body_addresses, *(item.getAddress() for item in instructions)}
    body = SimpleNamespace(instructions=instructions, contains=lambda target: target in addresses)
    return SimpleNamespace(
        getEntryPoint=lambda: address,
        getName=lambda: name,
        getPrototypeString=lambda *_: "void worker()",
        isExternal=lambda: external,
        getBody=lambda: body,
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
            getListing=lambda: SimpleNamespace(getInstructions=lambda body, _: iter(body.instructions)),
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
        self.assertEqual(3, result["schemaVersion"])
        self.assertEqual(3, result["functionCount"])
        self.assertFalse(result["truncated"])
        graph = result["callGraph"]
        self.assertFalse(graph["truncated"])
        self.assertTrue(all(c["isTailCall"] is False for c in graph["calls"]))
        self.assertEqual([
            ("00401000", "00401004", "00402000", False),
            ("00401000", "00401008", "EXTERNAL:00000001", True),
            ("00401000", "0040100c", None, True),
            ("00401000", "00401010", None, False),
            ("00402000", "00402004", "00402000", False),
        ], [(c["callerAddress"], c["callSiteAddress"], c["targetAddress"], c["isIndirect"]) for c in graph["calls"]])

    def test_exports_direct_and_external_tail_calls_without_following_thunks(self):
        functions = [
            function("1000", instructions=[instruction("1004", call=False, jump=True)]),
            function("2000", instructions=[instruction("2004", call=False, jump=True)]),
            function("EXTERNAL:1", external=True),
        ]
        refs = {
            "1004": [reference("2000", call=False, jump=True),
                     reference("2000", call=False, jump=True), reference("data", call=False)],
            "2004": [reference("EXTERNAL:1", call=False, jump=True)],
        }
        result, _ = self.export(functions, refs)
        self.assertFalse(result["callGraph"]["truncated"])
        calls = result["callGraph"]["calls"]
        self.assertEqual([("1000", "1004", "2000"), ("2000", "2004", "EXTERNAL:1")],
                         [(c["callerAddress"], c["callSiteAddress"], c["targetAddress"]) for c in calls])
        self.assertTrue(all(c["isTailCall"] and not c["isIndirect"] for c in calls))

    def test_does_not_infer_tail_calls_from_ambiguous_or_local_jumps(self):
        jump = lambda target, **kwargs: reference(target, call=False, jump=True, **kwargs)
        cases = [
            ({}, [], ()),
            ({}, [reference("2000")], ()),
            ({}, [reference("2000", call=False)], ()),
            ({}, [jump("1000")], ()),  # branch to the current entry is a loop
            ({}, [jump("1004")], ()),
            ({}, [jump("2001")], ()),  # interior of another function
            ({}, [jump("unknown")], ()),
            ({}, [jump("2000")], ("2000",)),  # overlapping function body
            ({}, [jump("2000"), jump("EXTERNAL:1")], ()),
            ({}, [jump("2000"), jump("unknown")], ()),
            ({}, [jump("unknown"), jump("2000")], ()),
            ({}, [jump("2000", indirect=True)], ()),
            ({}, [jump("2000", conditional=True)], ()),
            ({"conditional": True}, [jump("2000")], ()),
            ({"indirect": True}, [jump("2000")], ()),
            ({"fallthrough": "1008"}, [jump("2000")], ()),
        ]
        for options, refs, body_addresses in cases:
            with self.subTest(options=options, refs=refs, body_addresses=body_addresses):
                functions = [
                    function("1000", instructions=[instruction("1004", call=False, jump=True, **options)],
                             body_addresses=body_addresses),
                    function("2000"), function("EXTERNAL:1", external=True),
                ]
                result, _ = self.export(functions, {"1004": refs})
                self.assertEqual([], result["callGraph"]["calls"])
                self.assertFalse(result["callGraph"]["truncated"])

    def test_tail_calls_share_call_reference_instruction_and_output_budgets(self):
        functions = [
            function("1000", instructions=[instruction("1004", call=False, jump=True), instruction("1008")]),
            function("2000"),
        ]
        refs = {"1004": [reference("2000", call=False, jump=True)], "1008": [reference("2000")]}
        for limits, count in [({"max_calls": 1}, 1), ({"max_instructions": 1}, 1),
                              ({"max_references": 1}, 1), ({"max_references_per_instruction": 0}, 0),
                              ({"max_functions": 1}, 1), ({"max_json_chars": 750}, 0)]:
            with self.subTest(limits=limits):
                result, size = self.export(functions, refs, limits=limits)
                graph = result["callGraph"]
                self.assertTrue(graph["truncated"])
                self.assertEqual(count, len(graph["calls"]))
                if limits == {"max_functions": 1}:
                    self.assertFalse(graph["calls"][0]["isTailCall"])
                    self.assertIsNone(graph["calls"][0]["targetAddress"])
                elif count:
                    self.assertTrue(graph["calls"][0]["isTailCall"])
                if "max_json_chars" in limits:
                    self.assertLessEqual(size, limits["max_json_chars"])

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
