# -*- coding: utf-8 -*-
# ExeBlueprint 的 Ghidra 後置腳本：匯出函式與靜態 CALL 參照，不執行輸入程式。
#
# 用法（NativeAnalyzer 會自動帶入，也可手動執行）：
#   analyzeHeadless <proj-dir> <proj-name> -import <file> \
#       -scriptPath <此檔所在目錄> -postScript ExportFunctions.py <輸出 json 路徑> -deleteProject
#
# 輸出格式：
# v2 保留函式清單，另以 callGraph.calls 記錄 callerAddress、callSiteAddress、
# targetAddress（無法確認時為 null）及 isIndirect。跳躍／tail call 不在這一版範圍。

import json

args = getScriptArgs()
out = args[0]
fm = currentProgram.getFunctionManager()
funcs = []
function_objects = []
max_functions = 100000
max_string_chars = 16384
max_address_chars = 256
max_calls = 100000
max_instructions = 2000000
max_references = 2000000
max_references_per_instruction = 4096
max_json_chars = 24 * 1024 * 1024
fields_truncated = False
output_budget_truncated = False
estimated_json_chars = 512

def bounded(value):
    global fields_truncated
    if value is None:
        return ""
    if len(value) > max_string_chars:
        fields_truncated = True
    return value[:max_string_chars]

def address_text(address):
    value = str(address)
    if not value or len(value) > max_address_chars or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid or oversized Ghidra address")
    return value

def append_functions(iterator):
    global output_budget_truncated
    global estimated_json_chars
    for f in iterator:
        monitor.checkCancelled()
        if len(funcs) >= max_functions:
            return False
        item = {
            "name": bounded(f.getName()),
            "address": address_text(f.getEntryPoint()),
            "signature": bounded(f.getPrototypeString(False, False)),
            "external": f.isExternal(),
        }
        item_json_chars = len(json.dumps(item, separators=(",", ":"))) + 1
        if estimated_json_chars + item_json_chars > max_json_chars:
            output_budget_truncated = True
            return False
        funcs.append(item)
        function_objects.append(f)
        estimated_json_chars += item_json_chars
    return True

non_external_complete = append_functions(fm.getFunctions(True))
if non_external_complete and len(funcs) < max_functions:
    append_functions(fm.getExternalFunctions())

function_count = fm.getFunctionCount()
truncated = function_count > len(funcs) or fields_truncated or output_budget_truncated

calls = []
graph_truncated = truncated
instruction_count = 0
reference_count = 0
known_addresses = set(item["address"] for item in funcs)
listing = currentProgram.getListing()
references = currentProgram.getReferenceManager()

def append_call(caller, site, target, indirect):
    global graph_truncated
    global estimated_json_chars
    item = {
        "callerAddress": caller,
        "callSiteAddress": site,
        "targetAddress": target,
        "isIndirect": indirect,
    }
    item_json_chars = len(json.dumps(item, separators=(",", ":"))) + 1
    if len(calls) >= max_calls or estimated_json_chars + item_json_chars > max_json_chars:
        graph_truncated = True
        return False
    calls.append(item)
    estimated_json_chars += item_json_chars
    return True

def export_calls():
    global graph_truncated
    global instruction_count
    global reference_count
    for f in function_objects:
        monitor.checkCancelled()
        if f.isExternal():
            continue
        caller = address_text(f.getEntryPoint())
        for instruction in listing.getInstructions(f.getBody(), True):
            monitor.checkCancelled()
            if instruction_count >= max_instructions:
                graph_truncated = True
                return
            instruction_count += 1
            flow = instruction.getFlowType()
            if not flow.isCall():
                continue
            site = address_text(instruction.getAddress())
            indirect = flow.isComputed()
            # getReferencesFrom 會先配置整個陣列，必須在呼叫前確認大小。
            reference_size = references.getReferenceCountFrom(instruction.getAddress())
            if reference_size > min(max_references_per_instruction, max_references - reference_count):
                graph_truncated = True
                return
            targets = set()
            saw_call = False
            for reference in references.getReferencesFrom(instruction.getAddress()):
                monitor.checkCancelled()
                if reference_count >= max_references:
                    graph_truncated = True
                    return
                reference_count += 1
                if not reference.getReferenceType().isCall():
                    continue
                # 只接受 Ghidra 已指向函式入口的 CALL；不沿資料指標猜測目標。
                target_function = fm.getFunctionAt(reference.getToAddress())
                target = None if target_function is None else address_text(target_function.getEntryPoint())
                if target is not None and target not in known_addresses:
                    graph_truncated = True
                    target = None
                if target in targets:
                    continue
                targets.add(target)
                saw_call = True
                if not append_call(caller, site, target, indirect):
                    return
            if not saw_call and not append_call(caller, site, None, indirect):
                return

export_calls()
monitor.checkCancelled()
with open(out, "w") as fh:
    json.dump({
        "schemaVersion": 2,
        "functionCount": function_count,
        "functions": funcs,
        "truncated": truncated,
        "callGraph": {"calls": calls, "truncated": graph_truncated},
    }, fh, separators=(",", ":"))
