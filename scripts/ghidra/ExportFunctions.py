# ExeBlueprint 用的 Ghidra headless 後置腳本：把目前程式的函式匯出成 JSON。
#
# 用法（NativeAnalyzer 會自動帶入，也可手動執行）：
#   analyzeHeadless <proj-dir> <proj-name> -import <file> \
#       -scriptPath <此檔所在目錄> -postScript ExportFunctions.py <輸出 json 路徑> -deleteProject
#
# 輸出格式：
# { "schemaVersion": 1, "functionCount": int,
#   "functions": [ { "name", "address", "signature", "external" } ], "truncated": bool }

import json

args = getScriptArgs()
out = args[0]
fm = currentProgram.getFunctionManager()
funcs = []
max_functions = 100000
max_string_chars = 16384
max_json_chars = 24 * 1024 * 1024
fields_truncated = False
output_budget_truncated = False
estimated_json_chars = 128

def bounded(value):
    global fields_truncated
    if value is None:
        return ""
    if len(value) > max_string_chars:
        fields_truncated = True
    return value[:max_string_chars]

def append_functions(iterator):
    global output_budget_truncated
    global estimated_json_chars
    for f in iterator:
        if len(funcs) >= max_functions:
            return False
        item = {
            "name": bounded(f.getName()),
            "address": bounded(str(f.getEntryPoint())),
            "signature": bounded(f.getPrototypeString(False, False)),
            "external": f.isExternal(),
        }
        item_json_chars = len(json.dumps(item, separators=(",", ":"))) + 1
        if estimated_json_chars + item_json_chars > max_json_chars:
            output_budget_truncated = True
            return False
        funcs.append(item)
        estimated_json_chars += item_json_chars
    return True

non_external_complete = append_functions(fm.getFunctions(True))
if non_external_complete and len(funcs) < max_functions:
    append_functions(fm.getExternalFunctions())

function_count = fm.getFunctionCount()
truncated = function_count > len(funcs) or fields_truncated or output_budget_truncated

with open(out, "w") as fh:
    json.dump({
        "schemaVersion": 1,
        "functionCount": function_count,
        "functions": funcs,
        "truncated": truncated,
    }, fh)
