# ExeBlueprint 用的 Ghidra headless 後置腳本：把目前程式的函式匯出成 JSON。
#
# 用法（NativeAnalyzer 會自動帶入，也可手動執行）：
#   analyzeHeadless <proj-dir> <proj-name> -import <file> \
#       -scriptPath <此檔所在目錄> -postScript ExportFunctions.py <輸出 json 路徑> -deleteProject
#
# 輸出格式： { "functions": [ { "name", "address", "signature", "external" } ] }

import json

args = getScriptArgs()
out = args[0]
fm = currentProgram.getFunctionManager()
funcs = []
for f in fm.getFunctions(True):
    funcs.append({
        "name": f.getName(),
        "address": str(f.getEntryPoint()),
        "signature": f.getPrototypeString(False, False),
        "external": f.isExternal(),
    })

with open(out, "w") as fh:
    json.dump({"functions": funcs}, fh)
