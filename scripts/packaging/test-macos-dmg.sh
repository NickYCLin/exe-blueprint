#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin || "${GITHUB_ACTIONS:-}" != true || $# -ne 5 ]]; then
  echo '僅限 GitHub macOS runner：test-macos-dmg.sh <dmg> <stage> <version> <x64|arm64> <evidence-directory>' >&2
  exit 1
fi
dmg_path="$1"
stage_dir="$(cd "$2" && pwd -P)"
version="$3"
architecture="$4"
runner_root="$(cd "$RUNNER_TEMP" && pwd -P)"
evidence_dir="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$5")"
case "$evidence_dir" in
  "$runner_root"/*) ;;
  *) echo '驗收目錄必須位於 RUNNER_TEMP 內。' >&2; exit 1 ;;
esac
[[ ! -e "$evidence_dir" ]] || { echo '驗收目錄已存在。' >&2; exit 1; }
mkdir -p "$evidence_dir/mount" "$evidence_dir/copied"
mount_dir="$evidence_dir/mount"
mounted=false
cleanup() {
  if [[ "$mounted" == true ]]; then
    /usr/bin/hdiutil detach "$mount_dir" >> "$evidence_dir/detach.log" 2>&1 || true
  fi
}
trap cleanup EXIT

/usr/bin/hdiutil verify "$dmg_path" > "$evidence_dir/verify.log" 2>&1
mounted=true
/usr/bin/hdiutil attach -readonly -nobrowse -mountpoint "$mount_dir" "$dmg_path" > "$evidence_dir/mount.log" 2>&1
[[ -L "$mount_dir/Applications" && "$(readlink "$mount_dir/Applications")" == /Applications ]] ||
  { echo 'Applications 連結不符。' >&2; exit 1; }
/usr/bin/plutil -lint "$mount_dir/ExeBlueprint.app/Contents/Info.plist" > "$evidence_dir/plist.log"
app_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$mount_dir/ExeBlueprint.app/Contents/Info.plist")"
[[ "$app_version" == "$version" ]] || { echo '掛載後的 App 版本不符。' >&2; exit 1; }
case "$architecture" in
  x64) expected_arch=x86_64 ;;
  arm64) expected_arch=arm64 ;;
  *) echo '不支援的架構。' >&2; exit 1 ;;
esac
[[ "$(/usr/bin/lipo -archs "$mount_dir/ExeBlueprint.app/Contents/MacOS/ExeBlueprint")" == "$expected_arch" ]] ||
  { echo '掛載後的 App 架構不符。' >&2; exit 1; }
[[ -x "$mount_dir/ExeBlueprint.app/Contents/MacOS/ExeBlueprint" ]] || { echo 'App 缺少執行權限。' >&2; exit 1; }
"$mount_dir/exe-blueprint-cli" --version > "$evidence_dir/cli-version.txt"
[[ "$(cat "$evidence_dir/cli-version.txt")" == "$version" ]] || { echo '掛載後的 CLI 版本不符。' >&2; exit 1; }

# 模擬複製 app bundle，目的地僅在暫存目錄，不改動 runner 的 /Applications。
/usr/bin/ditto "$mount_dir/ExeBlueprint.app" "$evidence_dir/copied/ExeBlueprint.app"
python3 - "$stage_dir" "$mount_dir" "$evidence_dir" "$version" "$architecture" "$dmg_path" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

stage, mounted, evidence = map(Path, sys.argv[1:4])
version, architecture, dmg = sys.argv[4:]
count = 0

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

for source_root in ("ExeBlueprint.app", "exe-blueprint-cli", "README.txt"):
    root = stage / source_root
    paths = [root]
    if root.is_dir():
        paths += list(root.rglob("*"))
    for source in paths:
        relative = source.relative_to(stage)
        targets = [mounted / relative]
        if source_root == "ExeBlueprint.app":
            targets.append(evidence / "copied" / relative)
        for target in targets:
            if source.is_symlink():
                if not target.is_symlink() or os.readlink(source) != os.readlink(target):
                    raise RuntimeError(f"Symbolic link mismatch: {relative}")
            elif source.is_file():
                if not target.is_file() or target.is_symlink() or digest(source) != digest(target):
                    raise RuntimeError(f"Payload mismatch: {relative}")
                if source.stat().st_mode & 0o111 != target.stat().st_mode & 0o111:
                    raise RuntimeError(f"Executable permissions mismatch: {relative}")
            elif not target.is_dir() or target.is_symlink():
                raise RuntimeError(f"Missing directory: {relative}")
        if source.is_file() and not source.is_symlink():
            count += 1

summary = {
    "version": version, "architecture": architecture,
    "dmgSha256": digest(Path(dmg)), "verifiedPayloadFiles": count,
    "applicationsLinkVerified": True, "cliVersionVerified": True,
    "bundleCopyVerified": True, "guiLaunchVerified": False
}
(evidence / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
PY
/usr/bin/hdiutil detach "$mount_dir" > "$evidence_dir/detach.log" 2>&1
mounted=false
