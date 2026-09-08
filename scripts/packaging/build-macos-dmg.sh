#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin || $# -ne 4 ]]; then
  echo '用法（macOS）：build-macos-dmg.sh <stage> <output-directory> <version> <x64|arm64>' >&2
  exit 1
fi

stage_dir="$(cd "$1" && pwd -P)"
version="$3"
architecture="$4"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '版本格式必須是 major.minor.patch。' >&2; exit 1; }
case "$architecture" in
  x64) expected_arch=x86_64 ;;
  arm64) expected_arch=arm64 ;;
  *) echo '僅支援 x64 與 arm64。' >&2; exit 1 ;;
esac

for required in ExeBlueprint.app/Contents/Info.plist ExeBlueprint.app/Contents/MacOS/ExeBlueprint exe-blueprint-cli README.txt; do
  [[ -f "$stage_dir/$required" ]] || { echo "打包目錄缺少 $required。" >&2; exit 1; }
done
app_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$stage_dir/ExeBlueprint.app/Contents/Info.plist")"
[[ "$app_version" == "$version" ]] || { echo 'App bundle 版本不符。' >&2; exit 1; }
[[ "$(/usr/bin/lipo -archs "$stage_dir/ExeBlueprint.app/Contents/MacOS/ExeBlueprint")" == "$expected_arch" ]] ||
  { echo 'App bundle 架構不符。' >&2; exit 1; }
[[ "$(/usr/bin/lipo -archs "$stage_dir/exe-blueprint-cli")" == "$expected_arch" ]] ||
  { echo 'CLI 架構不符。' >&2; exit 1; }

mkdir -p "$2"
output_dir="$(cd "$2" && pwd -P)"
dmg_path="$output_dir/ExeBlueprint-v$version-macos-$architecture.dmg"
[[ ! -e "$dmg_path" ]] || { echo 'DMG 已存在，請使用新的輸出目錄。' >&2; exit 1; }
temp_base="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
scratch="$(mktemp -d "$temp_base/ExeBlueprint-dmg.XXXXXX")"
cleanup() {
  case "$scratch" in
    "$temp_base"/ExeBlueprint-dmg.*) rm -rf -- "$scratch" ;;
  esac
}
trap cleanup EXIT

# ditto 保留 app bundle 內的權限、連結與資源資訊。
/usr/bin/ditto "$stage_dir/ExeBlueprint.app" "$scratch/ExeBlueprint.app"
/usr/bin/ditto "$stage_dir/exe-blueprint-cli" "$scratch/exe-blueprint-cli"
/usr/bin/ditto "$stage_dir/README.txt" "$scratch/README.txt"
ln -s /Applications "$scratch/Applications"
/usr/bin/hdiutil create -quiet -format UDZO -volname ExeBlueprint -srcfolder "$scratch" "$dmg_path" >&2
printf '%s\n' "$dmg_path"
