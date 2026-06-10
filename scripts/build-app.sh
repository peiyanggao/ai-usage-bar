#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/AI Usage Bar.app"
SDK_ARGS=()
SANDBOX_ARGS=()

# Some Command Line Tools installs ship a newer default SDK than their Swift
# compiler can read; fall back to a stable SDK if no full Xcode is present.
if [[ ! -d /Applications/Xcode.app ]]; then
  for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk; do
    [[ -d "$sdk" ]] && SDK_ARGS=(--sdk "$sdk")
  done
fi
if [[ "${AI_USAGE_DISABLE_SWIFTPM_SANDBOX:-0}" == "1" ]]; then
  SANDBOX_ARGS=(--disable-sandbox)
fi

cd "$ROOT"
swift build -c release "${SDK_ARGS[@]}" "${SANDBOX_ARGS[@]}"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$ROOT/.build/release/AIUsageBar" "$APP/Contents/MacOS/AIUsageBar"
cp "$ROOT/App/Info.plist" "$APP/Contents/Info.plist"
codesign --force --deep --sign - "$APP"

echo "$APP"
