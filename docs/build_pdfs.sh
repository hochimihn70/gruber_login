#!/usr/bin/env bash
# Baut die PDFs in docs/ aus den HTML-Quellen in docs/src/.
# Voraussetzung: Google Chrome (oder Chromium) – keine LaTeX-/Office-Installation nötig.
set -euo pipefail

cd "$(dirname "$0")"

CHROME="${CHROME:-google-chrome}"
command -v "$CHROME" >/dev/null 2>&1 || CHROME=chromium

# Eigenes Profil, damit ein laufender Browser nicht stört.
PROFILE="$(mktemp -d)"
trap 'rm -rf "$PROFILE"' EXIT

build() {
  local source=$1
  local target=$2
  "$CHROME" \
    --headless \
    --disable-gpu \
    --no-sandbox \
    --user-data-dir="$PROFILE" \
    --no-pdf-header-footer \
    --virtual-time-budget=3000 \
    --print-to-pdf="$target" \
    "file://$PWD/src/$source"
  echo "gebaut: docs/$target"
}

build projektdokumentation.html Projektdokumentation_Gruber_Login.pdf
build sprechskript.html Sprechskript_Gruber_Login.pdf
