#!/usr/bin/env bash
# Renders docs/demo.svg, the screenshot in the README's quick start.
#
# It runs the real `scan --demo` in a pseudo-terminal (so the colours are the
# ones a user sees), keeps the head of the report and its score block, and
# hands that to freeze (https://github.com/charmbracelet/freeze):
#
#   go install github.com/charmbracelet/freeze@latest
#   TOOL=TOOLNAME hack/demo-screenshot.sh
#
# Rerun it whenever the sample snapshot or the report layout changes.
set -euo pipefail

TOOL="${TOOL:?set TOOL to the binary name, e.g. bitbucket-bench}"
HEAD="${HEAD:-24}"     # at most this many report lines kept from the top
COLS="${COLS:-88}"
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

go build -o "$work/$TOOL" "./cmd/$TOOL"

# script(1) gives the binary a terminal, so it colours and wraps as it would
# for a person. Its exit code (1: the sample has HIGH failures) is expected.
script -qec "stty cols $COLS rows 200; PATH=$work:\$PATH $TOOL scan --demo" /dev/null \
	| tr -d '\r' > "$work/full.ansi" || true

# The score block starts at the line beginning with SCORE (after colour codes).
score="$(grep -n $'^\e\\[1mSCORE' "$work/full.ansi" | cut -d: -f1)"
total="$(wc -l < "$work/full.ansi")"
# Cut at a finding boundary: a finding starts on an unindented line, so keep
# everything before the last such line within the first HEAD+1.
# One awk reading the whole file: a `| head` here would SIGPIPE under pipefail.
HEAD="$(awk -v max="$((HEAD + 1))" '{ gsub(/\033\[[0-9;]*m/, "") }
	NR > 6 && NR <= max && /^[^ \t]/ { last = NR } END { print last - 1 }' "$work/full.ansi")"
{
	printf '\e[32m$\e[0m %s scan --demo\n' "$TOOL"
	head -n "$HEAD" "$work/full.ansi"
	printf '\e[2m    ⋮  %d more lines: remaining findings, manual checks, rule links\e[0m\n\n' "$((score - HEAD - 1))"
	sed -n "${score},${total}p" "$work/full.ansi"
} > "$work/shot.ansi"

mkdir -p docs
freeze --language ansi \
	--window --padding 20,24 --margin 0 --border.radius 8 \
	--font.size 14 --line-height 1.3 --width "$((COLS * 9 + 48))" \
	-o docs/demo.svg < "$work/shot.ansi"
