#!/usr/bin/env bash
set -euo pipefail
BASE=/etc/recon/resolvers
OKDIR=$BASE/ok; mkdir -p "$OKDIR"
check() { awk 'NF && $1 !~ /^#/' "$1" | while read -r r; do dig +time=1 +tries=1 @"$r" A example.com >/dev/null 2>&1 && echo "$r"; done | sort -u > "$2"; }
check "$BASE/resolvers.txt"  "$OKDIR/v4.txt"
check "$BASE/resolvers6.txt" "$OKDIR/v6.txt"
cat "$OKDIR/v4.txt" "$OKDIR/v6.txt" | sort -u > "$OKDIR/merged.txt"
ln -sfn "$OKDIR/merged.txt" "$BASE/merged.txt"
