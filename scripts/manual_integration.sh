#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUDO_BIN="${SUDO_BIN:-sudo}"

pick_newest_exe() {
    local newest="" candidate
    for candidate in "$@"; do
        [[ -x "$candidate" ]] || continue
        if [[ -z "$newest" || "$candidate" -nt "$newest" ]]; then
            newest="$candidate"
        fi
    done
    printf '%s\n' "$newest"
}

if [[ -n "${NU_BIN:-}" ]]; then
    selected_nu="$NU_BIN"
else
    selected_nu="$(pick_newest_exe "$REPO_ROOT/target/debug/nu" "$REPO_ROOT/target/release/nu")"
    if [[ -z "$selected_nu" ]]; then
        selected_nu="$(command -v nu || true)"
    fi
fi

if [[ ! -x "$selected_nu" ]]; then
    echo "nu binary not found or not executable: ${selected_nu:-<empty>}" >&2
    exit 1
fi

if [[ -n "${PLUGIN_BIN:-}" ]]; then
    exec "$SUDO_BIN" env "PLUGIN_BIN=$PLUGIN_BIN" "$selected_nu" "$REPO_ROOT/scripts/manual_integration.nu"
else
    exec "$SUDO_BIN" "$selected_nu" "$REPO_ROOT/scripts/manual_integration.nu"
fi
