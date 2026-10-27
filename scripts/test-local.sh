#!/usr/bin/env bash
# Build/test only: never starts a tunnel, changes routes, or reads user configs.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${VPNT_SING_BOX:-}" ]]; then
    VPNT_SING_BOX="$(command -v sing-box || true)"
fi
if [[ -z "$VPNT_SING_BOX" || ! -x "$VPNT_SING_BOX" ]]; then
    echo 'Set VPNT_SING_BOX to the absolute path of your sing-box binary.' >&2
    exit 1
fi
export VPNT_SING_BOX
unset VPNT_UPDATE_GOLDEN
rustc --version
cargo --version
"$VPNT_SING_BOX" version
cargo test --locked -- --nocapture
cargo build --locked --release
