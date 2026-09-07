#!/usr/bin/env bash
# Prepare an isolated HOME for the NetWatch Lite demo recording, and print it.
#
# Why: netwatch reads its config from `dirs::config_dir()`, which is derived
# from $HOME. Recording against the operator's real config makes the GIF depend
# on whatever theme they happen to have set — the v0.28.0 take came out in
# `ocean` for exactly that reason. Pointing HOME at a scratch tree makes the
# recording reproducible and leaves the real config untouched.
#
# The demo pins `theme = "terminal"`, which resolves every colour through the
# terminal's own palette rather than netwatch's. Note that this also switches
# the chart fade and dot-grid off by design: both interpolate in RGB, which is
# precisely what a palette-deferring theme must not emit.
#
# Usage (from a tape):  export HOME=$(./scripts/demo-lite-env.sh)
set -euo pipefail

# Explicit template: `mktemp -t NAME` is BSD-only, and GNU coreutils fails it,
# which under `export HOME=$(...)` empties HOME instead of erroring visibly.
DEMO_HOME="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-demo-home.XXXXXX")"
CFG_DIR="$DEMO_HOME/Library/Application Support/netwatch"

# Linux puts it under ~/.config; create both so the tape is portable.
mkdir -p "$CFG_DIR" "$DEMO_HOME/.config/netwatch"

cat > "$CFG_DIR/config.toml" <<'TOML'
theme = "terminal"
graph_style = "dots"
graph_fade = false
TOML

cp "$CFG_DIR/config.toml" "$DEMO_HOME/.config/netwatch/config.toml"

echo "$DEMO_HOME"
