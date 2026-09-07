#!/usr/bin/env bash
# Prepare an isolated HOME for the NetWatch hero recording, and print it.
#
# Same reasoning as `demo-lite-env.sh` and `demo-dense-env.sh`: netwatch reads
# its config from `dirs::config_dir()`, which derives from $HOME, so recording
# against the operator's real config makes the GIF depend on whatever theme
# they happen to have set.
#
# Two deliberate differences from the Dense one:
#
#   - `theme = "nord"`, NOT `"terminal"`, for the same reason the Dense demo
#     pins an RGB theme: the hero ends on Dense, which encodes magnitude as a
#     colour ramp, and a palette-deferring theme flattens every ramp to a single
#     token by design (see `Ramps::from_theme`).
#
#   - NO `refresh_rate_ms`. The Dense demo pins 250 ms so its plot visibly
#     scrolls; the hero wants the opposite. The shipped default is 1000 ms
#     (`Config::default`, clamped to 100..=5000) — what a reader actually sees
#     on first run — and a quarter of the redraw rate means far fewer output
#     frames differ from the one before, which is most of the difference
#     between a hero GIF that fits in a README and one that doesn't: the same
#     tape at 250 ms recorded 8 MB, at the default 2 MB. The cost is a longer
#     window to fill — the throughput axis spans `plot_width * 2 * refresh_ms`
#     — so the tape pre-rolls for two and a half minutes before recording.
#
# Usage (from a tape):  export HOME=$(./scripts/demo-hero-env.sh)
set -euo pipefail

# Explicit template: `mktemp -t NAME` is BSD-only, and GNU coreutils fails it,
# which under `export HOME=$(...)` empties HOME instead of erroring visibly.
DEMO_HOME="$(mktemp -d "${TMPDIR:-/tmp}/netwatch-hero-home.XXXXXX")"
CFG_DIR="$DEMO_HOME/Library/Application Support/netwatch"

# Linux puts it under ~/.config; create both so the tape is portable.
mkdir -p "$CFG_DIR" "$DEMO_HOME/.config/netwatch"

cat > "$CFG_DIR/config.toml" <<'TOML'
theme = "nord"
view = "full"
graph_style = "dots"
graph_fade = false
TOML

cp "$CFG_DIR/config.toml" "$DEMO_HOME/.config/netwatch/config.toml"

echo "$DEMO_HOME"
