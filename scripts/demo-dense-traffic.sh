#!/usr/bin/env bash
# Background traffic generator for the NetWatch Dense demo recording.
#
# Dense puts a mirrored throughput graph at the top — download growing up from
# the time axis, upload growing down from it — over a connection table sorted
# by rate. That needs a different shape of traffic from the Lite demo:
#
#   - SEVERAL DISTINCT HOSTS, so the connection table has rows worth reading
#     and the sort order means something. One host hammered repeatedly is one
#     row.
#   - STAGGERED RATES, so the table sorts into a visibly different order
#     instead of four rows reading the same number.
#   - AN UPLOAD STREAM. This is the one the Lite generator doesn't need. A
#     download-only workload leaves the mirrored graph's lower half flat, which
#     records the headline feature as half a graph. Browsing really is
#     asymmetric — that asymmetry is the thing the mirror exists to show — but
#     a flat line shows it less well than a small one.
#   - LONG-LIVED FLOWS. Short bursts finish between connection snapshots and
#     the rows flicker in and out, so every stream is rate-limited to outlast
#     the recording, and restarts give netwatch fresh ClientHellos to read the
#     SNI from partway through.
#
# The REMOTE column shows that SNI when the handshake was captured, so start
# this AFTER netwatch is already capturing or the column reads back raw IPs.
#
# Usage:
#   ./scripts/demo-dense-traffic.sh     # runs until killed
#   pkill -f demo-dense-traffic.sh
set -uo pipefail

# url|rate — distinct hosts, each large enough to outlast the recording.
# Rates are high enough that the aggregate dominates whatever else the machine
# is doing. The plot's ceiling is the window's peak, so a background burst from
# an unrelated process sets the scale and squashes the demo's own traffic into
# the bottom of the box — more streams, running harder, make the aggregate both
# larger and steadier than any one interloper.
STREAMS=(
  "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz|2500k"
  "https://ftp.gnu.org/gnu/gcc/gcc-12.3.0/gcc-12.3.0.tar.gz|1200k"
  "https://download.thinkbroadband.com/100MB.zip|800k"
  "https://archive.apache.org/dist/httpd/httpd-2.4.58.tar.gz|400k"
  "https://ftp.gnu.org/gnu/emacs/emacs-29.1.tar.xz|600k"
  "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.tar.xz|300k"
)

# Upload payload for the graph's lower half. Random rather than zeroes so no
# transport can quietly compress it into nothing.
PAYLOAD="$(mktemp "${TMPDIR:-/tmp}/netwatch-dense-upload.XXXXXX")"
head -c 8000000 /dev/urandom > "$PAYLOAD"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  pkill -P $$ curl 2>/dev/null || true
  rm -f "$PAYLOAD"
  exit 0
}
trap cleanup INT TERM EXIT

for spec in "${STREAMS[@]}"; do
  url="${spec%%|*}"
  rate="${spec##*|}"
  (
    while :; do
      curl -s --limit-rate "$rate" --max-time 40 -o /dev/null "$url" || true
      sleep 2
    done
  ) &
  pids+=($!)
done

# Upload leg. Slower than the downloads on purpose: a real workload is
# asymmetric and the graph should look like one, just not like a flat line.
(
  while :; do
    curl -s --limit-rate 500k --max-time 40 -o /dev/null \
      -X POST --data-binary "@$PAYLOAD" https://httpbin.org/post || true
    sleep 2
  done
) &
pids+=($!)

wait
