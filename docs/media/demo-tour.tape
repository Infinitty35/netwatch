# NetWatch — the tour.
#
# Replaces the June recording, which predates the Egress tab and had no tape
# at all, so it could not be reproduced or corrected.
#
# Story, in five beats: NetWatch is useful in five seconds (Dashboard), it
# names the program behind every socket (Connections), it decodes what is
# actually on the wire (Packets), it draws the path (Topology), and — the
# newest and least ordinary — it learns what each program talks to and warns
# when that changes (Egress).
#
# Deliberately NOT shown: TLS 1.3 decryption. That is the hero GIF's job and
# needs SSLKEYLOGFILE plumbing; duplicating it here would make the tour longer
# without making it say more. Same for the promote → drift loop, which has its
# own recording in demo-egress.gif.
#
# Prereqs learned the hard way:
#
#   - Capture starts automatically at launch when BPF is available; `c` on the
#     Packets tab TOGGLES it, so pressing it here would stop capture mid-tour.
#     Don't add it back "to show capture starting".
#
#   - Traffic must start AFTER netwatch is capturing or the HOST column shows
#     raw IPs — SNI comes from the ClientHello, and a handshake that predates
#     capture is unreadable. Hence the delayed generator.
#
#   - HOME is redirected to a scratch tree pinning `theme = "terminal"`, so the
#     colours come from the terminal palette rather than whatever theme the
#     operator has set. The v0.28.0 take came out in `ocean` for want of this.
#
#   - Width has to clear ~130 columns or the tab bar and footer clip, which
#     reads as a broken render rather than an honest one.
#
# NOT CURRENTLY IN THE README. Dropped at v0.30: a ten-tab walkthrough breaks
# on every chrome change, and the tab table in the README says the same thing
# in text that cannot go stale. The tape is kept because the prereqs below were
# expensive to learn — re-record from it if a tour is wanted again, but do it
# after the chrome has settled, not before.
#
# Record with:  vhs docs/media/demo-tour.tape
# Needs: ./target/release/netwatch, vhs, scripts/demo-lite-traffic.sh.

Output docs/media/demo-tour.gif

Set Shell "bash"
Set FontSize 16
Set Width 1440
Set Height 760
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
# 14 rather than 18: the Packets tab is a fast-scrolling list, which is the
# worst case for GIF's palette-per-frame encoding. The June take was 9.2 MB,
# most of it those frames.
Set Framerate 14
Set Padding 10

Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "export HOME=$(./scripts/demo-lite-env.sh)"
Enter
Type "(sleep 5; ./scripts/demo-lite-traffic.sh >/dev/null 2>&1) &"
Enter
Type "clear"
Enter
Show

# ── 1. Dashboard — useful in five seconds ──────────────────────────────
# No flags, no config. Interfaces, aggregate bandwidth, top talkers,
# gateway and DNS health, latency heatmap.
Type "netwatch"
Enter
Sleep 16s

# ── 2. Connections — which program opened this socket ──────────────────
Type "2"
Sleep 9s

# ── 3. Packets — what is actually on the wire ──────────────────────────
# Live capture with real L7 decode. Narrow to TLS with a display filter to
# show the filter language without spending the tour on it.
Type "4"
Sleep 7s
Type "/"
Sleep 800ms
Type "tls"
Sleep 1500ms
Enter
Sleep 8s
Escape
Sleep 2s

# ── 4. Topology — the path, drawn ──────────────────────────────────────
# No traceroute here, deliberately. The remote list is rebuilt from live
# connections every run, so the cursor lands somewhere different each take:
# one attempt traced 127.0.0.1 (vhs's own loopback — a one-hop route to the
# machine we are already on), the next landed on a host traceroute could not
# resolve and the beat recorded an error. Neither is a fair picture of the
# feature, and there is no way to select a specific remote from a tape.
# The map is the thing worth showing; traceroute is documented in REFERENCE.
Type "6"
Sleep 10s

# ── 5. Egress — what each program talks to ─────────────────────────────
# The tab no other terminal tool has. Unfold one process to show the
# destinations behind it: hostname from the ClientHello, port, and the
# autonomous system.
Type "0"
Sleep 8s
Type " "
Sleep 9s

Type "q"
Sleep 1s

Hide
Type "pkill -f demo-lite-traffic.sh; pkill -f 'curl -s --limit-rate'"
Enter
Sleep 500ms
