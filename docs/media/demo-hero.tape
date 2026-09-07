# NetWatch — the README hero. A short tour, chosen for what it looks like.
#
# This is not the five-beat feature tour that demo-tour.tape records (dropped
# at v0.30 — see the note at the top of that file). The job here is narrower:
# a first-time reader scrolling past the title should want the binary before
# they have read a word. So the beats are picked for the render, not for
# coverage, and every one of them has to be worth looking at on its own:
#
#   1. Dashboard  — btop chrome. Rounded panels, titles inline in the brand
#                   accent, metadata right-aligned in the same border row, and
#                   a braille throughput plot already full of history.
#   2. Connections — a process name against every socket, with per-flow latency
#                   sparklines down the right.
#   3. Packets    — live L7 decode, colour-coded by protocol. Short: a fast
#                   scrolling list is the worst case GIF has (palette per
#                   frame), and the June tour spent most of 9.2 MB here.
#   4. Dense      — the signature. Mirrored braille graph, download growing up
#                   from the time axis and upload down from it, every cell
#                   coloured by its height rather than its series.
#
# Deliberately NOT shown: Diagnose, TLS decryption, the egress promote → drift
# loop. Each has its own recording further down the README, and each needs a
# paragraph of setup to be honest about. This one is meant to be watched, not
# read — anything that needs a caption to make sense belongs in a later GIF.
#
# Prereqs, inherited from the Dense tape and expensive to re-learn:
#
#   - THE THEME MUST BE RGB. `demo-hero-env.sh` pins `nord`. A
#     palette-deferring theme ("terminal") collapses every magnitude ramp to a
#     single token by design (see `Ramps::from_theme`), which would record the
#     whole point of this GIF as a block of one colour. Check the env script
#     actually took: it used BSD-only `mktemp -t`, which fails on GNU coreutils
#     and left `export HOME=$(...)` setting HOME to the empty string — netwatch
#     then found no config and recorded in the defaults, silently.

#   - THE LISTS MUST BE POPULATED before their beat. Connections opens grouped
#     and folded, and Packets opens with nothing selected — both render half an
#     empty screen. `z` unfolds every group; selecting a packet fills the detail
#     pane, the payload, the hex dump and the stream timeline, and stops the
#     list scrolling, which the GIF's file size also likes.
#
#   - DENSE NEEDS 130x44, and vhs's cell height moves between versions. 1250x770
#     at FontSize 14 is 133x46 under the vhs the older tapes were recorded with
#     and 133x38 under v0.11.0 — below the floor, which renders Dense's compact
#     fallback: two boxes instead of four, and no way to tell from the tape that
#     anything went wrong. The geometry below measures 135x47 under v0.11.0.
#     MEASURE IT (`stty size` under vhs at these settings) rather than trusting
#     this comment.

#   - THE FONT IS 11, NOT THE 14 THE OTHER TAPES USE, and that is a size
#     decision rather than a taste one. Dense's floor sets the character grid,
#     so the only way to spend fewer pixels on it is a smaller cell: 1100x745
#     carries 150x47 in fewer pixels than 1250x935 spends on 133x47. At
#     FontSize 14 this recording is 15 MB.
#
#     THE COLUMN COUNT IS LOAD-BEARING TWICE OVER, in opposite directions:
#       - Below ~140 the tab bar truncates `0 egress` to `0 egr`, which reads
#         as a broken render on the very first frame.
#       - At exactly 141 the Dashboard puts `interfaces` beside `connections`
#         (v0.30.1), and connections is then narrow enough to truncate half its
#         process names — `Socket T`, `isc-net-`, `unattrib`. Honest, ugly.
#     150 clears both: the tab bar is whole and the side-by-side layout has
#     room. Re-check this if the Dashboard's panel split moves again.
#
#   - TRAFFIC MUST START AFTER CAPTURE or REMOTE/HOST reads back raw IPs: the
#     name comes from the ClientHello's SNI, and a handshake that predates
#     capture is unreadable. Hence the delayed generator. It runs under `setsid`
#     and logs to /tmp/netwatch-hero-gen.log rather than /dev/null: as a plain
#     background job of the tape's shell it has died mid-take, and a take where
#     the generator quietly stopped looks exactly like a working one until you
#     notice every rx/s column reads `-`. CHECK THAT LOG, and check Connections
#     has curl rows, before believing a recording.
#
#   - PRE-ROLL BEFORE `Show`. The plots carry one sample per braille sub-column
#     and fill from the right, so a cold start is an empty left half. The env
#     script leaves `refresh_rate_ms` at its 1000 ms default rather than pinning
#     the Dense demo's 250 ms, which stretches the window fourfold and is why
#     the pre-roll below is 150s and not 80s. The Dashboard's throughput axis is
#     `plot_width * 2 * refresh_ms` (`graph::axis_window_secs`), so if that
#     panel opens with an empty left half, either the pre-roll is short or the
#     window maths moved underneath the tape — check both before re-recording. Recording opens on a screen
#     that has been up a while, which is the honest picture of the tool in use,
#     not a doctored one.

#   - SELECTING A PACKET NEEDS CAPTURE STOPPED FIRST. The ring holds 5000
#     packets and this generator pushes ~2500/s, so a selected packet is evicted
#     about two seconds later and the selection goes with it — long enough to
#     look like the keypress worked when you spot-check a frame, too short to
#     hold a beat. `c` stops capture (the footer says so), the list freezes, the
#     selection sticks, and the detail pane, payload, hex dump and stream
#     timeline stay up for as long as the beat needs. `c` again resumes, off
#     camera, before Dense. Chasing this as a dropped-keypress problem — longer
#     sleeps, more Ups, `n next expert` instead — costs four recordings and
#     fixes nothing.
#
#     It is also the cheap version. A scrolling packet list repaints the whole
#     table every frame and was 3.4 MB of an 8 MB take on its own; a frozen one
#     is nearly free.
#
#   - `V` CYCLES full → lite → dense, so reaching Dense passes through Lite.
#     Lite lays an 80x24 design into the left third of a 133-column frame — an
#     honest render that reads as a broken one. That transit is hidden; the cut
#     is to the same session, not a second recording.
#
# THEN RE-ENCODE IT. vhs v0.11.0 ignores `Set Framerate` for the GIF and writes
# 25 fps whatever the tape says, which is roughly 2.5x the frames this needs:
#
#   ffmpeg -i docs/media/demo-hero.gif \
#     -vf "fps=10,palettegen=stats_mode=diff:max_colors=64" -y /tmp/pal.png
#   ffmpeg -i docs/media/demo-hero.gif -i /tmp/pal.png \
#     -lavfi "fps=10[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle" \
#     -loop 0 -y docs/media/demo-hero.gif
#
# `dither=none` is deliberate: terminal output is flat colour, so dithering buys
# nothing visible and costs most of the inter-frame compression.
#
# Record with:  vhs docs/media/demo-hero.tape
# Needs: ./target/release/netwatch with cap_net_raw, vhs, ffmpeg, and
#        scripts/demo-hero-env.sh and scripts/demo-dense-traffic.sh.

Output docs/media/demo-hero.gif

Set Shell "bash"
Set FontSize 11
Set Width 1100
Set Height 745
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 10
Set Padding 8

Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "export HOME=$(./scripts/demo-hero-env.sh)"
Enter
Type "(sleep 8; setsid ./scripts/demo-dense-traffic.sh >/tmp/netwatch-hero-gen.log 2>&1 </dev/null &) &"
Enter
Type "clear"
Enter

# Launch and pre-roll off-camera until the throughput window has filled and the
# health probes have a baseline of their own.
Type "netwatch"
Enter
Sleep 150s
Show

# ── 1. Dashboard ───────────────────────────────────────────────────────
# No flags, no config, no setup. Interfaces, aggregate throughput, top
# talkers, gateway and DNS health, and the latency heatmap.
Sleep 7s

# ── 2. Connections ─────────────────────────────────────────────────────
# The column no bandwidth meter has: the program that opened the socket.
# `z` unfolds every process, so the screen carries sockets rather than ten
# collapsed group rows: PID, GeoIP, state with its retransmit glyphs, rates,
# and the selected flow's 30-second plot in the detail pane.
Type "2"
Sleep 3s
Type "z"
Sleep 4s
Type "j"
Sleep 3s

# ── 3. Packets ─────────────────────────────────────────────────────────
# Live capture, decoded at L7 rather than guessed from the port number. Let
# it scroll, stop capture, then select a packet: frame through DNS and GeoIP
# on the left, the conversation it belongs to on the right.
Type "4"
Sleep 3s
Type "c"
Sleep 800ms
Up
Sleep 700ms
Up
Sleep 6s

# ── 4. Dense ───────────────────────────────────────────────────────────
# Resume capture, then transit through Lite hidden; see the notes above.
Hide
Type "c"
Sleep 800ms
Type "V"
Sleep 1200ms
Type "V"
Sleep 3s
Show

# Four boxes, no header bar, no menu bar, no status bar. The mirrored graph
# up top, then per-interface rates and hop latency budgets, then the
# connection table.
Sleep 6s

# The selected row's detail is hoisted into the top of the same box — no
# second screen, no back button — carrying cwnd / ssthresh / mss / rwnd read
# straight from the kernel.
Type "j"
Sleep 5s

Hide
Type "q"
Sleep 1s
Type "pkill -f demo-dense-traffic.sh; pkill -f 'curl -s --limit-rate'"
Enter
Sleep 500ms
