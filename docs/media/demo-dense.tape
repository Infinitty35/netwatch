# NetWatch Dense — everything at once, on a terminal that can take it.
#
# Story: Lite spends 80x24 answering one question. The tabbed TUI spends ten
# tabs on ten. Dense spends a large terminal showing the lot — four boxes, no
# header bar, no menu bar, no status bar, every row carrying data. The headline
# is the mirrored graph: download grows up from the time axis, upload grows
# down from it, so traffic symmetry is a shape you recognise before you read a
# number. Underneath, the selected connection's detail is hoisted into the top
# of the same box, carrying kernel TCP state — no second screen, no back button.
#
# Prereqs learned the hard way:
#   - Dense needs 130x44 or it renders the compact fallback. Width/Height below
#     were measured, not guessed. Measure them again on any machine that
#     records this: cell metrics depend on the installed font and the vhs
#     build, so the pixel sizes are not portable. Record a throwaway tape with
#     the same FontSize/Padding/Theme that runs `stty size` and read the grid
#     off the frame. On this machine 1250x770 gives 133x38 — 133 columns clears
#     the width floor, but 38 rows is six short of 44, and netwatch responds by
#     dropping the interfaces and latency boxes, leaving the throughput graph
#     and the connection table alone. That is the compact fallback, and it
#     records the four-box layout as two. 1250x930 gives 133x47.
#   - The netwatch theme must be RGB. The Lite demo pins `theme = "terminal"`
#     so colours come from the user's palette — right there, fatal here. Dense
#     encodes magnitude as a colour ramp, and a palette-deferring theme flattens
#     every ramp to one token by design. `demo-dense-env.sh` pins `nord`.
#   - Traffic must start AFTER netwatch is capturing, or REMOTE shows raw IPs:
#     the name comes from the ClientHello's SNI, so a handshake that predates
#     capture is unreadable. Hence the delayed generator below.
#   - The generator uploads as well as downloads. Without an upload leg the
#     mirrored graph's lower half is flat, which records the headline feature
#     as half a graph.
#   - The plot carries one sample per braille sub-column and fills from the
#     right, so a cold start shows an empty left half for a full minute. The
#     recording pre-rolls hidden until the window is populated, then reveals a
#     screen that looks like one you've had open — which is the honest picture,
#     not a doctored one.
#
# Record with:  vhs docs/media/demo-dense.tape
# Needs: ./target/release/netwatch, vhs, scripts/demo-dense-{env,traffic}.sh.

Output docs/media/demo-dense.gif

Set Shell "bash"
Set FontSize 14
Set Width 1250
Set Height 930
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Framerate 10
Set Padding 10

# Hidden setup, as in the Lite tape: point `netwatch` at this repo's release
# build for the recording only, redirect HOME to a scratch config so the GIF
# doesn't inherit the operator's theme, and arm the traffic generator to start
# once capture is up.
Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "export HOME=$(./scripts/demo-dense-env.sh)"
Enter
Type "(sleep 5; ./scripts/demo-dense-traffic.sh >/dev/null 2>&1) &"
Enter
Type "clear"
Enter

# Launch and pre-roll off-camera until the throughput window has filled and the
# health probes have a baseline. Nothing is faked here — the recording simply
# starts at the point a real session becomes worth looking at.
Type "netwatch --view dense"
Enter
Sleep 75s
Show

# The screen, in full. Four boxes: the mirrored graph over per-interface rates
# and hop latency budgets, over the connection table. Watch the plot scroll —
# one sample per sub-column, one sub-column per tick.
Sleep 7s

# Walk down the connection list. The detail block at the top of the box follows
# the selection: socket pair, rates, RTT, retransmits, the decoded protocol, and
# cwnd / ssthresh / mss / rwnd read straight from the kernel.
Type "j"
Sleep 4s
Type "j"
Sleep 5s

# Back up to the busiest flow and sit on it, so the detail row and its 60-second
# rate plot are readable.
Type "k"
Sleep 5s

# Pause freezes the collectors; the screen stays legible rather than greying
# out, because pause is when you want to read it.
Type "p"
Sleep 3s
Type "p"
Sleep 2s

# `V` cycles full → lite → dense from any view. One keypress to the ten-tab
# instrument, sharing the same warm collectors — no restart, no lost history.
Type "V"
Sleep 5s

# Deliberately NOT shown: the third stop on the cycle. Lite is built for 80x24
# and renders its layout into the left third of this 133-column frame — an
# honest picture that reads as a broken one. Same call the Lite tape made in
# reverse.

Hide
Type "q"
Enter
Sleep 500ms

# Tear down the traffic generator.
Type "pkill -f demo-dense-traffic.sh; pkill -f 'curl -s --limit-rate'"
Enter
Sleep 500ms
