# NetWatch — Diagnose: issue → cause → remediation → verified close.
#
# The one loop no other terminal network tool closes. Five beats: something is
# wrong and the tab says what (issue), here is the explanation that survived
# testing and the checks that killed the others (cause), here is the fix and
# what it will do (remediation), press it (apply), and the issue closes itself
# when its own success condition holds (verify).
#
# Recorded against `--demo`, which replays the fixture scenario through the
# real engine, rules and UI at 6×. Prereqs learned the hard way:
#
#   - Diagnose has nothing to say on a healthy laptop, and needs 30 minutes of
#     baseline before it will say anything at all. Recording live gets you
#     "no issues detected · learning 47/1800" for the length of the GIF. That
#     is the correct behaviour and an unrecordable one, hence `--demo`.
#
#   - The DEMO banner in the engine strip is not suppressible and must stay in
#     frame. Every number on screen is from a recorded scenario; a GIF that
#     hides that is a GIF that misrepresents the tool.
#
#   - `↵` stages the fix and `y` confirms. Do not collapse them: the pause on
#     the confirm prompt is the beat that shows netwatch asks before it writes
#     to resolv.conf, which is the whole reason the prompt exists.
#
#   - The resolver rule verifies on `dns.rtt_p50 < 5ms for 60s`. At 6× that is
#     ten wall-clock seconds of holding after the apply, and the demo horizon
#     runs past the report window specifically to leave room for it. Do not
#     shorten the sleep after `y` — the close is the payoff, and cutting early
#     leaves the GIF ending on an unresolved issue.
#
#   - Width has to clear ~163 columns: 155 for the tab bar (ten tabs plus the
#     recorder and interface chips) and the rest for the detail pane, which is
#     where the cause checks live — the most interesting thing on the screen,
#     and the first thing to wrap into uselessness when the pane is squeezed.
#     1660px at FontSize 15 gets there; 1500 clipped "[9] Diagnose" in half,
#     which reads as a broken render rather than an honest one.
#
#   - HOME is redirected to a scratch tree pinning `theme = "terminal"`, same
#     as the other tapes, so the colours come from the terminal palette rather
#     than whatever theme the operator has set.
#
# Record with:  vhs docs/media/demo-diagnose.tape
# Needs: ./target/release/netwatch, vhs, scripts/demo-lite-env.sh.

Output docs/media/demo-diagnose.gif

Set Shell "bash"
Set FontSize 15
Set Width 1660
# 900px is ~44 rows at FontSize 15. The Diagnose screen fills from 42 rows up
# — the report preview takes whatever the detail pane leaves — and 860 landed
# at 41, one short, which recorded the one size with a dead band at the bottom
# of both columns.
Set Height 900
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
# The Diagnose tab is near-static text — no scrolling list — so it survives a
# lower framerate than the tour, and the palette-per-frame cost stays down.
Set Framerate 12
Set Padding 10

Hide
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "export HOME=$(./scripts/demo-lite-env.sh)"
Enter
Type "clear"
Enter
Show

# ── 1. The finding ─────────────────────────────────────────────────────
# Opens on Diagnose. The verdict line names the worst issue, when it
# started, and what to press; the detail pane opens on the resolver.
Type "netwatch --demo"
Enter
Sleep 9s

# ── 2. The cause, and what ruled the others out ────────────────────────
# Three ranked causes. The top one carries its checks: the alternate
# resolver is fast, the resolver itself is reachable, cached names still
# answer — which together say the recursion is slow, not the box.
Sleep 6s

# ── 3. The other findings ──────────────────────────────────────────────
# Down through the reroute (whose latency cost is filed underneath it, not
# counted twice) and the socket the receiver is queueing on.
Down
Sleep 5s
Down
Sleep 5s
Up
Up
Sleep 3s

# ── 4. The report is the screen ────────────────────────────────────────
# The preview already sits under the detail pane, built from the same
# `Vec<Issue>`; `o` gives it the whole screen to be read at length, and
# `o` again comes back. Same objects, same numbers as `e` would export.
Type "o"
Sleep 7s
Type "o"
Sleep 2s

# ── 5. Apply, and confirm ──────────────────────────────────────────────
# `↵` stages the remediation and asks. Nothing has been written yet.
Enter
Sleep 4s
Type "y"
Sleep 4s

# ── 6. Verify closes it ────────────────────────────────────────────────
# The engine is not told the problem is fixed. It watches the resolver, and
# when `dns.rtt_p50 < 5ms` has held for 60 scenario-seconds the issue
# auto-closes and drops off the verdict line by itself.
Sleep 14s

Type "q"
Sleep 1s
