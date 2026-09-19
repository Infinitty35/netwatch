#!/bin/sh
# See packaging/debian/postinst — capabilities are the administrator's call,
# so this prints the command rather than running it.
cat <<'MSG'

netwatch is installed. Packet capture needs elevated access:

  sudo netwatch                       # works as-is, or grant it once:
  sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/bin/netwatch

Capabilities attach to the file, so re-apply after each upgrade.

MSG
exit 0
