#!/usr/bin/env python3
"""Run ONLY inside fresh user, network and mount namespaces:
unshare --user --map-root-user --net --mount python3 tests/diagnose/health_lab.py --smoke

Drives examples/diagnose_lab, the real App::tick, against a namespace network
whose addresses are the ones the health prober uses on a real host:

  this namespace   nw0 192.0.2.1/24, default via 192.0.2.2
  gw               192.0.2.2/24 (gateway and resolver), 198.51.100.1/30, forwarding
  inet             198.51.100.2/30, and 1.1.1.1/32 on lo (internet probe, DNS
                   reference, trace target)

The prober's targets are fixed: the internet probe and the DNS reference are
both 1.1.1.1, and the resolver comes from /etc/resolv.conf. So a peer namespace
owns 1.1.1.1, a temp resolv.conf is bind-mounted over the real one, and sysfs is
remounted, because inside a user namespace /sys/class/net otherwise lists the
host's interfaces. No host setting changes: the mounts, addresses and sysctls
all live in namespaces that end with this process. Requires ip, nsenter,
unshare and mount.
"""
import argparse, json, os, pathlib, socket, struct, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/examples/diagnose_lab'
GATEWAY = '192.0.2.2'
INTERNET = '1.1.1.1'
# Wide enough that a busy CI runner's jitter stays under 3σ, narrow enough
# that the faults the scenarios stage (tens of ms and up) clear it.
SEED = {
    'gateway.rtt': {'mean': 1.0, 'sigma': 2.0},
    'dns.rtt_p50': {'mean': 2.0, 'sigma': 3.0},
    'path.rtt': {'mean': 2.0, 'sigma': 3.0},
}

# A resolver that answers the two questions the prober asks: `.` NS (the RTT
# probe) and `dns.google` A (the cross-check, with the answer set the real one
# has, so the two resolvers agree). Each query is answered on its own thread,
# so a delayed answer does not hold up the next. The mode file is read per
# query: ok, delay:<ms>, drop:<pct> or servfail.
RESPONDER = r'''
import pathlib, random, socket, struct, sys, threading, time
addr, mode, tcp_ports = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3:]
ANSWERS = {'dns.google': ['8.8.8.8', '8.8.4.4']}
def qname(buf, i):
    labels = []
    while buf[i]:
        labels.append(buf[i + 1:i + 1 + buf[i]].decode('ascii', 'replace'))
        i += 1 + buf[i]
    return '.'.join(labels).lower(), i + 1
def answer(sock, q, src):
    m = mode.read_text().strip()
    if m.startswith('drop:') and random.uniform(0, 100) < float(m[5:]):
        return
    if m.startswith('delay:'):
        time.sleep(float(m[6:]) / 1000)
    qid, _, _, _, _, ar = struct.unpack('>6H', q[:12])
    name, i = qname(q, 12)
    qtype = struct.unpack('>H', q[i:i + 2])[0]
    end = i + 4
    # DO in the OPT record: answer as a validating resolver would, with AD.
    dnssec = ar and q[end:end + 3] == b'\x00\x00\x29' and q[end + 7] & 0x80
    rcode, records = 0, []
    if m == 'servfail':
        rcode = 2
    elif name == '' and qtype == 2:
        ns = b''.join(bytes([len(l)]) + l.encode() for l in 'a.root-servers.net'.split('.')) + b'\0'
        records.append(struct.pack('>HHHIH', 0xc00c, 2, 1, 3600, len(ns)) + ns)
    elif name in ANSWERS:
        if qtype == 1:
            for ip in ANSWERS[name]:
                records.append(struct.pack('>HHHIH', 0xc00c, 1, 1, 300, 4) + socket.inet_aton(ip))
    elif name != '':
        rcode = 3
    flags = 0x8180 | (0x20 if dnssec and rcode == 0 else 0) | rcode
    sock.sendto(struct.pack('>6H', qid, flags, 1, len(records), 0, 0) + q[12:end] + b''.join(records), src)
def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, src = s.recvfrom(1500)
        if len(q) > 12:
            threading.Thread(target=answer, args=(s, q, src), daemon=True).start()
def tcp(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(64)
    while True:
        s.accept()[0].close()
for port in tcp_ports:
    threading.Thread(target=tcp, args=(port,), daemon=True).start()
dns()
'''


def cmd(*args, ns=None, check=True):
    prefix = ['nsenter', '-t', str(ns), '-n'] if ns else []
    return subprocess.run(prefix + list(map(str, args)), check=check, capture_output=True, text=True)


def ip(*args, **kw):
    return cmd('ip', *args, **kw)


def sysctl(key, value, ns=None):
    cmd('sh', '-c', f'echo "{value}" > /proc/sys/{key.replace(".", "/")}', ns=ns)


class Lab:
    """The namespaces, the resolvers and a temp home, torn down on exit."""

    def __init__(self):
        self.children = []
        self.tmp = None

    def __enter__(self):
        try:
            self.isolate()
            self.topology()
            self.services()
            self.make_home()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc):
        for p in reversed(self.children):
            if p.poll() is None:
                p.kill()
                p.wait()
        if self.tmp:
            self.tmp.cleanup()

    def isolate(self):
        assert os.geteuid() == 0, 'run with unshare --user --map-root-user --net --mount'
        # Protect against mistakenly executing as real root in the host namespace.
        assert pathlib.Path('/proc/self/uid_map').read_text().split()[1] != '0', 'isolated user namespace required'
        # Only possible in a mount namespace this user namespace owns, so a
        # sysfs that mounts is also proof the host's /sys is untouched.
        mounted = cmd('mount', '-t', 'sysfs', 'sysfs', '/sys', check=False)
        assert mounted.returncode == 0, f'{mounted.stderr.strip()}: a mount namespace is required (unshare --mount)'
        assert os.listdir('/sys/class/net') == ['lo'], os.listdir('/sys/class/net')
        self.tmp = tempfile.TemporaryDirectory(prefix='nw-health-')
        self.dir = pathlib.Path(self.tmp.name)
        # The resolver the App reads. realpath: on systemd hosts this is
        # stub-resolv.conf, and a bind over the symlink would not follow it.
        conf = self.dir / 'resolv.conf'
        conf.write_text(f'nameserver {GATEWAY}\n')
        cmd('mount', '--bind', conf, os.path.realpath('/etc/resolv.conf'))
        assert pathlib.Path('/etc/resolv.conf').read_text() == conf.read_text(), 'resolv.conf bind did not take'

    def peer(self):
        p = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
        self.children.append(p)
        mine = os.readlink('/proc/self/ns/net')
        deadline = time.monotonic() + 5
        while os.readlink(f'/proc/{p.pid}/ns/net') == mine:
            assert time.monotonic() < deadline, 'peer namespace did not start'
            time.sleep(0.01)
        return p.pid

    def topology(self):
        self.gw, self.inet = self.peer(), self.peer()
        gw, inet = self.gw, self.inet
        for ns in (None, gw, inet):
            ip('link', 'set', 'lo', 'up', ns=ns)
        ip('link', 'add', 'nw0', 'type', 'veth', 'peer', 'name', 'gw0')
        ip('link', 'set', 'gw0', 'netns', gw)
        ip('link', 'add', 'gw1', 'type', 'veth', 'peer', 'name', 'inet0', ns=gw)
        ip('link', 'set', 'inet0', 'netns', inet, ns=gw)
        for dev, addr, ns in [('nw0', '192.0.2.1/24', None), ('gw0', f'{GATEWAY}/24', gw),
                              ('gw1', '198.51.100.1/30', gw), ('inet0', '198.51.100.2/30', inet)]:
            ip('addr', 'add', addr, 'dev', dev, ns=ns)
            ip('link', 'set', dev, 'up', ns=ns)
        ip('addr', 'add', f'{INTERNET}/32', 'dev', 'lo', ns=inet)
        ip('route', 'add', 'default', 'via', GATEWAY)
        ip('route', 'add', f'{INTERNET}/32', 'via', '198.51.100.2', ns=gw)
        ip('route', 'add', 'default', 'via', '198.51.100.1', ns=inet)
        sysctl('net.ipv4.ip_forward', 1, ns=gw)
        # Every probe and trace hop is an ICMP reply; the default 1/s limit
        # would read as loss.
        for ns in (gw, inet):
            sysctl('net.ipv4.icmp_ratelimit', 0, ns=ns)
        # A fresh namespace refuses unprivileged ICMP sockets, and the kernel
        # rejects a range naming unmapped groups (so not "0 2147483647"
        # here): allow every group this user namespace maps.
        spans = [list(map(int, l.split())) for l in pathlib.Path('/proc/self/gid_map').read_text().splitlines()]
        sysctl('net.ipv4.ping_group_range', f'{min(s[0] for s in spans)} {max(s[0] + s[2] - 1 for s in spans)}')
        names = sorted(os.listdir('/sys/class/net'))
        assert names == ['lo', 'nw0'], f'/sys/class/net lists {names}: sysfs is not this namespace'

    def services(self):
        self.modes = {}
        for name, ns, addr, tcp in [('gw', self.gw, GATEWAY, []), ('inet', self.inet, INTERNET, ['443'])]:
            mode = self.dir / f'dns-{name}.mode'
            mode.write_text('ok')
            self.modes[name] = mode
            self.children.append(subprocess.Popen(
                ['nsenter', '-t', str(ns), '-n', sys.executable, '-c', RESPONDER, addr, str(mode), *tcp]))
        # /proc/net/udp spells a bound address as host-order hex, port 53 as 0035.
        deadline = time.monotonic() + 5
        while not all('%08X:0035' % struct.unpack('=I', socket.inet_aton(addr))[0]
                      in cmd('cat', '/proc/net/udp', ns=ns).stdout
                      for addr, ns in [(GATEWAY, self.gw), (INTERNET, self.inet)]):
            assert time.monotonic() < deadline, 'resolvers did not start'
            time.sleep(0.05)

    def dns_mode(self, name, mode):
        """Set a resolver's behaviour: ok, delay:<ms>, drop:<pct>, servfail."""
        self.modes[name].write_text(mode)

    def make_home(self):
        """The temp home the driver insists on: marked, with every XDG
        directory inside it and a config that records episodes."""
        self.home = self.dir / 'home'
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.home),
                    'TMPDIR': tempfile.gettempdir()}
        for var, sub in [('XDG_CACHE_HOME', '.cache'), ('XDG_CONFIG_HOME', '.config'),
                         ('XDG_STATE_HOME', '.local/state'), ('XDG_DATA_HOME', '.local/share')]:
            (self.home / sub).mkdir(parents=True)
            self.env[var] = str(self.home / sub)
        (self.home / '.netwatch-lab').write_text('')
        config = self.home / '.config/netwatch/config.toml'
        config.parent.mkdir()
        config.write_text('diagnose_record_episodes = true\ninsights_enabled = false\n\n'
                          f'[diagnose_probes]\ntrace_target = "{INTERNET}"\ntrace_refresh_secs = 30\n')
        self.seed = self.dir / 'seed.json'
        self.seed.write_text(json.dumps(SEED))

    def run(self, seconds, env=None, on_line=None):
        """Run the driver for `seconds`, returning its JSON lines and stderr.
        `on_line(row)` is called as each tick arrives, which is where a
        scenario changes a fault."""
        with open(self.dir / 'driver.err', 'w+') as stderr:
            p = subprocess.Popen([BIN, '--seconds', str(seconds), '--seed', self.seed, '--jsonl'],
                                 env=env or self.env, stdout=subprocess.PIPE, stderr=stderr, text=True)
            rows = []
            for line in p.stdout:
                rows.append(json.loads(line))
                if on_line:
                    on_line(rows[-1])
            p.wait()
            stderr.seek(0)
            err = stderr.read()
        assert p.returncode == 0, f'driver exited {p.returncode}: {err}'
        return rows, err


def first(rows, pred):
    return next((r['t'] for r in rows if pred(r)), None)


def smoke(lab, results):
    # The driver itself must refuse a home the lab did not make. The inherited
    # HOME is the real one.
    real = dict(lab.env, HOME=os.environ.get('HOME', '/root'))
    for var in ['XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME']:
        real.pop(var)
    refused = subprocess.run([BIN, '--seconds', '1', '--jsonl'], env=real, capture_output=True, text=True)
    assert refused.returncode != 0 and not refused.stdout, refused
    results.append({'case': 'driver refuses the real home', 'error': refused.stderr.strip()})
    print(json.dumps(results[-1]), flush=True)

    rows, err = lab.run(60)
    assert len(rows) == 60, len(rows)
    assert f'seeded dns.rtt_p50@{GATEWAY}, gateway.rtt@{GATEWAY}, path.rtt@internet' in err, err
    probes = {
        'gateway': first(rows, lambda r: r['probes']['gateway_target'] == GATEWAY and r['probes']['gateway_rtt_ms'] is not None),
        'dns': first(rows, lambda r: r['probes']['dns_target'] == GATEWAY and r['probes']['dns_rtt_ms'] is not None),
        'internet': first(rows, lambda r: r['probes']['internet_rtt_ms'] is not None),
    }
    for probe, t in probes.items():
        assert t is not None and t <= 10, (probe, t, rows[-1]['probes'])
    for probe in ['gateway_target', 'dns_target']:
        seen = {r['probes'][probe] for r in rows} - {None}
        assert seen == {GATEWAY}, (probe, seen)
    opened = sorted({i['key'] for r in rows for i in r['issues']})
    assert not opened, opened
    # Seeded σ rules are judging, not learning.
    last = {c['rule']: c['status'] for c in rows[-1]['coverage']}
    for rule in ['gateway.rtt_spike', 'dns.slow_resolver', 'dns.failing', 'gateway.unreachable']:
        assert last.get(rule) == 'available', (rule, last)
    # Where the run wrote: the seeded baselines, persisted at shutdown.
    assert (lab.home / '.cache/netwatch/baselines.json').is_file()
    results.append({'case': 'healthy 60s', 'measured_at': probes, 'issues': opened,
                    'coverage': last, 'probes': rows[-1]['probes'], 'verdict': rows[-1]['verdict']})
    print(json.dumps(results[-1]), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--smoke', action='store_true', help='60 s healthy: probes measured, nothing opens')
    args = ap.parse_args()
    if not args.smoke:
        ap.error('nothing to run: pass --smoke')
    assert BIN.exists(), f'{BIN}: cargo build --example diagnose_lab'
    results = []
    with Lab() as lab:
        smoke(lab, results)
    print(json.dumps({'passed': len(results), 'results': results}), flush=True)


if __name__ == '__main__':
    main()
