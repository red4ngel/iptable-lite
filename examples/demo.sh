#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

cat >"$TMP/rules" <<'EOF'
*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A INPUT -p tcp --dport 22 -m limit --limit 5/minute --limit-burst 2 -j ACCEPT
-A INPUT -p tcp --dport 22 -j DROP
-A INPUT -p tcp --dport 445 -j DROP
COMMIT
EOF

python3 - "$TMP" <<'PY'
import pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
def tcp(src, dst, port, ident):
    transport = struct.pack('!HHIIBBHHH', 40000 + ident, port, 0, 0, 5 << 4, 2, 65535, 0, 0)
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, ident, 0, 64, 6, 0,
                         bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    return (header + transport).hex()
def write(name, rows):
    (root / name).write_text('\n'.join(rows) + '\n')
write('order.hex', [tcp('192.0.2.1','198.51.100.1',22,1)])
write('state.hex', [tcp('192.0.2.2','198.51.100.1',445,2), tcp('192.0.2.2','198.51.100.1',445,2)])
write('rate.hex', [tcp('192.0.2.3','198.51.100.1',22,n) for n in range(3,6)])
write('scan.hex', [tcp('192.0.2.4',f'198.51.100.{n}',1000+n,10+n) for n in range(1,11)])
(root / 'bad.hex').write_text('4500\n')
PY

step() {
  printf '\n=== STEP %s: %s ===\n' "$1" "$2"
  shift 2
  PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m iptable_lite --rules "$TMP/rules" "$@"
}
step 1 'rule order and conflicting SSH rules' --check "$TMP/order.hex"
step 2 'state is created only after ACCEPT; SMB retry remains NEW' --check "$TMP/state.hex"
step 3 'per-rule rate limit exhausts after burst' --check "$TMP/rate.hex"
step 4 'scan detection raises an alert and blocks the source' --scan-detect --check "$TMP/scan.hex"
step 5 'malformed packet is dropped safely' --check "$TMP/bad.hex"
