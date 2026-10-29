#!/bin/sh
set -eu
QUEUE=${1:-1}
iptables -I OUTPUT -j NFQUEUE --queue-num "$QUEUE"
