#!/bin/sh
set -eu
QUEUE=${1:-0}
iptables -I INPUT -j NFQUEUE --queue-num "$QUEUE"
