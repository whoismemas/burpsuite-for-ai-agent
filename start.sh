#!/bin/bash
# burpAI - Jalanin, beres.
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Setup Windows port forwarding (WSL -> Windows)
WSL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$WSL_IP" ]; then
  powershell.exe -NoProfile -Command "netsh interface portproxy add v4tov4 listenport=9999 listenaddress=0.0.0.0 connectport=9999 connectaddress=$WSL_IP" 2>/dev/null
fi

node src/index.js
