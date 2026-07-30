#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# burpsuite-for-ai-agent — one-command setup
# ──────────────────────────────────────────────

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Burp Suite for AI Agent — Install      ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# ── 1. Install Node.js dependencies ──
echo "  [1/3] Installing Node.js dependencies..."
npm install --loglevel=warn 2>&1 | sed 's/^/       /'
echo "       Done."
echo ""

# ── 2. Print Burp plugin instructions ──
echo "  [2/3] Plugin ready:"
echo ""
echo "       File:  $DIR/plugin/burpAI.py"
echo ""
echo "       Load in Burp Suite:"
echo "         Extensions → Installed → Add"
echo "         Extension type: Python"
echo "         File: plugin/burpAI.py"
echo ""
echo "       On Windows + WSL, copy the file to Windows first:"
echo "         cp $DIR/plugin/burpAI.py /mnt/c/Users/YourName/Downloads/"
echo ""

# ── 3. Generate .mcp.json for OpenCode auto-registration ──
echo "  [3/3] Generating .mcp.json..."

MCP_FILE="$DIR/.mcp.json"

cat > "$MCP_FILE" <<MCPEOF
{
  "mcpServers": {
    "burp": {
      "type": "local",
      "command": ["node", "$DIR/src/index.js"]
    }
  }
}
MCPEOF

echo "       Created: $MCP_FILE"
echo ""

# ── Done ──
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Install complete!                      ║"
echo "  ║                                          ║"
echo "  ║   1. Start MCP server:                   ║"
echo "  ║      node src/index.js                   ║"
echo "  ║                                          ║"
echo "  ║   2. Load plugin in Burp Suite           ║"
echo "  ║                                          ║"
echo "  ║   3. In Burp → burpAI tab → Check Status ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
