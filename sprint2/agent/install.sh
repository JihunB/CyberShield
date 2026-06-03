#!/bin/bash
# CyberShield Agent — macOS Installer
# Run as: sudo bash install.sh YOUR_AGENT_TOKEN YOUR_CUSTOMER_ID YOUR_DOMAIN
#
# What this script does (explained step by step):
#   1. Copies the agent binary to /usr/local/bin/
#   2. Creates the config directory /etc/cybershield/
#   3. Writes config.json with your credentials
#   4. Installs a launchd plist → agent starts automatically on boot
#      and restarts if it crashes (KeepAlive = true)
#   5. Loads (starts) the agent immediately
#
# To uninstall:
#   sudo launchctl unload /Library/LaunchDaemons/io.cybershield.agent.plist
#   sudo rm /usr/local/bin/cybershield-agent
#   sudo rm -rf /etc/cybershield
#   sudo rm /Library/LaunchDaemons/io.cybershield.agent.plist

set -euo pipefail

# ── Arguments ────────────────────────────────────────────────────────────────
AGENT_TOKEN="${1:-}"
CUSTOMER_ID="${2:-}"
DOMAIN="${3:-}"
LANG="${4:-en}"
API_URL="${5:-https://cybershield-api.up.railway.app}"
SLACK_WEBHOOK="${6:-}"

if [[ -z "$AGENT_TOKEN" || -z "$CUSTOMER_ID" || -z "$DOMAIN" ]]; then
  echo "Usage: sudo bash install.sh <AGENT_TOKEN> <CUSTOMER_ID> <DOMAIN> [lang] [api_url] [slack_webhook]"
  echo "Example: sudo bash install.sh tok_abc123 cust_xyz456 example.com en"
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh ..."
  exit 1
fi

BINARY_NAME="cybershield-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/cybershield"
LOG_DIR="/var/log/cybershield"
PLIST_PATH="/Library/LaunchDaemons/io.cybershield.agent.plist"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberShield Agent macOS Installer"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Copy binary ────────────────────────────────────────────────────────────
echo "▶ Installing agent binary to $INSTALL_DIR/$BINARY_NAME"
if [[ ! -f "./$BINARY_NAME" ]]; then
  echo "  ERROR: $BINARY_NAME not found in current directory."
  echo "  Download from: https://cybershield.io/downloads/macos"
  exit 1
fi
install -m 755 "./$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
echo "  ✓ Binary installed"

# ── 2. Create directories ─────────────────────────────────────────────────────
echo "▶ Creating config and log directories"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chmod 700 "$CONFIG_DIR"   # only root can read config (secrets stored here)
chmod 755 "$LOG_DIR"
echo "  ✓ Directories created"

# ── 3. Write config.json ──────────────────────────────────────────────────────
echo "▶ Writing configuration"
cat > "$CONFIG_DIR/config.json" << CONFIGEOF
{
  "agent_token":   "$AGENT_TOKEN",
  "customer_id":   "$CUSTOMER_ID",
  "domain":        "$DOMAIN",
  "api_url":       "$API_URL",
  "lang":          "$LANG",
  "tier":          "free",
  "slack_webhook": "$SLACK_WEBHOOK",
  "kakao_token":   ""
}
CONFIGEOF
chmod 600 "$CONFIG_DIR/config.json"   # owner-read-only (root)
echo "  ✓ Config written to $CONFIG_DIR/config.json"

# ── 4. Install launchd service ────────────────────────────────────────────────
# launchd is macOS's service manager (equivalent to systemd on Linux).
# LaunchDaemons run as root at boot, before any user logs in.
# KeepAlive means launchd will restart the agent if it exits for any reason.
echo "▶ Installing launchd service (auto-start on boot)"
cat > "$PLIST_PATH" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.cybershield.agent</string>

  <key>ProgramArguments</key>
  <array>
    <string>$INSTALL_DIR/$BINARY_NAME</string>
    <string>-config</string>
    <string>$CONFIG_DIR/config.json</string>
  </array>

  <!-- Run as root so we can read auth logs -->
  <key>UserName</key>
  <string>root</string>

  <!-- Restart automatically if the agent crashes -->
  <key>KeepAlive</key>
  <true/>

  <!-- Start immediately when the plist is loaded -->
  <key>RunAtLoad</key>
  <true/>

  <!-- Log output to files so we can diagnose issues -->
  <key>StandardOutPath</key>
  <string>$LOG_DIR/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/agent-error.log</string>

  <!-- Throttle restarts — don't spin if it keeps crashing -->
  <key>ThrottleInterval</key>
  <integer>30</integer>
</dict>
</plist>
PLISTEOF
chmod 644 "$PLIST_PATH"
echo "  ✓ LaunchDaemon plist installed"

# ── 5. Load and start the agent ───────────────────────────────────────────────
echo "▶ Starting agent service"
# Unload first in case it was previously installed
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load "$PLIST_PATH"
sleep 2

# Check if it's running
if launchctl list | grep -q "io.cybershield.agent"; then
  echo "  ✓ Agent is running"
else
  echo "  ⚠ Agent may not have started — check logs:"
  echo "    tail -f $LOG_DIR/agent.log"
  echo "    tail -f $LOG_DIR/agent-error.log"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installation complete!"
echo ""
echo "  Domain monitored:  $DOMAIN"
echo "  Agent token:       ${AGENT_TOKEN:0:12}..."
echo "  Customer ID:       $CUSTOMER_ID"
echo ""
echo "  Log files:"
echo "    tail -f $LOG_DIR/agent.log"
echo ""
echo "  Check status:      launchctl list io.cybershield.agent"
echo "  Stop agent:        sudo launchctl unload $PLIST_PATH"
echo "  Uninstall:         sudo bash uninstall.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
