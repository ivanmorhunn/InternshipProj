#!/bin/bash
# cleanup.sh — Complete Headscale + Tailscale Removal Script
# Removes all traces of Headscale and Tailscale from the Raspberry Pi.
# Use this to reset to a clean state or before restoring from backup.
#
# WARNING: This is irreversible without a backup. Run backup.sh first.
#
# Usage: chmod +x cleanup.sh && ./cleanup.sh

echo "=== Headscale + Tailscale Cleanup Script ==="
echo "WARNING: This will completely remove Headscale and Tailscale."
echo "All connected clients will be disconnected."
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo "[1/9] Stopping services..."
sudo systemctl stop headscale 2>/dev/null || true
sudo systemctl stop tailscaled 2>/dev/null || true

echo "[2/9] Disabling services from autostart..."
sudo systemctl disable headscale 2>/dev/null || true
sudo systemctl disable tailscaled 2>/dev/null || true

echo "[3/9] Removing Headscale package and files..."
sudo apt remove headscale -y 2>/dev/null || true
sudo rm -rf /etc/headscale
sudo rm -rf /var/lib/headscale
sudo rm -rf /var/run/headscale
sudo rm -rf /run/headscale
sudo rm -f /usr/bin/headscale
sudo rm -f /etc/systemd/system/headscale.service

echo "[4/9] Removing Tailscale package and files..."
sudo apt remove tailscale -y 2>/dev/null || true
sudo rm -rf /var/lib/tailscale

echo "[5/9] Clearing iptables rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X
sudo apt remove iptables-persistent -y 2>/dev/null || true
sudo rm -f /etc/iptables/rules.v4
sudo rm -f /etc/iptables/rules.v6

echo "[6/9] Resetting IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv6.conf.all.forwarding=0
sudo sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
sudo sed -i '/net.ipv6.conf.all.forwarding=1/d' /etc/sysctl.conf

echo "[7/9] Removing downloaded installer files..."
rm -f ~/headscale.deb
rm -f ~/headscale_*.deb

echo "[8/9] Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "[9/9] Cleaning up apt cache..."
sudo apt autoremove -y
sudo apt clean

echo ""
echo "=== Cleanup Complete ==="
echo "Headscale and Tailscale have been fully removed."
echo "It is recommended to reboot the Pi now:"
echo "  sudo reboot"
