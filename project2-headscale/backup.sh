#!/bin/bash
# backup.sh — Headscale Backup Script
# Backs up the Headscale database, encryption keys, config, and iptables rules
# into a timestamped archive in your home directory.
#
# Usage: chmod +x backup.sh && ./backup.sh

set -e  # Exit immediately if any command fails

echo "=== Headscale Backup Script ==="
echo "Starting backup at $(date)"

# Create a temporary backup directory
BACKUP_DIR="$HOME/headscale-backup"
mkdir -p "$BACKUP_DIR"

echo "[1/5] Backing up Headscale database (contains all nodes, users, routes)..."
sudo cp /var/lib/headscale/db.sqlite "$BACKUP_DIR/"

echo "[2/5] Backing up noise encryption key..."
sudo cp /var/lib/headscale/noise_private.key "$BACKUP_DIR/"

echo "[3/5] Backing up Headscale configuration..."
sudo cp /etc/headscale/config.yaml "$BACKUP_DIR/"

echo "[4/5] Backing up iptables rules..."
sudo iptables-save > "$BACKUP_DIR/iptables-rules.txt"

echo "[5/5] Creating timestamped archive..."
cd "$HOME"
ARCHIVE_NAME="headscale-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$ARCHIVE_NAME" headscale-backup/

# Clean up the temporary folder
rm -rf "$BACKUP_DIR"

echo ""
echo "=== Backup Complete ==="
echo "Archive saved to: $HOME/$ARCHIVE_NAME"
ls -lh "$HOME/$ARCHIVE_NAME"
echo ""
echo "To restore, see the README.md for restore instructions."
