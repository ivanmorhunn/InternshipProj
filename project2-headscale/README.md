# Project 2 — Headscale Mesh Network

## What This Is

This project sets up a self-hosted mesh VPN using **Headscale** — an open-source, self-hosted implementation of the Tailscale coordination server. The Raspberry Pi acts as the control plane, and any Windows or Mac device can join the mesh using the standard Tailscale client pointed at the Pi instead of Tailscale's cloud.

This network was then used to expose the MeshCloud app (Project 3) to all mesh devices without opening public ports.

---

## Prerequisites

- Raspberry Pi running Raspberry Pi OS (64-bit, arm64) with a static/known IP
- A public IP address with port forwarding access to your router
- Windows or Mac client machines to join the mesh
- Internet access on all devices during setup

---

## File Structure

```
project2-headscale/
├── README.md               ← You are here
├── config.yaml.example     ← Headscale config template (copy and edit)
├── backup.sh               ← Backs up all Headscale data
└── cleanup.sh              ← Completely removes Headscale and Tailscale
```

---

## Setup Instructions

### PART 1: Raspberry Pi Setup (~15 min)

#### Step 1: Download and Install Headscale

```bash
HEADSCALE_VERSION="0.28.0"
HEADSCALE_ARCH="arm64"

wget --output-document=headscale.deb \
  "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${HEADSCALE_ARCH}.deb"

sudo apt install ./headscale.deb
```

#### Step 2: Fix Permissions

```bash
sudo mkdir -p /var/run/headscale
sudo chown -R headscale:headscale /var/lib/headscale /var/run/headscale /etc/headscale
sudo chmod 750 /var/lib/headscale /var/run/headscale
```

#### Step 3: Get Your Public IP

```bash
curl -4 ifconfig.me
# Write this down — you'll need it in the config
```

#### Step 4: Configure Headscale

```bash
# Create the config file (installation doesn't create it automatically)
sudo nano /etc/headscale/config.yaml
```

Copy the contents of `config.yaml.example` from this repo into the file.
Replace `YOUR_PUBLIC_IP` with your actual public IP from the step above.

```bash
# Set correct ownership on the config file
sudo chown headscale:headscale /etc/headscale/config.yaml
```

#### Step 5: Start Headscale and Create a User

```bash
# Enable and start the service
sudo systemctl enable --now headscale

# Create a user (replace "myuser" with any name you want)
sudo headscale users create myuser
```

#### Step 6: Port Forward on Your Router

1. Go to your router admin page (usually `http://192.168.1.1`)
2. Find Port Forwarding settings
3. Add a rule: **TCP/UDP port 8443 → your Raspberry Pi's local IP**
4. Save and apply

#### Step 7: Set Up the Pi as an Exit Node

```bash
# Enable IP forwarding so the Pi can route traffic for other devices
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf

# Set up NAT masquerading (replace wlan0 with eth0 if using ethernet)
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i tailscale0 -o wlan0 -j ACCEPT

# Save iptables rules so they survive reboot
sudo apt install iptables-persistent -y
```

#### Step 8: Install Tailscale on the Pi

```bash
# Add Tailscale GPG key
curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bullseye.noarmor.gpg | sudo tee \
  /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null

# Add Tailscale repository
curl -fsSL https://pkgs.tailscale.com/stable/raspbian/bullseye.tailscale-keyring.list | sudo tee \
  /etc/apt/sources.list.d/tailscale.list

sudo apt update
sudo apt install tailscale -y

sudo systemctl start tailscaled
sudo systemctl enable tailscaled
```

#### Step 9: Register the Pi with Headscale

```bash
# Connect Pi's Tailscale to your local Headscale server
sudo tailscale up --login-server=http://127.0.0.1:8443 --advertise-exit-node

# The command will print a registration key — copy it, then run:
sudo headscale nodes register --user myuser --key YOUR_KEY_HERE

# Approve the exit node routes
sudo headscale nodes approve-routes --identifier 1 --routes "0.0.0.0/0,::/0"
```

---

### PART 2: Adding Windows or Mac Clients (~5 min each)

#### Windows

1. Download Tailscale: https://tailscale.com/download/windows
2. Open a terminal and run:
   ```
   tailscale login --login-server=http://YOUR_PUBLIC_IP:8443
   ```
3. Copy the registration key that appears
4. On the Pi, register the device:
   ```bash
   sudo headscale nodes register --user myuser --key YOUR_KEY_HERE
   ```
5. To use the Pi as exit node: open Tailscale → Exit Node → select your Pi

#### Mac

1. Download Tailscale: https://tailscale.com/download/mac
2. Open Tailscale → Preferences → "Use alternate coordination server"
3. Enter: `http://YOUR_PUBLIC_IP:8443` → Click Log In
4. Copy the registration key and register on the Pi (same as Windows step 4)

---

## Verification

```bash
# On Pi — list all connected devices
sudo headscale nodes list

# On any client
tailscale status

# Ping another device using its mesh IP (100.64.x.x range)
ping 100.64.0.1
```

Go to https://whatismyipaddress.com — it should show your Pi's public IP, confirming traffic is routing through the exit node.

---

## Useful Commands

```bash
# Remove a device from the mesh
sudo headscale nodes list                          # find the ID
sudo headscale nodes delete --identifier <ID>

# Rename a device (run on the device itself)
tailscale set --hostname yournewname

# See all devices from any node
tailscale status
```

---

## Backup

Run `backup.sh` to snapshot your Headscale database, encryption keys, and config:
```bash
chmod +x backup.sh
./backup.sh
```

---

## Cleanup / Removal

Run `cleanup.sh` to completely remove Headscale and Tailscale from the Pi:
```bash
chmod +x cleanup.sh
./cleanup.sh
```
