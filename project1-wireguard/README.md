# Project 1 — WireGuard VPN

## What This Is

This project sets up a point-to-point VPN tunnel using WireGuard. One machine acts as the **VPN server** (the control node), and the other acts as the **peer** (client). All traffic from the peer is routed through the server.

This was the foundation for the larger mesh network built in Project 2.

---

## Prerequisites

- Two Linux machines (physical, VM, or Raspberry Pi)
- WireGuard installed on both:
  ```bash
  sudo apt update && sudo apt install wireguard -y
  ```
- Root/sudo access on both machines

---

## File Structure

```
project1-wireguard/
├── README.md
└── configs/
    ├── wg-server.conf    ← Goes on the VPN server machine
    └── wg-peer.conf      ← Goes on the peer/client machine
```

---

## Setup Instructions

### Step 1: Generate Keys (do this on each machine separately)

On the **server**:
```bash
wg genkey | tee server_private.key | wg pubkey > server_public.key
cat server_private.key   # copy this — goes in wg-server.conf
cat server_public.key    # copy this — goes in wg-peer.conf
```

On the **peer**:
```bash
wg genkey | tee peer_private.key | wg pubkey > peer_public.key
cat peer_private.key     # copy this — goes in wg-peer.conf
cat peer_public.key      # copy this — goes in wg-server.conf
```

### Step 2: Configure the Server

Copy `configs/wg-server.conf` to your server machine at `/etc/wireguard/wg0.conf`:
```bash
sudo cp wg-server.conf /etc/wireguard/wg0.conf
sudo nano /etc/wireguard/wg0.conf
```

Replace the placeholders:
- `YOUR CONTROL PRIVATE KEY HERE` → paste your server's private key
- `PUT YOUR PEER DEVICE KEY HERE` → paste your peer's public key

### Step 3: Configure the Peer

Copy `configs/wg-peer.conf` to your peer machine at `/etc/wireguard/wg0.conf`:
```bash
sudo cp wg-peer.conf /etc/wireguard/wg0.conf
sudo nano /etc/wireguard/wg0.conf
```

Replace the placeholders:
- `YOUR PEER PRIVATE KEY HERE` → paste your peer's private key
- `YOUR CONTROL PUBLIC KEY` → paste your server's public key
- `YOUR IP SERVERDEVICE` → paste your server's public IP address

### Step 4: Start the Tunnel

On **both machines**:
```bash
sudo wg-quick up wg0
```

To start automatically on boot:
```bash
sudo systemctl enable wg-quick@wg0
```

### Step 5: Verify the Connection

On either machine:
```bash
sudo wg show
```

Test connectivity:
```bash
# From peer, ping the server's VPN IP
ping 10.8.0.1

# From server, ping the peer's VPN IP
ping 10.8.0.3
```

---

## IP Address Layout

| Role | VPN IP |
|---|---|
| Server | 10.8.0.1 |
| Peer | 10.8.0.3 |

---

## Stopping the Tunnel

```bash
sudo wg-quick down wg0
```

---

## Troubleshooting

- **Cannot ping**: Make sure port `51820/UDP` is open on the server's firewall
  ```bash
  sudo ufw allow 51820/udp
  ```
- **wg show shows no handshake**: Double-check that the public/private keys are not swapped
- **AllowedIPs = 0.0.0.0/0** on the peer routes ALL traffic through the VPN — this is intentional for a full-tunnel setup
