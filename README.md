# Internship Projects — Ivan Morhun

This repository contains all three projects completed as part of the IST 432 cybersecurity internship lecture series under Professor Kaamran Raahemifar at Penn State University.

Each project builds on the last, culminating in a self-hosted private cloud accessible over a secure mesh VPN.

---

## Project Overview

| Folder | Project | Description |
|---|---|---|
| `project1-wireguard/` | WireGuard VPN | Point-to-point VPN tunnel between a control server and a peer device |
| `project2-headscale/` | Headscale Mesh Network | Self-hosted Tailscale coordination server on a Raspberry Pi with multi-device mesh |
| `project3-meshcloud/` | MeshCloud | Flask-based private cloud storage app running on Raspberry Pi, accessible via Headscale |

---

## How to Navigate This Repo

Each project folder contains its own `README.md` with full setup instructions. Start there.

```
meshcloud-internship/
├── README.md                        ← You are here
├── project1-wireguard/
│   ├── README.md                    ← WireGuard setup instructions
│   └── configs/
│       ├── wg-server.conf           ← Server config template
│       └── wg-peer.conf             ← Peer/client config template
├── project2-headscale/
│   ├── README.md                    ← Headscale setup instructions
│   ├── config.yaml.example          ← Headscale config template
│   ├── backup.sh                    ← Backup script
│   └── cleanup.sh                   ← Full removal script
└── project3-meshcloud/
    ├── README.md                    ← MeshCloud setup instructions
    ├── app.py                       ← Main Flask application
    ├── requirements.txt             ← Python dependencies
    ├── admin.conf.example           ← Admin credentials template
    ├── .gitignore
    └── static/
        ├── index.html               ← User-facing web UI
        └── admin.html               ← Admin panel UI
```

---

## Requirements Summary

- **Project 1**: Two Linux machines (or VMs) with WireGuard installed
- **Project 2**: Raspberry Pi (arm64), any Windows or Mac client with Tailscale
- **Project 3**: Python 3.8+, pip, any modern browser

---

## Author

Ivan Morhun — Penn State University, IST 432, Spring 2026
