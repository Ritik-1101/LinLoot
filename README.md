![Bash](https://img.shields.io/badge/Language-Bash-green)
![Python](https://img.shields.io/badge/Python-Integrated-blue)
![License](https://img.shields.io/badge/License-MIT-orange)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen)

# LinLoot - Linux Credential Hunting Framework

**LinLoot** is a lightweight, Bash-based post-exploitation tool designed for Red Teamers and CTF players. It automates the discovery of secrets, configuration files, and credentials on compromised Linux systems.

## 🚀 Features

- **High-Value Target Detection:** Automatically flags `id_rsa`, `shadow`, `.env`, and cloud credentials
- **Interactive Memory Dumping:** Uses `gcore` to dump process memory and grep for cleartext passwords (requires root)
- **Firefox Decryption:** Locates Firefox profiles and integrates with `firefox_decrypt.py` for password recovery
- **Log & History Analysis:** Scans bash history and auth logs for regex patterns (AWS keys, Bearer tokens)
- **Zero Dependencies:** Runs on standard Bash with mostly native binaries
- **Stealth Mode:** Option to skip memory dumping for low-profile operations

## 📥 Installation

### Clone Repository
```bash
git clone https://github.com/Ritik-1101/LinLoot.git
cd LinLoot
chmod +x linloot.sh
```

### Requirements
- Bash 4.0+
- Python 3 (for Firefox decryption module)
- Root privileges recommended for memory dumping

## ⚡ Usage

### Basic Scan
```bash
./linloot.sh
```

### Save Output to File
```bash
./linloot.sh -o target_loot.txt
```

### Stealth Mode (Skip Memory Dump)
```bash
./linloot.sh -m
```

### Show Help
```bash
./linloot.sh -h
```

## 📁 Tool Structure

```
LinLoot/
├── linloot.sh              # Main script
├── tools/
│   └── firefox_decrypt.py  # Firefox password decryption module
└── README.md
```

## 🔍 What It Scans

- SSH keys (`~/.ssh/id_rsa`, authorized_keys)
- Shadow file (`/etc/shadow`)
- Environment files (`.env`, `.env.local`)
- Cloud credentials (AWS, Azure, GCP)
- Browser profiles (Firefox, Chrome)
- Bash history and shell configs
- System logs and auth logs
- Process memory (if not in stealth mode)
- Common config files with potential credentials

## ⚠️ Disclaimer

This tool is for **educational purposes** and **authorized security testing only**. Do not run this on systems you do not have explicit permission to test. Unauthorized use is prohibited.

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

## ⚡ Quick Run (One-Liner)

To run without downloading the repository:

```bash
curl -s https://raw.githubusercontent.com/Ritik-1101/LinLoot/main/linloot.sh | bash
```

> **Note:** Running via curl requires trust in the source. For production use, download and review the code first.
