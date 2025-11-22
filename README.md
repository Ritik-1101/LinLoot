![Bash](https://img.shields.io/badge/Language-Bash-green)
![Python](https://img.shields.io/badge/Python-Integrated-blue)
![License](https://img.shields.io/badge/License-MIT-orange)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen)

# LinLoot - Linux Credential Hunting Framework

**LinLoot** is a lightweight, Bash-based post-exploitation tool designed for Red Teamers and CTF players. It automates the discovery of secrets, configuration files, and credentials on compromised Linux systems.

## 🚀 Features
- **High-Value Target Detection:** Automatically flags `id_rsa`, `shadow`, `.env`, and cloud credentials.
- **Interactive Memory Dumping:** Uses `gcore` to dump process memory and grep for cleartext passwords (requires root).
- **Firefox Decryption Prep:** Locates profiles and suggests decryption tools.
- **Log & History Analysis:** Scans bash history and auth logs for regex patterns (AWS keys, Bearer tokens).
- **Zero Dependencies:** Runs on standard Bash (mostly native binaries).

## 📥 Installation
```bash
git clone https://github.com/Ritik-1101/LinLoot.git
cd LinLoot
chmod +x linloot.sh
````

## ⚡ Usage

**Basic Scan:**

```bash
./linloot.sh
```

**Save Output to File:**

```bash
./linloot.sh -o target_loot.txt
```

**Stealth Mode (Skip Memory Dump):**

```bash
./linloot.sh -m
```

## ⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. Do not run this on systems you do not have permission to test.


## ⚡ Quick Run (One-Liner)
To run without downloading the repo (Standard Bash features only):

```bash
curl -s https://raw.githubusercontent.com/Ritik-1101/LinLoot/main/linloot.sh | bash