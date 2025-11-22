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
git clone [https://github.com/Ritik-1101/LinLoot.git](https://github.com/Ritik-1101/LinLoot.git)
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


```bash
curl -s https://raw.githubusercontent.com/Ritik-1101/LinLoot/main/linloot.sh | bash
```
