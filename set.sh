#!/usr/bin/env bash
################################################################################
# set.sh
#
# A colorful bash script that:
#  1) Checks for required packages (tmux, gdb-multiarch, python3, pip3, pwntools).
#  2) Asks the user to input the target architecture [amd64, arm, aarch64, i386].
#  3) Maps each architecture to the correct QEMU binary and default libc path.
#  4) Asks the user to input a custom libc path (or use the default).
#  5) Asks the user to input the ELF binary path to debug.
#  6) Generates a Python script (ex.py) with the chosen parameters (QEMU, libc, ELF).
#
# Usage:
#   ./set.sh
################################################################################

###############################
# 1) Color Definitions
###############################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'  # No Color

###############################
# 2) Basic Utility Functions
###############################
check_package() {
  local pkg="$1"
  echo -e "${CYAN}Checking for ${pkg}...${NC}"
  if ! command -v "$pkg" &>/dev/null; then
    echo -e "${RED}[Error]${NC} ${pkg} not found. Please install it and re-run."
    exit 1
  else
    echo -e "${GREEN}[OK]${NC} ${pkg} is installed."
  fi
}

###############################
# 3) Initial Package Checks
###############################
echo -e "${YELLOW}==> Checking required packages...${NC}"

# 3.1. tmux
check_package "tmux"

# 3.2. gdb-multiarch
check_package "gdb-multiarch"

# 3.3. python3
check_package "python3"

# 3.4. pip3
check_package "pip3"

# 3.5. pwntools (python package)
echo -e "${CYAN}Checking for pwntools installation (pip)...${NC}"
if ! pip3 show pwntools &>/dev/null; then
  echo -e "${RED}[Error]${NC} pwntools not found. Please install via 'pip3 install pwntools'."
  exit 1
else
  echo -e "${GREEN}[OK]${NC} pwntools is installed."
fi

###############################
# 4) Architecture and QEMU Mapping
###############################
# We'll define default QEMU binary name, GDB arch, and default libc path for each.
declare -A QEMU_MAP
declare -A GDB_MAP
declare -A LIBC_DEFAULT_MAP

QEMU_MAP["amd64"]="qemu-x86_64-static"
QEMU_MAP["arm"]="qemu-arm-static"
QEMU_MAP["aarch64"]="qemu-aarch64-static"
QEMU_MAP["i386"]="qemu-i386-static"

GDB_MAP["amd64"]="i386:x86-64"
GDB_MAP["arm"]="arm"
GDB_MAP["aarch64"]="aarch64"
GDB_MAP["i386"]="i386"

# Typical default paths on Ubuntu
LIBC_DEFAULT_MAP["amd64"]="/usr/x86_64-linux-gnu/"
LIBC_DEFAULT_MAP["arm"]="/usr/arm-linux-gnueabihf/"
LIBC_DEFAULT_MAP["aarch64"]="/usr/aarch64-linux-gnu/"
LIBC_DEFAULT_MAP["i386"]="/usr/i386-linux-gnu/"

###############################
# 5) User Inputs
###############################
echo -e "${YELLOW}\n==> Gathering user inputs...${NC}"

echo -e "${BLUE}Select Architecture:${NC}"
echo -e "  1) amd64"
echo -e "  2) arm"
echo -e "  3) aarch64"
echo -e "  4) i386"

ARCH=""
while true; do
  read -rp "Enter number (1-4): " arch_choice
  case "$arch_choice" in
    1) ARCH="amd64" ;;
    2) ARCH="arm" ;;
    3) ARCH="aarch64" ;;
    4) ARCH="i386" ;;
    *) echo -e "${RED}[Error]${NC} Invalid choice. Please enter a number between 1 and 4." ; continue ;;
  esac
  break
done

QEMU_NAME="${QEMU_MAP[$ARCH]}"
GDB_ARCH="${GDB_MAP[$ARCH]}"
DEFAULT_LIBC_PATH="${LIBC_DEFAULT_MAP[$ARCH]}"

# Verify that QEMU binary is installed
echo -e "${CYAN}Verifying QEMU binary '${QEMU_NAME}' for architecture '${ARCH}'...${NC}"
if ! command -v "$QEMU_NAME" &>/dev/null; then
  echo -e "${RED}[Error]${NC} '${QEMU_NAME}' not found. Please install it and re-run."
  exit 1
else
  echo -e "${GREEN}[OK]${NC} '${QEMU_NAME}' is available."
fi

# Ask user for libc path (or default)
echo -e "${BLUE}Enter libc path (or press Enter to use '${DEFAULT_LIBC_PATH}'):${NC}"
read -rp "libc path: " LIBC_PATH
if [ -z "$LIBC_PATH" ]; then
  LIBC_PATH="$DEFAULT_LIBC_PATH"
fi

# Validate that the directory exists
if [ ! -d "$LIBC_PATH" ]; then
  echo -e "${RED}[Error]${NC} The libc directory '${LIBC_PATH}' does not exist."
  exit 1
fi
echo -e "${GREEN}Using libc path: ${LIBC_PATH}${NC}"

# Ask user for ELF path
echo -e "${BLUE}Enter ELF binary path:${NC}"
read -rp "ELF binary path: " ELF_PATH
if [ ! -f "$ELF_PATH" ]; then
  echo -e "${RED}[Error]${NC} The ELF binary '${ELF_PATH}' does not exist."
  exit 1
fi
echo -e "${GREEN}Using ELF binary path: ${ELF_PATH}${NC}"

###############################
# 6) Generate ex.py
###############################
echo -e "${YELLOW}\n==> Generating ex.py...${NC}"

cat <<EOF > ex.py
#!/usr/bin/env python3

from pwn import *
import os
import sys
import subprocess
import time

context.log_level = 'debug'

# ---------------------------------------------------
# 1) Binary & GDB Script Config
# ---------------------------------------------------
binary_path = '${ELF_PATH}'
context.binary = binary_path
context.arch = '${ARCH}'
context.endian = 'little'

# ELF Load (optional)
e = ELF(binary_path)

# GDB Commands
gdb_commands = """
set architecture ${GDB_ARCH}
target remote localhost:1234
set sysroot ${LIBC_PATH}
b main
c
"""

# Write GDB Script
gdb_script_path = '/tmp/pwnlib-gdbscript.gdb'
with open(gdb_script_path, 'w') as f:
    f.write(gdb_commands)

# ---------------------------------------------------
# 2) Arg Check
# ---------------------------------------------------
if len(sys.argv) < 2:
    print("Usage: python3 ex.py [r|gdb]")
    sys.exit(1)

mode = sys.argv[1]

# ---------------------------------------------------
# 3) QEMU Launch
# ---------------------------------------------------
if mode == 'r':
    # Simple run mode
    r = process([
        '${QEMU_NAME}',
        '-L', '${LIBC_PATH}',
        binary_path
    ])

elif mode == 'gdb':
    # Debug mode: QEMU as GDB server
    r = process([
        '${QEMU_NAME}',
        '-L', '${LIBC_PATH}',
        '-g', '1234',
        binary_path
    ])
    print("[+] QEMU started with GDB server on port 1234")

    # Allow QEMU to start
    time.sleep(1.5)

    # ---------------------------------------------------
    # 4) tmux Pane Split & GDB
    # ---------------------------------------------------
    split_cmd = [
        'tmux', 'split-window',
        '-h',
        '-P',
        '-F', '#{pane_id}',
        'bash'
    ]
    try:
        new_pane_id = subprocess.check_output(split_cmd).strip().decode()
        print(f"[+] Created new pane: {new_pane_id}")
        time.sleep(0.5)

        gdb_cmd = f"gdb-multiarch {binary_path} -x {gdb_script_path}"
        send_keys_cmd = [
            'tmux', 'send-keys',
            '-t', new_pane_id,
            gdb_cmd, 'Enter'
        ]
        subprocess.call(send_keys_cmd)
        print(f"[+] Launched GDB in pane {new_pane_id} (right side).")
    except Exception as e:
        print(f"[-] Failed to create or send commands to new tmux pane: {e}")

else:
    print("Invalid argument. Use 'r' to run or 'gdb' to debug.")
    sys.exit(1)

# ---------------------------------------------------
# 5) Pwntools Interactive (Left Pane)
# ---------------------------------------------------
def recv_main(num):
    r.recvuntil(b'>> ')
    r.sendline(str(num).encode())

r.interactive()
EOF

chmod +x ex.py

echo -e "${MAGENTA}\n---------------------------------------------------"
echo -e "ex.py generated successfully!"
echo -e "Architecture: ${ARCH}"
echo -e "QEMU binary: ${QEMU_NAME}"
echo -e "Default GDB arch: ${GDB_ARCH}"
echo -e "Libc path: ${LIBC_PATH}"
echo -e "ELF binary path: ${ELF_PATH}"
echo -e "---------------------------------------------------${NC}"
echo -e "${GREEN}To run:\n  ./ex.py r   # run mode\n  ./ex.py gdb # debug mode${NC}"