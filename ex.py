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
binary_path = './prob'
context.binary = binary_path
context.arch = 'amd64'
context.endian = 'little'

# ELF Load (optional)
e = ELF(binary_path)

# GDB Commands
gdb_commands = """
set architecture i386:x86-64
target remote localhost:1234
set sysroot /usr/x86_64-linux-gnu/
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
        'qemu-x86_64-static',
        '-L', '/usr/x86_64-linux-gnu/',
        binary_path
    ])

elif mode == 'gdb':
    # Debug mode: QEMU as GDB server
    r = process([
        'qemu-x86_64-static',
        '-L', '/usr/x86_64-linux-gnu/',
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
