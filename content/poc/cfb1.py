#!/usr/bin/env python3
"""
CFB1 Keygen — Crackmes for Beginners #1
Reverse-engineered from CFB1.exe (x64 PE, MSVC C++)

Algorithm (from disassembly @ 0x1400066e0):
─────────────────────────────────────────────────────────
  serial = ""
  for i, c in enumerate(username):
      val = (i + 0x5A) XOR ord(c)   # index+90, XOR char
      val = (val + 0x13) & 0xFF      # add 19, keep byte
      serial += "%02X" % val         # 2-digit uppercase hex

Flags confirmed from disasm:
  AND ~0x600   → clears dec/oct basefield
  OR  0x800    → set hex format
  OR  0x004    → set uppercase flag
  setw(2) / setfill('0') → zero-padded 2-digit output
─────────────────────────────────────────────────────────
"""

import sys
import argparse

RESET  = "\033[0m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def c(text, code): return f"{code}{text}{RESET}"


def keygen(username: str) -> str:
    """Compute the valid serial for a given username."""
    serial = ""
    for i, ch in enumerate(username):
        val = (i + 0x5A) ^ ord(ch)   # index + 90, XOR with ASCII value
        val = (val + 0x13) & 0xFF     # add 19, wrap to byte
        serial += "%02X" % val        # uppercase 2-digit hex
    return serial


def main():
    parser = argparse.ArgumentParser(
        description="CFB1 Keygen — generates valid serial for any username",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cfb1_keygen.py admin
  python3 cfb1_keygen.py "John Doe"
  python3 cfb1_keygen.py          ← interactive mode
        """,
    )
    parser.add_argument("username", nargs="?", help="Username (min 4 chars)")
    args = parser.parse_args()

    print(c("\n═══════════════════════════════════════", CYAN))
    print(c("  CFB1 Keygen — Crackmes For Beginners", BOLD))
    print(c("═══════════════════════════════════════\n", CYAN))

    if args.username:
        username = args.username
    else:
        try:
            username = input(c("  Enter username: ", BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    if len(username) < 4:
        print(c("\n  ✗ Username must be at least 4 characters!\n", RED))
        sys.exit(1)

    serial = keygen(username)

    print()
    print(c("  Username : ", DIM) + c(username, BOLD))
    print(c("  Serial   : ", DIM) + c(serial, GREEN + BOLD))
    print()
    print(c("  Algorithm per character:", DIM))
    print(c("    val = ((index + 0x5A) XOR ord(char) + 0x13) & 0xFF", DIM))
    print(c("    serial += '%02X' % val", DIM))

    # Show per-char breakdown
    print()
    print(c("  Breakdown:", DIM))
    print(c("  %-4s  %-6s  %-8s  %-8s  %-8s  %s" % (
        "idx", "char", "idx+0x5A", "^ord(c)", "+0x13", "hex"), DIM))
    print(c("  " + "─" * 52, DIM))
    for i, ch in enumerate(username):
        step1 = i + 0x5A
        step2 = step1 ^ ord(ch)
        step3 = (step2 + 0x13) & 0xFF
        print("  %-4d  %-6s  %-8s  %-8s  %-8s  %02X" % (
            i, repr(ch), hex(step1), hex(step2), hex(step3), step3))

    print()


if __name__ == "__main__":
    main()
