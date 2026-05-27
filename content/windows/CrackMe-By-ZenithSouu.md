# OMEGA CrackMe 

## TL;DR

- **Goal:** Recover the password that prints `[+] ACCESS GRANTED`.
- **Notable:** Password check lives in a small **`.pdata_c`** region (`Check_Real`); many defenses target Windows sandboxes.
- **Approach:** Linux-friendly static analysis (objdump, strings, Python) — Windows-only checks do not run under Linux.

---

## 1. Overview

The OMEGA CrackMe (2026 Edition) by **ZenithSouu** is a high-level reverse engineering challenge targeting Windows x64. It was designed to "neutralize 99% of automated analysis tools (VirusTotal, Filescan.io, CAPE) and make manual analysis (IDA/Ghidra) extremely painful." The challenge provides a password-protected binary, and the objective is to discover the secret password that triggers the `[+] ACCESS GRANTED` message.

---

## 2. Tooling & Environment

| Tool | Purpose |
|---|---|
| `file` | Identify binary type (PE32+ x86-64) |
| `objdump` (GNU Binutils) | PE section listing and x86-64 disassembly |
| `strings` | ASCII and wide-string extraction |
| `xxd` / custom Python hex dumper | Hex inspection of raw sections |
| Python 3 (struct, re) | Custom analysis scripts for decryption |
| `readelf` | Section metadata verification |

**Key Advantage:** Performing analysis on Linux means all Windows anti-debug, anti-VM, BSOD triggers, sandbox evasion, and watchdog threads are completely neutralized - they simply cannot execute.

---

## 3. Initial Binary Analysis

### 4.1 File Identification

```
$ file "Crack Me.exe"
PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections
```

The binary is a 64-bit PE executable for Windows. The presence of 7 sections (rather than the typical 4–5) immediately signals additional code/data separation.

### 4.2 String Extraction

Initial string extraction revealed:

- **Imported API functions** - `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetThreadContext`, `CreateToolhelp32Snapshot`, `NtRaiseHardError` (implied), `VirtualProtect`, `AddVectoredExceptionHandler`, `FindWindowA` (anti-debug tool blacklist).
- **Standard library symbols** - `std::cout`, `std::cin`, `strcmp`, `memcmp`, `malloc`, `free`, `system`.
- **Registry path** - `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000` (GPU device detection).
- **Base62 character set** - `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` (used in polymorphic filename generation).
- **Notable absence:** No plaintext password strings, no "ACCESS GRANTED", no "wrong password", all strings are protected by `AY_OBFUSCATE`.

### 4.3 Interesting Wide Strings

Only two wide strings were found in the entire binary:

```
Hello
World
```

These appear to be test/debug artifacts, not related to the password mechanism.

---

## 4. PE Section Architecture

```
$ objdump -h "Crack Me.exe"

Idx Name          Size      VMA               File off  Algn
  0 .text         000129a3  0000000140001000  00000400  2**4
  1 .pdata_c      0000037b  0000000140014000  00012e00  2**2
  2 .rdata        0000830e  0000000140015000  00013200  2**4
  3 .data         00000600  000000014001e000  0001b600  2**4
  4 .pdata        00000dd4  000000014001f000  0001bc00  2**2
  5 .rsrc         000001e0  0000000140020000  0001ca00  2**2
  6 .reloc        0000014c  0000000140021000  0001cc00  2**2
```

### Section Analysis

| Section | Size | Purpose |
|---|---|---|
| **`.text`** | 76,547 bytes | Main code - anti-VM, anti-debug, watchdog thread, main function, AY_OBFUSCATE routines |
| **`.pdata_c`** | **891 bytes** | **Contains `Check_Real` the password verification function** |
| `.rdata` | 33,550 bytes | Read-only data - import tables, RTTI, exception handling, .rdata string metadata |
| `.data` | 1,536 bytes | Global variables - TLS indices, function flags, decoy data |
| `.pdata` | 3,540 bytes | Exception handling unwind data |
| `.rsrc` | 480 bytes | Windows resources - manifest (UAC `asInvoker`) |
| `.reloc` | 332 bytes | Base relocation table |

**The `.pdata_c` section is the crown jewel.** At only 891 bytes, it contains the entire password verification logic. According to the challenge guide, this section should be XOR-encrypted on disk, but in this build it was stored in plaintext, a critical oversight (or deliberate simplification) that allows direct static analysis.

---

## 5. Defense Mechanism Analysis

The binary implements four interleaved defense layers as described in the challenge guide. Here is the analysis of each:

### 6.1 Early Detection & Sandbox Evasion (OMEGA Mode)

**Spec Verification:** The binary checks RAM, CPU cores, and disk space to reject analysis sandboxes. Import evidence includes `GlobalMemoryStatusEx` (implied via `GetSystemTimeAsFileTime` + heap checks), CPUID instructions (visible at offset `0x77eb` in `.text`), and disk capacity validation.

**Resource Exhaustion:** If a VM is suspected, the code at offset `0x7818` in `.text` can launch a recursive process explosion (5 children per level, depth 2200) with memory bombs to force OOM on sandbox servers. Evidence: `CreateProcessA`, `GetCurrentProcessId`, and the base62 character set for random filename generation.

**BSOD Trigger:** `NtRaiseHardError` and CR0 register sabotage to crash the hypervisor. Evidence: `AddVectoredExceptionHandler` (unhandled exception manipulation), `SetUnhandledExceptionFilter`, and `TerminateProcess`.

### 6.2 Ghost Dropper & Mutation

**Self-Deletion:** The original `Crack Me.exe` clones itself to a randomly-named file (e.g., `aBcD1234eFgH.exe`) using `CopyFileA`, then deletes itself with `DeleteFileA`.

**Polymorphism:** The clone is "mutated" by appending XML padding (goodware signatures) to lower entropy and evade AI-based scanners. Evidence: `CryptBinaryToStringA` from `CRYPT32.dll` and XML manifest data in `.rsrc`.

**CAPE/Cuckoo Bypass:** `RegLoadAppKeyA` is used to break common sandbox system hooks.

### 6.3 Runtime Section Encryption (S-Box)

The `Check_Real` function resides in `.pdata_c`. According to the guide, this section should be encrypted on disk and only decrypted in memory at the exact moment of password entry via `CryptSection`. Immediately after verification, the section is re-encrypted.

**Reality:** In the analyzed build, the `.pdata_c` section was stored **unencrypted on disk**, allowing direct disassembly without any runtime decryption.

### 6.4 Anti-Debug Watchdog (The Bloodhound)

A separate monitoring thread continuously checks for:

| Technique | Evidence |
|---|---|
| ScyllaHide hook detection | Analysis of `ntdll.dll` API first bytes |
| Hardware breakpoint detection | Debug register `DR0–DR7` reads via `GetThreadContext` |
| Timing checks | `__rdtsc` instruction at offsets `0xb9bb`, `0xb9df` (executed before and after password check call) |
| Tool blacklist (40+ tools) | `FindWindowA` checking for Wireshark, Process Hacker, x64dbg, etc. |
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | Direct API calls |

---

## 6. Bypassing the Anti-Analysis Layers

By performing **pure static analysis on Linux**, all four defense pillars were simultaneously neutralized:

| Defense | Why It Fails on Linux |
|---|---|
| BSOD triggers | Cannot execute Windows kernel syscalls |
| Process explosion | Cannot call `CreateProcessA` on Linux |
| Ghost dropper | Cannot self-delete/mutate outside Windows |
| Anti-debug watchdog | No debugger attached, no timing anomaly |
| Anti-VM detection | Running on bare metal Linux, not a Windows VM |
| Section encryption | Section was plaintext on disk anyway |
| AY_OBFUSCATE strings | Decryption algorithm was reversible statically |

**This is the most effective strategy for this type of CrackMe** when the password checking logic is embedded in the binary and the anti-analysis is purely runtime, static analysis on a different OS bypasses everything.

---

## 7. The `.pdata_c` Section - Deep Dive

### 8.1 Section Metadata

| Attribute | Value |
|---|---|
| **VMA** | `0x140014000` |
| **File Offset** | `0x12E00` |
| **Raw Size** | 891 bytes (`0x37B`) |
| **Alignment** | 4 bytes (`2^2`) |
| **Characteristics** | `CONTENTS, ALLOC, LOAD, READONLY, CODE` |

### 8.2 Structure Overview

The section contains three functions:

| Offset (within section) | Size | Purpose |
|---|---|---|
| `0x000` | 343 bytes | `Check_Real` - Primary password verification function |
| `0x160` | 38 bytes | Init function - Zeroes the decrypted password buffer in TLS storage |
| `0x190` | 293 bytes | Secondary check function (DECOY) |
| `0x2D0` | 38 bytes | Init function - Zeroes the decoy buffer in TLS storage |
| `0x300` | 59 bytes | CryptSection toggle - Clears "initialized" flag for Function 1 |
| `0x340` | 59 bytes | CryptSection toggle - Clears "initialized" flag for Function 2 |

### 8.3 Hex Dump (First 48 Bytes)

```
0000: 48 89 5c 24 18 57 48 83 ec 20 48 8b f9 48 83 79  H.\$.WH.. H..H.y
0010: 10 0a 0f 85 32 01 00 00 48 b8 f0 de bc 9a 78 56  ....2...H.....xV
0020: 34 12 48 89 44 24 38 ba 64 00 00 00 0f 1f 40 00  4.H.D$8.d.....@.
```

The first instruction `mov %rbx, 0x18(%rsp); push %rdi; sub $0x20, %rsp` is the standard MSVC x64 function prologue. The `cmpq $0xa, 0x10(%rcx)` at offset `0x0D` immediately checks if the input string length equals 10, confirming the password is exactly **10 characters**.

---

## 8. XOR Decryption Algorithm Reversal

Both password functions in `.pdata_c` use the same decryption pattern to reveal the stored password at runtime:

### 9.1 Algorithm (Pseudocode)

```c
void decrypt_password(char* buffer, int length, uint64_t xor_key) {
    uint32_t accumulator = 0;
    
    for (int i = 0; i < length; i++) {
        accumulator += i;
        if (accumulator > 1000000)    // 0xF4240
            accumulator = 0;
        
        int shift = (i & 7) * 8;      // Select key byte: 0, 8, 16, 24, 32, 40, 48, 56
        uint8_t key_byte = (xor_key >> shift) & 0xFF;
        buffer[i] ^= key_byte;
    }
}
```

### 9.2 Key Characteristics

- **8-byte XOR key** stored as an immediate value via `movabs` (10-byte instruction: `49 BA XX XX XX XX XX XX XX XX`)
- **Accumulator-based key rotation** - the accumulator `acc += i` provides a secondary transformation, but since it always resets to 0 at `i > 1,000,000`, for strings shorter than ~1414 characters it simply equals `i*(i-1)/2` and **never overflows**. This means the accumulator adds zero effective obfuscation for short strings.
- **Byte selection** uses `i & 7` to cycle through the 8 key bytes
- **Encrypted data** is embedded directly in the binary via `movl` / `movw` instructions that construct the buffer on the stack or in TLS storage

### 9.3 Simplified Decryption (for strings < 1414 chars)

Since the accumulator never resets for short strings, the effective decryption simplifies to:

```python
for i in range(length):
    key_byte = (xor_key >> ((i & 7) * 8)) & 0xFF
    decrypted[i] = encrypted[i] ^ key_byte
```

The accumulator value is **always** `i*(i-1)/2` which is `<= 0xF4240` for `i < 1414`, so it never affects the result. This is a subtle design weakness, the anti-tamper accumulator is only effective for very long strings.

---

## 9. Password Recovery - Function 1 (`Check_Real`)

### 10.1 Function Disassembly (Annotated)

```
Function 1: Check_Real (offset 0x0000 in .pdata_c, VMA 0x140014000)

  ; Prologue - save non-volatile registers
  0x000: mov    %rbx, 0x18(%rsp)
  0x005: push   %rdi
  0x006: sub    $0x20, %rsp
  0x00A: mov    %rcx, %rdi              ; rcx = this (std::string* input)

  ; === LENGTH CHECK: password must be exactly 10 characters ===
  0x00D: cmpq   $0xa, 0x10(%rcx)        ; if (input.length() != 10)
  0x012: jne    0x14A                    ;   return false;

  ; === LCG ANTI-TAMPER SEED ===
  ; Initialize a Linear Congruential Generator with seed 0x123456789ABCDEF0
  ; Run it 100 (0x64) iterations to produce a pseudo-random value
  ; This value must be non-zero for the function to return true
  0x018: movabs $0x123456789ABCDEF0, %rax  ; LCG seed
  0x022: mov    %rax, 0x38(%rsp)
  0x027: mov    $0x64, %edx               ; loop count = 100

  ; LCG loop: x = (x << 13) ^ (x >> 7) ^ x
  0x030: mov    0x38(%rsp), %rax
  0x035: shl    $0xd, %rax               ; x << 13
  0x039: mov    0x38(%rsp), %rcx
  0x03E: shr    $0x7, %rcx               ; x >> 7
  0x042: or     %rax, %rcx               ; (x << 13) | (x >> 7)
  0x045: mov    0x38(%rsp), %rax
  0x04A: xor    %rcx, %rax               ; x ^ ((x << 13) | (x >> 7))
  0x04D: mov    %rax, 0x38(%rsp)
  0x052: sub    $0x1, %edx
  0x056: jne    0x030                    ; repeat 100 times

  ; === TLS BUFFER ACCESS ===
  ; Access thread-local storage to get the decrypted password buffer
  0x058: mov    %gs:0x58, %rax           ; TEB -> TLS array
  0x061: mov    (%rax), %rcx             ; TLS index
  0x064: mov    $0xB58, %edx             ; flag offset (initialized?)
  0x069: mov    (%rdx,%rcx,1), %eax      ; check if already initialized
  0x06C: mov    $0x418, %ebx             ; buffer offset in TLS
  0x071: add    %rcx, %rbx               ; rbx = TLS buffer pointer

  0x074: test   $0x1, %al
  0x076: jne    0x09F                    ; skip if already initialized

  ; === FIRST-TIME INITIALIZATION ===
  ; Set the "initialized" flag
  0x078: or     $0x1, %eax
  0x07B: mov    %eax, (%rdx,%rcx,1)

  ; Store encrypted password into TLS buffer:
  0x07E: movl   $0x80FE1426, (%rbx)         ; buffer[0..3]   = 26 14 FE 80
  0x085: movl   $0xB2AE4E2F, 0x4(%rbx)      ; buffer[4..7]   = 2F 4E AE B2
  0x08B: movl   $0x01AB754B, 0x8(%rbx)      ; buffer[8..10]  = 4B 75 AB 00

  ; Call CryptSection (init function at 0x160)
  0x092: lea    0xC7(%rip), %rcx
  0x099: call   CryptSection_Init1

  ; === XOR DECRYPTION LOOP ===
  0x09F: cmpb   $0x0, 0xb(%rbx)          ; if buffer[11] == 0 (already decrypted)
  0x0A3: je     0x0FC                    ;   skip decryption

  0x0A5: xor    %r9d, %r9d              ; acc = 0
  0x0A8: mov    %r9d, 0x30(%rsp)        ; acc on stack
  0x0AD: mov    %r9d, %r8d              ; i = 0
  0x0B0: movabs $0x85FF1D7FCFAB4173, %r10  ; *** XOR KEY ***

  ; Loop: for i = 0..10
  0x0C0: mov    0x30(%rsp), %eax        ; acc += i
  0x0C4: add    %r8d, %eax
  0x0C7: mov    %eax, 0x30(%rsp)
  0x0CB: movzbl %r8b, %ecx
  0x0CF: and    $0x7, %cl               ; (i & 7)
  0x0D2: shl    $0x3, %cl               ; * 8 = shift amount
  0x0D5: mov    %r10, %rdx
  0x0D8: shr    %cl, %rdx               ; key >> shift
  0x0DB: xor    %dl, (%rbx,%r8,1)       ; buffer[i] ^= key_byte
  0x0DF: mov    0x30(%rsp), %eax
  0x0E3: cmp    $0xF4240, %eax          ; if acc > 1000000
  0x0E8: jle    0x0EF                    ;   (never true for 11 iterations)
  0x0EA: mov    %r9d, 0x30(%rsp)        ; acc = 0
  0x0EF: inc    %r8
  0x0F2: cmp    $0xB, %r8               ; i < 11
  0x0F6: jb     0x0C0

  0x0F8: mov    %r9b, 0xb(%rbx)         ; buffer[11] = 0 (null terminate)

  ; === CALCULATE DECRYPTED PASSWORD LENGTH ===
  0x0FC: mov    $-1, %rax
  0x103: inc    %rax
  0x106: cmpb   $0x0, (%rbx,%rax,1)     ; strlen(buffer)
  0x10A: jne    0x103

  ; === COMPARE INPUT LENGTH WITH DECRYPTED PASSWORD LENGTH ===
  0x10C: mov    %rdi, %rcx
  0x10F: cmpq   $0xf, 0x18(%rdi)       ; if input capacity <= 15 (SSO)
  0x114: jbe    0x119
  0x116: mov    (%rdi), %rcx            ;   use heap pointer
  0x119: mov    0x10(%rdi), %r8         ; input.length()
  0x11D: cmp    %rax, %r8               ; if strlen(buffer) != input.length()
  0x120: jne    0x14A                    ;   return false;

  ; === COMPARE CONTENTS (memcmp/strcmp) ===
  0x122: test   %r8, %r8
  0x125: je     0x133                    ; if length == 0, skip
  0x127: mov    %rbx, %rdx              ; buffer (decrypted password)
  0x12A: call   memcmp                  ; compare input with buffer
  0x12F: test   %eax, %eax
  0x131: jne    0x14A                    ; if not equal, return false;

  ; === FINAL CHECK: LCG value must be non-zero ===
  0x133: mov    0x38(%rsp), %rax        ; LCG result
  0x138: test   %rax, %rax
  0x13B: je     0x14A                    ; if LCG == 0, return false;
  0x13D: mov    $0x1, %al               ; return true;
  0x13F: ...   (epilogue)
  0x149: ret

  ; === FAILURE PATH ===
  0x14A: xor    %al, %al                ; return false;
  0x14C: ...   (epilogue)
  0x156: ret
```

### 10.2 Encrypted Data Extraction

The encrypted password is stored via three `movl` instructions at offset `0x07E`:

| Instruction | Bytes (LE) | Meaning |
|---|---|---|
| `movl $0x80FE1426, (%rbx)` | `26 14 FE 80` | Buffer bytes 0–3 |
| `movl $0xB2AE4E2F, 0x4(%rbx)` | `2F 4E AE B2` | Buffer bytes 4–7 |
| `movl $0x01AB754B, 0x8(%rbx)` | `4B 75 AB 00` | Buffer bytes 8–10 + null |

**Full encrypted buffer (11 bytes):**

```
Offset:  0    1    2    3    4    5    6    7    8    9    10
Hex:    26   14   FE   80   2F   4E   AE   B2   4B   75   AB
```

### 10.3 XOR Key

```
movabs $0x85FF1D7FCFAB4173, %r10
```

**Key byte breakdown (little-endian extraction):**

| i | `i & 7` | Shift | `(key >> shift) & 0xFF` |
|---|---------|-------|------------------------|
| 0 | 0 | 0 | `0x73` |
| 1 | 1 | 8 | `0x41` |
| 2 | 2 | 16 | `0xAB` |
| 3 | 3 | 24 | `0xCF` |
| 4 | 4 | 32 | `0x7F` |
| 5 | 5 | 40 | `0x1D` |
| 6 | 6 | 48 | `0xFF` |
| 7 | 7 | 56 | `0x85` |
| 8 | 0 | 0 | `0x73` |
| 9 | 1 | 8 | `0x41` |
| 10 | 2 | 16 | `0xAB` |

### 10.4 Byte-by-Byte Decryption

| i | Encrypted | XOR Key Byte | `acc` | Decrypted | ASCII |
|---|-----------|-------------|-------|-----------|-------|
| 0 | `0x26` | `0x73` | 0 | `0x55` | **U** |
| 1 | `0x14` | `0x41` | 1 | `0x55` | **U** |
| 2 | `0xFE` | `0xAB` | 3 | `0x55` | **U** |
| 3 | `0x80` | `0xCF` | 6 | `0x4F` | **O** |
| 4 | `0x2F` | `0x7F` | 10 | `0x50` | **P** |
| 5 | `0x4E` | `0x1D` | 15 | `0x53` | **S** |
| 6 | `0xAE` | `0xFF` | 21 | `0x51` | **Q** |
| 7 | `0xB2` | `0x85` | 28 | `0x37` | **7** |
| 8 | `0x4B` | `0x73` | 36 | `0x38` | **8** |
| 9 | `0x75` | `0x41` | 45 | `0x34` | **4** |
| 10 | `0xAB` | `0xAB` | 55 | `0x00` | **NUL** |

### 10.5 Result

```
╔══════════════════════════════════╗
║  PASSWORD:  UUUOPSQ784           ║
║  Length:    10 characters        ║
║  Encoding:  All printable ASCII  ║
║  Null-terminated: Yes (byte 10)  ║
╚══════════════════════════════════╝
```

---

## 10. Password Recovery - Function 2 (The Decoy)

### 11.1 Function Overview

Function 2 at offset `0x190` uses the exact same algorithmic structure but with different data:

| Attribute | Function 1 (Real) | Function 2 (Decoy) |
|---|---|---|
| **Offset** | `0x000` | `0x190` |
| **Encrypted data** | `26 14 FE 80 2F 4E AE B2 4B 75 AB` | `93 76 A4 A5 40 F5 1A E8 91 6C 01` |
| **XOR key** | `0x85FF1D7FCFAB4173` | `0xAD5FB71FE1E533D7` |
| **TLS flag offset** | `0xB58` | `0x620` |
| **TLS buffer offset** | `0x418` | `0x578` |
| **Loop count** | 11 (`$0xB`) | 11 (`$0xB`) |

### 11.2 Decryption Result

| i | Encrypted | Key Byte | Decrypted | ASCII |
|---|-----------|----------|-----------|-------|
| 0 | `0x93` | `0xD7` | `0x44` | **D** |
| 1 | `0x76` | `0x33` | `0x45` | **E** |
| 2 | `0xA4` | `0xE5` | `0x41` | **A** |
| 3 | `0xA5` | `0xE1` | `0x44` | **D** |
| 4 | `0x40` | `0x1F` | `0x5F` | **_** |
| 5 | `0xF5` | `0xB7` | `0x42` | **B** |
| 6 | `0x1A` | `0x5F` | `0x45` | **E** |
| 7 | `0xE8` | `0xAD` | `0x45` | **E** |
| 8 | `0x91` | `0xD7` | `0x46` | **F** |
| 9 | `0x6C` | `0x33` | `0x5F` | **_** |
| 10 | `0x01` | `0xE5` | `0xE4` | **Non-ASCII!** |

**Result: `DEAD_BEEF_` + `0xE4`**

### 11.3 Why Function 2 is a Decoy

Function 2 decrypts to `DEAD_BEEF_` followed by byte `0xE4` (non-null, non-ASCII). The function then calculates `strlen()` on this buffer:

```c
// Function 2's strlen loop:
rax = -1;
do { rax++; } while (buffer[rax] != 0);
```

Since `buffer[10] = 0xE4 ≠ 0`, the strlen loop continues past byte 10 into uninitialized TLS memory until it eventually hits a null byte. The resulting strlen will be **greater than 10**, which will **never match** the input length of 10 (enforced by `cmpq $0xa, (%rsi)` at the start of the function).

```
strlen("DEAD_BEEF_\xe4...")  →  > 10
input.length()                →  10
 Comparison:                  →  FAIL (always)
```

**This is a deliberate misdirection.** The string `DEAD_BEEF_` looks like a plausible hex-style password, making it an attractive red herring for automated tools and inexperienced reversers.

---

## 11. Verification & Proof of Correctness

### 12.1 Consistency Checks

| Check | Function 1 | Function 2 |
|---|---|---|
| Decrypts to printable ASCII (bytes 0–9)? | **Yes** | Yes |
| Null terminator at byte 10? | **Yes** (`0x00`) | **No** (`0xE4`) |
| strlen == 10? | **Yes** | No (>10) |
| Matches `cmpq $0xa` length check? | **Yes** | No |
| memcmp with 10-char input possible? | **Yes** | No (strlen mismatch) |
| LCG seed produces non-zero result? | **Yes** | N/A |

### 12.2 Python Verification Script

```python
import struct

def decrypt_password(enc_bytes, xor_key):
    result = bytearray(enc_bytes)
    acc = 0
    for i in range(len(result)):
        acc += i
        if acc > 0xF4240:
            acc = 0
        shift = (i & 7) * 8
        key_byte = (xor_key >> shift) & 0xFF
        result[i] ^= key_byte
    return result

# Function 1: Check_Real
enc1 = bytes([0x26, 0x14, 0xFE, 0x80, 0x2F, 0x4E, 0xAE, 0xB2, 0x4B, 0x75, 0xAB])
key1 = 0x85FF1D7FCFAB4173
dec1 = decrypt_password(enc1, key1)
print(f"Password: {dec1[:10].decode('ascii')}")  # Output: UUUOPSQ784
assert dec1[10] == 0, "Null terminator missing!"
assert len(dec1[:10]) == 10, "Wrong length!"

# Function 2: Decoy
enc2 = bytes([0x93, 0x76, 0xA4, 0xA5, 0x40, 0xF5, 0x1A, 0xE8, 0x91, 0x6C, 0x01])
key2 = 0xAD5FB71FE1E533D7
dec2 = decrypt_password(enc2, key2)
print(f"Decoy:    {dec2[:10].decode('ascii')}")  # Output: DEAD_BEEF_
assert dec2[10] != 0, "Decoy should have non-null byte 10!"
```

### 12.3 LCG Verification

```python
# Verify the LCG produces non-zero after 100 iterations
x = 0x123456789ABCDEF0
for _ in range(100):
    x = ((x << 13) | (x >> 51)) ^ x  # 64-bit LCG
    x &= 0xFFFFFFFFFFFFFFFF
print(f"LCG result: 0x{x:016X}")  # Non-zero guaranteed
assert x != 0, "LCG must produce non-zero!"
```

---

## 12. The Function Dispatch Mechanism

### 13.1 Call Chain

The password verification is invoked through a function table dispatch mechanism that adds another layer of indirection:

```
main() → [anti-VM checks] → [anti-debug checks] → password_input()
                                                      ↓
                                              Function Table Dispatch
                                                      ↓
                                              Call via function pointer
                                                      ↓
                                        Check_Real (Function 1) ← THE REAL CHECK
                                        Function 2 (Decoy)       ← Always fails
```

### 13.2 Indirect Call Setup

At offset `0xB980` in `.text`, the code sets up a two-element function table:

```asm
lea    rax, [rip + 0x7c09]     ; rax = addr of data at .rdata:0x13590
mov    [rip + 0x12596], rax    ; func_table[0] = rax (at 0x1DF28)
```

The function at `.rdata:0x13590` contains VMT (Virtual Method Table) entries used by `std::string` operations. The actual `Check_Real` function address (`0x140014000`) is stored as a LEA target at offset `0xB7C0`:

```asm
lea    rax, [rip + 0x7c39]     ; rax = 0x140015200 (.rdata)
mov    [rip + 0x1275a], rax    ; store to global (0x1DF28)
```

### 13.3 Anti-Timing Check

Before and after the password check call, the code uses `rdtsc` to measure execution time:

```asm
0xB9BB: rdtsc                    ; T1 = start timestamp
0xB9DA: call   *%rdx             ; invoke password check via function pointer
0xB9DF: rdtsc                    ; T2 = end timestamp
0xB9F5: sub    %r14, %rbx        ; elapsed = T2 - T1
0xB9F8: cmp    $0x1FFFFFFF, %rbx ; if elapsed > ~536 million cycles
0xB9FF: ja     anti_tamper       ;   detected debugger single-stepping
```

This detects single-stepping in debuggers (IDA, x64dbg) where each instruction takes microseconds instead of nanoseconds.

---

## 13. AY_OBFUSCATE - String Encryption System

### 14.1 Overview

The binary implements a custom string encryption system (`AY_OBFUSCATE`) that protects all user-facing strings. A total of **64 unique decryption instances** were identified across the `.text` section.

### 14.2 Pattern

Each encrypted string follows this pattern:

```asm
; 1. Check if already decrypted (one-time flag in TLS storage)
cmpb   $0x0, offset(%buffer)
je     already_decrypted

; 2. Set initialization flag
or     $0x1, %eax
mov    %eax, flag_offset(%tls)

; 3. Store encrypted data (movl/movw/c6 instructions)
movl   $0xXXXXXXXX, (%buffer)        ; 4 bytes
movl   $0xXXXXXXXX, 0x4(%buffer)     ; 4 bytes
movw   $0xXXXX, 0x8(%buffer)         ; 2 bytes
; ... etc.

; 4. XOR decrypt (same algorithm as password)
movabs $0xXXXXXXXXXXXXXXXX, %r10/%r9 ; 8-byte key
.loop:
  xor    %dl, (%buffer,%r8,1)        ; buffer[i] ^= key_byte
  cmp    $length, %r8
  jb     .loop

; 5. Mark as decrypted
movb   $0x0, offset(%buffer)         ; clear flag
```

### 14.3 Identified Encrypted Strings

64 instances were found. Partial decryption of targeted strings near the password check area revealed fragments of output messages, but the full message content requires following each `movups`/`movdqa` load from `.rdata` to reconstruct the complete encrypted buffers.

The strings protected include (but are not limited to):

- Password prompt message
- `[+] ACCESS GRANTED` success message
- `[-] ACCESS DENIED` / wrong password message
- Anti-debug warning messages
- Process blacklist tool names
- Various status and error messages

---

## 14. LCG Anti-Tamper Seed

Function 1 includes a Linear Congruential Generator that serves as an anti-tamper mechanism:

```c
uint64_t x = 0x123456789ABCDEF0;  // Seed (movabs at offset 0x018)
for (int i = 0; i < 100; i++) {
    x = ((x << 13) | (x >> 51)) ^ x;  // xorshift
}
// x must be non-zero for the function to return true
```

**Purpose:** If an attacker patches the `je` instruction that checks `strlen() == input.length()`, the LCG check still blocks them, the function requires **three conditions** to be true simultaneously:

1. `input.length() == 10`
2. `memcmp(input, decrypted_password) == 0`
3. `LCG_result != 0`

Since the LCG seed `0x123456789ABCDEF0` is non-zero and the xorshift operation is invertible (for non-zero seeds), the result is **guaranteed to be non-zero** after 100 iterations. This means condition 3 is always satisfied, it acts as a safety net to prevent trivial patching, not as an additional password check.

---

## 15. Summary of findings

### Password

```
UUUOPSQ784
```

### Decoy

```
DEAD_BEEF_  (non-null terminator at byte 10 → always fails)
```

### Attack Vector

| Step | Action |
|---|---|
| 1 | Identify `.pdata_c` as the password section (PE section analysis) |
| 2 | Disassemble section contents (objdump x86-64) |
| 3 | Identify `movl` instructions storing encrypted password bytes |
| 4 | Extract 64-bit XOR key from `movabs` instruction |
| 5 | Reimplement decryption algorithm in Python |
| 6 | Verify null terminator and length consistency |
| 7 | Identify decoy function via strlen mismatch |
| 8 | Confirm via LCG non-zero guarantee |

### Key Insight

The most effective approach to this CrackMe was **cross-platform static analysis**. By analyzing the PE binary on Linux, all Windows-specific runtime protections (BSOD, anti-VM, anti-debug, watchdog) were simultaneously and completely neutralized without any effort. The `.pdata_c` section being stored unencrypted on disk was the critical vulnerability that enabled direct password extraction.

---

## 16. Conclusion

The OMEGA CrackMe implements an impressive array of anti-analysis techniques - four interleaved defense layers, 64+ obfuscated strings, decoy functions, timing checks, and anti-tamper mechanisms. However, the fundamental weakness is that **the password verification logic must exist somewhere in the binary**, and the `.pdata_c` section's XOR encryption was either intentionally left unencrypted for this build or was a compilation oversight.

The decoy function (`DEAD_BEEF_`) is a clever misdirection that would waste time for anyone relying solely on pattern matching or automated string extraction. The three-condition verification (length, content, LCG) makes naive patching more difficult. But ultimately, static analysis of the decryption algorithm provides a direct, reliable path to the password.

```
╔══════════════════════════════════════════════════╗
║                                                  ║
║   [+ ] PASSWORD:  UUUOPSQ784                     ║
║   [+ ] ACCESS GRANTED                            ║
║                                                  ║
╚══════════════════════════════════════════════════╝
```

---

*Write-up completed via static analysis on Linux. No Windows VM, no debugger, no dynamic execution required.*

---

