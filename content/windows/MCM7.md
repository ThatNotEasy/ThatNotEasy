# MCM v7.0 


## TL;DR

- **Key:** `MCM_SUCK_1_Su_3_ck_3_Suck_7` (inner payload validation chain).
- **Technique:** Dynamic API hashing + emulated decrypt of ~421 KB inner PE after tens of millions of instructions.

---

## 1. Overview

MCM v7.0 is a heavily obfuscated 64-bit Windows console crackme featuring **six layers of protection**: FNV-1a API hashing, an XOR state machine, seven anti-debug gates, control flow flattening with ~61K cases, a three-layer encryption pipeline (block cipher + XOR + PRNG-seeded Fisher-Yates shuffle), and decoy PE sections. The actual crackme logic is hidden inside a **421KB encrypted embedded PE** within the `.data` section, only decrypted at runtime.

Using a custom Unicorn Engine emulator with hooked API resolvers and a clean LCG-based PRNG, the payload was fully decrypted after **80 million emulated instructions**. Disassembly of the inner PE revealed a **multi-stage serial validation chain** culminating in the key `MCM_SUCK_1_Su_3_ck_3_Suck_7`.

---

## 2. Binary identification

| Property | Value |
|---|---|
| **File size** | 4,330,496 bytes (4.2 MB) |
| **SHA-256** | `7fe04b2c7edda31b41ea0a444e456503926aef20b6387ee8393ed48d866a3294` |
| **MD5** | `820914480d7260f22d229d336ed4d29f` |
| **Architecture** | x86-64 (PE32+) |
| **Subsystem** | WINDOWS_CUI (Console) |
| **Entry Point** | `0x140008030` (RVA `0x8030`) |
| **Image Base** | `0x140000000` |
| **Compiler** | MSVC (Rich header + CODEVIEW debug info) |
| **PDB Path** | `CrackMeByPwn.pdb` |
| **Timestamp** | 2026-04-02 18:16:27 UTC |
| **Import Table** | **NONE** — all APIs resolved dynamically at runtime |
| **TLS Directory** | Not present |
| **Digital Signature** | Not present |

---

## 3. PE section analysis

The binary contains **13 sections** — significantly more than typical executables.

| Section | VirtSize | RawSize | Entropy | Permissions | Role |
|---|---|---|---|---|---|
| `.text` | 0x2E5C4C | 0x2E5E00 | 5.71 | X,e,r | Code (3 MB) |
| `.rdata` | 0xC5AC8 | 0xC5C00 | 6.54 | R,r | Read-only data (nearly empty of strings) |
| **`.data`** | **0x66E20** | **0x67000** | **7.9993** | R,r,w | **Encrypted payload (421 KB)** |
| `.pdata` | 0x384 | 0x400 | 4.26 | R,r | Exception data |
| `.xbs3` | 0x3736 | 0x3800 | 4.52 | R,r,w | Decoy (author watermark) |
| `.nfsni` | 0x2B5D | 0x2C00 | 4.52 | R,e,r | Decoy |
| `.vpjy` | 0xE48 | 0x1000 | 4.43 | R,e,r | Decoy |
| `.0lz` | 0xF68 | 0x1000 | 4.51 | R,e,r | Decoy |
| `.as7` | 0xE16 | 0x1000 | 4.41 | R,e,r | Decoy |
| `.20att` | 0x12AB | 0x1400 | 4.49 | R,r,w | Decoy |
| `.dnzv` | 0x2923 | 0x2A00 | 4.52 | R,r,w | Decoy |
| `.t53j` | 0xC4D | 0xE00 | 4.41 | R,e,r | Decoy |
| `.reloc` | 0x10 | 0x200 | 0.18 | R,r | Minimal relocations |

### Key Observations

- **`.data` at entropy 7.9993** — virtually indistinguishable from random noise. This is the encrypted Stage 2 payload.
- **8 randomly-named sections** (`.xbs3` through `.t53j`) are filled with the repeating string `"hello It's crackme by @pwn.by (discord)"`. They serve as both author watermarks and integrity anchors — the entry point reads the first byte (`0x68` = `'h'`) from each and sums them as a checksum.
- **No import table** means the binary resolves every Windows API call at runtime via PEB walking and hash matching. There are zero clues about functionality from the import directory alone.

---

## 4. Obfuscation layer 1: API hashing via PEB walking

All 11 API resolver functions share an identical structure:

```
1. Read PEB via gs:[0x60]
2. Walk PEB_LDR_DATA.InMemoryOrderModuleList
3. For each loaded module, read BaseDllName (UTF-16)
4. Hash each character with modified FNV-1a:
     - Uppercase a-z (sub 0x20)
     - Sign-extend low byte to 32 bits
     - XOR with hash accumulator
     - Multiply by 0x01000193
5. Compare hash against target DLL hash
6. On match, walk the module's export table
7. Hash each export name, compare against target function hash
8. Return function pointer
```

**Hash algorithm:** Modified FNV-1a  
- **Basis:** `0x811C9DC5`  
- **Prime:** `0x01000193`  
- **Difference from standard:** Operates on sign-extended low byte of each character, not raw byte.

### Resolved APIs

All 11 resolvers target `kernel32.dll` (hash `0x29CDD463`):

| Resolver RVA | Function Hash | API |
|---|---|---|
| `0x1AB0` | `0x4FF7FB75` | `GetTickCount` |
| `0x2D40` | `0x6D3D9A28` | `Sleep` |
| `0x3200` | `0xAC392D5A` | `ExitProcess` |
| `0x3B30` | `0xAC392D5A` | `ExitProcess` |
| `0x3ED0` | `0xAC392D5A` | `ExitProcess` |
| `0x4270` | `0x4FF7FB75` | `GetTickCount` |
| `0x5D60` | `0xD1AFE3BC` | `GetComputerNameA` |
| `0x6120` | `0x38E87001` | `VirtualAlloc` |
| `0x6A30` | `0x81178A12` | `VirtualFree` |
| `0x6DD0` | `0xAC392D5A` | `ExitProcess` |
| `0x7740` | `0x4FF7FB75` | `GetTickCount` |

Notable: **No I/O APIs** (no `ReadConsoleW`, `WriteConsoleW`, `scanf`, `printf`). This confirmed early on that the actual crackme logic lives inside the encrypted payload.

---

## 5. Obfuscation layer 2: XOR state machine

The entry point at `0x140008030` constructs a 64-bit "state variable" from 8 encrypted bytes on the stack:

| Stack Offset | Encrypted | XOR Key | Decrypted | Bit Shift |
|---|---|---|---|---|
| `[rsp+0x40]` | `0x71` | `0x9F` | `0xEE` | `<<0` |
| `[rsp+0x41]` | `0x73` | `0xE5` | `0x96` | `<<8` |
| `[rsp+0x43]` | `0x82` | `0xEE` | `0x6C` | `<<16` |
| `[rsp+0x45]` | `0x2E` | `0x40` | `0x6E` | `<<24` |
| `[rsp+0x44]` | `0xD8` | `0xDA` | `0x02` | `<<32` |
| `[rsp+0x42]` | `0xD9` | `0x77` | `0xAE` | `<<40` |
| `[rsp+0x46]` | `0xF8` | `0x60` | `0x98` | `<<48` |
| `[rsp+0x47]` | `0xEA` | `0x5B` | `0xB1` | `<<56` |

**Initial state = `0xB198AE026E6C96EE`**

This value serves as the decryption key seed for the entire Stage 2 payload.

Before the XOR chain, the entry point reads the first byte from each of the 8 decoy sections (`0x68` = `'h'` each time) and sums them to `0x340`. This is a basic integrity check — if any decoy section is modified, the sum changes and downstream logic breaks.

---

## 6. Obfuscation layer 3: anti-debug / anti-analysis gates

Seven gates sit between the XOR chain and the decryption routine. Each gate, if triggered, XORs the state variable with a corruption constant — silently breaking the decryption key without any visible error.

| # | Check | Trigger Condition | XOR Corruption |
|---|---|---|---|
| 1 | `IsDebuggerPresent` | Debugger attached | `0xA3F17C928E4D05B6` |
| 2 | Timing: too fast | `GetTickCount` delta < 30ms after `Sleep(50)` | `0x5C8E1A7F` |
| 3 | Timing: too slow | `GetTickCount` delta > 5000ms | `0x3D92B4E1` |
| 4 | ComputerName fail | `GetComputerNameA` returns 0 | `0xE7A2C3D8` |
| 5 | ComputerName empty | Buffer first byte is null | `0x6B19F4A5` |
| 6 | PID-based dispatch | Deterministic: always selects `table[2]` = 0 (no change) | No-op |
| 7 | RDTSC timing | Feeds into CFF dispatcher, additional timing entropy | Indirect |

**On clean execution** (no debugger, normal timing, real machine with a hostname), **none of the gates fire**, and the state remains `0xB198AE026E6C96EE`.

Gate 6 deserves special note: it computes `(PID XOR PID) + 2 = 2`, indexes into a function pointer table `[0x7A3C, 0x91E5, 0, 0x4DB8]`, and XORs the result with the state. Since `table[2] = 0`, this is always a no-op — a clever decoy that looks like it depends on the PID but doesn't.

---

## 7. Obfuscation layer 4: control flow flattening

After the anti-debug gates, the code enters a massive CFF dispatcher:

```asm
mov  dword ptr [rsp+0x78], 0x4623     ; initial case
...
lea  rcx, [image_base]                 ; jump table base
mov  eax, [rcx + rax*4 + 0x2A94DC]    ; load case offset
add  rax, rcx                          ; compute target VA
jmp  rax                               ; dispatch
```

- **Dispatcher variable:** `[rsp+0x78]`
- **Jump table:** at image base + `0x2A94DC`
- **Case range:** `0x1000` to `0xFFFF` (~61,437 possible cases)
- **Initial case:** `0x4623`

Each case performs a small block of operations, then updates the dispatcher variable (often through opaque predicates like `val XOR 0x5C; val XOR 0x30; cmp result, 0; cmovne eax, ...`) to select the next case.

This structure obliterates the original control flow graph, making static analysis of execution order nearly impossible without emulation.

---

## 8. Obfuscation layer 5: three-layer encryption pipeline

The decryption routine (reached via CFF case chain) is located at `0x1402A866F` and processes the entire `.data` section (0x66E00 = 421,376 bytes).

### Setup Phase (0x1402A866F)

```asm
mov  rax, [rsp + 0x12110]          ; load original state
and  rcx, 0                         ; rcx = 0 (no-op XOR)
xor  rax, rcx                       ; state unchanged
mov  [rsp + 0x3ac58], rax           ; copy state for decrypt
```

Hardcoded constants written to stack:
- **32-byte key:** `9D3A8B53 4B6D5A6A 61390CCD EDF03179 E2C5C52B 6B28DDD5 98EE7A89 F17675F3`
- **12-byte nonce:** `E4B48C29 8F31D743 6AF8C6A0`
- **Counter seed:** `0x8E8B7204`

### Layer 1: Block Cipher (ChaCha20-like)

The outer loop processes `.data` in **64-byte blocks** — the hallmark of ChaCha20:

```
for offset in range(0, 0x66E00, 64):
    generate_keystream_block(cipher_ctx, output_buf)  ; call 0x23B0
    for i in range(min(64, remaining)):
        data[offset + i] ^= keystream[i]
```

The cipher context is initialized at `0x10A0` with the key, nonce, and counter.

### Layer 2: Sub + Key XOR Pass

```python
for i in range(0x66E00):
    data[i] = (data[i] - (i ^ 0xAB)) & 0xFF          # subtract (index XOR 0xAB)
    key = ((state & 0xFFFF) + i * 0x37) & 0xFF         # derive key byte from state
    data[i] ^= key                                      # XOR with key
```

Where `state & 0xFFFF = 0x96EE`.

### Layer 3: PRNG-Seeded Fisher-Yates Shuffle

After the XOR passes, `VirtualAlloc` allocates a `0x66E00 * 4`-byte buffer (1,685,504 bytes) and performs a **Fisher-Yates shuffle** to permute all bytes:

```
for i in range(0x66E00 - 1, 0, -1):
    j = prng() % (i + 1)
    buffer[i] = j                    ; store permutation indices
```

Then the shuffle is applied to reorder the `.data` bytes.

### The PRNG (0x1400076D0)

A **PCG-style Linear Congruential Generator** with RDTSC-based anti-debug:

```
state = state * 0x5851F42D4C957F2D + 0x14057B7EF767814F
return (state >> 32) & 0x7FFFFFFF
```

The PRNG also performs two `RDTSC` calls and checks the timing delta. If the delta exceeds ~50 million cycles (~20ms), it XORs the PRNG state with a corruption byte — another silent anti-debug mechanism.

**On clean execution**, the two `RDTSC` calls return nearly identical values, making `cmovbe ecx, 0` fire, resulting in `XOR state, 0` — a no-op.

---

## 9. Automated solver

Since the entire decryption pipeline is deterministic given the clean state value, I built a **Unicorn Engine-based emulator** that:

1. **Maps all 13 PE sections** into emulator memory
2. **Skips the CFF** by jumping directly to the decrypt setup at `0x1402A866F`
3. **Sets the state** to `0xB198AE026E6C96EE` at `[rsp + 0x12110]`
4. **Hooks all 11 API resolvers** — returns mock function pointers without executing the PEB walking code
5. **Hooks VirtualAlloc/VirtualFree** — provides real memory allocations within the emulator
6. **Hooks the PRNG** — implements the clean LCG directly (avoiding RDTSC complications)
7. **Runs for 80 million instructions** (~89 seconds) until the decryption completes
8. **Dumps the decrypted `.data` section** and searches for strings

### Results

| Metric | Before | After |
|---|---|---|
| **Entropy** | 7.9996 | **6.4948** |
| **Readable strings** | 0 | **10,369** |
| **Structure** | Random noise | **Valid PE (MZ header)** |

The decrypted payload is a complete **64-bit MSVC-compiled PE** with:
- 7 sections: `.text`, `.smc`, `.data`, `.pdata`, `.idata`, `.fptable`, `.reloc`
- Full import table: `ReadConsoleW`, `WriteConsoleW`, `GetStdHandle`, `IsDebuggerPresent`, etc.
- Entry point at RVA `0x39F2C`

---

## 10. Inner PE analysis — the actual crackme

### Program Messages

| Offset | String | Purpose |
|---|---|---|
| `0xD9D0` | `MCM v7.0 \| :) Suck Suck Suck :)` | Success message |
| `0xD9F0` | `MCM v7.0 \| Don't RE This.` | Taunt |
| `0xDA10` | `MCM v7.0 \| HI! https://pwned.space/` | Banner |
| `0xDA38` | `MCM v7.0 \| Hello https://pwned.space/` | Alternate banner |
| `0xDA70` | `RunParent: ALARM! UD2 exception ...` | Anti-tamper |

### Serial Validation Chain

The inner PE implements a **multi-stage serial check** at `0x140031340`. Each stage compares the input length and content against a hardcoded string via `call 0x140059640` (a `memcmp`-like function):

| Stage | Length Check | Expected Input | On Match |
|---|---|---|---|
| 1 | `cmp r13, 0x12` (18) | `777SuckSuckSuck777` | Opens main validation |
| 2 | `cmp r13, 0x0C` (12) | `SuckSuckSuck` | Sets flag |
| 3 | `cmp r13, 0x08` (8) | `SuckSuck` | Sets flag |
| 4 | `cmp r13, 0x1D` (29) | `0xCC01Suck55Suck3FUNC13Suck37` | Sets flag |
| **5** | **`cmp r13, 0x1B` (27)** | **`MCM_SUCK_1_Su_3_ck_3_Suck_7`** | **Victory!** |

### Victory Condition

When Stage 5 matches, the code executes:

```asm
xor  dword ptr [rip + 0x31997], 0xDEAD     ; unlock token A
xor  dword ptr [rip + 0x319A9], 0xBEEF     ; unlock token B
call 0x140020670                             ; resolve Sleep
mov  ecx, 0x12C                              ; Sleep(300ms)
call rax
```

### Mask-Based Validation

A secondary validation path at `0x14001F56F` uses a **mask string**:

```
Mask: xxxxxxxx???xxxxxxx???xx????xxx?xx???xxxx?x?x???xxxx
Key:  MCM_SUCK_1_Su_3_ck_3_Suck_7
```

The algorithm:
```asm
cmp  al, 0x78              ; if mask[i] == 'x'
jne  skip_check            ;   wildcard → skip
movzx eax, [key_ptr]       ; load expected char
cmp  [input_ptr], al       ;   compare input char with key char
jne  fail                  ;   mismatch → reject
```

Where `x` = exact match required, `?` = any character accepted.

---

## 11. Solution

### Primary Key

```
MCM_SUCK_1_Su_3_ck_3_Suck_7
```

### Full Serial Chain (if multi-stage input is required)

```
Stage 1: 777SuckSuckSuck777
Stage 2: SuckSuckSuck
Stage 3: SuckSuck
Stage 4: 0xCC01Suck55Suck3FUNC13Suck37
Stage 5: MCM_SUCK_1_Su_3_ck_3_Suck_7
```

---

## 12. Protection summary

```
┌─────────────────────────────────────────────────────────┐
│                    CrackMe_packed.exe                    │
│                      (Outer PE)                         │
├─────────────────────────────────────────────────────────┤
│ Layer 1: FNV-1a API Hashing (PEB walking, 11 resolvers) │
│ Layer 2: XOR State Machine (8-byte → 0xB198AE026E6C96EE)│
│ Layer 3: 7 Anti-Debug Gates (silent state corruption)    │
│ Layer 4: Control Flow Flattening (~61K switch cases)     │
│ Layer 5: 3-Layer Encryption:                             │
│   ├─ Block cipher (ChaCha20-like, 64B blocks, 32B key)  │
│   ├─ Sub-XOR pass (state-derived key, per-byte)          │
│   └─ Fisher-Yates shuffle (LCG PRNG, state-seeded)       │
│ Layer 6: 8 Decoy Sections (watermark + integrity check)   │
├─────────────────────────────────────────────────────────┤
│                   Decrypted Payload                      │
│                    (Inner PE, 421KB)                     │
├─────────────────────────────────────────────────────────┤
│ - .smc section (self-modifying code)                     │
│ - Multi-stage serial validation (5 stages)               │
│ - Mask-based character comparison                        │
│ - DEAD/BEEF unlock on success                            │
│ - UD2 exception anti-tamper                              │
│ - ReadConsoleW/WriteConsoleW for I/O                     │
└─────────────────────────────────────────────────────────┘
```

---

## 13. x64dbg quick-solve reference

For those who prefer a debugger-based approach:

### Patches (NOP the anti-debug XORs)

| Address | Original | Patch | Purpose |
|---|---|---|---|
| `0x1400082B9` | `48 33 C1` | `90 90 90` | Kill IsDebuggerPresent gate |
| `0x14000834F` | `48 35 7F 1A 8E 5C` | `90 90 90 90 90 90` | Kill timing-fast gate |
| `0x140008378` | `48 35 E1 B4 92 3D` | `90 90 90 90 90 90` | Kill timing-slow gate |
| `0x1400083EA` | `48 33 C1` | `90 90 90` | Kill ComputerName-fail gate |
| `0x14000841B` | `48 35 A5 F4 19 6B` | `90 90 90 90 90 90` | Kill ComputerName-empty gate |

### Breakpoints

| Address | When | What to check |
|---|---|---|
| `0x14000849F` | After all gates | `[rsp+0x12110]` should be `0xB198AE026E6C96EE` |
| `0x1402A88DA` | Decrypt start | State at `[rsp+0x3AC58]` |
| `0x1402A8BB9` | **Decrypt done** | Dump `0x1403AD000`, size `0x66E00` |

### Dump command

```
savedata "decrypted_inner.exe", 0x1403AD000, 0x66E00
```

---

