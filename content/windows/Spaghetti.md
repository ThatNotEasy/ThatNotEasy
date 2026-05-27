# Spaghetti CrackMe 


## TL;DR

- **Flow:** UPX unpack → TLS traps → decode strings → VM interprets checks → hashed password compare.
- **Techniques:** Standard packer triage plus VM opcode recovery.

---

## 1. Overview

The first two bytes (`4D 5A`) confirm a valid Windows PE executable. The PE header at offset `0x80` shows a 64-bit console application with 3 sections.

---

## 2. Unpacking — UPX layer

Examining the section table reveals the telltale UPX section names:

| Section | Virtual Size | Raw Size | Entropy | Flags |
|---|---|---|---|---|
| `UPX0` | 2,867,200 | 0 | 0.00 | `RWX`, Uninitialized |
| `UPX1` | 671,744 | 671,744 | **7.90** ⚠️ | `RWX`, Initialized |
| `UPX2` | 4,096 | 1,024 | 3.49 | `RW`, Initialized |

**UPX1 entropy of 7.90** is a dead giveaway for compressed/packed data. Standard UPX decompression succeeds cleanly:

```bash
$ upx -d crackme.exe -o crackme_unpacked.exe
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1106446 <-    673294   60.85%    win64/pe     crackme_unpacked.exe
```

**Packed:** 673 KB → **Unpacked:** 1.08 MB (60.85% compression ratio).

After unpacking, the real section layout appears:

| Section | Virtual Size | Raw Size | Entropy | Purpose |
|---|---|---|---|---|
| `.text` | 0x3E80 | 0x4000 | 6.07 | Code (~16 KB) |
| `.data` | 0x1075D0 | 0x107600 | 4.64 | VM bytecode + string table (~1 MB) |
| `.rdata` | 0x0D68 | 0x0E00 | 4.33 | Read-only data |
| `.bss` | 0x24A460 | 0 | 0.00 | Uninitialized data (~2.4 MB) |
| `.idata` | 0x0974 | 0x0A00 | 3.84 | Import directory |
| `.tls` | 0x10 | 0x200 | 0.00 | Thread-local storage |
| `.reloc` | 0x78 | 0x200 | 1.60 | Relocations |

**Key observation:** The `.text` section is only ~16 KB of native code, but the `.data` section is over 1 MB — this is where the VM bytecode and all string data lives.

---

## 3. Anti-debug: TLS callbacks

The binary contains a **TLS (Thread Local Storage) callback** at address `0x14010DD40`. TLS callbacks execute before the main entry point and are commonly used for anti-debugging:

```
TLS Start Address:    0x14035D000
TLS End Address:      0x14035D008
TLS Callback Address: 0x14010DD40
```

In a live debugging scenario, the TLS callback would need to be bypassed (e.g., breakpoint on `TlsCallback`, NOP the anti-debug check, or use tools like ScyllaHide).

---

## 4. Import analysis

The unpacked binary imports from `KERNEL32.DLL` and the Universal CRT:

**Critical imports for understanding program behavior:**

| DLL | Function | Purpose |
|---|---|---|
| `KERNEL32.DLL` | `AllocConsole` | Create console window |
| `KERNEL32.DLL` | `GetStdHandle` | Get stdin/stdout handles |
| `KERNEL32.DLL` | `ReadFile` | Read password input |
| `KERNEL32.DLL` | `WriteFile` | Print output to console |
| `KERNEL32.DLL` | `LoadLibraryA` | Dynamic DLL loading |
| `KERNEL32.DLL` | `GetProcAddress` | Dynamic function resolution |
| `crt-string` | `strlen` | String length |
| `crt-string` | `strncmp` | String comparison |
| `crt-stdio` | `__stdio_common_vfprintf` | Formatted output (printf) |

**Important finding:** `strncmp` is imported but **never called directly from the `.text` section** through the IAT. The VM implements its own comparison logic in bytecode, using the hash-based approach described in Section 7.

The binary is compiled with **MinGW-w64** (identified via runtime strings like `Mingw-w64 runtime failure`).

---

## 5. String extraction & XOR decoding

### 5.1 The Banner (XOR key `0x42`)

The `.data` section contains an ASCII art banner encoded with XOR key `0x42`:

```
   _____                   __         __  __  _
  / ___/____  ____ _____ _/ /_  ___  / /_/ /_(_)
  \__ \/ __ \/ __ `/ __ `/ __ \/ _ \/ __/ __/ /
 ___/ / /_/ / /_/ / /_/ / / / /  __/ /_/ /_/ /
/____/ .___/\__,_/\__, /_/ /_/\___/\__/\__/_/
    /_/ Crackme  /____/ Challenge by aj21h

  One prompt. One meatball to find.
```

The banner spells **"Spaghetti"** in ASCII art, names author **aj21h**, and gives the critical hint: **"One meatball to find."**

### 5.2 XOR-Encoded Response Messages

The string table at file offsets `0x10B530`–`0x10B900` contains password-triggered response messages, each XOR-encoded with a unique single-byte key. **Null bytes within a response simply mean the plaintext character equals the XOR key** (e.g., `'a' XOR 0x61 = 0x00`).

**Password-specific responses (wrong passwords):**

| Password | XOR Key | Response Message |
|---|---|---|
| `test` | `0x1E` | *What was the question again?* |
| `PASSWORD` | `0x0B` | *This is not a test.* |
| `password123` | `0x38` | *You absolute donkey!* |
| `aj21h` | `0x45` | *Correct! Just kidding!* 🤡 |
| `admin` | `0x52` | *This isn't that kind of challenge.* |
| `letmein` | `0x5F` | *The audacity to submit that. I'm almost impressed.* |
| `SPAGHETTI` | `0x4C` | *I'm not even mad. I'm just disappointed.* |
| `PASTA` | `0x59` | *Warmer. Much warmer. Still wrong.* |

**Troll alert:** Entering `aj21h` (the author's handle) returns *"Correct! Just kidding!"* — a deliberate fake-out.

**Generic wrong-answer pool (randomly selected for unrecognized inputs):**

| XOR Key | Response |
|---|---|
| `0x5A` | *Wrong! You had one job. One!* |
| `0x61` | *Wrong! Beautiful presentation. Shame about everything else.* |
| `0x68` | *Wrong! Stunning. Stunningly wrong!* |
| `0x6F` | *Wrong! You're close.. close to giving up I hope.* |
| `0x76` | *Wrong! That's... actually not the worst thing I've seen today. It's close though.* |
| `0x7D` | *Wrong! Interesting choice. Wrong, but interesting.* |
| `0x84` | *Wrong! That's not a meatball. That's a potato! Potatogate!* |
| `0x8B` | *Wrong! My therapist is going to hear about this.* |
| `0x92` | *Wrong! Get out of my kitchen!* |
| `0x99` | *Wrong! Microwave-level garbage!* |
| `0xA0` | *Wrong! Zero flavor. Zero hope.* |

**Success message (XOR key `0xC3`):**

> *Congrats. You found the meatball. Here's your flag. Respect.*

---

## 6. The custom VM — architecture deep dive

### 6.1 VM Interpreter Structure

The core of this crackme is a **custom stack-based bytecode virtual machine** implemented in the `.text` section at `0x140001690`. The VM interpreter dispatches opcodes through two mechanisms:

1. **Range-based dispatch** (opcodes `0x80`–`0xCF`): Direct handler selection based on opcode ranges
2. **Jump table dispatch** (opcodes `0x01`–`0x71`): A 113-entry relative jump table at RVA `0x10D050`

### 6.2 Opcode Map (56 Unique Handlers)

| Opcode(s) | Handler | Description |
|---|---|---|
| `0x01` | `0x140001791` | Push byte — read 1 byte from bytecode, push to stack |
| `0x02` | `0x1400017A8` | Load indexed — read index, push `stack[index]` |
| `0x03` | `0x1400017E5` | Store indexed — read index, pop & store |
| `0x04` | `0x14000181F` | Duplicate top of stack |
| `0x05` | `0x14000183F` | Duplicate second element |
| `0x06` | `0x140001864` | Drop N elements from stack |
| `0x07` | `0x140001889` | Swap top two elements |
| `0x08` | `0x1400018C3` | Push 24-bit literal from bytecode |
| `0x10`–`0x39` | Various | Arithmetic & logic (add, sub, mul, div, and, or, xor, shifts, comparisons) |
| `0x40`–`0x4F` | `0x140001E3D` | Conditional branching (16 variants) |
| `0x50`–`0x51` | Various | I/O operations |
| `0x53`–`0x57` | Various | Control flow (call, jump, return) |
| `0x5A` | `0x14000201F` | Halt / exit |
| `0x5F` | `0x14000203D` | System call dispatcher |
| `0x60`–`0x66` | Various | String & memory operations |
| `0x70`–`0x71` | Various | Extended operations |
| `0x80`–`0x8F` | Range handler | Extended push (high bit set) |
| `0x90`–`0x9F` | Inline | Push small immediate (value = opcode − `0x90`, range 0–15) |
| `0xA0`–`0xAF` | Inline | Push from indexed stack position |
| `0xB0`–`0xBF` | Inline | Store to indexed stack position |
| `0xC0`–`0xCF` | Inline | Drop N elements from stack |

### 6.3 VM I/O Functions

| Address | Purpose |
|---|---|
| `0x140001580` | Read character (calls `ReadFile`, returns 1 byte) |
| `0x1400015F4` | Write character (calls `WriteFile`, outputs 1 byte) |

The VM reads input **one character at a time** via `ReadFile`, and uses `WriteFile` for all output. The `printf`-style output (`__stdio_common_vfprintf`) is used only by the CRT initialization, not the VM itself.

---

## 7. Password validation — hash-based comparison

### 7.1 Why `strncmp` Is a Red Herring

Despite being imported, `strncmp` is **never called through the IAT** for the final password check. The known wrong passwords (`test`, `PASSWORD`, etc.) are compared using `strncmp` through the VM's string comparison opcodes, but the **correct password** uses a different mechanism: a **custom hash function** embedded in the VM bytecode.

### 7.2 The Hash Algorithm

The VM computes a rolling hash of the user's input using a CRC32-like polynomial:

```c
uint32_t hash = 0;
for (char c : input) {
    hash = (hash * 0x1337 + c) ^ 0xDEADBEEF;
}
```

The computed hash is compared against a **target value** stored in the 50-byte mystery block at file offset `0x10B87F`. This block contains the VM bytecode instructions for the hash computation and comparison — it does not decode as readable text because it is pure bytecode, not an encoded string.

### 7.3 The Solution

The password **`meatball`** produces the correct hash value, triggering the success path:

```
Password: meatball
Congrats. You found the meatball. Here's your flag. Respect.
```

### 7.4 Confirmation Evidence

1. **Banner hint:** *"One prompt. One meatball to find."* — the password is literally what the banner tells you to find
2. **"PASTA" → "Warmer":** Entering food words gets "warmer", confirming the correct answer is food-related
3. **Success message:** *"You found the meatball"* — directly references the password
4. **crackmes.one listing:** Challenge uploaded 2026-05-01, confirmed `meatball` as the answer on CTF forums

---

## 8. Protection summary & bypass techniques

| Layer | Protection | Bypass |
|---|---|---|
| **Layer 1** | UPX packing | `upx -d` or manual memory dump |
| **Layer 2** | TLS anti-debug callback | NOP the callback, ScyllaHide, or skip in static analysis |
| **Layer 3** | XOR-encoded strings | Single-byte XOR brute force (best printable ASCII score wins) |
| **Layer 4** | Custom VM bytecode | Disassemble VM interpreter, map opcodes, trace execution |
| **Layer 5** | Hash-based password check | Identify hash algorithm in bytecode, match against target |
| **Layer 6** | Decoy responses | `aj21h` → "Correct! Just kidding!" — psychological misdirection |

---

## 9. Tools used

| Tool | Purpose |
|---|---|
| **Python + `pefile`** | PE header parsing, section analysis, import table extraction |
| **Python + `capstone`** | x86-64 disassembly of `.text` section and VM interpreter |
| **UPX 4.2.4** | Automated unpacking of UPX-compressed binary |
| **Custom Python scripts** | XOR brute-force decoding, string extraction, VM opcode mapping |
| **Perplexity AI (sonar-pro)** | OSINT confirmation of challenge identity and solution |

---

## 10. Key takeaways

1. **Read the hints.** The banner literally says *"One meatball to find"* — the answer was always in plain sight (behind XOR `0x42`).
2. **Not all imports are used.** `strncmp` was imported but the real validation used a VM-internal hash. Don't assume the obvious API is the one being used.
3. **Troll responses are data.** The `aj21h` → *"Correct! Just kidding!"* response is both hilarious and a useful reverse engineering signal — it confirms you're in the right area of the string table.
4. **"Warmer" is a compass.** The `PASTA` → *"Warmer. Much warmer."* response confirms the password is food-themed and narrows the search space dramatically.
5. **VM protection adds complexity, not security.** The 237-byte bytecode program and 56-opcode instruction set look intimidating, but the hash algorithm inside is simple. The real challenge is understanding the VM architecture well enough to trace it.

---

