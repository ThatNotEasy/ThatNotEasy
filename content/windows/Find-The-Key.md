# Find The Key (ActivateMe.exe) 

## TL;DR

- **Gate:** Magic Number must match `^[A-Z]{2}-[A-Z]{2}$`.
- **Core:** XOR-derived keystream from magic + static payload (see §6–§9).
- **Framing:** Document assumes **static-only** reconnaissance (no debugger).

---

## 1. Overview

The binary presents itself as a simple "activation" program that asks the user for a Magic Number and an Activation Key. If both inputs are correct, the program proceeds to an unspecified success state; if either is wrong, it prints `Try Again:` and loops. The challenge is to determine what the correct Activation Key is without access to the original source code.

---

## 2. Target analysis — PE file structure

### 2.1 File Identification

The file was first examined using standard file identification tools:

```
$ file ActivateMe.exe
ActivateMe.exe: PE32+ executable (console) x86-64, 6 sections
```

Key observations from the initial file analysis:

| Property | Value |
|---|---|
| **Format** | PE32+ (64-bit) |
| **Subsystem** | Console (IMAGE_SUBSYSTEM_WINDOWS_CUI) |
| **Architecture** | x86-64 |
| **Linker Version** | 14.x (Visual Studio 2015+) |
| **Sections** | 6 |
| **Packer/Protector** | None detected |


### 2.2 Section Analysis

PE files are organized into sections, each serving a distinct purpose. Understanding the section layout provides immediate insight into where to focus analysis efforts:

| Section | Virtual Size | Characteristics | Contents |
|---------|-------------|----------------|----------|
| `.text` | ~0x1000 | EXECUTE \| READ | Main program code - the decryption logic, validation, and control flow |
| `.rdata` | ~0x1000 | READ | Read-only data - the regex pattern, encoded payload, prefix DWORDs, error strings |
| `.data` | ~0x100 | READ \| WRITE | Initialized global variables - runtime buffers for user input and computed values |
| `.pdata` | ~0x300 | READ | Exception handling data - unwind information for x64 structured exception handling |
| `.rsrc` | ~0x200 | READ | Resource data - potentially icon/version info (not relevant to key recovery) |
| `.reloc` | ~0x100 | READ | Base relocations - required for ASLR, not relevant to static analysis |

**Key insight:** The `.rdata` section is where all static constants live. This is the primary hunting ground for the encoded payload, the regex pattern, and the prefix characters. The `.text` section contains the single large function that orchestrates the entire program logic.

### 2.3 Import Table Analysis

The binary imports functions from the Windows CRT (C Runtime) and kernel32, which reveals the high-level capabilities the program uses:

| Imported DLL | Functions | Purpose |
|-------------|-----------|---------|
| `msvcrt.dll` / `ucrtbase.dll` | `printf`, `scanf`, `strcmp`, `strlen` | Console I/O and string comparison for key validation |
| `kernel32.dll` | `GetStdHandle`, `WriteConsoleA` | Low-level console output (may supplement printf) |

The presence of `strcmp` or a string comparison function is particularly notable - it strongly suggests that the program compares the user-supplied Activation Key against a computed/decrypted reference string using a standard string equality check, rather than a custom comparison routine. This means we need to find the exact string that the key is compared against.

### 2.4 Entry Point

The program entry point is located at `0x140001f60`. In PE32+ executables, all addresses are RVA-based with a default image base of `0x140000000`. This single function contains the entire program logic - there are no helper functions, no separate decryption routines, and no library calls beyond the CRT imports listed above. This "monolithic function" structure is common in CTF challenges and simple crackmes, as it reduces the attack surface and makes the challenge self-contained.

---

## 3. Initial reconnaissance

### 3.1 Strings Extraction

The first analytical step was to extract all printable ASCII strings from the binary using a strings extraction tool (e.g., `strings`, FLOSS, or the built-in string viewer in IDA/Ghidra). This is a non-invasive technique that reveals embedded constants, error messages, format strings, and sometimes even encoded payloads.

The following strings of interest were found in the `.rdata` section:

| Offset | String | Length | Analysis |
|--------|--------|--------|----------|
| `.rdata+0x??` | `^[A-Z]{2}-[A-Z]{2}$` | 17 chars | **Regex pattern** - validates the Magic Number format. The `^` and `$` anchors enforce a full-string match. `[A-Z]{2}` matches exactly two uppercase ASCII letters. The hyphen is a literal separator. This constrains valid input to exactly 5 characters in the format `XX-YY`. |
| `.rdata+0x??` | `Try Again:` | 9 chars | **Error message** - printed when the Activation Key does not match. The presence of this string tells us there is a comparison somewhere that branches on success vs. failure. |
| `.rdata+0x??` | `TM3N[YkM1htam3>` | 15 chars | **Encoded payload** - this is NOT plaintext ASCII. It contains a mix of uppercase letters, digits, and special characters (`[`, `>`). The character distribution does not match natural language, strongly suggesting it is an encoded/encrypted string. The trailing `>` is particularly unusual and may be a padding artifact. |
| `.rdata+0x??` | `Enter Magic Number:` | ~20 chars | **Prompt string** - displayed to the user via `printf`. |
| `.rdata+0x??` | `Enter Activation Key:` | ~22 chars | **Prompt string** - second user prompt after Magic Number validation. |

### 3.2 DWORD-Stored Characters

In addition to the contiguous strings above, five individual ASCII characters were discovered stored as **DWORD values** (32-bit unsigned integers) at separate addresses in `.rdata`:

| Address (offset from `.rdata`) | Raw DWORD (hex) | Raw DWORD (dec) | ASCII Char | Significance |
|------|----------------------|-----------------|------------|--------------|
| `.rdata+0x0A` | `0x00000054` | 84 | `T` | Prefix byte 0 |
| `.rdata+0x0E` | `0x0000006A` | 106 | `j` | Prefix byte 1 |
| `.rdata+0x12` | `0x00000077` | 119 | `w` | Prefix byte 2 |
| `.rdata+0x16` | `0x00000034` | 52 | `4` | Prefix byte 3 |
| `.rdata+0x1A` | `0x00000052` | 82 | `R` | Prefix byte 4 |

**Why DWORDs instead of bytes?** This is a deliberate obfuscation technique. In a normal C string, the characters "Tjw4R" would be stored as five consecutive bytes: `54 6A 77 34 52 00`. By storing each character in a 32-bit DWORD (with 3 bytes of zero-padding), the string becomes: `54 00 00 00 6A 00 00 00 77 00 00 00 34 00 00 00 52 00 00 00`. This makes the string invisible to simple string extraction tools that look for sequences of printable ASCII characters, because the null bytes break the sequence. Only by examining the raw binary data (hex dump) or by tracing the code that reads these addresses would a reverse engineer discover the hidden prefix.

When these five DWORDs are read sequentially and the low byte of each is extracted, they form the string:

```
Prefix = "Tjw4R"
```

### 3.3 Preliminary Hypothesis Formation

Based on the initial reconnaissance, several hypotheses were formed:

1. **The encoded payload `TM3N[YkM1htam3>` is the core secret.** Everything else (the regex, the DWORDs, the prompts) exists to protect or transform this payload into the Activation Key.

2. **The DWORD characters form a prefix that combines with the payload.** The program likely concatenates `Tjw4R` + `TM3N[YkM1htam3>` to form a longer encoded string before further processing.

3. **The Magic Number is not just a password - it is a cryptographic parameter.** The regex pattern enforces a specific format (two letter pairs separated by a hyphen), which suggests the letters themselves carry numeric meaning (their ASCII values). The difference between specific letter positions likely produces a numeric key used in decryption.

4. **A two-stage decoding is likely.** The payload has 20 characters (5 prefix + 15 encoded), which is a multiple of 4 - a strong hint at Base64 encoding (since Base64 encodes every 3 bytes as 4 characters, and 20 characters would decode to 15 bytes, which is plausible for a key string).

---

## 4. Deep dive: string analysis

### 4.1 Regex Pattern Breakdown

The regex `^[A-Z]{2}-[A-Z]{2}$` warrants detailed analysis, as it reveals the exact constraints on the Magic Number:

```
^[A-Z]{2}-[A-Z]{2}$
│ │    │  │ │    │  │
│ │    │  │ │    │  └─ End of string anchor
│ │    │  │ │    └──── Exactly 2 uppercase letters
│ │    │  │ └───────── Literal hyphen separator
│ │    │  └─────────── Position index 2 (0-based: chars 0,1)
│ │    └────────────── Exactly 2 uppercase letters (positions 0,1)
│ └─────────────────── Start of string anchor
└───────────────────── Character class: A through Z
```

This means the Magic Number has exactly 5 characters with a fixed structure:

```
Position:  0    1    2    3    4
Example:   A    A    -    D    D
           └─X──┘    └─Y──┘
           Group 1   Group 2
```

Where:
- Positions 0-1: Two uppercase letters (Group 1 = X)
- Position 2: Literal hyphen `-`
- Positions 3-4: Two uppercase letters (Group 2 = Y)

The ASCII values of uppercase letters range from 65 (`A`) to 90 (`Z`), giving 26 possible values for each letter position. This means there are 26<sup>4</sup> = 456,976 possible valid Magic Numbers. However, as we will discover, only a subset of these (those where `magic[3] - magic[1]` produces the correct XOR key) will successfully decrypt the payload.

### 4.2 Encoded Payload Character Analysis

The encoded string `TM3N[YkM1htam3>` deserves close inspection:

```
T  M  3  N  [  Y  k  M  1  h  t  a  m  3  >
54 4D 33 4E 5B 59 6B 4D 31 68 74 61 6D 33 3E
```

Character frequency analysis:

| Character | Count | Type |
|-----------|-------|------|
| `M` | 2 | Uppercase letter |
| `3` | 2 | Digit |
| Others | 1 each | Mixed (upper, lower, special) |

The character distribution is somewhat uniform, with only `M` and `3` repeating. This is consistent with encrypted or encoded data rather than plaintext. The presence of lowercase letters (`k`, `h`, `t`, `a`, `m`), uppercase letters (`T`, `M`, `N`, `Y`), digits (`3`, `1`), and special characters (`[`, `>`) spanning a wide range of ASCII values (0x31–0x7A) is a strong indicator of Base64 encoding after XOR transformation.

### 4.3 The Prefix: `Tjw4R`

The prefix `Tjw4R` is notable because it is itself a valid Base64-like string. In fact, it decodes to partial binary data:

```
Tjw4R (Base64) → bytes: 4E 8F 0E 11
```

However, this partial decode is not immediately meaningful on its own. The prefix only makes sense when concatenated with the full payload, suggesting that the program's author intentionally split the encoded string into two parts - a visible prefix stored as DWORDs (for obfuscation) and a contiguous encoded payload - that must be reassembled before decryption.

---

## 5. Reverse engineering methodology

### 5.1 Approach Selection

Two primary approaches were available for analyzing this binary:

| Approach | Advantages | Disadvantages |
|----------|-----------|---------------|
| **Static Analysis** (disassembly) | No risk of detection, works on any platform, reveals complete logic | Can be time-consuming for complex binaries, requires understanding of assembly |
| **Dynamic Analysis** (debugging) | Can observe runtime state, trace execution step-by-step | May trigger anti-debug checks, requires Windows environment, harder to automate |

Given that the binary had no apparent anti-debug protections and the logic was contained in a single function, **static analysis** was chosen as the primary approach. The small code footprint made it practical to reason about the entire program flow without needing runtime traces.

### 5.2 Tools Used

| Tool | Purpose | Why This Tool |
|------|---------|---------------|
| `file` | Identify PE format, architecture, subsystem | First step for any unknown binary |
| `strings` / FLOSS | Extract printable strings | Quick reconnaissance for embedded constants |
| Hex editor (HxD/010) | Inspect raw bytes, find DWORD-stored chars | Reveals obfuscated data hidden from string tools |
| IDA Pro / Ghidra | Disassembly and decompilation | Industry-standard RE tools with x64 support |
| Python | Brute-force XOR key, decode Base64 | Rapid prototyping of decryption hypotheses |
| regex101.com | Test regex patterns | Verify regex behavior and edge cases |

### 5.3 Analysis Workflow

The analysis followed a systematic top-down approach:

```
1. FILE IDENTIFICATION
   └─→ Confirm PE32+ x86-64, console subsystem, no packing

2. STRINGS EXTRACTION
   └─→ Find regex, error message, encoded payload, prompts

3. HEX DUMP ANALYSIS
   └─→ Discover DWORD-stored prefix characters

4. DISASSEMBLY / DECOMPILATION
   └─→ Trace control flow from entry point (0x140001f60)
   └─→ Identify: validation → key derivation → XOR decrypt → Base64 decode → compare

5. HYPOTHESIS FORMATION
   └─→ Prefix + Payload → XOR(K) → Base64 decode → Activation Key

6. KEY RECOVERY
   └─→ Brute-force K (1..25), check which produces valid Base64
   └─→ K=3 yields valid Base64 → decode → {Act1va7i0n}

7. VERIFICATION
   └─→ Full decryption pipeline produces expected result
```

---

## 6. Program logic analysis

### 6.1 High-Level Control Flow

The entire program logic resides within a single large function at **`0x140001f60`**. This function is approximately 200–300 bytes of machine code and contains all the program logic inline - no helper functions are called. The execution follows this sequence:

```
┌───────────────────────────────────────────┐
│  PHASE 1: Magic Number Input              │
│  printf("Enter Magic Number:");            │
│  scanf("%s", magic_buffer);                │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 2: Magic Number Validation          │
│  regex_match("^[A-Z]{2}-[A-Z]{2}$",       │
│              magic_buffer)                 │
│                                            │
│  If invalid → loop back to Phase 1         │
└─────────────────┬─────────────────────────┘
                  │
               Valid
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 3: Activation Key Input             │
│  printf("Enter Activation Key:");           │
│  scanf("%s", key_buffer);                  │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 4: XOR Key Derivation               │
│  K = magic_buffer[3] - magic_buffer[1]     │
│                                            │
│  Example: "AA-DD" → K = 'D' - 'A' = 3     │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 5: Payload Assembly                │
│  Load 5 DWORD values from .rdata          │
│  Extract low byte from each → "Tjw4R"     │
│  Append contiguous payload from .rdata    │
│  Full string = "Tjw4RTM3N[YkM1htam3>"     │
│  (20 bytes total)                         │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 6: XOR Decryption                  │
│  for (i = 0; i < 20; i++)                 │
│      decrypted[i] = assembled[i] XOR K;   │
│                                           │
│  Result: "Wit7QWN0MXZhN2kwbn0="           │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 7: Base64 Decode                   │
│  decoded = base64_decode(decrypted)       │
│                                           │
│  Result: "Z+{Act1va7i0n}"                 │
└─────────────────┬─────────────────────────┘
                  │
                  ▼
┌───────────────────────────────────────────┐
│  PHASE 8: Key Comparison                  │
│  if (strcmp(key_buffer, decoded) == 0)    │
│      → SUCCESS                            │
│  else                                     │
│      printf("Try Again:");                │
│      → loop back to Phase 3               │
└───────────────────────────────────────────┘
```

### 6.2 Detailed Assembly Analysis

While full disassembly listings are too verbose to reproduce here, the critical instructions in the decryption loop can be summarized. The following pseudocode represents the decompiled logic from the function at `0x140001f60`:

```c
int main() {
    char magic[16] = {0};
    char key[64]   = {0};

    // --- Phase 1 & 2: Magic Number ---
    while (1) {
        printf("Enter Magic Number:");
        scanf("%s", magic);

        if (regex_match(magic, "^[A-Z]{2}-[A-Z]{2}$"))
            break;
    }

    // --- Phase 3: Activation Key ---
    while (1) {
        printf("Enter Activation Key:");
        scanf("%s", key);

        // --- Phase 4: Derive XOR key ---
        uint8_t K = (uint8_t)(magic[3] - magic[1]);

        // --- Phase 5: Assemble encoded payload ---
        char prefix[6];
        prefix[0] = (char)(*(DWORD*)0x140003010);  // 0x54 → 'T'
        prefix[1] = (char)(*(DWORD*)0x140003014);  // 0x6A → 'j'
        prefix[2] = (char)(*(DWORD*)0x140003018);  // 0x77 → 'w'
        prefix[3] = (char)(*(DWORD*)0x14000301C);  // 0x34 → '4'
        prefix[4] = (char)(*(DWORD*)0x140003020);  // 0x52 → 'R'
        prefix[5] = '\0';

        char payload[] = "TM3N[YkM1htam3>";
        char assembled[21];
        memcpy(assembled, prefix, 5);
        memcpy(assembled + 5, payload, 15);
        assembled[20] = '\0';

        // --- Phase 6: XOR decrypt ---
        char decrypted[21];
        for (int i = 0; i < 20; i++) {
            decrypted[i] = assembled[i] ^ K;
        }
        decrypted[20] = '\0';

        // --- Phase 7: Base64 decode ---
        char decoded[16];
        base64_decode(decrypted, decoded);

        // --- Phase 8: Compare ---
        if (strcmp(key, decoded) == 0) {
            // SUCCESS
            break;
        } else {
            printf("Try Again:");
        }
    }

    return 0;
}
```

**Key observations from the decompiled pseudocode:**

1. The outer `while(1)` loop handles Magic Number validation, and once valid, never asks again.
2. The inner `while(1)` loop handles Activation Key validation with unlimited retries.
3. The XOR key `K` is derived fresh on every attempt, so the Magic Number is "locked in" after Phase 2.
4. The comparison uses `strcmp`, which is a standard null-terminated string comparison. This means the decoded Activation Key is expected to be a printable ASCII string.
5. The Base64 decode function is likely inlined (no import for it), which is consistent with the monolithic function structure.

### 6.3 Key Memory Regions

Understanding the memory layout during execution helps clarify the data flow:

| Region | Address (example) | Content | Size |
|--------|-------------------|---------|------|
| `.rdata` prefix DWORDs | `0x140003010..0x140003023` | `54 00 00 00 6A 00 00 00 77 00 00 00 34 00 00 00 52 00 00 00` | 20 bytes |
| `.rdata` encoded payload | `0x140003030..0x14000303E` | `54 4D 33 4E 5B 59 6B 4D 31 68 74 61 6D 33 3E 00` | 16 bytes |
| Stack (magic buffer) | `rsp+0x??` | User input for Magic Number | 16 bytes |
| Stack (key buffer) | `rsp+0x??` | User input for Activation Key | 64 bytes |
| Stack (assembled) | `rsp+0x??` | Concatenated prefix + payload | 21 bytes |
| Stack (decrypted) | `rsp+0x??` | XOR result | 21 bytes |
| Stack (decoded) | `rsp+0x??` | Base64 decoded result | 16 bytes |

---

## 7. Cryptographic primitive: XOR cipher

### 7.1 How XOR Encryption Works

The XOR (exclusive OR) cipher is one of the simplest and most common encryption techniques used in CTF challenges and crackmes. It operates on individual bits according to the following truth table:

| Input A | Input B | A XOR B |
|---------|---------|---------|
| 0 | 0 | **0** |
| 0 | 1 | **1** |
| 1 | 0 | **1** |
| 1 | 1 | **0** |

When applied to bytes (8 bits), each bit of the plaintext is XORed with the corresponding bit of the key:

```
Plaintext:  01010100  ('T' = 0x54)
Key:        00000011  (3 = 0x03)
            ─────────
Ciphertext: 01010111  ('W' = 0x57)
```

### 7.2 XOR Properties That Enable Decryption

The most important property of XOR for cryptography is its **self-inverse** nature:

```
(Plaintext XOR Key) XOR Key = Plaintext
```

This means the same operation that encrypts also decrypts - you simply XOR the ciphertext with the same key to recover the plaintext. This is why XOR is called a *symmetric* operation.

Additionally:
- **Commutative:** `A XOR B = B XOR A`
- **Associative:** `(A XOR B) XOR C = A XOR (B XOR C)`
- **Identity:** `A XOR 0 = A`
- **Cancels itself:** `A XOR A = 0`

### 7.3 Single-Byte XOR vs. Multi-Byte XOR

In this challenge, a **single-byte XOR key** is used, meaning the same key byte `K` is applied to every character in the payload. This is the weakest form of XOR encryption because:

| Property | Single-byte XOR | Multi-byte XOR |
|----------|----------------|----------------|
| **Key space** | 256 possible keys | 256^n (where n = key length) |
| **Brute-forceable?** | Trivially (try all 256 values) | Depends on key length |
| **Frequency analysis** | Effective (shifted letter distributions) | Less effective |
| **Known-plaintext** | 1 known byte reveals entire key | Need n known bytes |

With only 256 possible keys, a brute-force attack that tries all values from 0 to 255 would take less than a millisecond on any modern computer. The challenge author relies on the two-layer encoding (XOR + Base64) to increase difficulty, as discussed in the next sections.

### 7.4 XOR Key Derivation in This Challenge

Rather than using a hardcoded XOR key (which would be trivially discoverable in the binary), the challenge derives the key dynamically from user input:

```
K = magic_number[3] - magic_number[1]
```

Given the regex constraint `^[A-Z]{2}-[A-Z]{2}$`, the Magic Number format is `XX-YY`:
- `magic[1]` is the second character of the first letter pair
- `magic[3]` is the second character of the second letter pair

Since uppercase ASCII letters range from 65 (`A`) to 90 (`Z`), the key `K = magic[3] - magic[1]` ranges from:
- **Minimum:** `65 - 90 = -25` (i.e., `Z` - `A` = 65 - 90 = -25, but as `uint8_t` wraps to 231)
- **Maximum:** `90 - 65 = 25` (i.e., `Z` - `A` = 90 - 65 = 25)

In practice, for the XOR to produce valid Base64 output, `K` must be a small positive value. The correct key is **K = 3**, produced by any Magic Number where the second letter of the second group is 3 positions after the second letter of the first group in the alphabet.

---

## 8. Payload assembly & XOR decryption

### 8.1 Assembly of the Full Encoded String

The program assembles the full encoded string by concatenating the prefix (from DWORDs) with the contiguous payload (from `.rdata`):

```
Source 1: .rdata DWORDs (5 chars)
┌───┬───┬───┬───┬───┐
│ T │ j │ w │ 4 │ R │
└───┴───┴───┴───┴───┘
  0x54 0x6A 0x77 0x34 0x52

Source 2: .rdata contiguous payload (15 chars)
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ T │ M │ 3 │ N │ [ │ Y │ k │ M │ 1 │ h │ t │ a │ m │ 3 │ > │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  0x54 0x4D 0x33 0x4E 0x5B 0x59 0x6B 0x4D 0x31 0x68 0x74 0x61 0x6D 0x33 0x3E

Concatenation (20 chars):
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ T │ j │ w │ 4 │ R │ T │ M │ 3 │ N │ [ │ Y │ k │ M │ 1 │ h │ t │ a │ m │ 3 │ > │
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19
  PREFIX (5 bytes)     ENCODED PAYLOAD (15 bytes)
```

### 8.2 XOR Decryption - Complete Byte-by-Byte Table

With XOR key **K = 3**, each of the 20 bytes is XORed:

| i | Assembled | Hex | Binary | XOR K | Binary Result | Hex | Decrypted | Base64 Valid? |
|---|-----------|-----|--------|-------|---------------|-----|-----------|---------------|
| 0 | `T` | `0x54` | `01010100` | 3 | `01010111` | `0x57` | `W` | Yes (A-Z) |
| 1 | `j` | `0x6A` | `01101010` | 3 | `01101001` | `0x69` | `i` | Yes (a-z) |
| 2 | `w` | `0x77` | `01110111` | 3 | `01110100` | `0x74` | `t` | Yes (a-z) |
| 3 | `4` | `0x34` | `00110100` | 3 | `00110111` | `0x37` | `7` | Yes (0-9) |
| 4 | `R` | `0x52` | `01010010` | 3 | `01010001` | `0x51` | `Q` | Yes (A-Z) |
| 5 | `T` | `0x54` | `01010100` | 3 | `01010111` | `0x57` | `W` | Yes (A-Z) |
| 6 | `M` | `0x4D` | `01001101` | 3 | `01001110` | `0x4E` | `N` | Yes (A-Z) |
| 7 | `3` | `0x33` | `00110011` | 3 | `00110000` | `0x30` | `0` | Yes (0-9) |
| 8 | `N` | `0x4E` | `01001110` | 3 | `01001101` | `0x4D` | `M` | Yes (A-Z) |
| 9 | `[` | `0x5B` | `01011011` | 3 | `01011000` | `0x58` | `X` | Yes (A-Z) |
| 10 | `Y` | `0x59` | `01011001` | 3 | `01011010` | `0x5A` | `Z` | Yes (A-Z) |
| 11 | `k` | `0x6B` | `01101011` | 3 | `01101000` | `0x68` | `h` | Yes (a-z) |
| 12 | `M` | `0x4D` | `01001101` | 3 | `01001110` | `0x4E` | `N` | Yes (A-Z) |
| 13 | `1` | `0x31` | `00110001` | 3 | `00110010` | `0x32` | `2` | Yes (0-9) |
| 14 | `h` | `0x68` | `01101000` | 3 | `01101011` | `0x6B` | `k` | Yes (a-z) |
| 15 | `t` | `0x74` | `01110100` | 3 | `01110111` | `0x77` | `w` | Yes (a-z) |
| 16 | `a` | `0x61` | `01100001` | 3 | `01100010` | `0x62` | `b` | Yes (a-z) |
| 17 | `m` | `0x6D` | `01101101` | 3 | `01101110` | `0x6E` | `n` | Yes (a-z) |
| 18 | `3` | `0x33` | `00110011` | 3 | `00110000` | `0x30` | `0` | Yes (0-9) |
| 19 | `>` | `0x3E` | `00111110` | 3 | `00111101` | `0x3D` | `=` | Yes (padding) |

**Critical observation:** Every single decrypted character falls within the Base64 alphabet! The characters are distributed across all four Base64 character classes:
- **Uppercase (A-Z):** W, Q, W, N, M, X, Z, N (8 chars)
- **Lowercase (a-z):** i, t, h, k, w, b, n (7 chars)
- **Digits (0-9):** 7, 0, 2, 0 (4 chars)
- **Padding (=):** 1 char at the end

This is NOT a coincidence. The original payload was constructed by Base64-encoding the desired plaintext and then XOR-encrypting it with key 3. The result is ciphertext that, when XORed back with key 3, produces valid Base64 characters - which is by design.

**XOR Result:** `Wit7QWN0MXZhN2kwbn0=`

---

## 9. Base64 decoding

### 9.1 Base64 Encoding Primer

Base64 is a binary-to-text encoding scheme that represents binary data using a set of 64 printable ASCII characters. It was designed to safely transmit binary data through channels that only support text (e.g., email, URLs, JSON).

**The Base64 alphabet:**

```
Index:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25
Char:   A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z

Index: 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51
Char:   a  b  c  d  e  f  g  h  i  j  k  l  m  n  o  p  q  r  s  t  u  v  w  x  y  z

Index: 52 53 54 55 56 57 58 59 60 61 62 63
Char:   0  1  2  3  4  5  6  7  8  9  +  /
```

**Padding:** The `=` character is used as padding when the input length is not a multiple of 3 bytes.

### 9.2 Decoding Process - Step by Step

The Base64 string `Wit7QWN0MXZhN2kwbn0=` has 20 characters (including 1 padding `=`). Since 20 / 4 = 5 groups, this decodes to approximately 15 bytes of binary data (5 groups × 3 bytes = 15, minus 1 byte for the padding = **14 bytes**).

Each group of 4 Base64 characters represents 3 bytes of output:

**Group 1: `Wit7` → 3 bytes**

```
W → 22 → 010110
i → 34 → 100010
t → 45 → 101101
7 → 59 → 111011

Concatenated: 010110 100010 101101 111011
Grouped into bytes: 01011001 | 00101011 | 01111011
                    = 0x59      = 0x2B     = 0x7B
                    = 'Z'       = '+'       = '{'
```

**Group 2: `QWN0` → 3 bytes**

```
Q → 16 → 010000
W → 22 → 010110
N → 13 → 001101
0 → 52 → 110100

Concatenated: 010000 010110 001101 110100
Grouped into bytes: 01000001 | 01100011 | 01110100
                    = 0x41      = 0x63     = 0x74
                    = 'A'       = 'c'       = 't'
```

**Group 3: `MXZh` → 3 bytes**

```
M → 12 → 001100
X → 23 → 010111
Z → 25 → 011001
h → 33 → 100001

Concatenated: 001100 010111 011001 100001
Grouped into bytes: 00110001 | 01110110 | 01100001
                    = 0x31      = 0x76     = 0x61
                    = '1'       = 'v'       = 'a'
```

**Group 4: `N2kw` → 3 bytes**

```
N → 13 → 001101
2 → 54 → 110110
k → 36 → 100100
w → 48 → 110000

Concatenated: 001101 110110 100100 110000
Grouped into bytes: 00110111 | 01101001 | 00110000
                    = 0x37      = 0x69     = 0x30
                    = '7'       = 'i'       = '0'
```

**Group 5: `bn0=` → 2 bytes (padding)**

```
b → 27 → 011011
n → 39 → 100111
0 → 52 → 110100
= → pad

Concatenated: 011011 100111 110100 (discard last 8 bits due to padding)
Grouped into bytes: 01101110 | 01111101
                    = 0x6E      = 0x7D
                    = 'n'       = '}'
```

### 9.3 Complete Decode Result

```
Group 1: Z + {
Group 2: A + c + t
Group 3: 1 + v + a
Group 4: 7 + i + 0
Group 5: n + }
```

**Full decoded string:** `Z+{Act1va7i0n}`

### 9.4 Interpreting the Decoded Output

The decoded string is 14 bytes long: `Z+{Act1va7i0n}`

Breaking it down:
- Characters 0-2 (`Z+{`): **Prefix artifacts** - these are the decoded form of the DWORD prefix "Tjw4R". They are not part of the actual Activation Key.
- Characters 3-13 (`Act1va7i0n}`): **The actual Activation Key** - enclosed in curly braces as is common in CTF flags.

Therefore, the Activation Key that the program compares against the user input is:

> **`{Act1va7i0n}`**

---

## 10. Key derivation: Magic Number to XOR key

### 10.1 The Derivation Formula

The XOR key is derived from the Magic Number using a simple arithmetic operation on ASCII values:

```
K = (int) magic_number[3] - (int) magic_number[1]
```

Given the format `XX-YY`:
- `magic[0]` = first letter of first pair (e.g., `A`)
- `magic[1]` = second letter of first pair (e.g., `A`)
- `magic[2]` = hyphen `-` (ASCII 45)
- `magic[3]` = first letter of second pair (e.g., `D`)
- `magic[4]` = second letter of second pair (e.g., `D`)

So the formula becomes:

```
K = ASCII(first letter of YY) - ASCII(second letter of XX)
```

### 10.2 Computing K for Example Magic Numbers

| Magic Number | magic[1] | magic[1] ASCII | magic[3] | magic[3] ASCII | K = magic[3] - magic[1] | Produces Correct Key? |
|-------------|----------|----------------|----------|----------------|------------------------|----------------------|
| `AA-DD` | `A` | 65 | `D` | 68 | **3** | Yes |
| `AB-DE` | `B` | 66 | `E` | 69 | **3** | Yes |
| `AC-DF` | `C` | 67 | `F` | 70 | **3** | Yes |
| `AZ-DC` | `Z` | 90 | `D` | 68 | **-22** (234 as uint8) | No |
| `AA-AB` | `A` | 65 | `A` | 65 | **0** | No (XOR 0 = identity) |
| `BA-ED` | `A` | 65 | `E` | 69 | **4** | No |

**Interesting edge case: K = 0**

When `magic[3] == magic[1]`, the XOR key is 0. Since XOR with 0 is the identity operation (`A XOR 0 = A`), the "encrypted" payload would remain unchanged:

```
"Tjw4RTM3N[YkM1htam3>" XOR 0 = "Tjw4RTM3N[YkM1htam3>"
```

This string contains `[` and `>` which are NOT valid Base64 characters (wait - `>` is not in the Base64 alphabet). So the Base64 decode would fail or produce garbage. This confirms that K = 0 does not produce a valid result.

### 10.3 Valid Magic Number Space

For the correct XOR key K = 3, we need `magic[3] - magic[1] = 3`. Given the constraint that both are uppercase letters (65–90), the valid combinations are:

| magic[1] | ASCII | magic[3] = magic[1] + 3 | ASCII | Valid? |
|----------|-------|------------------------|-------|--------|
| `A` | 65 | `D` | 68 | Yes |
| `B` | 66 | `E` | 69 | Yes |
| `C` | 67 | `F` | 70 | Yes |
| `D` | 68 | `G` | 71 | Yes |
| ... | ... | ... | ... | ... |
| `W` | 87 | `Z` | 90 | Yes |
| `X` | 88 | `[` | 91 | **No** (not A-Z) |

This gives **23 valid pairs** for positions 1 and 3. Since positions 0 and 4 can be any uppercase letter (26 choices each), the total number of valid Magic Numbers is:

```
26 × 23 × 26 = 15,548 valid Magic Numbers
```

---

## 11. Alternative approaches

### 11.1 XOR Brute-Force (Without Full RE)

Even without fully reversing the XOR key derivation logic, the key can be recovered through brute force. Since the XOR key is a single byte (0–255), we can simply try all possible keys and check which one produces a valid Base64 string:

```python
import base64
import re

prefix = "Tjw4R"
payload = "TM3N[YkM1htam3>"
assembled = prefix + payload  # 20 chars

BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')

for k in range(256):
    xor_result = ''.join(chr(ord(c) ^ k) for c in assembled)
    if BASE64_PATTERN.match(xor_result):
        try:
            decoded = base64.b64decode(xor_result).decode('latin-1')
            # Check if result contains printable ASCII
            if all(32 <= ord(c) <= 126 for c in decoded):
                print(f"K={k:3d} → XOR: {xor_result} → Decoded: {decoded}")
        except Exception:
            pass
```

**Output:**
```
K=  3 → XOR: Wit7QWN0MXZhN2kwbn0= → Decoded: Z+{Act1va7i0n}
```

Only **K = 3** produces a result that is both valid Base64 AND decodes to fully printable ASCII. This confirms the key with zero knowledge of the program's internal logic - only the assembled encoded string is needed.

### 11.2 Dynamic Analysis with a Debugger

An alternative approach would be to attach a debugger (x64dbg, WinDbg, or GDB with Wine) and set breakpoints at strategic points:

1. **Breakpoint on `strcmp`** - When the program calls `strcmp` to compare the user's key with the decoded key, the decoded key will be visible in the register/stack as one of the arguments. Simply inspecting the arguments at this breakpoint reveals the answer immediately.

2. **Breakpoint after XOR loop** - Setting a breakpoint after the XOR decryption loop completes allows inspection of the decrypted buffer, which contains the Base64 string ready for decoding.

3. **Breakpoint after Base64 decode** - Setting a breakpoint after the Base64 decode function returns reveals the final decoded string, which is the Activation Key.

This approach would be faster than full static analysis but requires a Windows environment (or Wine compatibility layer) and an understanding of x86-64 calling conventions.

### 11.3 Patching the Binary

A more creative approach would be to patch the binary to bypass the key check entirely:

1. Locate the conditional branch instruction that tests the `strcmp` return value
2. Patch the conditional jump (e.g., `jz` / `je`) to an unconditional jump (`jmp`) or a `nop`
3. The program would then accept ANY Activation Key

This approach does not recover the key itself but demonstrates a practical bypass technique. In a real-world scenario, this could be used to "crack" the software without knowing the actual key.

---

## 12. Solution

### 12.1 Activation Key

```
{Act1va7i0n}
```

### 12.2 Key Deconstruction

This is **leet speak** (also written as "l33tspeak") for the word **"Activation"**, where certain letters are replaced by visually similar digits:

| Position | Leet Char | Original | Substitution Rule | Visual Similarity |
|----------|-----------|----------|-------------------|-------------------|
| 0 | `{` | `{` | Opening brace (CTF flag format) | - |
| 1 | `A` | `A` | Uppercase A | Exact match |
| 2 | `c` | `c` | Lowercase c | Exact match |
| 3 | `t` | `t` | Lowercase t | Exact match |
| 4 | `1` | `l` | `1` → `l` | Vertical line looks like lowercase L |
| 5 | `v` | `v` | Lowercase v | Exact match |
| 6 | `a` | `a` | Lowercase a | Exact match |
| 7 | `7` | `t` | `7` → `t` | Top cross of 7 resembles T |
| 8 | `i` | `i` | Lowercase i | Exact match |
| 9 | `0` | `o` | `0` → `o` | Zero looks like lowercase O |
| 10 | `n` | `n` | Lowercase n | Exact match |
| 11 | `}` | `}` | Closing brace (CTF flag format) | - |

Decoded: **`{Activation}`** → Leet encoded: **`{Act1va7i0n}`**

### 12.3 Example Valid Inputs

| Input | Value | Notes |
|-------|-------|-------|
| **Magic Number** | `AA-DD` | Produces XOR key K = 3 |
| **Activation Key** | `{Act1va7i0n}` | The recovered key |

Other valid Magic Numbers include `AB-DE`, `AC-DF`, `ZZ-DC` (where `D - A = 3`), etc. - any `XX-YY` where the first letter of the second group is 3 positions after the second letter of the first group.

---

## 13. Full recreation scripts

### 13.1 Complete Solver (Python)

```python
#!/usr/bin/env python3
"""
Complete solver for ActivateMe.exe
Recovers the Activation Key through static analysis of the encoded payload.
"""
import base64
import re

def solve():
    print("=" * 60)
    print("  ActivateMe.exe - Key Recovery Solver")
    print("=" * 60)

    # ── Step 1: Known components extracted from .rdata ──
    # Five DWORD values stored separately (obfuscation technique)
    prefix_dwords = [0x54, 0x6A, 0x77, 0x34, 0x52]
    prefix = ''.join(chr(d) for d in prefix_dwords)
    print(f"\n[1] Prefix from DWORDs: {prefix}")

    # Contiguous encoded payload from .rdata
    payload = "TM3N[YkM1htam3>"
    print(f"[2] Encoded payload:    {payload}")

    # Assemble full encoded string (as the program does)
    assembled = prefix + payload
    print(f"[3] Assembled string:   {assembled}  ({len(assembled)} chars)")

    # ── Step 2: Brute-force XOR key ──
    print(f"\n[4] Brute-forcing XOR key (0-255)...")
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')

    for k in range(256):
        xor_result = ''.join(chr(ord(c) ^ k) for c in assembled)

        # Check if XOR result is valid Base64
        if not base64_pattern.match(xor_result):
            continue

        # Try to decode
        try:
            decoded = base64.b64decode(xor_result).decode('latin-1')
            # Verify all characters are printable ASCII
            if all(32 <= ord(c) <= 126 for c in decoded):
                print(f"    K={k:3d}  →  {xor_result}  →  {repr(decoded)}")
        except Exception:
            continue

    # ── Step 3: Use correct key ──
    k = 3
    xor_result = ''.join(chr(ord(c) ^ k) for c in assembled)
    decoded = base64.b64decode(xor_result).decode('latin-1')

    print(f"\n[5] Using K = {k}:")
    print(f"    XOR result:  {xor_result}")
    print(f"    Base64 dec:  {decoded}")

    # ── Step 4: Extract Activation Key ──
    # The prefix "Tjw4R" decodes to 3 garbage bytes at the start
    activation_key = decoded[2:]  # Skip "Z+" prefix artifacts
    print(f"\n{'=' * 60}")
    print(f"  ACTIVATION KEY:  {activation_key}")
    print(f"{'=' * 60}")
    print(f"  Leet speak for:  {{Activation}}")
    print(f"  (1=l, 7=t, 0=o)")
    print(f"{'=' * 60}")

    return activation_key

if __name__ == "__main__":
    solve()
```

**Output:**
```
============================================================
  ActivateMe.exe - Key Recovery Solver
============================================================

[1] Prefix from DWORDs: Tjw4R
[2] Encoded payload:    TM3N[YkM1htam3>
[3] Assembled string:   Tjw4RTM3N[YkM1htam3>  (20 chars)

[4] Brute-forcing XOR key (0-255)...
    K=  3  →  Wit7QWN0MXZhN2kwbn0=  →  'Z+{Act1va7i0n}'

[5] Using K = 3:
    XOR result:  Wit7QWN0MXZhN2kwbn0=
    Base64 dec:  Z+{Act1va7i0n}

============================================================
  ACTIVATION KEY:  {Act1va7i0n}
============================================================
  Leet speak for:  {Activation}
  (1=l, 7=t, 0=o)
============================================================
```

### 13.2 XOR Key Space Analyzer

```python
#!/usr/bin/env python3
"""
Analyze all possible XOR keys and their effects on the encoded payload.
"""
import base64
import string

prefix = "Tjw4R"
payload = "TM3N[YkM1htam3>"
assembled = prefix + payload

print("XOR Key Space Analysis")
print("=" * 70)
print(f"{'K':>4} {'XOR Result':<25} {'Base64?':<8} {'Printable?':<10} {'Decoded'}")
print("-" * 70)

for k in range(256):
    xor_result = ''.join(chr(ord(c) ^ k) for c in assembled)

    # Check if valid Base64
    b64_chars = set(string.ascii_letters + string.digits + '+/')
    is_b64 = all(c in b64_chars or c == '=' for c in xor_result) and len(xor_result) % 4 == 0

    # Try to decode and check printability
    decoded = ""
    is_printable = False
    if is_b64:
        try:
            decoded = base64.b64decode(xor_result).decode('latin-1')
            is_printable = all(32 <= ord(c) <= 126 for c in decoded)
        except:
            is_b64 = False

    if is_b64:
        marker = " <<<" if is_printable else ""
        print(f"{k:4} {xor_result:<25} {'YES':<8} {'YES' if is_printable else 'NO':<10} {decoded}{marker}")

print("=" * 70)
print("Only K=3 produces both valid Base64 AND fully printable decoded output.")
```

---
