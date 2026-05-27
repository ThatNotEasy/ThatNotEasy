# KeyGenMe.exe 


## TL;DR

- **Seed:** Current Windows username via **`GetUserNameA`** (not arbitrary user input in-app).
- **Pipeline:** Username → SHA-256 hex → **`key_transform`** → compare to typed key.

---

## 1. Overview

The binary prompts with `Enter Your Identify Key:` and validates input against a dynamically computed value. A correct key displays `Good Job Brou!`, while an incorrect key displays `Wrong Key!`.

---

## 2. Initial reconnaissance

### 2.1 File Identification

| Property | Value |
|---|---|
| Architecture | x86-64 (PE32+) |
| Subsystem | Windows Console (IMAGE_SUBSYSTEM_WINDOWS_CUI) |
| Sections | `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc` |
| Compiler | MSVC (Visual Studio - PDB path: `C:\Users\Admin\source\repos\CrackMe\x64\Release\CrackMe.pdb`) |
| Linked Libraries | KERNEL32.dll, ADVAPI32.dll, MSVCP140.dll, VCRUNTIME140.dll, VCRUNTIME140_1.dll, various UCRT APIs |

### 2.2 Notable Imports

The import table reveals critical API calls:

| DLL | Import | Purpose |
|---|---|---|
| ADVAPI32.dll | `GetUserNameA` | **Retrieves the current Windows username** - this is the seed for the dynamic key |
| KERNEL32.dll | `IsDebuggerPresent` | Anti-debugging check (non-fatal) |
| KERNEL32.dll | `GetCurrentProcessId` | Process identification |
| KERNEL32.dll | `Sleep` | Delay function (post-success) |

### 2.3 String Analysis

Key strings extracted from `.rdata`:

| Address (VA) | String | Significance |
|---|---|---|
| `0x1400064B8` | `Enter Your Identify Key:` | User prompt |
| `0x1400064D8` | `Good Job Brou!` | Success message |
| `0x1400064E8` | `Wrong Key!` | Failure message |

---

## 3. Entry point & main function

**Entry Point RVA:** `0x4800` (standard MSVC CRT entry)  
**Main Function:** Located at `0x140001430`

### 3.1 High-Level Control Flow

```
main() at 0x140001430:
  │
  ├── Stack frame setup (rbp, r12-r15 saved)
  ├── Stack cookie initialization
  │
  ├── GetUserNameA(username_buf, &size=256)
  │     └── Stores username at [rbp-0x20]
  │
  ├── strlen(username) → username_len
  │
  ├── copy_username_to_local_buffer(username, username_len)
  │     └── Username copy at [rsp+0x38]
  │
  ├── call hash_and_format(username_start, username_end, output_buf)
  │     └── output_buf at [rsp+0x78] → SHA-256 hex string
  │
  ├── key_transform(sha256_hex_string)
  │     └── result_key at [rsp+0x58]
  │
  ├── cout << "Enter Your Identify Key:"
  ├── cin >> user_input ([rbp-0x68])
  │
  ├── Compare user_input with result_key:
  │     ├── if (user_input.length != result_key.length) → "Wrong Key!"
  │     ├── if (memcmp(user_input.data, result_key.data, length) == 0) → "Good Job Brou!"
  │     └── else → "Wrong Key!"
  │
  └── Sleep(3000) on success, then cleanup
```

---

## 4. Deep analysis: hash function

### 4.1 SHA-256 Verification

The binary contains a **standard SHA-256** implementation at function `0x1400037f0`. This was verified by examining two critical data sets in `.rdata`:

**Initial Hash Values (H0–H7) at `0x1400065B0`:**
```
H0 = 0x6a09e667    H1 = 0xbb67ae85    H2 = 0x3c6ef372    H3 = 0xa54ff53a
H4 = 0x510e527f    H5 = 0x9b05688c    H6 = 0x1f83d9ab    H7 = 0x5be0cd19
```
These match the SHA-256 specification (FIPS 180-4) exactly.

**Round Constants (K[0–63]) at `0x1400065D0`:**
```
K[0] = 0x428a2f98   K[1] = 0x71374491   K[2] = 0xb5c0fbcf   K[3] = 0xe9b5dba5
K[4] = 0x3956c25b   K[5] = 0x59f111f1   K[6] = 0x923f82a4   K[7] = 0xab1c5ed5
```
All 64 constants match the standard. The implementation processes input in 64-byte blocks via function `0x140003a50`, with proper Merkle–Damgård padding handled at `0x140001290`.

### 4.2 Hash Function Prototype

```c
// Reconstructed from disassembly at 0x1400037f0
void sha256_hash(
    const uint8_t* input_start,   // rcx
    const uint8_t* input_end,     // rdx  
    uint8_t*       output_32bytes,// r8  - 32-byte digest
    void*          stack_cookie   // r9
);
```

### 4.3 Hash-to-Hex Formatting

Function `0x140002DE0` wraps the SHA-256 hash with an `std::ostringstream` to produce the hexadecimal string representation:

```c
// Reconstructed from disassembly at 0x140002DE0
void hash_to_hex_string(
    const uint8_t* username_start,    // rcx
    const uint8_t* username_end,      // rdx
    std::string*     output_hex_str   // r8  - receives "abcdef..." (64 chars)
);
```

**Formatting details observed in the assembly:**
- The stream is configured with `std::hex` (set via flag bit manipulation at `0x140002EC9–0x140002ED2`).
- `std::setw(2)` and `std::setfill('0')` ensure each byte is rendered as a zero-padded 2-character hex value.
- The loop at `0x140002ED6–0x140002F0E` iterates over all 32 hash bytes, calling `operator<<(unsigned int)` for each.
- Output is **lowercase hex** (no `std::uppercase` flag set).
- The final 64-character hex string is extracted from the `ostringstream` and stored in the output buffer.

---

## 5. Deep analysis: key transformation

This is the core of the challenge. After the SHA-256 hex string is generated, it undergoes a character-level transformation at `0x1400015D9–0x140001723`.

### 5.1 Transformation Loop

```asm
; Setup result string (empty, SSO mode, capacity=15)
1400015D9: mov     r14d, 2                  ; initial state
1400015E2: movups  [rsp+0x58], xmm0         ; clear result string
1400015F3: mov     [rsp+0x70], 15           ; SSO capacity = 15
1400015F8: mov     [rsp+0x58], dil          ; null terminator

; Iterate through SHA-256 hex string
1400015FD: lea     r12, [rsp+0x78]          ; r12 = hex_string data pointer
140001618: mov     rax, ...                 ; compute end pointer
140001624: cmp     r12, rax
140001627: je      0x14000172E              ; exit if at end

; Per-character processing loop body
140001630: movsx   ebx, BYTE [r12]          ; load current character
140001637: call    isdigit                  ; is it a digit?
14000163D: test    eax, eax
14000163F: jne     0x14000171B              ; YES → SKIP (jump to increment)
```

### 5.2 The Transformation Formula

For each non-digit character (i.e., hex letters `a` through `f`):

```asm
140001645: lea     eax, [rbx-0x61]          ; eax = ord(c) - ord('a')  = c - 97
140001648: cdq                              ; sign-extend eax → edx:eax
140001649: sub     eax, edx                 ; adjust for signed division
14000164B: sar     eax, 1                   ; eax = floor((c - 'a') / 2)
14000164D: mov     edx, eax                 ; edx = computed value
14000164F: lea     rcx, [rbp-0x48]          ; std::string for to_string result
140001653: call    std::to_string(int_val)  ; convert to decimal string
```

Then, for each digit in the resulting decimal string:

```asm
140001692: movzx   r9d, BYTE [rbx]          ; load digit character
140001696: add     r9b, 0x31                ; r9b = ord(digit) + 0x31
1400016B7: mov     BYTE [rax+rdi], r9b      ; append to result
```

### 5.3 Mapping Table

The complete character mapping derived from the transformation:

| Hex Char | `ord(c) - 'a'` | `floor(x / 2)` | `str(val)` | Each digit + 0x31 | Appended Char |
|---|---|---|---|---|---|
| `a` (0x61) | 0 | 0 | `"0"` | `0x30 + 0x31 = 0x61` | **`a`** |
| `b` (0x62) | 1 | 0 | `"0"` | `0x30 + 0x31 = 0x61` | **`a`** |
| `c` (0x63) | 2 | 1 | `"1"` | `0x31 + 0x31 = 0x62` | **`b`** |
| `d` (0x64) | 3 | 1 | `"1"` | `0x31 + 0x31 = 0x62` | **`b`** |
| `e` (0x65) | 4 | 2 | `"2"` | `0x32 + 0x31 = 0x63` | **`c`** |
| `f` (0x66) | 5 | 2 | `"2"` | `0x32 + 0x31 = 0x63` | **`c`** |

**Simplified mapping:** `{a,b} → a`, `{c,d} → b`, `{e,f} → c`

Digit characters (`0`–`9`) are completely removed from the output.

---

## 6. Key validation

### 6.1 Input Collection

```asm
14000175B: lea     rdx, [rip+0x4D56]       ; "Enter Your Identify Key:"
140001762: mov     rcx, [rip+0x4A07]       ; std::cout
140001769: call    operator<<              ; print prompt

14000176E: lea     rdx, [rbp-0x68]         ; user input buffer
140001772: mov     rcx, [rip+0x4A0F]       ; std::cin
140001779: call    operator>>              ; read user input
```

### 6.2 Comparison Logic

```asm
14000179F: mov     r8, [rbp-0x58]          ; r8 = user_input._Mysize
1400017A3: cmp     r8, rdi                 ; compare with expected key length
1400017A6: jne     0x1400017B1             ; length mismatch → "Wrong Key!"

1400017A8: call    memcmp                  ; memcmp(user_data, key_data, length)
1400017AD: test    eax, eax
1400017AF: je      0x140001805             ; match → "Good Job Brou!"
```

The validation is strict:
1. **Exact length check** - user input length must equal the generated key length.
2. **Exact byte comparison** - uses `memcmp` for content verification.

---

## 7. Complete algorithm summary

```
┌──────────────────────────────────────────────────────────┐
│                   KeyGenMe.exe Algorithm                 │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Input:  Windows Username (from GetUserNameA)            │
│                                                          │
│  Step 1: digest = SHA-256(username)                      │
│          → 32-byte hash → 64-char lowercase hex string   │
│                                                          │
│  Step 2: For each character c in digest:                 │
│          ├─ If c ∈ {'0'...'9'}:  SKIP                    │
│          └─ If c ∈ {'a'...'f'}:                          │
│              val = ⌊(ord(c) - ord('a')) / 2⌋              │
│              For each digit d in str(val):               │
│                  output += chr(ord(d) + 0x31)            │
│                                                          │
│  Step 3: Compare user_input against output               │
│                                                          │
│  Result: Only {'a', 'b', 'c'} appear in the key          │
│          Key length varies (typically 20-30 chars)       │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 8. Proof-of-concept keygen (Python)

```python
import hashlib

def generate_key(username: str) -> str:
    sha256_hex = hashlib.sha256(username.encode('ascii')).hexdigest()
    key = ""
    for c in sha256_hex:
        if c.isdigit():
            continue
        val = (ord(c) - ord('a')) // 2
        for digit_char in str(val):
            key += chr(ord(digit_char) + 0x31)
    return key
```

### Example Outputs

| Username | SHA-256 (first 16 chars) | Generated Key |
|---|---|---|
| `Admin` | `c1c224b03cd9bc7b...` | `bbabbabaabcbabcbbbbbbacabbc` |
| `Administrator` | `e7d3e769f3f593da...` | `cbcccbabbabbacbbbabaabacccaca` |
| `User` | `b512d97e7cbf97c2...` | `abcbacbcbaaaaaaaccbcaaab` |
| `test` | `9f86d081884c7d65...` | `cbbbaccaababaaccaaabbbbaca` |
| `root` | `4813494d137e1631...` | `bcaaababaacaaaabcbccba` |

---

