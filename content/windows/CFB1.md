# CFB1 — Crackmes for Beginners #1


## TL;DR

- **Algorithm:** Per-character transform: `(index + 0x5A) XOR ord(char)`, add `0x13`, mask to byte, format as uppercase hex.
- **Goal:** Keygen for any username ≥ 4 characters.
- **Approach:** Static analysis — `strings` → xrefs → locate `compute_serial` → reverse the 3-instruction core loop.

---

## 1. Overview

CFB1 is a straightforward username-to-serial keygenme designed for newcomers. There are no hardcoded string passwords to find in memory; instead, the program implements a basic mathematical loop over each character of the username. The challenge requires reverse-engineering this loop to produce a keygen that computes the correct serial for any given username of at least 4 characters. The serial is a concatenation of 2-digit uppercase hex values — one per input character — making the output length proportional to the username length.

**Goal:** Given any username (≥ 4 characters), compute the correct serial key.

---

## 2. Initial reconnaissance

### 2.1 File Identification

```
File      : CFB1.exe
Format    : PE32+ (x64)
Compiler  : MSVC C++ (standard library string / iostream)
Packing   : None
ImageBase : 0x140000000
EntryPoint: RVA 0x9F8C
```

**Sections:**

| Name | VA | Size |
|---|---|---|
| `.text` | `0x00001000` | `0x2A2B8` |
| `.rdata` | `0x0002C000` | `0x12C36` |
| `.data` | `0x0003F000` | `0x002600` |
| `.pdata` | `0x00042000` | `0x002520` |

Extracting readable strings immediately reveals the program flow — **no hardcoded serial**:

```
[+] Enter Username (min 4 chars):
[-] Error: Username is too short! Must be at least 4 characters.
[+] Enter Serial Key:
[*] Verifying key...
[+] ACCESS GRANTED! Congratulations!
[-] ACCESS DENIED! Invalid key.
```

No password string to grep — we have to reverse the math.

---

## 3. Locating the serial check

### 3.1 Finding the entry point

Scanning `.rdata` for the prompt strings gives us their virtual addresses:

| String | VA |
|---|---|
| `[+] Enter Username` | `0x14002C8E0` |
| `[+] Enter Serial Key` | `0x14002C970` |
| `[*] Verifying key...` | `0x14002C989` |
| `ACCESS GRANTED` | `0x14002C9DF` |
| `ACCESS DENIED` | `0x14002CA4F` |

Cross-referencing the **serial prompt** string via RIP-relative `LEA` instructions in `.text` lands us at:

```asm
0x140007793  lea rdx, [rip + 0x251d6]   ; → "[+] Enter Serial Key:"
```

This is inside the **main verification function**, starting around `0x140007500`.

### 3.2 Tracing the verify call

After both strings are read, the program calls into a dedicated serial-compute function:

```asm
0x140007960  lea rdx, [rbp - 0x39]     ; rdx = &username_str
0x140007964  lea rcx, [rbp - 0x19]     ; rcx = &output_str  (destination)
0x140007968  call 0x1400066E0          ; compute_serial(username, &computed)
```

Then it compares the computed serial against what the user typed:

```asm
0x140007986  cmp r8, qword ptr [rbp - 9]  ; compare lengths
0x14000798a  jne 0x1400079ae              ; → ACCESS DENIED
0x140007990  test r8, r8
0x140007993  je  0x14000799e
0x140007995  call 0x1400297a0             ; memcmp(computed, input, len)
0x14000799a  test eax, eax
0x14000799c  jne 0x1400079ae              ; → ACCESS DENIED
; fall-through → ACCESS GRANTED
```

**Target:** Reverse `compute_serial` at `0x1400066E0`.

---

## 4. Reversing the algorithm

### 4.1 Full disassembly of `compute_serial` (`0x1400066E0`)

The function takes two arguments:
- `rcx` → pointer to username `std::string`
- `rdx` → pointer to output `std::string`

The key loop runs from `rbp = 0` to `rbp < username.length()`:

```asm
0x140006720  cmp  qword ptr [rbx + 0x18], 0xf   ; SSO check (small string opt.)
0x140006725  jbe  0x14000672c
0x140006727  mov  rcx, qword ptr [rbx]          ; rcx = heap ptr if large
0x14000672a  jmp  0x14000672f
0x14000672c  mov  rcx, rbx                      ; rcx = inline buffer if small

; ─── THE CORE ─────────────────────────────────────────────────────────────────
0x14000672f  lea  eax, [rbp + 0x5a]              ; al = index + 90
0x140006732  xor  al, byte ptr [rcx + rbp]       ; al ^= username[index]
0x140006735  add  al, 0x13                       ; al += 19
0x140006737  movzx edi, al                       ; edi = (uint8_t) al
; ──────────────────────────────────────────────────────────────────────────────

; Set output format on ostringstream:
0x140006743  and dword ptr [...], 0xFFFFF9FF      ; clear dec/oct basefield
0x14000674b  or  dword ptr [...], 0x800           ; set hex flag
0x14000675c  or  dword ptr [...], 0x4             ; set uppercase flag
;             setw(2) + setfill('0') applied separately → zero-padded

0x01400067a6  call 0x140003b00                    ; append edi to ostringstream
0x01400067ab  inc  rbp                            ; ++index
0x01400067ae  cmp  rbp, qword ptr [rbx + 0x10]    ; index < length?
0x01400067b2  jb   0x140006720                    ; loop
```

### 4.2 Algorithm in plain English

For **each character** of the username:

| Step | Operation | Notes |
|---|---|---|
| 1 | `val = index + 0x5A` | index (0-based) + 90 |
| 2 | `val = val XOR ord(char)` | XOR with ASCII code of character |
| 3 | `val = (val + 0x13) & 0xFF` | add 19, keep as a single byte |
| 4 | `serial += "%02X" % val` | append as 2-digit **uppercase** hex |

### 4.3 Why uppercase?

The format flags `OR 0x4` maps directly to `ios_base::uppercase` in MSVC's iostream flag enum. Confirmed by observing digits like `0x3C` → `3C` (no letters) vs. values ≥ `0xA0` after masking producing `A`–`F` in output.

---

## 5. The keygen

```python
#!/usr/bin/env python3
"""
CFB1 Keygen — Crackmes for Beginners #1
Algorithm reversed from compute_serial() @ VA 0x1400066E0
"""

import sys

def keygen(username: str) -> str:
    """Compute the valid serial key for the given username."""
    serial = ""
    for i, ch in enumerate(username):
        val = (i + 0x5A) ^ ord(ch)   # step 1+2: index+90, XOR char
        val = (val + 0x13) & 0xFF    # step 3: add 19, wrap byte
        serial += "%02X" % val       # step 4: uppercase 2-digit hex
    return serial


def main():
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("[+] Enter username: ").strip()

    if len(username) < 4:
        print("[-] Username must be at least 4 characters.")
        sys.exit(1)

    serial = keygen(username)
    print(f"[+] Username : {username}")
    print(f"[+] Serial   : {serial}")


if __name__ == "__main__":
    main()
```

---

## 6. Verification

### 6.1 Step-by-step for `admin`

| idx | char | idx + 0x5A | XOR ord(c) | + 0x13 | Output |
|-----|------|-----------|------------|--------|--------|
| 0 | `a` (0x61) | `0x5A` | `0x5A ^ 0x61 = 0x3B` | `0x3B + 0x13 = 0x4E` | `4E` |
| 1 | `d` (0x64) | `0x5B` | `0x5B ^ 0x64 = 0x3F` | `0x3F + 0x13 = 0x52` | `52` |
| 2 | `m` (0x6D) | `0x5C` | `0x5C ^ 0x6D = 0x31` | `0x31 + 0x13 = 0x44` | `44` |
| 3 | `i` (0x69) | `0x5D` | `0x5D ^ 0x69 = 0x34` | `0x34 + 0x13 = 0x47` | `47` |
| 4 | `n` (0x6E) | `0x5E` | `0x5E ^ 0x6E = 0x30` | `0x30 + 0x13 = 0x43` | `43` |

**Serial → `4E52444743`**

### 6.2 More examples

| Username | Serial |
|----------|--------|
| `admin` | `4E52444743` |
| `user` | `423B4C42` |
| `test` | `4151423C` |
| `John` | `23474746` |
| `crack` | `4C3C505148` |
| `hello` | `4551434444` |

---

## 7. Conclusion

The challenge uses a straightforward **per-character transform**:

```
serial = concat( "%02X" % (((i + 90) XOR ord(c) + 19) & 0xFF)
                 for i, c in enumerate(username) )
```

No anti-debug, no obfuscation, no multi-pass hashing — just a single-pass loop over the username chars. The only subtlety is tracking down the output format flags (`uppercase`, `hex`, `setw(2)`, `setfill('0')`) buried in the C++ iostream machinery.

**Key takeaways for beginners:**
- `strings` → locate prompts → find xrefs → navigate to check function
- Identify the loop bounds (`cmp rbp, [rbx+0x10]` = length check)
- The 3-instruction core (`lea + xor + add`) is the entire algorithm
- C++ iostream format flags (`0x4`, `0x800`) reveal output encoding

*Solved with static analysis only — no debugger, no emulator, no execution.*
