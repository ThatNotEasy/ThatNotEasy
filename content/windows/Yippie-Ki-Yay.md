# Yippie Ki Yay 


## TL;DR

- **Password:** Recovered from XOR with **`0xAA`** (hardcoded ciphertext in `.data`).
- **Obfuscation:** TLS callback hides imports; bogus hash routines act as noise.

---

## 1. Overview

The binary shows **no obvious plaintext** password or prompts under naive `strings`. A **TLS callback** resolves `printf` / `scanf` / `strcmp` / `puts` at runtime, while status strings like **`ok`** / **`no`** are built via XOR. Analysis reduces to finding ciphertext blobs and the XOR key, then confirming against **`strcmp`**.

---

## 2. Initial reconnaissance

Running `file` on the binary reveals a standard 64-bit Windows console executable compiled with GCC:

```
PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Key observations from initial analysis:

- **Stripped binary**: No symbol information available, making static analysis harder.
- **GCC MinGW compilation**: Suggests C/C++ source code compiled on a POSIX-like environment targeting Windows.
- **10 sections**: Unusually high section count for a simple crackme, which is a sign of deliberate obfuscation or complex CRT initialization.
- **No imported `printf`/`scanf`/`strcmp` in the traditional sense**: These are resolved dynamically via a TLS callback, hiding the real API dependencies.

Running `strings` on the binary reveals no immediately visible password strings, format strings, or success/failure messages — a strong indicator that all strings are encrypted.

---

## 3. Section analysis

The binary contains the following sections:

| Section | Virtual Address | Virtual Size | Purpose |
|---|---|---|---|
| `.text` | `0x1000` | `0x2500` | Code (executable) |
| `.data` | `0x4000` | `0x170` | Encrypted strings + CRT data |
| `.rdata` | `0x5000` | `0xF88` | Read-only data, DLL names, format strings |
| `.eh_fram` | `0x6000` | `0x4` | Exception handling frames |
| `.pdata` | `0x7000` | `0x318` | Exception handling data |
| `.xdata` | `0x8000` | `0x2FC` | Exception handling data |
| `.bss` | `0x9000` | `0x1D0` | Uninitialized data |
| `.idata` | `0xA000` | `0xA68` | Import directory |
| `.tls` | `0xB000` | `0x10` | TLS (Thread Local Storage) callback data |
| `.reloc` | `0xC000` | `0x84` | Base relocations |

The **`.tls`** section is particularly interesting — its presence indicates a TLS callback, which executes before `main()` and is commonly used for anti-debugging and dynamic API resolution.

---

## 4. Anti-analysis techniques identified

This binary employs multiple layers of obfuscation to frustrate reverse engineering:

### 3.1 XOR String Encryption (Key: `0xAA`)

All user-facing strings are XOR-encrypted with the single-byte key `0xAA`. This includes the password prompt, the expected password, and the success/failure messages. The encrypted blobs are stored in the `.data` section.

### 3.2 SSE2 SIMD XOR Decryption

The prompt string ("Enter password: ") is decrypted using SSE2 SIMD instructions (`pxor xmm0, [mem]`), which is unusual for a simple crackme and adds complexity for analysts using basic string search tools.

### 3.3 Dead-Code Hash Chain

The password decryption subroutine at `0x140001770` contains a complex, multi-step hash computation involving XOR, subtraction, bit shifts, and multiplication. This hash chain is **computed but never used** — it serves purely as a red herring to waste analyst time.

### 3.4 Dynamic DLL Loading via TLS Callback

A TLS callback at `0x1400015e0` dynamically loads `ucrtbase.dll` using `LoadLibraryA` and resolves API functions (`printf`, `scanf`, `strcmp`, `puts`, etc.) via `GetProcAddress`. This means these critical functions do not appear in the static import table, hiding the program's true behavior from tools like `objdump` or IDA's import analysis.

### 3.5 Indirect API Calls

All resolved API calls are made through indirect jumps (`jmp qword ptr [rip + offset]`), adding another layer of indirection that makes it harder to trace the program's control flow.

### 3.6 XOR-Obfuscated Output Messages

Even the two-character success ("ok") and failure ("no") messages are constructed at runtime by XOR-ing word-sized values loaded from different memory locations with the `0xAAAA` key.

### 3.7 Separate Helper Functions for Hash Operations

The hash chain operations (XOR, shift, multiply) are implemented as individual leaf functions at `0x140001720`–`0x140001768`, making the decompiled code appear more complex than it actually is.

---

## 5. String decryption — XOR 0xAA

### 4.1 Encrypted Data in `.data` Section

Two key encrypted blobs were identified in the `.data` section:

**At Virtual Address `0x140004030`** (16 bytes — the prompt string):

```
EF C4 DE CF D8 8A DA CB D9 D9 DD C5 D8 CE 90 8A
```

**At Virtual Address `0x140004010`** (13 bytes — the password):

```
F3 C3 DA DA C3 CF 87 E1 C3 87 F3 CB D3
```

### 4.2 XOR Key

The XOR key `0xAA` is referenced from multiple locations:

- Loaded as an immediate: `mov eax, 0xAAAAAAAA` (used in `pshufd` + `pxor`)
- Loaded from data: `movzx eax, word ptr [0x140005058]` where the data contains `AA AA`
- Hardcoded in the byte-level XOR loop: `xor edx, 0xFFFFFFAA`

### 4.3 Decryption: Prompt String

The prompt is decrypted using SSE2 SIMD in the main function:

```assembly
0x14000342d:  mov     eax, 0xAAAAAAAA           ; XOR key (4 bytes)
0x140003457:  pshufd  xmm0, xmm0, 0             ; Broadcast to all 16 bytes
0x14000345c:  pxor    xmm0, xmmword ptr [0x4030] ; XOR decrypt in one instruction
0x140003487:  movaps  xmmword ptr [rsp+0xb0], xmm0  ; Store result
```

Decryption result:

| Index | Encrypted | XOR 0xAA | ASCII |
|---|---|---|---|
| 0 | `EF` | `45` | `E` |
| 1 | `C4` | `6E` | `n` |
| 2 | `DE` | `74` | `t` |
| 3 | `CF` | `65` | `e` |
| 4 | `D8` | `72` | `r` |
| 5 | `8A` | `20` | ` ` |
| 6 | `DA` | `70` | `p` |
| 7 | `CB` | `61` | `a` |
| 8 | `D9` | `73` | `s` |
| 9 | `D9` | `73` | `s` |
| 10 | `DD` | `77` | `w` |
| 11 | `C5` | `6F` | `o` |
| 12 | `D8` | `72` | `r` |
| 13 | `CE` | `64` | `d` |
| 14 | `90` | `3A` | `:` |
| 15 | `8A` | `20` | ` ` |

**Result: `Enter password: `**

### 4.4 Decryption: Password String

The password is decrypted in a dedicated subroutine at `0x140001770` using a byte-by-byte XOR loop:

```assembly
0x1400017e0:  movzx   edx, byte ptr [r8 + rax]   ; Load encrypted byte
0x1400017e5:  xor     edx, 0xFFFFFFAA              ; XOR with key
0x1400017e8:  mov     byte ptr [rcx + rax], dl      ; Store decrypted byte
0x1400017eb:  add     rax, 1                        ; Next byte
0x1400017ef:  cmp     rax, 0xD                      ; Loop counter = 13
0x1400017f3:  jne     0x1400017e0                   ; Repeat
0x1400017f5:  mov     byte ptr [rcx + 0xD], 0       ; Null terminate
```

Decryption result:

| Index | Encrypted | XOR 0xAA | ASCII |
|---|---|---|---|
| 0 | `F3` | `59` | `Y` |
| 1 | `C3` | `69` | `i` |
| 2 | `DA` | `70` | `p` |
| 3 | `DA` | `70` | `p` |
| 4 | `C3` | `69` | `i` |
| 5 | `CF` | `65` | `e` |
| 6 | `87` | `2D` | `-` |
| 7 | `E1` | `4B` | `K` |
| 8 | `C3` | `69` | `i` |
| 9 | `87` | `2D` | `-` |
| 10 | `F3` | `59` | `Y` |
| 11 | `CB` | `61` | `a` |
| 12 | `D3` | `79` | `y` |

**Result: `Yippie-Ki-Yay`**

---

## 6. Dead-code hash chain (red herring)

The subroutine at `0x140001770` contains a deceptive hash chain computation **before** the actual XOR decryption loop. This is designed to confuse analysts into believing the password is derived from a complex cryptographic transformation.

### 5.1 The Hash Chain (Inlined)

```c
uint32_t val = 0x1337;
val = val ^ 0x12345678;          // val = 0x1234454F
val = val - 0x65432110;          // val = 0xACF1243F (unsigned)
val = (val * 8) ^ (val >> 5);    // val = 0x62EEA8D9
val = val ^ 0x35014541;          // val = 0x57EFED98
val = val * 129;                  // val = 0x4FE6B998
val = val ^ (val >> 11);         // val = 0x4FEF454F
```

### 5.2 Why It's Dead Code

The computed hash value (`0x4FEF454F`) is stored at `[rsp + 0xC]` but is **never read or used** by any subsequent instruction. The XOR decryption loop that follows uses the hardcoded key `0xAA` directly — not the hash value.

This is a classic **anti-reverse-engineering misdirection technique**: by placing complex-looking arithmetic before the simple XOR loop, the analyst's attention is drawn to the hash chain, potentially leading them to waste time trying to reverse the hash transformation when it's completely irrelevant.

### 5.3 Corresponding Helper Functions

The binary also defines the hash operations as separate leaf functions (likely an artifact of the compiler inlining), adding to the appearance of complexity:

| Address | Function | Operation |
|---|---|---|
| `0x140001720` | `xor_transform` | `val ^ 0x12345678` then `val - 0x65432110` |
| `0x140001730` | `hash_mix_1` | `(val * 8) ^ (val >> 5)` |
| `0x140001740` | `xor_const` | `val ^ 0x35014541` |
| `0x140001750` | `mul_129` | `val * 128 + val` (i.e., `val * 129`) |
| `0x140001760` | `hash_mix_2` | `val ^ (val >> 11)` |

---

## 7. TLS callback — dynamic API resolution

### 6.1 TLS Callback at `0x1400015E0`

Before `main()` executes, the binary runs a TLS (Thread Local Storage) callback that dynamically loads `ucrtbase.dll` and resolves the API functions it needs:

```assembly
; Load ucrtbase.dll
0x1400015ed:  lea     rsi, [rip + 0x3A0C]         ; rsi -> "ucrtbase.dll" string
0x1400015f4:  mov     rcx, rsi
0x1400015f7:  call    qword ptr [rip + 0x8CEB]    ; GetModuleHandleA("ucrtbase.dll")

; If not loaded, try LoadLibraryA
0x140001600:  test    rax, rax
0x140001603:  je      load_library_path

; Resolve printf
0x140001615:  lea     rdx, [rip + 0x39F7]         ; "printf"
0x14000161c:  mov     rcx, rbx
0x140001626:  call    rdi                         ; GetProcAddress(module, "printf")

; Resolve scanf
0x140001628:  lea     rdx, [rip + 0x39FA]         ; "scanf" (actually __stdio_common_vfscanf)
0x14000162f:  mov     rcx, rbx
0x140001635:  call    rdi                         ; GetProcAddress(module, "scanf")

; Resolve strcmp
0x140001643:  lea     rdx, [rip + 0x7A16]         ; "strcmp"
0x14000164a:  lea     rcx, [rip + 0x49AF]
0x140001651:  call    rsi                         ; Store resolved address
```

### 6.2 Effect

By resolving API functions dynamically in a TLS callback, the binary hides its real dependencies from static analysis tools. The import table only shows `KERNEL32.dll` and CRT infrastructure DLLs, while the actual program logic depends on `printf`, `scanf`, `strcmp`, and `puts` — none of which appear directly in the imports.

This technique also means that the resolved function pointers are stored in writable memory locations and called through indirect jumps, adding another layer of indirection:

```assembly
0x140003270:  jmp     qword ptr [rip + 0x720A]    ; Indirect jump to resolved strcmp
0x1400032c0:  jmp     qword ptr [rip + 0x71A2]    ; Indirect jump to resolved scanf
0x140003340:  jmp     qword ptr [rip + 0x70D2]    ; Indirect jump to resolved printf
```

---

## 8. Main function — full reverse engineering

### 7.1 Function Entry (`0x140003420`)

The actual `main` function begins at `0x140003420` (the entry point at `0x140001125` is CRT startup code that eventually calls this function).

```assembly
0x140003420:  push    rbx
0x140003421:  sub     rsp, 0xF0                   ; Large stack frame (240 bytes)
0x140003428:  call    0x1400018B7                  ; CRT initialization
```

### 7.2 Prompt Decryption and Display

```assembly
; Step 1: Prepare XOR key in SSE2 register
0x14000342d:  mov     eax, 0xAAAAAAAA              ; XOR key pattern
0x140003440:  movd    xmm0, eax                    ; Load into xmm0
0x140003457:  pshufd  xmm0, xmm0, 0                ; Broadcast to all 4 dwords

; Step 2: Decrypt "Enter password: " using SIMD XOR
0x14000345c:  pxor    xmm0, xmmword ptr [rip+0xBCC] ; XOR with encrypted data @0x4030
0x140003487:  movaps  xmmword ptr [rsp+0xB0], xmm0 ; Store decrypted string on stack
0x140003472:  mov     byte ptr [rsp+0xC0], 0        ; Null terminate

; Step 3: Print the prompt
0x140003450:  lea     rcx, [rip+0x1BF9]             ; rcx = "%s" format string
0x14000347f:  lea     rdx, [rsp+0xB0]               ; rdx = "Enter password: "
0x140003494:  call    0x140002F40                    ; printf("%s", "Enter password: ")
```

### 7.3 Read User Input

```assembly
0x14000346d:  lea     rbx, [rsp+0x30]               ; Input buffer on stack
0x140003499:  mov     rdx, rbx                       ; rdx = input buffer
0x14000349c:  lea     rcx, [rip+0x1BB0]              ; rcx = "%63s" format string
0x1400034a3:  call    0x140002EE0                    ; scanf("%63s", input_buffer)
```

The input is limited to 63 characters (plus null terminator = 64 bytes buffer).

### 7.4 Decrypt and Compare Password

```assembly
; Decrypt the expected password
0x1400034a8:  lea     rcx, [rsp+0x70]               ; Output buffer
0x1400034ad:  call    0x140001770                    ; Decrypt "Yippie-Ki-Yay" via XOR 0xAA

; Compare with user input
0x1400034b2:  mov     rdx, rcx                       ; rdx = decrypted password
0x1400034b5:  mov     rcx, rbx                       ; rcx = user input
0x1400034b8:  call    0x140003270                    ; strcmp(input, password)

; Branch on result
0x1400034bd:  test    eax, eax
0x1400034bf:  jne     0x1400034D6                    ; If not equal -> failure
```

### 7.5 Print Result

```assembly
; Success path (strcmp == 0)
0x1400034c1:  lea     rcx, [rsp+0x20]               ; "ok"
0x1400034c6:  call    0x1400032C8                    ; printf("ok")

; Failure path (strcmp != 0)
0x1400034d6:  lea     rcx, [rsp+0x28]               ; "no"
0x1400034db:  call    0x1400032C8                    ; printf("no")

; Return
0x1400034cb:  xor     eax, eax                       ; return 0
0x1400034cd:  add     rsp, 0xF0
0x1400034d4:  pop     rbx
0x1400034d5:  ret
```

---

## 9. Password validation algorithm

The complete validation logic in pseudocode:

```c
int main() {
    // Step 1: Initialize CRT
    init_crt();

    // Step 2: Decrypt prompt via SIMD XOR
    char prompt[16];
    uint8_t xor_key = 0xAA;
    __m128i xmm_key = _mm_set1_epi8(0xAA);
    __m128i encrypted = _mm_loadu_si128((void*)0x140004030);
    __m128i decrypted = _mm_xor_si128(xmm_key, encrypted);
    _mm_storeu_si128((__m128i*)prompt, decrypted);
    prompt[15] = '\0';

    // Step 3: Print prompt and read input
    printf("%s", prompt);       // "Enter password: "
    char input[64];
    scanf("%63s", input);       // Read max 63 chars

    // Step 4: Decrypt expected password
    char expected[14];
    uint8_t enc_pass[] = {0xF3,0xC3,0xDA,0xDA,0xC3,0xCF,0x87,0xE1,0xC3,0x87,0xF3,0xCB,0xD3};
    for (int i = 0; i < 13; i++) {
        expected[i] = enc_pass[i] ^ 0xAA;
    }
    expected[13] = '\0';

    // Step 5: Compare
    if (strcmp(input, expected) == 0) {
        printf("ok");
    } else {
        printf("no");
    }

    return 0;
}
```

**Note**: The dead-code hash chain is omitted from this pseudocode because it has no effect on the program's behavior.

---

## 10. Status message obfuscation

The binary doesn't store "ok" and "no" as plaintext strings. Instead, it constructs them at runtime by XOR-ing word-sized values:

```assembly
; Load obfuscated components
0x140003432:  movzx   edx, word ptr [0x140004020]    ; edx = 0xC1C5
0x140003439:  movzx   ebx, word ptr [0x14000401E]    ; ebx = 0xC5C4
0x140003444:  movzx   eax, word ptr [0x140005058]    ; eax = 0xAAAA (XOR key)

; Compute: success_msg = 0xC1C5 ^ 0xAAAA = 0x6B6F -> "ok" (little-endian)
0x140003469:  xor     edx, eax
0x14000347a:  mov     word ptr [rsp+0x20], dx

; Compute: failure_msg = 0xAAAA ^ 0xC5C4 = 0x6F6E -> "no" (little-endian)
0x14000346b:  xor     eax, ebx
0x14000348f:  mov     word ptr [rsp+0x28], ax

; Null terminate both strings
0x14000344b:  mov     byte ptr [rsp+0x22], 0
0x140003464:  mov     byte ptr [rsp+0x2A], 0
```

The values `0xC1C5` and `0xC5C4` are embedded within the encrypted "Yippie-Ki-Yay" data at addresses `0x401E` and `0x4020`, which is a clever reuse of existing encrypted data for additional obfuscation.

---

## 11. The password

```
┌─────────────────────────────────────────────┐
│                                             │
│     PASSWORD:  Yippie-Ki-Yay               │
│                                             │
└─────────────────────────────────────────────┘
```

Running the binary with this password will display:

```
Enter password: Yippie-Ki-Yay
ok
```

---

## 12. PoC / Keygen (Python)

A standalone Python keygen that reverses all obfuscation layers:

```python
#!/usr/bin/env python3
"""
PoC / Keygen for b.exe — No binary patching required.
Recovers the hardcoded password by reversing XOR obfuscation.
"""

def xor_decrypt(data: bytes, key: int) -> bytes:
    """XOR each byte of data with the given key."""
    return bytes([b ^ key for b in data])


def main():
    # Encrypted data extracted from .data section
    encrypted_prompt   = bytes.fromhex("efc4decfd88adacbd9d9ddc5d8ce908a")
    encrypted_password = bytes.fromhex("f3c3dadac3cf87e1c387f3cbd3")
    xor_key = 0xAA

    # Decrypt
    prompt   = xor_decrypt(encrypted_prompt, xor_key).rstrip().decode()
    password = xor_decrypt(encrypted_password, xor_key).rstrip(b'\x00').decode()

    print(f"Prompt:   \"{prompt}\"")
    print(f"Password: \"{password}\"")


if __name__ == "__main__":
    main()
```

**Output:**
```
Prompt:   "Enter password: "
Password: "Yippie-Ki-Yay"
```

---

## 13. Conclusion

This crackme demonstrates several common but effective anti-reverse-engineering techniques:

1. **XOR string encryption** prevents trivial password extraction via `strings` or hex editor inspection.
2. **SSE2 SIMD decryption** adds complexity to the disassembly and avoids simple `xor byte ptr` patterns.
3. **Dead-code hash chains** (seed `0x1337` → multi-step transformation) mislead analysts into attempting to reverse a non-existent key derivation.
4. **TLS callback API resolution** hides the program's true dependencies from static import analysis.
5. **Indirect calls through IAT** obscure the relationship between call sites and their target functions.
6. **Runtime message construction** prevents plaintext "ok"/"no" strings from appearing in the binary.

Despite these layers, the core vulnerability is straightforward: the password is **hardcoded** and encrypted with a **single-byte XOR key** (`0xAA`). Once the XOR pattern is identified, the password is trivially recoverable without any need to patch or modify the binary.

**Key takeaway**: No amount of obfuscation can protect a hardcoded secret. The only secure approach is to perform cryptographic operations (hashing, HMAC, etc.) server-side or use proper key derivation functions.

---

*Writeup generated through static analysis using objdump, pefile, and Capstone disassembly framework.*

---

