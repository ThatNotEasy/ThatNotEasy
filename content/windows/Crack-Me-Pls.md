# CrackMePls.exe 

## TL;DR

- **Mechanism:** Password is derived from a hash of the username (not a static string).
- **Artifacts:** PDB path exposes project **`crackme-lvl1`**; standard C++ iostream I/O.

---

## 1. Overview

The binary is a console application compiled with MSVC in Release mode. Based on the PDB path embedded in the `.rdata` section, the original project was named **crackme-lvl1** and was created by a user named **Kryptos**. The program prompts for a username and password, computes a custom hash of the username, derives an expected password from that hash, and then compares the user-supplied password against the derived value. If they match, it prints "Access granted"; otherwise, "Access denied."

---

## 2. Initial reconnaissance

### File Identification

```
$ file crackmepls.exe
crackmepls.exe: PE32+ executable for MS Windows 6.00 (console), x86-64, 6 sections
```

The binary is a 64-bit PE executable for Windows with six sections: `.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, and `.reloc`. The `.rsrc` section contains an application manifest requesting `asInvoker` execution level, and the `.reloc` section contains address fixups for ASLR.

### Strings Analysis

Running `strings` on the binary reveals several critical strings that immediately outline the program's behavior:

```
User:
Pass:
Access granted
Access denied
C:\Users\Kryptos\source\repos\crackme-lvl1\x64\Release\crackme-lvl1.pdb
```

These strings tell us the program:
1. Prompts for a **username** with the prefix `User: `
2. Prompts for a **password** with the prefix `Pass: `
3. Outputs either `Access granted` or `Access denied` based on validation
4. Was authored by **Kryptos** (from the PDB path)

Additional standard MSVC C++ runtime strings are present (`bad allocation`, `string too long`, `bad cast`, etc.), confirming this is a C++ application using the MSVC standard library (`std::cin`, `std::cout`, `std::string`).

---

## 3. Disassembly & static analysis

### Locating the Main Function

The main application logic begins at address **`0x140001290`**. This function can be identified by its function prologue — it saves multiple callee-saved registers (`rbx`, `rbp`, `rsi`, `rdi`, `r13`, `r14`, `r15`), allocates a large stack frame (`sub $0x90, %rsp`), and sets up a stack canary by reading from `__security_cookie` at `0x140005040`:

```asm
140001290:  mov    %rsp,%r11              ; save original stack pointer
140001293:  push   %rbx
140001294:  push   %rbp
140001295:  push   %rsi
140001296:  push   %rdi
140001297:  push   %r13
140001299:  push   %r14
14000129b:  push   %r15
14000129d:  sub    $0x90,%rsp              ; 144 bytes of local storage
1400012a4:  mov    0x3d95(%rip),%rax       ; __security_cookie
1400012ab:  xor    %rsp,%rax               ; XOR with stack pointer
1400012ae:  mov    %rax,0x88(%rsp)         ; store canary on stack
```

### Program Flow

The main function performs the following operations in sequence:

1. **Initialize two `std::string` objects** on the stack (for username and password input)
2. **Print "User: "** and read the username via `std::cin`
3. **Print "Pass: "** and read the password via `std::cin`
4. **Compute a custom hash** of the username
5. **Convert the hash to a decimal string** (this is the expected password)
6. **Compare** the user-supplied password with the expected password
7. **Print the result** ("Access granted" or "Access denied")
8. **Clean up** the `std::string` objects and return

---

## 4. String initialization

The program uses MSVC's Small String Optimization (SSO) for `std::string`. The SSO buffer size is 15 bytes (capacity `0xf`), stored inline in the `std::string` object. Two string objects are created:

- **Username string** at `0x48(%rsp)` — initialized with capacity 15, empty content
- **Password string** at `0x68(%rsp)` — initialized with capacity 15, empty content

```asm
1400012b6:  xor    %ebx,%ebx              ; ebx = 0 (null byte)
1400012bb:  xorps  %xmm0,%xmm0            ; zero out 16 bytes
1400012cc:  mov    %bl,0x48(%rsp)         ; null-terminate username SSO buffer
1400012d0:  movups %xmm0,0x68(%rsp)       ; zero out password area
1400012d5:  mov    %rbx,-0x50(%r11)       ; username size = 0
1400012d9:  movq   $0xf,-0x48(%r11)       ; username capacity = 15 (SSO)
1400012e1:  mov    %bl,0x68(%rsp)         ; null-terminate password SSO buffer
```

---

## 5. Input prompting and reading

### Print "User: " (0x1400012e5)

```asm
1400012e5:  lea    0x20c8(%rip),%rdx      ; rdx = "User: " (0x1400033b4)
1400012ec:  mov    0x1dcd(%rip),%rcx      ; rcx = std::cout
1400012f3:  call   0x1400017d0            ; operator<<(cout, "User: ")
```

### Read Username (0x1400012f8)

```asm
1400012f8:  lea    0x48(%rsp),%rdx        ; rdx = &username_string
1400012fd:  mov    0x1dac(%rip),%rcx      ; rcx = std::cin
140001304:  call   0x1400019a0            ; std::cin >> username
```

### Print "Pass: " (0x140001309)

```asm
140001309:  lea    0x20ac(%rip),%rdx      ; rdx = "Pass: " (0x1400033bc)
140001310:  mov    0x1da9(%rip),%rcx      ; rcx = std::cout
140001317:  call   0x1400017d0            ; operator<<(cout, "Pass: ")
```

### Read Password (0x14000131c)

```asm
14000131c:  lea    0x68(%rsp),%rdx        ; rdx = &password_string
140001321:  mov    0x1d88(%rip),%rcx      ; rcx = std::cin
140001328:  call   0x1400019a0            ; std::cin >> password
```

---

## 6. Custom hash algorithm — core logic

This is the heart of the crackme. After reading both inputs, the program computes a custom hash of the username string at addresses **0x14000132D through 0x140001384**.

### Hash Computation (0x14000132D – 0x14000137B)

```asm
14000132d:  mov    %ebx,%r8d              ; r8d = 0 (hash accumulator, h = 0)
140001330:  mov    %ebx,%edx              ; edx = 0 (loop counter, i = 0)
140001332:  mov    0x60(%rsp),%rbp        ; rbp = username.capacity()
140001337:  mov    0x48(%rsp),%rbx        ; rbx = username data pointer
14000133c:  mov    0x58(%rsp),%r9         ; r9 = username.length()
140001341:  test   %r9,%r9               ; if length == 0
140001344:  je     0x14000137d            ;   skip loop

; --- Loop body (iterates over each character) ---
140001350:  lea    0x48(%rsp),%rax        ; rax = SSO buffer address
140001355:  cmp    $0xf,%rbp              ; if capacity > 15 (heap-allocated)
140001359:  cmova  %rbx,%rax              ;   use heap pointer instead
14000135d:  movsbl (%rax,%rdx,1),%ecx    ; ecx = sign_extend_byte(username[i])
140001361:  lea    0x1(%rdx),%eax         ; eax = i + 1
140001364:  imul   %ecx,%eax             ; eax = (i + 1) * char_val
140001367:  add    %r8d,%eax             ; eax = (i + 1) * char_val + h
14000136a:  lea    0x0(,%eax,8),%r8d     ; r8d = eax * 8
140001372:  xor    %eax,%r8d             ; r8d = (eax * 8) ^ eax
140001375:  inc    %rdx                  ; i++
140001378:  cmp    %r9,%rdx              ; if i < length
14000137b:  jb     0x140001350           ;   continue loop
```

### Post-Processing (0x14000137D – 0x140001384)

```asm
14000137d:  imul   $0x539,%r8d,%edx      ; edx = hash * 0x539 (1337)
140001384:  xor    $0x5a5a,%edx          ; edx = (hash * 1337) ^ 0x5a5a (23130)
```

### Deconstructing the Hash Algorithm

Let `username = s[0] s[1] ... s[n-1]` and let `h₀ = 0`. For each character at index `i`:

```
c_i    = sign_extend_byte(s[i])          // movsbl: sign-extended byte value
val_i  = (i + 1) * c_i + h_i            // intermediate value
h_{i+1} = (val_i * 8) XOR val_i          // hash update: rotate-style mixing
```

All arithmetic is performed in 32-bit unsigned (wrapping) mode due to the x86 register sizes.

After processing all characters, the final hash is transformed:

```
final = (h_n * 1337) XOR 23130           // constants 0x539 and 0x5A5A
```

The result is interpreted as a **signed 32-bit integer** before being converted to a decimal string.

### Hash Algorithm in C

```c
uint32_t hash_username(const char* username, size_t len) {
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) {
        int8_t c = (int8_t)username[i];       // movsbl sign extension
        uint32_t val = (uint32_t)((i + 1) * c) + h;
        h = (val << 3) ^ val;                  // (val * 8) XOR val
    }
    return (h * 0x539) ^ 0x5A5A;
}
```

The hash function uses a combination of position-dependent multiplication (each character's contribution is weighted by its 1-indexed position), additive accumulation, and a bitwise XOR-fold with a left shift (similar to a bit rotation). The final multiplication by 1337 and XOR with 23130 acts as an additional avalanche step to spread the bits of the hash value.

---

## 7. Integer-to-string conversion (0x140001610)

After computing the hash, the program calls a function at **0x140001610** to convert the signed 32-bit integer in `edx` to a decimal string representation stored in a `std::string`.

```asm
14000138a:  lea    0x28(%rsp),%rcx       ; rcx = &output_string
14000138f:  call   0x140001610           ; itoa(&output_string, edx)
```

### Function at 0x140001610 — Analysis

This function implements a standard integer-to-decimal-string conversion, commonly generated by MSVC as part of `std::to_string()`:

```asm
140001610:  push   %rbx
140001612:  push   %rbp
140001613:  push   %rdi
140001614:  sub    $0x50,%rsp
...
140001633:  mov    %edx,%r8d             ; r8d = value to convert
140001636:  mov    %rcx,%rbx             ; rbx = output string pointer
140001639:  test   %edx,%edx             ; check if value is negative
14000163b:  jns    0x140001672            ; jump if non-negative

; Negative path: negate and add '-' sign
14000163d:  neg    %r8d                  ; r8d = -value
140001640:  dec    %rdi                  ; move buffer pointer backward
140001643:  mov    $0xcccccccd,%eax      ; magic constant for division by 10
140001648:  mul    %r8d                  ; unsigned multiply
14000164b:  shr    $0x3,%edx             ; edx = value / 10
14000164e:  movzbl %dl,%eax              ; digit = quotient
140001651:  shl    $0x2,%al              ; al = digit * 4
140001654:  lea    (%rax,%rdx,1),%ecx    ; ecx = digit * 5
140001657:  add    %cl,%cl               ; cl = digit * 10
140001659:  sub    %cl,%r8b              ; r8b = value - digit*10 = value % 10
14000165c:  add    $0x30,%r8b            ; convert to ASCII ('0' = 0x30)
140001660:  mov    %r8b,(%rdi)           ; store digit in buffer
140001663:  mov    %edx,%r8d             ; r8d = quotient for next iteration
140001666:  test   %edx,%edx             ; while quotient != 0
140001668:  jne    0x140001640
14000166a:  dec    %rdi
14000166d:  movb   $0x2d,(%rdi)          ; append '-' sign (0x2d)
140001670:  jmp    0x14000169c

; Positive path: same division loop without sign handling
140001672:  dec    %rdi
140001675:  mov    $0xcccccccd,%eax      ; magic constant for division by 10
14000167a:  mul    %r8d
14000167d:  shr    $0x3,%edx             ; edx = value / 10
140001680:  movzbl %dl,%eax
140001683:  shl    $0x2,%al
140001686:  lea    (%rax,%rdx,1),%ecx    ; ecx = digit * 5
140001689:  add    %cl,%cl               ; cl = digit * 10
14000168b:  sub    %cl,%r8b              ; r8b = value % 10
14000168e:  add    $0x30,%r8b            ; ASCII digit
140001692:  mov    %r8b,(%rdi)           ; store digit
140001695:  mov    %edx,%r8d             ; quotient
140001698:  test   %edx,%edx
14000169a:  jne    0x140001672

; Build std::string from digit buffer
14000169c:  xorps  %xmm0,%xmm0
1400016a4:  movups %xmm0,(%rbx)          ; clear string internals
1400016ac:  mov    %rbp,0x10(%rbx)       ; set size = 0
1400016b0:  mov    %rbp,0x18(%rbx)       ; set capacity = 0 (will be set below)
; ... (SSO or heap allocation based on string length)
```

The function extracts decimal digits by repeatedly dividing by 10 using the compiler's magic number optimization (`0xCCCCCCC` with `shr $3` is equivalent to unsigned division by 10). Each remainder is converted to its ASCII representation by adding `0x30`. The digits are stored in reverse order (LSB first) in a stack buffer and then copied into the output `std::string` in the correct order.

**Key insight:** The expected password is simply the decimal string representation of the final hash value. There are no lookup tables, no external keys, and no encoded data — the password is entirely deterministic and computed from the username.

---

## 8. Password comparison (0x140001394 – 0x1400013E7)

After generating the expected password string, the program compares it with the user-supplied password:

```asm
140001394:  mov    0x80(%rsp),%r13       ; r13 = generated_password.capacity()
14000139c:  lea    0x68(%rsp),%rdx       ; rdx = &user_password (SSO or heap)
1400013a1:  mov    0x68(%rsp),%rdi       ; rdi = user_password data pointer
1400013a6:  cmp    $0xf,%r13             ; if generated_password capacity > 15
1400013aa:  cmova  %rdi,%rdx             ;   use heap pointer for password data
1400013ae:  mov    0x38(%rsp),%r8        ; r8 = generated_password.size()
1400013b3:  mov    0x40(%rsp),%r15       ; r15 = generated_password.capacity()
1400013b8:  lea    0x28(%rsp),%rcx       ; rcx = &generated_password
1400013bd:  mov    0x28(%rsp),%rsi       ; rsi = generated_password data pointer
1400013c2:  cmp    $0xf,%r15             ; if capacity > 15
1400013c6:  cmova  %rsi,%rcx             ;   use heap pointer

; Size comparison first (optimization: avoid memcmp if sizes differ)
1400013ca:  cmp    0x78(%rsp),%r8        ; compare sizes: generated vs user
1400013cf:  je     0x1400013d6            ; if sizes match, proceed
1400013d1:  xor    %r14b,%r14b           ; r14b = 0 (FAIL: sizes don't match)
1400013d4:  jmp    0x1400013eb

1400013d6:  test   %r8,%r8               ; if size == 0
1400013d9:  jne    0x1400013e0            ;   skip to memcmp
1400013db:  mov    $0x1,%r14b            ; r14b = 1 (PASS: both empty strings)
1400013de:  jmp    0x1400013eb

; Byte-by-byte comparison via memcmp
1400013e0:  call   0x140002b03           ; memcmp(generated_data, user_data, size)
1400013e5:  test   %eax,%eax
1400013e7:  sete   %r14b                 ; r14b = 1 if memcmp returned 0
```

The comparison follows the standard `std::string::operator==` implementation:
1. **Quick reject**: If the string sizes differ, immediately return false (`r14b = 0`)
2. **Empty check**: If both sizes are 0, return true (`r14b = 1`)
3. **Full comparison**: Otherwise, call `memcmp()` on the raw character data and set `r14b = 1` only if `memcmp` returns 0 (strings are identical)

---

## 9. Result output (0x14000142B – 0x14000143E)

```asm
14000142b:  test   %r14b,%r14b           ; check comparison result
14000142e:  lea    0x1f93(%rip),%rdx     ; rdx = "Access granted" (0x1400033c8)
140001435:  jne    0x14000143e            ; if r14b != 0, print "Access granted"
140001437:  lea    0x1f9a(%rip),%rdx     ; rdx = "Access denied" (0x1400033d8)
14000143e:  call   0x1400017d0           ; operator<<(cout, message)
```

If `r14b` is non-zero (comparison succeeded), the program loads the address of "Access granted" and prints it. Otherwise, it loads "Access denied" and prints that instead.

---

## 10. Complete algorithm summary

The program implements a simple challenge-response mechanism:

```
1. Read username and password from user
2. Compute hash of username using custom algorithm
3. Convert hash to decimal string (this IS the correct password)
4. Compare user-provided password with computed password
5. Print "Access granted" if they match, "Access denied" otherwise
```

In pseudocode:

```python
def crackme_password(username):
    h = 0
    for i, char in enumerate(username):
        c = sign_extend_byte(ord(char))
        val = (i + 1) * c + h       # position-weighted character + accumulator
        h = (val * 8) ^ val          # bit-mixing step
    final = (h * 1337) ^ 23130       # final avalanche
    return str(sign_extend_32(final))  # convert to signed decimal string
```

---

## 11. Solver / Keygen

The following Python script acts as a complete keygen for this crackme. Given any username, it computes the correct password:

```python
#!/usr/bin/env python3
"""
crackmepls.exe Keygen
Computes the correct password for any given username.
"""

def compute_password(username: str) -> str:
    """Compute the password for a given username."""
    h = 0  # hash accumulator (uint32)
    
    for i in range(len(username)):
        # movsbl: sign-extend byte to 32-bit
        c = ord(username[i])
        if c > 127:
            c -= 256
        
        # Core hash: val = (position * char) + prev_hash
        val = ((i + 1) * c + h) & 0xFFFFFFFF
        # Mixing: h = (val * 8) XOR val
        h = ((val << 3) ^ val) & 0xFFFFFFFF
    
    # Final transformation: multiply by 1337, XOR with 23130
    final = ((h * 0x539) ^ 0x5a5a) & 0xFFFFFFFF
    
    # Interpret as signed 32-bit integer
    if final >= 0x80000000:
        final -= 0x100000000
    
    return str(final)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter username: ")
    
    password = compute_password(username)
    print(f"Password for '{username}': {password}")
```

### Example Outputs

| Username | Password |
|---|---|
| (empty) | `23130` |
| `a` | `1152315` |
| `admin` | `2110634480` |
| `test` | `766580965` |
| `root` | `807610543` |
| `user` | `807476856` |
| `hello` | `1003269115` |
| `password` | `668709240` |
| `flag` | `850578111` |
| `ctf` | `125178759` |
| `Kryptos` | `-17147161` |

### Step-by-Step Walkthrough for Username "admin"

| Step | i | char | c (ASCII) | val = (i+1)*c + h | h' = (val*8) ^ val |
|---|---|---|---|---|---|
| 0 | 0 | `a` | 97 | (1 * 97) + 0 = 97 | (776) ^ 97 = **873** (0x369) |
| 1 | 1 | `d` | 100 | (2 * 100) + 873 = 1073 | (8584) ^ 1073 = **9657** (0x25B9) |
| 2 | 2 | `m` | 109 | (3 * 109) + 9657 = 9984 | (79872) ^ 9984 = **73472** (0x11F00) |
| 3 | 3 | `i` | 105 | (4 * 105) + 73472 = 73892 | (591136) ^ 73892 = **533892** (0x82584) |
| 4 | 4 | `n` | 110 | (5 * 110) + 533892 = 534442 | (4275536) ^ 534442 = **4790042** (0x491AFA) |

**Final hash**: (4790042 * 1337) ^ 23130 = 6406192654 ^ 23130 = **2110634480** (0x7DCDB9F0)

**Password**: `2110634480`

---
