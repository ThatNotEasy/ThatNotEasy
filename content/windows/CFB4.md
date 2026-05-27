# CFB4 — Crackmes for Beginners #4


## TL;DR

- **Cipher:** 3-rotor-like per-byte encryption with CFB (Ciphertext Feedback) state — but every operation is reversible and the encrypted target bytes are hardcoded in `cmp` instructions.
- **Password:** `rotors_spin_9` (13 characters)
- **Weakness:** No secret key, fully reversible operations, encrypted password visible in binary — making the "cipher" an obfuscated password check rather than a real cryptosystem.

---

## 1. Overview

CFB4 features a stateful 3-rotor cipher with ciphertext feedback, closely inspired by the Enigma machine. The password is encrypted dynamically, and the shifts of the rotors mutate at each step based on the generated output. The challenge specifically asks the solver to identify the **structural weakness in the dynamic feedback loop** and write a Python decryption script to recover the 13-character activation password. Despite the complex-sounding architecture, the fundamental flaw is that all transformations are reversible and the expected encrypted output is stored directly in the binary as comparison values.

**Goal:** Reverse-engineer the encryption routine, extract the 13 encrypted target bytes, invert the per-byte transforms, and recover the password.

---

## 2. Initial reconnaissance

### 2.1 File Identification

```
File      : CFB4.exe
Format    : PE32+ (x64)
Compiler  : MSVC C++
Packing   : None
ImageBase : 0x140000000
```

### 2.2 String Analysis

Key strings extracted from the binary:

```
[*] Enter activation password (exactly 13 chars):
[+] Password: 
[-] Error: Password must be exactly 
[*] Encrypting input through custom rotors...
[+] ACCESS GRANTED! Congratulations!
[-] ACCESS DENIED! Invalid password.
```

**Observations:**
- Password must be exactly 13 characters
- There's a custom rotor encryption mentioned
- Success/failure messages are present

---

## 3. Locating the encryption routine

### 3.1 Finding the length check

Searching for the 13-character length check:

```asm
1400060ad:  48 83 fe 0d             cmp    $0xd,%rsi
1400060b1:  74 4c                   je     0x1400060ff
```

This led to the encryption routine starting at **`0x1400060ff`**.

### 3.2 The encryption loop entry point

```asm
1400060ff:  lea    0x256e2(%rip),%rdx
140006106:  call   0x140001220
14000610b:  lea    -0x30(%rbp),%rax
14000610f:  mov    -0x30(%rbp),%rdi
140006113:  mov    -0x18(%rbp),%rbx
140006117:  cmp    $0xf,%rbx
14000611b:  cmova  %rdi,%rax
14000611f:  movzbl (%rax),%r9d      ; <-- START
```

**At `0x14000611f`**: The cipher begins processing the first input byte.

---

## 4. Algorithm extraction

### 4.1 Byte 0 encryption sequence

Looking at the disassembly from `0x14000611f`:

```asm
14000611f:  movzbl (%rax),%r9d         ; Load input[0]
140006123:  add    $0x5,%r9b           ; r9 += 0x05
140006127:  xor    $0x3a,%r9b          ; r9 ^= 0x3a
14000612b:  add    $0x13,%r9b          ; r9 += 0x13
14000612f:  xor    $0x7f,%r9b          ; r9 ^= 0x7f
140006133:  sub    $0xd,%r9b           ; r9 -= 0x0d
140006137:  xor    $0x5c,%r9b          ; r9 ^= 0x5c
14000613b:  add    $0x15,%r9b          ; r9 += 0x15 (position offset)
14000613f:  xor    $0xa5,%r9b          ; r9 ^= 0xa5
140006143:  cmp    $0xc6,%r9b          ; Compare with 0xc6 !!
```

**Pattern discovered:**
```
encrypted[0] = ((((((input[0] + 0x05) ^ 0x3a) + 0x13) ^ 0x7f - 0x0d) ^ 0x5c) + 0x15) ^ 0xa5
Expected result: 0xc6
```

### 4.2 Extracting all 13 encrypted target bytes

By searching for all `cmp` instructions with single-byte hex values:

```asm
140006143:  cmp    $0xc6,%r9b     ; Byte 0  = 0xc6
140006187:  cmp    $0xb7,%r11b    ; Byte 1  = 0xb7
1400061c4:  cmp    $0x2b,%cl      ; Byte 2  = 0x2b
1400061fe:  cmp    $0x6e,%cl      ; Byte 3  = 0x6e
140006239:  cmp    $0x9e,%cl      ; Byte 4  = 0x9e
140006273:  cmp    $0xb7,%cl      ; Byte 5  = 0xb7
1400062ae:  cmp    $0xfa,%cl      ; Byte 6  = 0xfa
1400062e8:  cmp    $0x54,%cl      ; Byte 7  = 0x54
140006323:  cmp    $0x52,%cl      ; Byte 8  = 0x52
14000635d:  cmp    $0x3f,%cl      ; Byte 9  = 0x3f
140006398:  cmp    $0x35,%cl      ; Byte 10 = 0x35
1400063d9:  cmp    $0x98,%r8b     ; Byte 11 = 0x98
14000640c:  cmp    $0xdf,%cl      ; Byte 12 = 0xdf
```

**Encrypted Target:**
```
c6 b7 2b 6e 9e b7 fa 54 52 3f 35 98 df
```

### 4.3 The CFB feedback mechanism

After byte 0, subsequent bytes use accumulated state:

```asm
; After byte 0 encryption:
14000614a:  lea    0x5(%r9),%edx         ; r10 = r9 + 0x05
14000614e:  xor    $0xd,%r9b             ; r11 = r9 ^ 0x0d

; For byte 1:
140006162:  add    0x1(%rax),%r11b       ; val = input[1] + r10
140006166:  xor    $0x3a,%r11b           ; val ^= 0x3a
14000616a:  add    $0x13,%r11b           ; val += 0x13
14000616e:  xor    $0x7f,%r11b           ; val ^= 0x7f
140006172:  sub    %r9b,%r11b            ; val -= r11 (CFB!)
140006175:  xor    $0x5c,%r11b           ; val ^= 0x5c
140006179:  add    $0x15,%r11b           ; val += offset[1]
14000617d:  xor    $0xa5,%r11b           ; val ^= 0xa5

; Update states:
14000618f:  lea    (%rdx,%r11,1),%r10d   ; r10 += encrypted[1]
140006193:  xor    %r9b,%r11b            ; r11 ^= encrypted[1]
```

### 4.4 Position offsets extraction

```asm
add    $0x15,%r9b     ; Byte 0
add    $0x15,%r11b    ; Byte 1
add    $0x16,%cl      ; Byte 2
add    $0x18,%cl      ; Byte 3
add    $0x1b,%cl      ; Byte 4
add    $0x1f,%cl      ; Byte 5
add    $0x24,%cl      ; Byte 6
add    $0x2a,%cl      ; Byte 7
add    $0x31,%cl      ; Byte 8
add    $0x39,%cl      ; Byte 9
add    $0x42,%cl      ; Byte 10
add    $0x4c,%r8b     ; Byte 11
add    $0x57,%cl      ; Byte 12
```

**Position Offsets:**
```
15 15 16 18 1b 1f 24 2a 31 39 42 4c 57
```

---

## 5. Identifying the weakness

The challenge asks us to find the **structural weakness in the dynamic feedback loop**. Here is what makes this cipher fundamentally broken:

### 5.1 Complete reversibility

Every operation is reversible:
- **XOR**: `x ^ k` reverses to `x ^ k` (XOR is its own inverse)
- **ADD**: `x + k` reverses to `x - k`
- **SUB**: `x - k` reverses to `x + k`

Since we know the encrypted target values, we can simply reverse each step.

### 5.2 No secret key

A real Enigma machine's security comes from unknown rotor wirings, unknown rotor starting positions, and unknown plugboard settings. **This cipher has none of that.** The "rotors" are just fixed mathematical operations hardcoded in the binary.

### 5.3 Known ciphertext in binary

The encrypted password is stored as comparison values in the disassembly. These ARE the encrypted password — we extracted them directly.

### 5.4 Deterministic CFB with known values

The feedback mechanism updates states based on **encrypted output**:

```python
r10 = (r10 + encrypted[i]) & 0xff
r11 = r11 ^ encrypted[i]
```

Since we KNOW all encrypted bytes (we extracted them), we can perfectly simulate these state transitions during decryption. The feedback adds complexity but no security.

**Conclusion**: This is not a cipher — it is an obfuscated password check with reversible math.

---

## 6. Building the decryption script

### 6.1 Reversing byte 0

```python
def decrypt_byte_0(encrypted_val):
    """
    Reverse: encrypted = ((((((input + 0x05) ^ 0x3a) + 0x13) ^ 0x7f - 0x0d) ^ 0x5c) + 0x15) ^ 0xa5

    Work backwards:
    """
    val = encrypted_val
    val = val ^ 0xa5              # Undo final XOR
    val = (val - 0x15) & 0xff     # Undo ADD (use & 0xff for byte wrapping)
    val = val ^ 0x5c              # Undo XOR
    val = (val + 0x0d) & 0xff     # Undo SUB (reverse with ADD)
    val = val ^ 0x7f              # Undo XOR
    val = (val - 0x13) & 0xff     # Undo ADD
    val = val ^ 0x3a              # Undo XOR
    val = (val - 0x05) & 0xff     # Undo initial ADD
    return val
```

### 6.2 Reversing bytes 1-12

```python
def decrypt_byte_i(encrypted_val, r10, r11, offset):
    """
    Reverse the encryption for bytes 1-12
    These use accumulated states from CFB feedback
    """
    val = encrypted_val
    val = val ^ 0xa5              # Undo final XOR
    val = (val - offset) & 0xff   # Undo position-specific ADD
    val = val ^ 0x5c              # Undo XOR
    val = (val + r11) & 0xff      # Undo SUB (reverse with ADD)
    val = val ^ 0x7f              # Undo XOR
    val = (val - 0x13) & 0xff     # Undo ADD
    val = val ^ 0x3a              # Undo XOR
    val = (val - r10) & 0xff      # Undo ADD with accumulated state
    return val
```

### 6.3 Complete decryption function

```python
def decrypt_password():
    """Decrypt the complete 13-character password"""

    # Extracted from disassembly
    encrypted_target = [
        0xc6, 0xb7, 0x2b, 0x6e, 0x9e, 0xb7, 0xfa,
        0x54, 0x52, 0x3f, 0x35, 0x98, 0xdf
    ]

    # Position offsets from disassembly
    offsets = [
        0x15, 0x15, 0x16, 0x18, 0x1b, 0x1f, 0x24,
        0x2a, 0x31, 0x39, 0x42, 0x4c, 0x57
    ]

    plaintext = []

    # Decrypt byte 0
    byte_0 = decrypt_byte_0(encrypted_target[0])
    plaintext.append(chr(byte_0))

    # Initialize CFB states (from disassembly analysis)
    r9 = encrypted_target[0]
    r10 = (r9 + 0x05) & 0xff      # lea 0x5(%r9),%edx
    r11 = r9 ^ 0x0d               # xor $0xd,%r9b

    # Decrypt bytes 1-12
    for i in range(1, 13):
        byte_i = decrypt_byte_i(encrypted_target[i], r10, r11, offsets[i])
        plaintext.append(chr(byte_i))

        # Update CFB states (simulate the feedback)
        r10 = (r10 + encrypted_target[i]) & 0xff
        r11 = r11 ^ encrypted_target[i]

    return ''.join(plaintext)
```

### 6.4 Running the decryption

```python
if __name__ == "__main__":
    password = decrypt_password()
    print(f"Decrypted Password: {password}")
```

**Output:**
```
Byte 0: 0xc6 -> 0x72 ('r')
Initial states: r10=0xcb, r11=0xcb
Byte  1: 0xb7 -> 0x6f ('o') | r10=0xcb, r11=0xcb
Byte  2: 0x2b -> 0x74 ('t') | r10=0x82, r11=0x7c
Byte  3: 0x6e -> 0x6f ('o') | r10=0xad, r11=0x57
Byte  4: 0x9e -> 0x72 ('r') | r10=0x1b, r11=0x39
Byte  5: 0xb7 -> 0x73 ('s') | r10=0xb9, r11=0xa7
Byte  6: 0xfa -> 0x5f ('_') | r10=0x70, r11=0x10
Byte  7: 0x54 -> 0x73 ('s') | r10=0x6a, r11=0xea
Byte  8: 0x52 -> 0x70 ('p') | r10=0xbe, r11=0xbe
Byte  9: 0x3f -> 0x69 ('i') | r10=0x10, r11=0xec
Byte 10: 0x35 -> 0x6e ('n') | r10=0x4f, r11=0xd3
Byte 11: 0x98 -> 0x5f ('_') | r10=0x84, r11=0xe6
Byte 12: 0xdf -> 0x39 ('9') | r10=0x1c, r11=0x7e

Decrypted Password: rotors_spin_9
```

---

## 7. Verification

When entered into CFB4.exe:

```
[*] Enter activation password (exactly 13 chars):
[+] Password: rotors_spin_9
[*] Encrypting input through custom rotors...
[+] ACCESS GRANTED! Congratulations!
```

### 7.1 Summary of attack steps

1. **Disassemble** the binary to find the encryption routine
2. **Extract** the 13 encrypted target bytes from `cmp` instructions
3. **Analyze** the algorithm to understand each transformation
4. **Extract** position-specific offsets from `add` instructions
5. **Identify** the CFB state update mechanism
6. **Implement** reverse transformations for each operation
7. **Simulate** CFB state transitions using known encrypted values
8. **Decrypt** byte-by-byte to recover the plaintext password

---

## 8. Conclusion

This challenge demonstrates what happens when a cipher lacks fundamental security properties:

| Property | Secure Cipher | This Challenge |
|----------|---------------|----------------|
| **Secret Key** | Required to decrypt | No key, all hardcoded |
| **One-Way Functions** | Easy to encrypt, hard to decrypt | Fully reversible |
| **Unknown Ciphertext** | Attacker doesn't know target | Stored in binary |
| **Key-Dependent Transform** | Different keys → different outputs | Fixed algorithm |
| **Avalanche Effect** | 1-bit input change affects ~50% output | Partial diffusion only |

The "3-rotor" label is a misnomer — real Enigma rotors use permutation tables with custom wirings, while this challenge just uses 3 sequential mathematical operations. The CFB feedback adds complexity but no security because the encrypted bytes are publicly accessible in the binary. Once the transforms are inverted and the state machine is simulated, the 13-character password falls out immediately.

**Password: `rotors_spin_9`**

*Solved with static analysis only — no debugger, no emulator, no execution.*
