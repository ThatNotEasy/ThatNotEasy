# Almost Impossible 

## TL;DR

- **Goal:** Supply a PNG whose QR payload matches a per-run EC target; two independent checks must pass.
- **Stack:** X11, libpng, zbar, OpenSSL EC — target is ~25 bits; brute force on the secret space is practical.
- **Writeup focus:** How the target is generated, how validation works, and why the search space stays small.

---

## 1. Overview

The binary presents itself as an "almost impossible" challenge - it generates a fresh cryptographic target on every launch using randomness, displays encrypted/encoded target data, and requires the user to provide a PNG artifact (image with QR code) containing the exact secret that satisfies two independent cryptographic checks. The catch? The secret space is deliberately constrained to 25 bits, making brute-force search entirely feasible - the challenge is *almost* impossible, but not quite.

---

## 2. Binary Profiling

| Property         | Value                                              |
|------------------|----------------------------------------------------|
| ELF Class        | 64-bit                                             |
| Data Encoding    | 2's complement, little endian                      |
| OS/ABI           | UNIX - GNU                                         |
| Type             | DYN (Position-Independent Executable)              |
| Machine          | Advanced Micro Devices X86-64                      |
| Stripped         | Yes (no debug symbols)                             |
| Linking          | Dynamically linked                                 |
| Interpreter      | /lib64/ld-linux-x86-64.so.2                        |
| GLIBC version    | 2.42 (Ubuntu amd64)                                |
| Entry point      | 0x7a30                                             |
| Main function    | 0x65f9 (computed from entry point `__libc_start_main` first argument) |

**Notable string constants found in the binary:**

| String              | Purpose                                      |
|---------------------|----------------------------------------------|
| `AI - Almost Impossible` | Window title                          |
| `TARGET`            | GUI button label                              |
| `COPY`              | GUI button to copy data to clipboard         |
| `IMAGE PATH`        | File path input for PNG artifact              |
| `VERIFY`            | GUI button to trigger validation              |
| `QUIT`              | GUI button to exit                            |
| `Access granted.`   | Success message (at `0x21193`)                |
| `Access denied.`    | Failure message (at `0x211a3`)                |
| `Invalid artifact.` | Error when QR code not found (at `0x211b2`)   |
| `Ready.`            | Status message                                |
| `xopen`             | X11 display initialization status             |
| `png-open`          | PNG processing stage                          |
| `png-sig`           | PNG signature verification stage              |
| `png-create`        | PNG create struct stage                       |
| `png-info`          | PNG info reading stage                        |
| `png-read`          | PNG image read stage                          |
| `zbar-scanner`      | Barcode scanner initialization stage          |
| `zbar-image`        | ZBar image creation stage                     |
| `qr`                | QR code symbol type indicator                 |
| `payload`           | Extracted QR code data                        |
| `target-import`     | Target data import stage                      |
| `group`             | EC group creation status                      |
| `bn-set`            | Bignum setup status                           |
| `export`            | Data export status                            |
| `rng`               | Random number generation status               |
| `gc`                | Garbage collection status                     |

---

## 3. Imported Libraries & Their Roles

### 3.1 libcrypto.so.3 (OpenSSL 3.0)

The binary uses OpenSSL's Elliptic Curve (EC) API for the core cryptographic operations. The following functions are imported:

| Function                  | Purpose                                           |
|---------------------------|---------------------------------------------------|
| `EC_GROUP_new_by_curve_name` | Create an EC group for a named curve           |
| `EC_GROUP_set_asn1_flag`    | Set ASN1 flag for point conversion format      |
| `EC_GROUP_free`             | Free EC group                                 |
| `EC_POINT_new`              | Create a new EC point                         |
| `EC_POINT_mul`              | Scalar multiplication: `r = n*G + m*Q`        |
| `EC_POINT_cmp`              | Compare two EC points for equality            |
| `EC_POINT_oct2point`        | Convert octet string to EC point              |
| `EC_POINT_point2oct`        | Convert EC point to octet string              |
| `EC_POINT_clear_free`       | Securely free an EC point                     |
| `BN_new` / `BN_clear_free`  | Bignum allocation/deallocation                |
| `BN_set_word`               | Set bignum from unsigned long                 |
| `BN_dec2bn`                 | Convert decimal string to bignum              |
| `BN_CTX_new` / `BN_CTX_free`| Bignum context management                     |
| `RAND_bytes`                | Generate cryptographically secure random bytes|

### 3.2 libpng16.so.16

Used to read and validate the PNG image artifact:

- `png_create_read_struct`, `png_create_info_struct` - PNG reading setup
- `png_init_io`, `png_read_info`, `png_read_image` - Image data extraction
- `png_sig_cmp` - PNG signature validation
- `png_set_gray_to_rgb`, `png_set_palette_to_rgb`, `png_set_expand_gray_1_2_4_to_8`, `png_set_tRNS_to_alpha`, `png_set_strip_16`, `png_set_filler` - Color space normalization
- `png_get_image_width`, `png_get_image_height`, `png_get_color_type`, `png_get_bit_depth`, `png_get_rowbytes`, `png_get_valid` - Image metadata queries

### 3.3 libzbar.so.0

Used for QR code scanning from the PNG image:

- `zbar_image_scanner_create`, `zbar_image_scanner_destroy` - Scanner lifecycle
- `zbar_image_scanner_set_config` - Scanner configuration (enables QR code scanning)
- `zbar_image_create`, `zbar_image_destroy` - Image lifecycle for zbar
- `zbar_image_set_format`, `zbar_image_set_size`, `zbar_image_set_data` - Image setup
- `zbar_scan_image` - Perform barcode/QR detection
- `zbar_image_first_symbol`, `zbar_symbol_next` - Iterate detected symbols
- `zbar_symbol_get_type` - Check symbol type (expects `0x40` = ZBAR_QRCODE)
- `zbar_symbol_get_data`, `zbar_symbol_get_data_length` - Extract QR data

### 3.4 libX11.so.6

Used for the GUI:

- `XOpenDisplay`, `XCloseDisplay` - Display connection
- `XCreateSimpleWindow`, `XMapWindow`, `XDestroyWindow` - Window management
- `XCreateGC`, `XFreeGC` - Graphics context
- `XDrawString`, `XDrawRectangle`, `XFillRectangle` - Drawing primitives
- `XSetForeground`, `XAllocNamedColor` - Color management
- `XLoadQueryFont`, `XSetFont` - Font management
- `XSelectInput`, `XNextEvent`, `XLookupString` - Event handling
- `XStoreBuffer`, `XInternAtom`, `XSetSelectionOwner`, `XChangeProperty`, `XSendEvent` - Clipboard operations

---

## 4. Application Architecture

The application follows a multi-stage pipeline:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  X11 GUI    │───>│  PNG Reader  │───>│  ZBar QR    │───>│  EC Verify   │
│  (libX11)   │    │  (libpng)    │    │  Scanner    │    │  (libcrypto) │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                                                                    │
                                                               ┌────┴────┐
                                                               │ Result  │
                                                               │ Granted │
                                                               │ Denied  │
                                                               └─────────┘
```

### 4.1 Startup Flow (Main Function at `0x65f9`)

1. **Initialize C++ strings** - Large stack frame (~0x408 bytes) zeroed and initialized with string objects
2. **X11 Display** (`0x679b`) - `XOpenDisplay(NULL)`. If this fails, the application throws `std::runtime_error("xopen")` and exits
3. **GUI Setup** - Create window with title "AI - Almost Impossible", buttons (TARGET, COPY, IMAGE PATH, VERIFY, QUIT), and display areas
4. **Target Generation** - Upon clicking TARGET or at startup, generate the cryptographic target (see Section 5)
5. **Event Loop** - Process X11 events for button clicks and text input

### 4.2 Key GUI Controls

| Button      | Action                                                                 |
|-------------|------------------------------------------------------------------------|
| TARGET      | (Re)generates a random cryptographic target                            |
| IMAGE PATH  | Text input for the path to the PNG artifact file                       |
| VERIFY      | Reads the PNG, scans for QR codes, validates the payload               |
| COPY        | Copies target data (encrypted EC point) to the X11 clipboard           |
| QUIT        | Exits the application                                                  |

---

## 5. Target Generation Algorithm

When a new target is generated (TARGET button or startup), the binary executes the following sequence:

### Step 1: Random Scalar Generation (`0x6a76`)

```assembly
0x6a76:  RAND_bytes(&random_buf, 4)          ; Generate 4 random bytes
0x6ac4:  eax = random_buf[0..3]              ; Load as 32-bit int
0x6ad7:  eax &= 0x00FFFFFF                   ; Mask to 24 bits
0x6adc:  eax |= 0x01000000                   ; Set bit 25 → range [0x01000000, 0x01FFFFFF]
0x6ae1:  store eax as scalar                  ; Store for later use
```

The resulting scalar is in the range `[0x01000000, 0x01FFFFFF]` = `[16,777,216, 33,554,431]`. This is a **25-bit** integer with the top bit forced to 1, giving a search space of exactly **16,777,216** values.

### Step 2: EC Group Setup (`0x6b5b` - `0x6bbc`)

```assembly
0x6b56:  edi = 0x2CA                         ; NID_secp256k1 = 714
0x6b5b:  EC_GROUP_new_by_curve_name(0x2CA)   ; Create secp256k1 group
0x6bb4:  EC_GROUP_set_asn1_flag(group, 1)    ; POINT_CONVERSION_COMPRESSED
```

The curve used is **secp256k1** (the same curve used in Bitcoin), identified by NID 714 (0x2CA). The ASN1 flag is set to `POINT_CONVERSION_COMPRESSED`, meaning all point serializations will use the compressed format (33 bytes: 1 prefix byte + 32 x-coordinate bytes).

### Step 3: EC Point Computation (`0x6c6a` - `0x6cf3`)

```assembly
0x6c19:  BN_new()                            ; Create bignum
0x6c6a:  BN_set_word(bn, scalar)             ; bn = scalar
0x6cf3:  EC_POINT_mul(group, point, bn, NULL, NULL, ctx)  ; point = scalar * G
```

This computes the public key point `P = scalar × G` where `G` is the generator of secp256k1.

### Step 4: Point Serialization (`0x6d32`)

```assembly
0x6d0b:  edx = 2                            ; POINT_CONVERSION_COMPRESSED
0x6d32:  EC_POINT_point2oct(group, point, 2, buf, buf_len, ctx)
```

The compressed EC point is serialized into a 33-byte buffer. For secp256k1, this produces either:
- `02 || x` (if y is even)
- `03 || x` (if y is odd)

### Step 5: Encryption of Target Data

The compressed point and a flag value are encrypted using a custom XOR stream cipher (see Section 6) with two different key derivations:

```
encrypted_point = xor_decrypt(compressed_point, scalar ^ 0x13579BDF)
encrypted_flag  = xor_decrypt(flag_bytes,    scalar ^ 0x2468ACE1)
```

These encrypted values are stored in the application state and displayed in the GUI.

---

## 6. Cryptographic Primitives

### 6.1 SplitMix64 PRNG (`0x7b2a`)

The binary implements the SplitMix64 pseudorandom number generator, a standard algorithm used in Java's `SplittableRandom`. This is used as the keystream generator for the XOR stream cipher.

**C equivalent (decompiled from assembly):**

```c
uint64_t splitmix64(uint64_t seed) {
    seed += 0x9E3779B97F4A7C15ULL;          // Golden ratio
    uint64_t z = seed;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
```

**Assembly trace at `0x7b2a`:**

```
7b2a: movabs $0x9e3779b97f4a7c15, %rax    ; Load golden ratio constant
7b34: add    %rdi, %rax                     ; seed += golden_ratio
7b37: mov    %rax, %rdi
7b3a: shr    $0x1e, %rdi                    ; rdi = seed >> 30
7b3e: xor    %rax, %rdi                     ; rdi ^= seed
7b41: movabs $0xbf58476d1ce4e5b9, %rax     ; Mix constant 1
7b4b: imul   %rax, %rdi                     ; z *= mix1
7b4f: movabs $0x94d049bb133111eb, %rax     ; Mix constant 2
7b59: mov    %rdi, %rdx
7b5c: shr    $0x1b, %rdx                    ; rdx = z >> 27
7b60: xor    %rdi, %rdx                     ; rdx ^= z
7b63: imul   %rax, %rdx                     ; z *= mix2
7b67: mov    %rdx, %rax
7b6a: shr    $0x1f, %rax                    ; rax = z >> 31
7b6e: xor    %rdx, %rax                     ; return z ^ (z >> 31)
7b71: ret
```

### 6.2 XOR Stream Cipher (`0x89ad` / `0x8a9c`)

The binary implements a custom XOR stream cipher using SplitMix64 as the keystream generator. Two variants exist at slightly different addresses but use the same core algorithm.

**Algorithm:**

```c
void xor_decrypt(uint8_t *output, const uint8_t *input, size_t len, uint32_t key) {
    const uint64_t MAGIC = 0xa6f1d249e13b7c55ULL;
    uint64_t seed = ((uint64_t)key) ^ MAGIC;     // Zero-extend key to 64-bit
    uint64_t state = splitmix64(seed);           // Initial state (stepping stone)

    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0) {
            state = splitmix64(state + i + 1);   // Generate new 8-byte keystream block
        }
        uint8_t key_byte = (state >> ((i % 8) * 8)) & 0xFF;
        output[i] = input[i] ^ key_byte;
    }
}
```

**Key observations:**

1. The XOR magic constant `0xa6f1d249e13b7c55` is embedded at `0x89d3` and `0x8af9`
2. The initial `splitmix64(seed)` call produces a stepping-stone value that is **not** directly used for encryption
3. The first actual keystream block is generated by `splitmix64(initial_state + 1)` at byte index 0
4. Subsequent blocks use `splitmix64(prev_state + i + 1)` at indices 8, 16, 24, ...
5. This means the keystream is deterministic given the key, and the same function serves for both encryption and decryption (XOR stream cipher property)

**Assembly trace of the keystream loop at `0x89e5`–`0x8a1f`:**

```
89e5: mov    (%r12),%r8              ; r8 = input data pointer
89e9: mov    0x8(%r12),%rdx          ; rdx = end pointer
89ee: sub    %r8,%rdx                ; rdx = data length
89f1: cmp    %rdx,%rsi               ; if (index >= length) exit
89f4: jae    8a21
89f6: mov    %rsi,%rcx               ; rcx = index
89f9: and    $0x7,%ecx               ; rcx = index % 8
89fc: jne    8a08                    ; if not aligned, skip PRNG call
89fe: lea    0x1(%rax,%rsi,1),%rdi   ; rdi = state + index + 1
8a03: call   7b2a                    ; state = splitmix64(rdi)
8a08: mov    (%rbx),%rdi             ; rdi = output buffer
8a0b: shl    $0x3,%rcx               ; rcx = (index % 8) * 8
8a0f: mov    %rax,%rdx               ; rdx = PRNG state
8a12: shr    %cl,%rdx                ; rdx = state >> byte_offset
8a15: xor    (%r8,%rsi,1),%dl        ; dl ^= input[index]
8a19: mov    %dl,(%rdi,%rsi,1)       ; output[index] = dl
8a1c: inc    %rsi                    ; index++
8a1f: jmp    89e5                    ; loop
```

### 6.3 Key Derivation

Two distinct key derivation paths are used, each applying a different XOR mask to the scalar before feeding it into the stream cipher:

| Purpose        | XOR Mask     | Assembly Location |
|----------------|-------------|-------------------|
| EC Point Encrypt | `0x13579BDF` | `0x9a64: xor $0x13579bdf,%edx` |
| Flag Encrypt    | `0x2468ACE1` | `0x9b64: xor $0x2468ace1,%edx` |

The derived keys are:
```
key_ec   = scalar ^ 0x13579BDF   → used for encrypted_point
key_flag = scalar ^ 0x2468ACE1   → used for encrypted_flag
```

---

## 7. The Validation Pipeline

When the user clicks VERIFY, the binary executes the following validation pipeline:

### Stage 1: PNG Reading (`0x91a0`–`0x933b`)

1. Open the file from IMAGE PATH
2. Validate PNG signature (first 8 bytes)
3. Create PNG read struct and info struct
4. Read and normalize the image data (convert to 8-bit RGBA)
5. Extract raw pixel data (width × height × 4 bytes)

### Stage 2: QR Code Scanning (`0x93a0`–`0x944d`)

```assembly
0x93a9:  symbol = zbar_image_first_symbol(image)
0x93bd:  type = zbar_symbol_get_type(symbol)
0x93c2:  cmp    $0x40, %eax               ; ZBAR_QRCODE = 64
0x93c5:  jne    9440                       ; Skip if not QR code
0x93ca:  data = zbar_symbol_get_data(symbol)
0x93da:  length = zbar_symbol_get_data_length(symbol)
```

The scanner iterates through all detected QR codes using `zbar_symbol_next()`, looking specifically for symbols of type `ZBAR_QRCODE` (0x40). When found, the QR data is extracted as a string.

If no QR code is found, the binary displays **"Invalid artifact."** and aborts verification.

### Stage 3: QR Payload Parsing (`0x9556`–`0x96c7`)

The QR payload must be in the format: **`<decimal_number>:<hex_string>`**

```assembly
0x9561:  colon = memchr(data, 0x3A, length)   ; Find ':' separator
0x9695:  cmp    $0x10, hex_length             ; Hex part must be exactly 16 chars
0x969e:  jne    96cc                           ; Error if not 16 chars
0x96aa:  loop:                                 ; Validate each hex char
0x96ad:  sub    $0x30, char                    ; char - '0'
0x96b0:  cmp    $0x9, char                     ; Must be 0-9
0x96b4:  jbe    valid_digit
0x96b6:  sub    $0x41, char                    ; char - 'A'
0x96b9:  cmp    $0x5, char                     ; Must be A-F
0x96bc:  ja     invalid
```

**Validation rules for the QR payload:**

1. Must contain exactly one `:` (colon) separator
2. **Part before `:`** - Must consist only of ASCII digits `0-9`
3. **Part after `:`** - Must be exactly 16 hexadecimal characters `[0-9A-F]`
4. The decimal number is parsed character-by-character: `value = value * 10 + (char - '0')`
5. The parsed decimal value must be in range `[0x01000000, 0x01FFFFFF]`

### Stage 4: EC Point Computation (`0x993c`–`0x9a06`)

```assembly
0x994b:  BN_dec2bn(&bn, decimal_string)          ; Parse decimal to bignum
0x999d:  EC_POINT_mul(group, computed_point, bn, NULL, NULL, ctx)  ; Q = scalar * G
0x6d32:  EC_POINT_point2oct(group, computed_point, 2, buf, len, ctx)  ; Serialize Q
```

The decimal scalar from the QR code is converted to a BIGNUM using OpenSSL's `BN_dec2bn()`, then used to compute `Q = scalar × G` on secp256k1. The resulting point is serialized in compressed format.

### Stage 5: First Check - EC Point Comparison (`0x9a54`–`0x9b4e`)

```assembly
0x9a54:  mov    0xd0(%rbx),%edx              ; edx = scalar (from QR decimal)
0x9a64:  xor    $0x13579bdf,%edx             ; key = scalar ^ 0x13579BDF
0x9a6a:  call   xor_decrypt                   ; Decrypt the stored encrypted_point
0x9adc:  EC_POINT_oct2point(group, point, decrypted)  ; Parse decrypted bytes as EC point
0x9b44:  EC_POINT_cmp(group, computed_Q, decrypted_point)  ; Compare points
0x9b4c:  test   %eax,%eax
0x9b4e:  jne    9bd8                          ; If NOT equal → fail immediately
```

**What happens:**
1. The scalar from the QR code is XOR'd with `0x13579BDF` to derive the decryption key
2. The stored encrypted EC point is decrypted using this key
3. The decrypted bytes are parsed as an EC point using `EC_POINT_oct2point()`
4. The computed point (from `scalar × G`) is compared with the decrypted point using `EC_POINT_cmp()`
5. If they differ, verification **fails immediately** - the flag check is never reached

This is the primary security check: **the scalar must be the discrete logarithm of the target point with respect to G on secp256k1.**

### Stage 6: Second Check - Flag Comparison (`0x9b54`–`0x9bad`)

```assembly
0x9b54:  mov    0xd0(%rbx),%edx              ; edx = scalar
0x9b64:  xor    $0x2468ace1,%edx             ; key = scalar ^ 0x2468ACE1
0x9b6a:  call   xor_decrypt                   ; Decrypt the stored encrypted_flag
0x9b87:  cmp    %r8,%rsi                      ; Compare lengths
0x9b8a:  jne    fail
0x9b9d:  mov    (%r9,%rax,1),%cl             ; Load decrypted flag byte
0x9ba1:  xor    (%rdi,%rax,1),%cl             ; XOR with QR hex bytes
0x9ba4:  inc    %rax
0x9ba7:  or     %ecx,%edx                    ; Accumulate differences
0x9ba9:  jmp    loop
0x9bab:  test   %dl,%dl                      ; Any differences?
0x9bad:  sete   %r15b                         ; r15 = 1 if match, 0 if not
```

**What happens:**
1. The scalar is XOR'd with `0x2468ACE1` to derive the second decryption key
2. The stored encrypted flag is decrypted
3. The 16 hex characters from the QR code (after `:`) are converted to 8 raw bytes
4. A byte-by-byte comparison is performed between the decrypted flag and the QR hex bytes
5. The result (stored in `r15b`) determines the final outcome

### Stage 7: Final Decision (`0x9c29`)

```assembly
0x9c29:  test   %r15b,%r15b                  ; Check both-checks result
0x9c2c:  jne    9cc3                          ; If r15b == 1 → "Access granted."
0x9c32:  jmp    9cf4                          ; If r15b == 0 → "Access denied."
```

**Result mapping:**

| Condition                              | `r15b` | Output            |
|----------------------------------------|--------|-------------------|
| EC check fails                         | 0      | "Access denied."  |
| EC check passes, flag check fails      | 0      | "Access denied."  |
| EC check passes, flag check passes     | 1      | "Access granted." |

---

## 8. Why Only One Input Works

### 8.1 The Elliptic Curve Discrete Logarithm Problem (ECDLP)

The fundamental security of the first check rests on the Elliptic Curve Discrete Logarithm Problem: given point `P = scalar × G`, find `scalar`. For well-chosen curves like secp256k1 with a 256-bit order, this problem is computationally infeasible.

**However**, the binary deliberately constrains the scalar to only 25 bits (range `[0x01000000, 0x01FFFFFF]`). This means:

- The total search space is exactly **16,777,216** values
- A brute-force search trying each `k × G` and comparing with the target point takes only **seconds to minutes** on modern hardware
- For any given target point displayed by the binary, there exists **exactly one** scalar in the valid range that satisfies `scalar × G = target_point`

This is why only **one very specific input** can satisfy the EC check - the discrete logarithm is unique, and the constrained range ensures it can be found.

### 8.2 The Double-Lock Mechanism

Even if an attacker somehow bypasses the EC check, the flag check provides a second independent verification:

1. The flag bytes are encrypted with a **different key** (`scalar ^ 0x2468ACE1` vs `scalar ^ 0x13579BDF`)
2. The attacker must provide the correct flag bytes in the QR code (as 16 hex characters)
3. The decrypted flag must match the provided hex bytes exactly

This means:
- Knowing the target point alone is not sufficient - the attacker also needs the encrypted flag data
- The flag and the EC point are independently encrypted, providing defense in depth
- A correct solution requires **both** the correct scalar **and** the correct decrypted flag bytes

### 8.3 The "Almost Impossible" Design

The challenge is aptly named. The design creates a layered defense:

| Layer              | Protection Mechanism                        |
|--------------------|---------------------------------------------|
| Randomness         | New target each run (RAND_bytes)            |
| EC Cryptography    | ECDLP on secp256k1 (256-bit curve)          |
| Stream Cipher      | SplitMix64-based XOR encryption             |
| Input Validation   | Strict format checking (decimal + hex)      |
| Double Lock        | Two independent checks must both pass        |

The **intentional weakness** is the 25-bit scalar constraint. Without this constraint (i.e., using a full 256-bit scalar), solving the challenge would require breaking ECDLP on secp256k1 - truly "almost impossible." With the constraint, brute force is straightforward.

---

## 9. Proof of Concept

### 9.1 Attack Strategy

Given the binary's displayed target (compressed EC point and encrypted data), the attack proceeds as follows:

```
1. Extract the compressed EC point from the binary's display
2. Extract the encrypted flag bytes from the binary's display
3. Brute-force: for k in [0x01000000, 0x01FFFFFF]:
       if k * G == target_point → found scalar
4. Decrypt flag: flag = xor_decrypt(enc_flag, scalar ^ 0x2468ACE1)
5. Construct QR payload: "<scalar_decimal>:<flag_hex>"
6. Generate QR code PNG image
7. Feed to binary → "Access granted."
```

### 9.2 PoC Script

The complete PoC script is saved as `poc.py`. Key components:

```python
import ecdsa

# SplitMix64 PRNG (from 0x7b2a)
def splitmix64(seed):
    seed = (seed + 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
    z = seed
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & 0xFFFFFFFFFFFFFFFF
    return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF

# XOR stream cipher (from 0x89ad)
def xor_decrypt(data, key32):
    MAGIC = 0xa6f1d249e13b7c55
    seed = (key32 & 0xFFFFFFFF) ^ MAGIC
    state = splitmix64(seed)
    result = bytearray(len(data))
    for i in range(len(data)):
        if i % 8 == 0:
            state = splitmix64(state + i + 1)
        key_byte = (state >> ((i % 8) * 8)) & 0xFF
        result[i] = data[i] ^ key_byte
    return bytes(result)

# Brute-force scalar
def brute_force_scalar(target_compressed_point):
    G = ecdsa.SECP256k1.generator
    target_vk = ecdsa.VerifyingKey.from_string(
        target_compressed_point, curve=ecdsa.SECP256k1
    )
    target_pt = target_vk.pubkey.point

    current = 0x01000000 * G  # Start from minimum scalar
    for offset in range(0x01000000):
        if current.x() == target_pt.x() and current.y() == target_pt.y():
            return 0x01000000 + offset
        current = current + G
    return None

# Decrypt the flag
scalar = brute_force_scalar(target_point_bytes)
flag = xor_decrypt(encrypted_flag_bytes, scalar ^ 0x2468ACE1)
payload = f"{scalar}:{flag.hex().upper()}"
```

### 9.3 Demo Run

Using a test scalar `0x01000010`:

```
Target point:   03196c41677812e19c1c7a234ba31dd546065b963c17dcff0c2db107a140874e59
Searching from 0x1000000 to 0x01000010...
FOUND scalar:   16777232 (0x01000010)
Decrypted flag: b'ALMOST_W'
QR payload:     16777232:414C4D4F53545F57
```

The PoC generates a PNG image [poc_artifact](/static/img/poc_artifact.png) containing a QR code with this payload. When fed to the binary's VERIFY function, it produces **"Access granted."**

| [poc_artifact](/static/img/poc_artifact.png) | QR code PNG with valid payload (→ Access granted)    |
| [bad_artifact](/static/img/bad_artifact.png) | QR code PNG with wrong scalar (→ Access denied)      |

---