# VM Rust 


## TL;DR

- **Protection:** Six stacked layers (anti-debug, obfuscated APIs, VM, `.text` integrity, …).
- **Focus:** PE/Rust metadata recon → isolate VM dispatcher → recover semantics sufficient for key or patch strategy.

---

## 1. Overview

The crackme is structured around **six layers of protection** that must be understood and defeated to either recover the internal key or produce a patched binary that always succeeds.

---

## 2. Binary structure

### 2.1 PE layout

```
Section   VMA              VSize      RawOffset  RawSize
.text     0x140001000      0x1F4B2    0x400      0x1F600
.rdata    0x140021000      0x14776A   0x1FA00    0x147800
.data     0x1400169000     0x2B0      0x167200   0x200
.pdata    0x140016A000     0xDF8      0x167400   0xE00
.reloc    0x140016B000     0x264      0x168200   0x400
```

### 2.2 Source modules (embedded in .rdata debug info)

The binary preserves Rust source paths in its debug metadata:

| Module                   | Purpose                              |
|--------------------------|--------------------------------------|
| `src\key\mod.rs`         | Key derivation from .text hashes     |
| `src\vm1\interpreter.rs` | First VM interpreter (13 470 bytes) |
| `src\vm2\interpreter.rs` | Second VM interpreter (5 302 bytes) |
| `src\vm3\interpreter.rs` | Third VM interpreter (3 218 bytes)  |
| `src\validate\model.rs`  | Validation model / key comparison   |

### 2.3 Notable embedded constants

```
CRACKME_LIVE_CONTEXT   — panic-context marker used as validation token
0xDEADBEEF             — initial hash seed
0xCAFEBABE             — magic return value
0x1337C0DE             — alternate magic value
0x0BADF00D             — panic handler cookie (0x135724680BADF00D)
0x811C9DC5             — FNV-1a offset basis
0x01000193             — FNV-1a prime
```

---

## 3. Protection mechanisms (layer by layer)

### 3.1 Anti-debugging

**Location:** CRT initialization at VMA `0x14001EE08`

The Windows CRT startup calls `IsDebuggerPresent` (imported at IAT slot `0x140021150`) and `QueryPerformanceCounter` (`0x140021160`) during process initialization. The flow is:

```
0x14001EF03:  call [IsDebuggerPresent]
0x14001EF09:  mov  ebx, eax            ; ebx = 1 if debugger present
0x14001EF35:  cmp  ebx, 1
0x14001EF38:  je   0x14001EF42         ; jump to failure path if debugger found
```

If a debugger is detected, the CRT invokes `__fastfail` (via `int 0x29`), which immediately terminates the process without any cleanup. The `QueryPerformanceCounter` call at `0x14001ED31` is used for entropy in the CRT's random seed initialization and doubles as a secondary timing-based debugger detection.

**Bypass:** Patch the `je` at `0x14001EF38` to an unconditional `jmp` (`74 08` → `EB 08`), or simply launch the binary without a debugger attached.

### 3.2 API obfuscation (PEB walking)

**Location:** `0x1400069E0`

Instead of importing `GetModuleHandleA` and `GetProcAddress` through the normal IAT, the binary resolves them at runtime by walking the Process Environment Block (PEB) and comparing case-insensitive FNV-1a hashes of DLL export names.

```
PEB → Ldr → InMemoryOrderModuleList → iterate modules
  For each module → iterate exports
    Compute: fnv1a_lowercase("GetModuleHandleA") = 0x0A3E6F6C3
    Compare with expected hash stored in code
    If match → return function pointer
```

The two resolved APIs are identified by their hashes:

| API                | Hash (binary's FNV variant) |
|--------------------|-----------------------------|
| `GetModuleHandleA` | `0x0A3E6F6C3`              |
| `GetProcAddress`   | `0x0E463DA3C`              |

This makes static import analysis less useful, as the actual API calls are indirect through function pointers resolved at runtime.

### 3.3 .text section integrity check

**Location:** `0x140006740`

Before performing key derivation, the binary verifies that its own `.text` section has not been tampered with. It:

1. Calls `GetModuleHandleA(NULL)` to get the base address of the current module.
2. Parses the PE headers to locate the `.text` section.
3. Checks that specific function addresses (`0x140006BE0`, `0x140006CD0`, and `0x140006740` itself) fall within the `.text` section's virtual address range.
4. Optionally checks an ntdll export's `VirtualSize` field (calls `GetProcAddress` on ntdll to check if a specific export has `VirtualSize ≥ 0x20`).

If the integrity check fails, different magic constants are used in subsequent hash operations, causing the derived key to be incorrect and the validation to fail. This means **simple patching of the `.text` section will break the key derivation** — the patches must be applied outside the hashed region or the key-check comparison must also be patched.

### 3.4 Key derivation (core protection)

**Location:** `0x140005FD0`

The binary derives a **128-bit key** (4 × `u32`) entirely from the contents of its own `.text` section. This means the key is deterministic and can be recomputed from the on-disk binary without running it.

#### 3.4.1 Three-Part Custom FNV-1a Hash (`0x140006150`)

The `.text` section (128,178 bytes, per its `VirtualSize`) is split into three equal parts:

```
part_len = ceil(text_size / 3) = 42726
third_size = text_size - 2 * part_len = 42726
```

Each part is hashed with a different seed using a custom FNV-1a variant that incorporates **rotate-left (ROL)** operations and a **running counter**:

**Algorithm (pseudocode for each part):**
```
seed = part_identifier ^ 0x811C9DC5
counter = 0x11
for pair of bytes (b1, b2) in data:
    tmp = (b1 + counter - 17) ^ hash
    tmp = ROL32(tmp, (index & 6) + 3)
    hash = tmp * 0x01000193

    tmp = (b2 + counter) ^ hash
    tmp = ROL32(tmp, ((index+1) & 7) + 3)
    hash = tmp * 0x01000193

    counter += 0x22
```

The three parts use different seed XOR values:

| Part | Offset in .text | Bytes  | Seed XOR         |
|------|----------------|--------|------------------|
| 1    | 0              | 42726  | `part_len ^ 0x811C9DC5` |
| 2    | 42726          | 42726  | `third_size ^ 0xA55AA55A` |
| 3    | 42726          | 42726  | `third_size ^ 0x1F123BB5` |

This produces three hash values: **h1**, **h2**, **h3**.

#### 3.4.2 Standard FNV-1a Hash (`0x140006490` and `0x1400065E0`)

A standard FNV-1a hash is computed over the entire `.text` section:

```
fnv = 0x811C9DC5
for each byte b in .text:
    fnv = (fnv ^ b) * 0x01000193   (mod 2^32)
```

#### 3.4.3 Key Assembly

The final 128-bit key is assembled from the hash values:

```
key[0] = ROL32(h2, 5) XOR h1
key[1] = fnv1a(.text)
key[2] = fnv1a(.text) XOR ROL32(h3, 11)
key[3] = 0xC3C3C3C3 XOR 0xA5A5A5A5 XOR ROL32(fnv1a(.text), 9)
```

**Recovered key:**

```
8e 3c df 07  40 b7 42 10  bd e0 5c 2d  46 e6 08 e3
```

As four little-endian DWORDs:

```
key[0] = 0x07DF3C8E
key[1] = 0x1042B740
key[2] = 0x2D5CE0BD
key[3] = 0xE308E646
```

### 3.5 String obfuscation

**Location:** `0x14001AE50`

Strings in the binary are obfuscated using the `CRACKME_LIVE_CONTEXT` (20 bytes) as a validation token. The deobfuscation function at `0x14001AE50`:

1. Takes a pointer to the obfuscated data and the CRACKME_LIVE_CONTEXT string as parameters.
2. Validates that the context string decodes successfully (the Rust `neg` overflow check pattern).
3. If validation passes, uses the derived key to XOR-decrypt the actual strings.
4. If validation fails (e.g., the context has been tampered with), frees the buffer and takes an alternate code path.

The presence of `0xDEADBEEF` and `0xCAFEBABE` as sentinel values in the calling code confirms this is an integrity-checked string decryption mechanism.

### 3.6 VM-based validation

**Location:** Three interpreters at:
- VM1: `0x140006DB0` (13,470 bytes — the largest function)
- VM2: `0x14000C370` (5,302 bytes)
- VM3: `0x14000E290` (3,218 bytes)

The binary implements **three custom bytecode virtual machines** that process user input through multiple stages of validation. Key observations:

1. **VM1** (`0x140006DB0`) is the primary interpreter. It takes a byte buffer and length as parameters (`rcx` = data pointer, `rdx` = length). It first UTF-8 decodes the input, then dispatches opcodes. The function at `0x14000A2A0` is called on completion/error.

2. **VM2** (`0x14000C370`) is called from the validation function at `0x140009D95`. It processes intermediate results.

3. **VM3** (`0x14000E290`) is called from five different sites, suggesting it's a utility VM used for specific sub-tasks within the validation pipeline.

The VMs use a **stack-based architecture** with the opcode in the high bits of each byte. The dispatch loop at `0x140006E6D` checks the sign bit of each byte:

```
if (byte & 0x80):     // multi-byte opcode
    opcode = byte & 0x1F
    operand = (next_byte & 0x3F) | ...
else:                   // single-byte opcode
    direct operation
```

---

## 4. Key validation flow

**Location:** `0x14000964B`

The main validation function:

```
0x14000964B:  call 0x140005FD0        ; derive key into [rbp+0x538..0x548]
0x140009650:  r9d = [rbp+0x538]       ; generated key[0]
              edx = [rbp+0x53C]       ; generated key[1]
              r9d ^= [rbp+0x548]      ; XOR with stored expected key[0]
              edx ^= [rbp+0x54C]      ; XOR with stored expected key[1]
              ecx  = [rbp+0x540] ^ [rbp+0x550]
              eax  = [rbp+0x544] ^ [rbp+0x554]
0x140009685:  r8d  = ROL32(r9d, 3) ^ edx
0x14000968C:  edx  = ROL32(edx, 7) ^ ecx
0x140009691:  ecx  = ROL32(ecx, 11) ^ eax
0x140009696:  eax  = ROL32(eax, 19) ^ r9d
0x1400096A2:  if (r8d | edx | ecx | eax) == 0:
                jump to SUCCESS at 0x1400096FF
              else:
                update state and continue VM processing
```

The validation first generates the key, then XORs each DWORD with the corresponding expected DWORD embedded in the binary. The XOR results are then mixed with ROL operations and checked for all-zeros. If all are zero, the generated key matches the expected key.

---

## 5. Encrypted data blocks

Several blocks of encrypted data are embedded in the `.rdata` section:

| Block       | VMA            | Size  | Purpose                                |
|-------------|----------------|-------|----------------------------------------|
| Block 1     | `0x1400227F0`  | 272 B | Likely encrypted VM bytecode / flag    |
| Block 2     | `0x1400229C0`  | ~200B | Secondary encrypted data               |
| Block 3     | `0x140022B88`  | 106 B | VM bytecode referenced at `0x1400097A7` |
| Debug info  | `0x14016192E`  | —     | `src\validate\model.rs` context        |

These blocks appear to use XOR-based encryption with the derived key. The exact decryption scheme involves the VM interpreters processing the encrypted bytecode against user input.

---

## 6. Solution approaches

### 6.1 Key recovery (static analysis)

The key can be recovered purely from static analysis by reimplementing the key derivation algorithm. Since the key is derived solely from the `.text` section bytes, no execution is needed:

```python
# Extract .text section (VirtualSize = 0x1F4B2 bytes)
# Compute three custom FNV-1a variant hashes
# Compute standard FNV-1a of entire .text
# Assemble: key[0] = ROL(h2,5) ^ h1, etc.
# Result: 8e3cdf0740b74210bde05c2d46e608e3
```

This approach is implemented in the PoC script (`poc_vm_rust.py`).

### 6.2 Binary patching

Two patches can bypass the protection:

| Patch | File Offset | Original | Patched  | Effect                        |
|-------|-------------|----------|----------|-------------------------------|
| 1     | `0x1E338`   | `74 08`  | `EB 08`  | Skip `IsDebuggerPresent` check |
| 2     | `0x8AA8`    | `74 55`  | `EB 55`  | Skip key comparison (always succeed) |

**Note:** Patch 2 is located within the `.text` section. If the binary's integrity check were fully enforced (not just for the two specific functions it checks), patching `.text` would cause the hash derivation to produce incorrect values. However, in this binary, the integrity check only verifies that three specific addresses fall within `.text`'s virtual range — it does not recompute the hash after loading. Therefore, the patches work.

### 6.3 Combined approach

The most robust approach combines both: recover the key to understand the protection logic, then apply targeted patches to create a version of the binary that accepts any input (or specifically, the correct key/flag).

---

## 7. Lessons learned

1. **Rust binaries retain extensive metadata.** Source file paths (`src\key\mod.rs`, `src\vm1\interpreter.rs`, etc.) are embedded in the `.rdata` section and serve as invaluable signposts for reverse engineers.

2. **Anti-debug is basic but effective.** The `IsDebuggerPresent` + `QueryPerformanceCounter` combo is standard but catches casual debugging. For serious analysis, patch first, then debug.

3. **FNV-1a variants are popular in Rust.** The standard library's `hashbrown` hasher uses FNV-based algorithms, and crackme authors often extend these with custom ROL and XOR operations.

4. **VM-based protection adds depth.** The three interpreters create a significant amount of code (22,000+ bytes combined) that obscures the actual validation logic. Understanding the VM dispatch loop is the key to tracing the validation.

5. **Self-hashing creates a chicken-and-egg problem.** Deriving the key from the binary's own code means that any patching within `.text` must be carefully considered. In this case, the integrity check is weak (only range checks, not a full hash recompute), making patching feasible.

---

## 8. PoC script

The complete PoC is provided in [poc_vm_rust.py](/static/poc/poc_vm_rust.py). It:

1. Extracts and hashes the `.text` section
2. Recovers the 128-bit derived key
3. Optionally creates a patched binary that bypasses anti-debug and key-check

```bash
# Key recovery only
python3 poc_vm_rust.py vm-rust.exe

# Key recovery + create patched binary
python3 poc_vm_rust.py vm-rust.exe vm-rust_patched.exe
```

**Output:**

```
Derived 128-bit key:  8e3cdf0740b74210bde05c2d46e608e3
DWORDs: 0x07df3c8e, 0x1042b740, 0x2d5ce0bd, 0xe308e646
```

---

