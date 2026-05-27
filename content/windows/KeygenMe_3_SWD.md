# KeygenMe_3_SWD 

## TL;DR

| Input | Role |
|--------|------|
| **Username** | Typed string, length **3–15**. Drives expected **secret** via checksums on `toupper(username)`. |
| **Secret code** | Fixed layout **`####-#####-###`** (14 chars). Three segments are **base-36** integers tied to those checksums. |
| **Verification PIN** | Decimal digits, length **under 11**, value **≤ `0x7FFFFFFF`**. Must equal **`FUN_1400025a0(username, secret)`** (after that function clears bit 31). |

The PIN check XORs two 32-bit words derived from **`FUN_1400028d0`**. That transform is injective on 32 bits, so the PIN must match the hash **exactly**.

**Critical implementation detail:** the tail of **`FUN_1400025a0`** uses **signed** x86 **`IMUL`** on 32-bit operands. Reimplementing those steps as unsigned `uint32 × uint32 (mod 2³²)` yields **wrong PINs** while the secret can still match.

---

## 1. Overview

This writeup reconstructs how **`FUN_140002bd0`** drives the UI, how **`FUN_140001ec0`** / **`FUN_140002100`** validate the secret against **`toupper(username)`**, and how **`FUN_1400025a0`** plus **`FUN_140002910`** / **`FUN_1400028d0`** tie the PIN to that hash—including **signed x86 `IMUL`** in the avalanche (§8.1), which unsigned-only models get wrong.

Notable **`.rdata`** strings include banner lines such as `KeygenMe No 3`, prompts **`Username:`**, **`Secret code:`**, **`Verification PIN:`**, and ANSI sequences like **`[2K\r`** used to redraw prompts after invalid input.

---

## 2. Methodology

1. Load the PE in **Ghidra**, let auto-analysis finish, identify **`FUN_140002bd0`** as the interactive driver (string xrefs from `Username:`).
2. Map **`FUN_140001ec0`**, **`FUN_140001f80`**, **`FUN_140002100`**, **`FUN_1400025a0`**, **`FUN_140002910`**, **`FUN_1400028d0`** from call sites.
3. Confirm ambiguous math (especially **`FUN_1400025a0`**) against **disassembly**: MSVC emits **`IMUL`** with **signed** semantics for the final multiplicative mixing.
4. Reimplement in Python with explicit **`uint32`** rotates and **`imul32`** for those steps; verify against the running binary.

---

## 3. Program flow (main interactive routine)

The handler **`FUN_140002bd0`** (VA **`0x140002bd0`**) roughly performs:

1. **`system("cls")`** — clear console.
2. **`FUN_140001dc0`** — print ASCII banner (`KeygenMe No 3`, box drawing).
3. **Username loop** — read a line with **`std::getline`-style** logic into a **`std::string`**. Repeat until **`len > 2`** and **`len < 0x10`** (so **3 ≤ len ≤ 15**).
4. **Secret loop** — read until **`FUN_140001ec0(secret) != 0`** (format gate).
5. **PIN loop** — read until **`FUN_140001f80(pin_string, &parsed_uint) != 0`**.
6. Print status lines (**`Secret code ->`** / **`Verification PIN ->`**) by comparing:
   - **`FUN_140002100`** on copies of username + secret (secret validity vs username).
   - **`FUN_140002910`** on copies of username + secret + **`parsed_uint`** (PIN validity).
7. **`system("pause")`**.

**Important:** The username is whatever the user types into **`stdin`**. This build does **not** call **`GetUserNameA`**; any writeup that keys material only off the Windows account name does **not** apply here.

---

## 4. Username constraints

Enforced only by the read loop in **`FUN_140002bd0`**:

- Length **strictly greater than 2** and **strictly less than `0x10`** → **3–15** characters inclusive.
- For a faithful keygen, restrict to **ASCII** so **`toupper`** / checksums match MSVC expectations (extended characters were not analyzed for locale edge cases).

---

## 5. Secret code — syntactic gate (`FUN_140001ec0`)

**VA:** **`0x140001ec0`**

Conditions (all required):

| Rule | Detail |
|------|--------|
| Length | **`14`** |
| Hyphens | **`secret[4] == '-'`** and **`secret[10] == '-'`** |
| Other positions | Each character must satisfy **`isalnum`** (alphanumeric C locale) |

Layout:

```text
indices:  0 1 2 3   4   5 6 7 8 9   10   11 12 13
          X X X X   -   X X X X X   -    X X X
```

So the template is **`XXXX-XXXXX-XXX`**.

---

## 6. Secret code — semantic validation (`FUN_140002100`)

**VA:** **`0x140002100`**

The function receives **copies** of the username string and secret string. It uppercases the **username copy** in place via **`toupper`** over **`[begin, end)`**, then derives three integers from that uppercase string **`U`**.

### 6.1 Username statistics

Let **`n = len(U)`**, indices **`i ∈ [0, n)`**, **`oᵢ = ord(U[i])`** (ASCII).

| Symbol | Definition |
|--------|------------|
| **`S`** | **`Σᵢ oᵢ · (i + 1)`** |
| **`X`** | **`⨁ᵢ (oᵢ + i)`** — bitwise XOR fold; start **`0`** |
| **`P`** | **`Πᵢ (oᵢ + 3) mod 100000`**, multiplicative accumulator initialized to **`1`** |

### 6.2 Segment targets (32-bit integers)

```text
A = (S XOR 0x5A5A) mod 0xB640
B = (P + X · 0x539) mod 0x39AA400
C = (S + P + X) mod 0xB640
```

### 6.3 Base-36 decoding (`FUN_140001ff0`)

**VA:** **`0x140001ff0`**

Each contiguous segment (without hyphens) is parsed left-to-right:

```text
value = 0
for each character c:
    if '0' <= c <= '9':
        value = value * 36 + (ord(c) - 0x30)
    else:
        value = value * 36 + (ord(c) - 0x37)   # expects A–Z for alphabetic
```

Radix is **`0x24 (36)`**. **`isalnum`** allows lowercase letters too; if the user enters lowercase, parsing uses the same **`0x37`** bias (category **`Letter`** path in the binary). The offline keygen emits **uppercase** segments.

### 6.4 Equality checks

Let **`v₀`, `v₁`, `v₂`** be the parsed values of the three segments (lengths **4**, **5**, **3**). The routine accepts the secret when:

```text
v₀ == A
v₁ == B
v₂ == C
```

### 6.5 Encoding a valid secret for a username

Given **`A`, `B`, `C`**, encode each in base 36 with fixed widths **4 / 5 / 3** (leading **`0`** padding), then insert hyphens:

```text
secret = base36(A, 4) + "-" + base36(B, 5) + "-" + base36(C, 3)
```

---

## 7. Verification PIN — input parsing (`FUN_140001f80`)

**VA:** **`0x140001f80`**

Rough gate:

- String non-empty.
- Every character is a decimal digit (**`isdigit`**).
- Length **strictly less than `0xB` (11)** — so **at most 10** digits (consistent with a 32-bit decimal UI).
- **`strtol(..., base 10)`** succeeds and **`parsed ≤ 0x7FFFFFFF`** (rejects overflow / negative patterns per CRT checks).

The parsed **`unsigned int`** is passed into **`FUN_140002910`**.

---

## 8. Username–secret mixing hash (`FUN_1400025a0`)

**VA:** **`0x1400025a0`**

Called from **`FUN_140002910`** with fresh **`std::string`** copies of username and secret. Internally it:

1. Uppercases the username copy (**`FUN_140003530`** + **`toupper`**).
2. Builds:

```text
blob = UPPER(username) + chr(len(secret) XOR 0x5A) + secret
```

The middle byte is **`push_back(byte(len(secret) XOR 0x5A))`** — for the canonical **14**-character secret, **`len XOR 0x5A == 0x44`** (**`'D'`**).

3. Initializes **`a = 0xA3B1C2D3`**, **`b = 0x1F2E3D4C`**.

For each index **`i`** and byte **`o`** of **`blob`**:

| Step | Operation (32-bit unsigned unless noted) |
|------|------------------------------------------|
| 1 | **`a ^= o + i·0x11`** |
| 2 | **`a = ROL32(a, (i mod 5) + 3)`** |
| 3 | **`a += b XOR 0x9E3779B9`** |
| 4 | **`b ^= a + o·0x83`** |
| 5 | **`b = ROR32(b, (i mod 7) + 2)`** |
| 6 | **`b += (a << 3) XOR 0x7F4A7C15`** |
| 7 | If **`i`** is odd, **swap** **`a`** and **`b`** (**`FUN_1400036d0`**). |

**Primitives:**

- **`FUN_1400020a0`** — **`ROL32`**
- **`FUN_1400020d0`** — **`ROR32`**

### 8.1 Final avalanche (and the signed-`IMUL` trap)

Let **`t = a XOR b XOR ((a XOR b) >> 16)`** (32-bit).

Then (matching **`IMUL`** in **`FUN_1400025a0`** disassembly):

```text
t = imul32_s(t, -0x7A143595)
t = t XOR (t >> 13)
t = imul32_s(t, -0x3D4D51CB)
t = t XOR (t >> 16)
```

Here **`imul32_s`** means: interpret both operands as **signed `int32`**, multiply in **`ℤ`**, keep the **low 32 bits** (two’s complement). This is **not** the same as interpreting operands as **`uint32`** and reducing **`unsigned_product mod 2³²`** in general.

The executable clears the **sign bit** with **`BTR EAX, 31`** before returning — equivalent to **`t & 0x7FFFFFFF`** for the returned **`DWORD`**.

**Returned hash:** **`H = t & 0x7FFFFFFF`**.

---

## 9. PIN check (`FUN_140002910` / `FUN_1400028d0`)

**VA:** **`FUN_140002910 @ 0x140002910`**, **`FUN_1400028d0 @ 0x1400028d0`**

Let **`P`** be the parsed PIN (**`uint32`**, **`≤ 0x7FFFFFFF`**) and **`H`** the hash from **`FUN_1400025a0`**.

Compute:

```text
T(x) = ROL32(x XOR 0xA5A5A5A5, 7) + 0x3C6EF372    (mod 2³²)
```

(`FUN_1400028d0` returns this as a **`DWORD`** bit pattern.)

The binary checks **`T(H) XOR T(P) == 0`** by testing each byte of the XOR result (equivalent to full **32-bit** zero).

Because **`ROL32`**, XOR with **`0xA5A5A5A5`**, and addition modulo **`2³²`** compose injectively on **`ℤ/(2³²ℤ)`** for fixed constants in practice here, **`T(H) == T(P)`** implies **`H == P`**.

So the **verification PIN is exactly the hash output** **`H`**, printed as decimal without leading-zero nonsense beyond what **`strtol`** accepts.

---

## 10. Offline keygen recipe

Given **username** **`u`** satisfying length rules:

1. **`U = toupper(u)`** (ASCII uppercase).
2. Compute **`S`, `X`, `P`** from **`U`** as in §6.1.
3. Compute **`A`, `B`, `C`** as in §6.2.
4. **`secret = encode36(A,4) + "-" + encode36(B,5) + "-" + encode36(C,3)`**.
5. Build **`blob`** as in §8 (same **`toupper`** rule + length XOR **`0x5A`** + **`secret`**).
6. Run the **`a`/`b`** loop and final avalanche (**§8.1**, **`signed IMUL`** for the two constants).
7. **`pin = H`** as returned (**`& 0x7FFFFFFF`**).

---

## 11. Implementation pitfalls

| Pitfall | Effect |
|---------|--------|
| **Unsigned multiply** at the end of **`FUN_1400025a0`** | Wrong PIN; secret can still match. Fix: **signed `int32 × int32`**, low 32 bits. |
| Assuming **`GetUserNameA`** | Wrong username seed; this binary reads **typed** username only. |
| Lowercase vs uppercase segments | Parser accepts **`isalnum`**; values change if letters differ. Prefer emitting **A–Z** to match intended difficulty. |

---

## 12. Proof of concept

**Script:** `content/poc/KeygenMe_3_SWD.py`

```bash
python content/poc/KeygenMe_3_SWD.py <username>
```

It prints **Username**, **Secret code**, and **Verification PIN** for the supplied string.

### Worked examples

| Username | Secret code | Verification PIN |
|----------|-------------|-------------------|
| `Admin` | `0IKG-04FSD-10V` | `1225975944` |
| `Ap0dexMe0` | `0G3R-03RDY-D2R` | `1011050458` |

---

## 13. Function quick reference

| VA | Name | Purpose |
|----|------|---------|
| `0x140002bd0` | Main UI / orchestration | Prompt loops, calls validators |
| `0x140001ec0` | Secret syntax | Length 14, hyphens, `isalnum` |
| `0x140001ff0` | Base-36 parse | Segment → integer |
| `0x140002100` | Secret semantics | Username stats → **`A`,`B`,`C`** compare |
| `0x140001f80` | PIN parse | Decimal digits, **`≤ 0x7FFFFFFF`** |
| `0x1400025a0` | Mixing hash | **`blob → H`** (watch **signed `IMUL`**) |
| `0x1400028d0` | PIN transform | **`T(x)`** for XOR compare |
| `0x140002910` | PIN check | **`T(H) XOR T(P)`** must be zero |

---

## 14. Conclusion

**KeygenMe_3_SWD** ties three inputs together: the **secret** is a deterministic **base-36** triple derived from **uppercase username statistics**; the **PIN** is a **31-bit hash** of **`upper(username) ∥ chr(len(secret) XOR 0x5A) ∥ secret`** with a specific **x86 signed-multiply** finale. Once those pieces are modeled faithfully—especially **`IMUL`**—the challenge reduces to a short Python script and passes the binary’s **`PASS`**/**`FAIL`** gates without patching.

---
