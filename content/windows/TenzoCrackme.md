# TenzoCrackme 


## TL;DR

- **Password:** `wowyoufoundit`
- **Approach:** Pure static analysis — decode stack blobs with the documented XOR/key recurrence, then invert the byte checks / state machine.
- **Anti-debug:** `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` clustered near `main` — informational for static work.

---

## 1. Overview

The binary hides prompts and messages behind a small **stack-built XOR decoder** (see §3). **`main`** performs anti-debug checks, decodes strings, reads a password, and runs a **multi-step verifier** with both real constraints and decoy branches. The unique satisfying password is **`wowyoufoundit`** under the modeled checks.

---

## 2. Initial recon

Basic file properties:

```
PE32+ executable (console) x86-64, for MS Windows, 6 sections
ImageBase: 0x140000000   EntryPoint: 0x00007000
Sections: .text .rdata .data .pdata .fptable .reloc
```

The import table is plain MSVC runtime + a handful of suspicious imports that hint at antidebug:

```
KERNEL32:  IsDebuggerPresent, CheckRemoteDebuggerPresent, GetCurrentProcess, ...
```

`strings` returns essentially nothing useful. The prompts and result messages are not present in plaintext, which means they're decoded at runtime. The crackme description confirms this ("runtime string decoding, multi-round state mixing, a couple of antidebug checks").

Cross-referencing the IAT entries against the disassembly gives the call sites for each antidebug import — three calls to `IsDebuggerPresent` and one to `CheckRemoteDebuggerPresent`, all clustered near `0x140003E91`/`0x140003EB1`. That neighborhood is `main`.

---

## 3. The string decoder

The very first thing `main` does is build a 19-byte blob on the stack from immediates and pass it to `0x140002EB0`:

```asm
mov  dword [rbp-0x59], 0xD6A81167
mov  dword [rbp-0x55], 0xA1BED633
mov  dword [rbp-0x51], 0xFBF287F2
mov  dword [rbp-0x4D], 0x83D13BAD
mov  word  [rbp-0x49], 0x616A
mov  byte  [rbp-0x47], 0x45
lea  rdx, [rbp-0x19]   ; { begin, end } pair
lea  rcx, [rbp-9]      ; output std::string
call 0x140002EB0       ; decoder
```

The decoder loop, condensed:

```asm
; bpl = 0x5A   (key)
; r14d = 0
loop:
    movsx eax, al              ; al was clobbered by the iter-end "mov rax,[rsp+0x90]"
    imul  r14d, eax, 0x0D
    add   r14b, bpl            ; key
    xor   r14b, [r13]          ; xor with src byte
    ; ... store r14b to dst ...
iter_end:
    movzx eax, bpl
    add   al, al
    add   al, 0x11
    add   bpl, al              ; key = 3*key + 0x11   (mod 256)
    inc   r13
    mov   rax, [rsp+0x90]      ; <-- this overwrites al
    inc   rax
    mov   [rsp+0x90], rax      ; loop counter ++
    cmp   r13, rcx
    jne   loop
```

The crucial observation is that `mov rax, [rsp+0x90]` happens **after** the `add bpl, al` that updates the key, and it overwrites `al` with the loop counter. So when the loop jumps back to the top, `al == i` (the iteration index). The `imul r14d, eax, 0xD` therefore mixes in `i*13`, not the previous output. The cipher boils down to:

```
out[i] = ((i * 13) + key_i) ^ src[i]
key_0   = 0x5A
key_{i+1} = (3 * key_i + 0x11) mod 256
```

Plugging the first blob into that produces `== Tenzo Crackme ==` — confirmation that the model is right. Decoding every blob found in `main`:

| Address of blob | Length | Decoded |
|---|---|---|
| `[rbp-0x59]` (1st) | 19 | `== Tenzo Crackme ==` |
| `[rbp-0x19]` (1st) | 16 | `Enter password: ` |
| `[rbp-0x59]` after success | 55 | `Congrats! Access granted. You found the right password.` |
| `[rbp-0x59]` failure | 29 | `Nope. That password is wrong.` |
| `[rbp-0x59]` antidebug branch | 53 | `Debugger detected. Come back without training wheels.` |

The decoder is correct and the entire UI surface is now mapped.

---

## 4. Antidebug

Right after printing the prompt and reading `cin` into a `std::string`, three checks fire:

```asm
call qword [IsDebuggerPresent]
test eax, eax
jne  fail_antidbg

call qword [GetCurrentProcess]
mov  rcx, rax
lea  rdx, [rbp-0x69]
call qword [CheckRemoteDebuggerPresent]
test eax, eax
je   skip_check
cmp  dword [rbp-0x69], ebx
jne  fail_antidbg
skip_check:

mov  rax, qword gs:[0x60]    ; PEB
test rax, rax
je   skip_peb
cmp  byte [rax+2], bl        ; PEB.BeingDebugged
jne  fail_antidbg
```

Three independent debugger checks: the API, the remote-debugger API, and the PEB flag. Solving statically sidesteps all of them since the binary is never executed under a debugger.

---

## 5. The verification flow

After the prompt is printed and the line is read, `main` runs four logical "checks" in sequence. Three of them matter; one is a decoy. From `0x140003FFD` onwards:

```
test r10, r10                 ; r10 = input length
je   skip_decoy_hash
... decoy hash loop ...       ; computes a value; result goes nowhere
and  r9b, 3
cmp  r9b, 1
jne  skip_decoy_hash          ; <-- both branches converge here
```

The "decoy hash" is a moderately complicated mixing routine whose accumulator is checked against `(r9b & 3) == 1`. **Both branches of that comparison fall through to the same length check** (`cmp r10, 0xD`), so the routine has no actual effect on whether a password is accepted — it's pure misdirection for anyone running the binary under a debugger and watching what gets compared to what.

The real checks are:

1. **Length** must be exactly `0xD` (13).
2. **Per-byte XOR/rotate accumulator** must reach 0 (loop at `0x140004106`–`0x1400041B6`).
3. **Full state-mixing function** at `0x140003920` must return true.

### 5.1 Per-byte check

A small hand-rolled state machine dispatches on `eax` ∈ {`0x41`, `0x52`/`0x53`, `0x68`}. Stripping the dispatch noise, each round does:

```
t  = input[i] ^ table1[i]
t  = (t + ((i + 3) * 0x11)) & 0xFF
t  = ror8(t, 5)
t ^= (0xA5 - 7*i) & 0xFF
t ^= table2[i]
r9b |= t
```

After 13 rounds, success requires `r9b == 0`, i.e. **every** intermediate `t` must be 0. The two tables sit in stack immediates:

```
table1 = 21 43 65 87 19 2B 3D 4F 51 62 73 84 95
table2 = E9 1D AC B3 E6 B5 DC 22 93 A0 F8 86 56
```

Each step is invertible:

```
t = 0
⇒ ror8(z, 5) = ((0xA5 - 7*i) & 0xFF) ^ table2[i]            with z = (input[i] ^ table1[i] + (i+3)*0x11) & 0xFF
⇒ z          = rol8(((0xA5 - 7*i) & 0xFF) ^ table2[i], 5)
⇒ input[i]   = ((z - (i+3)*0x11) & 0xFF) ^ table1[i]
```

Plugging through gives a unique 13-byte answer:

```
wowyoufoundit
```

That is enough to commit to a candidate. The next stage independently re-validates it.

### 5.2 The state-mixing check (`0x140003920`)

This is a longer, more elaborate routine. Pseudocode of the full function:

```c
bool verify_full(const std::string& s) {
    if (s.size() != 13) return false;

    uint32_t state1[4] = { 0x13572468, 0x89ABCDEF, 0x10203040, 0x55667788 };

    // ---- Phase 1: 13 rounds, fold each input byte into state1 ----
    for (int i = 0; i < 13; ++i) {
        // mix input[i] into state1[i & 3]
        int r9   = i & 3;
        int cl   = ((i % 5) ? ... : ...)            // computed via div-by-10 idiom
                 = ((i - 5 * (i / 10)) + 3) & 0xFF; // i.e. (i mod 10 mod 5? — read as cl = (i - 5*(i/10) + 3) & 0xFF
        uint32_t e = s[i] ^ state1[r9];
        e += (uint32_t(i) * 0x045D9F3B) ^ 0x9E3779B9;
        state1[r9] = rol32(e, cl);

        // self-mix state1[(i+1) & 3] using state1[i & 3]
        uint32_t c = (uint32_t(i) * 0x1021)
                   + state1[i & 3] + 0x7F4A7C15;
        state1[(i + 1) & 3] ^= c;
    }

    // ---- Phase 2: 24 rounds, state-only cross-mix with state2 ----
    uint32_t state2[4] = { 0xA5C31F27, 0xC3D2E1F0, 0x1BADC0DE, 0x0F1E2D3C };
    uint32_t r11 = 0;
    for (int r10 = 0; r10 < 24; ++r10) {
        int r9   = r10 & 3;
        int idx  = (r9 + 1) & 3;
        uint8_t cl_b = ((r10 & 0xFF) - (((r10 / 7) & 0xFF) * 7)) & 0xFF; // r10 mod 7
        uint32_t e = ((state1[idx] ^ state2[r9]) + r11 + state1[r9]) & 0xFFFFFFFF;
        state1[r9]  = rol32(e, (cl_b + 5) & 0xFF);

        uint8_t cl_a = ((r10 & 0xFF) - 5 * ((r10 / 10) & 0xFF) + 3) & 0xFF; // ~r10 mod 10 ish
        uint32_t f   = (state2[idx] + state1[r9]) & 0xFFFFFFFF;
        state1[idx] ^= ror32(f, cl_a);

        r11 += 0x1F123BB5;
    }

    // ---- Final: hash the input and fold into state1 ----
    uint32_t h = hash_final(s);                    // function at 0x140003670
    state1[0] ^= ror32(h, 0x1D);
    state1[1] += ror32(h, 0x15);
    state1[2] ^= ror32(h, 0x07);
    state1[3] += ror32(h, 0x0D);

    static const uint32_t target[4] =
        { 0x8C6B0B39, 0xA7F1FE86, 0x9F811A0A, 0xC86DA593 };
    return memcmp(state1, target, 16) == 0;
}
```

`hash_final` (the function at `0x140003670`) is itself non-trivial — a per-byte chained mixer with `ror32` and Knuth's golden-ratio constant `0x9E3779B9`:

```c
uint32_t hash_final(const std::string& s) {
    uint32_t r10 = 0xC001D00D;
    for (size_t i = 0; i < s.size(); ++i) {
        uint8_t  cl  = ((i & 0xFF) - 5*((i/10) & 0xFF) + 3) & 0xFF;
        uint32_t e   = ((uint32_t)s[i] * 0x045D9F3B);
        e            = rol32(e, cl) ^ r10;
        uint32_t c   = (uint32_t)i * 0x1021;
        r10          = e;
        e           += 0x9E3779B9;
        r10          = ror32(r10, 7);
        r10         ^= (e + c);
    }
    return r10;
}
```

This stage is **not** trivially invertible — Phase 2 alone runs 24 rounds of state mixing with no input dependency, but Phase 1 and the final-hash step entangle every input byte with all four state words. There's no clean per-byte algebra here.

The right play is to treat this as a **secondary verifier** rather than a solver target: the per-byte check in §5.1 already pins the password to a unique 13-byte string, so the only thing left to do is run the state-mix simulation on that candidate and confirm it lands on the target.

Running the simulation in Python with the candidate `b"wowyoufoundit"` yields:

```
state1 after final mix = [0x8C6B0B39, 0xA7F1FE86, 0x9F811A0A, 0xC86DA593]
target                 = [0x8C6B0B39, 0xA7F1FE86, 0x9F811A0A, 0xC86DA593]
```

All four 32-bit words match. Hitting all 128 bits by accident has probability `2^-128`, so this is independent confirmation that:

- the per-byte inversion is correct,
- the simulated full-state routine is faithful to the binary,
- and the password is indeed `wowyoufoundit`.

---

## 6. Why the design works as a crackme

Looking at it as a whole, the binary uses three layered tactics:

- **Cosmetic friction** — runtime string decoding hides every prompt and message, so static `strings` shows nothing useful. A dynamic analyst sees the messages but learns nothing about the verifier.
- **Decoy work** — the first hash loop is structurally identical to the real per-byte check, but its result is silently discarded. An attacker tracing the data flow can spend real time reversing it before realising both branches converge unconditionally.
- **Layered checks** — the meaningful constraints (per-byte tables and full state mixing) are intentionally split: the first is invertible byte-by-byte, the second is not. Anyone who only finds the second one is forced into either Z3 or guessing the algorithm; anyone who only finds the first one might miss the dispatch state machine entirely.

What ultimately breaks the design is the per-byte check being algebraically clean: each byte appears in exactly one constraint, with all operations (XOR, mod-256 add, 8-bit rotate) trivially invertible. Once that's spotted, the candidate falls out and the heavier mixer becomes a verifier rather than an obstacle.

---

## 7. Final answer

```
wowyoufoundit
```

The companion script `solve_tenzo.py` reproduces the entire derivation: it decodes every embedded string, recovers the 13-byte password by inverting the per-byte check, then independently re-simulates all three verification stages against the candidate and reports pass/fail for each.

```
$ python3 solve_tenzo.py
=== TenzoCrackme.exe — Solver ===

Decoded strings (sanity check on the cipher model):
  title      b'== Tenzo Crackme =='
  prompt     b'Enter password: '
  success    b'Congrats! Access granted. You found the right password.'
  failure    b'Nope. That password is wrong.'
  antidebug  b'Debugger detected. Come back without training wheels.'

Recovered password : 'wowyoufoundit'
Length             : 13

Re-running every check against the candidate:
  [1] length == 13               -> True
  [2] per-byte accumulator == 0  -> True
  [3] full state == target       -> True

SUCCESS — password is: wowyoufoundit
```

---

