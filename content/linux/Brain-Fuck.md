# Brain-Fuck 

## TL;DR

- **Flag (password):** `bruh wtf`
- **Success output:** `you made it hero`
- **Core idea:** 30k-cell tape + data pointer; password read as 8 characters; real logic buried in obfuscation.

---

## 1. Overview

The program reads **eight** characters from stdin and prints nothing on failure; on success it emits **`you made it hero`**. There are almost no useful plaintext strings — behavior must be recovered from the interpreter-shaped control flow and tape layout in `main`.

---

## 2. Initial reconnaissance

### File Analysis

```
$ file a.out
a.out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cc1d1a8521e9876d6a7cf0c94f75c5c7afe53fe6,
for GNU/Linux 3.2.0, with debug_info, not stripped
```

The binary is not stripped and includes debug information, but the `main` function is an enormous 160KB+ block of code — a clear sign of heavy obfuscation or code generation.

### Strings & Imports

Running `strings` reveals very little: standard library names (`putchar`, `usleep`, `getchar`, `getpid`, `memset`, `write`, `__stack_chk_fail`) and GCC build metadata. No obvious password strings, no format strings, no helpful hints.

The imported functions tell a story though:
- `memset` — initializing a buffer
- `getchar` — reading input character by character
- `putchar` — outputting characters
- `usleep` — timing delays (suspicious)
- `getpid` — getting process ID (suspicious in a password checker)
- `write` — writing to file descriptors

### Running the Binary

When run with arbitrary input, the program silently exits with code 0 and no output — regardless of what you type. It reads exactly 8 characters from stdin and produces no visible output for incorrect passwords.

---

## 3. Deep reverse engineering

### Step 1: Disassembly Overview

Using `objdump -d`, the main function spans from address `0x1199` to `0x282d6` — over 32,000 instructions. The sheer size immediately suggests either generated code or extreme obfuscation.

### Step 2: Identifying the Core Data Model

The first few instructions of `main` reveal the data model:

```asm
; Allocate 0x9310 bytes of stack space
sub    $0x9310,%rsp

; Initialize buffer with memset
lea    -0x7540(%rbp),%rax    ; buffer at rbp-0x7540
mov    $0x7530,%edx          ; size = 30000 bytes
mov    $0x0,%esi             ; fill = 0
call   memset@plt

; Initialize pointer
lea    -0x7540(%rbp),%rax
mov    %rax,-0x88b0(%rbp)    ; ptr = buffer start

; Initialize aux variable
movq   $0x0,-0x88a8(%rbp)    ; aux = 0
```

**Key variables identified:**
| Stack Offset | Purpose | Analogy |
|-------------|---------|---------|
| `-0x7540(%rbp)` | Buffer (30000 bytes) | Brainfuck tape |
| `-0x88b0(%rbp)` | Pointer into buffer | Brainfuck data pointer |
| `-0x88a8(%rbp)` | Auxiliary variable | Junk/obfuscation |

This is the classic Brainfuck interpreter data model: a 30,000-byte tape with a movable pointer.

### Step 3: Recognizing Obfuscation Patterns

The 32,000+ instructions are not all meaningful. Several obfuscation patterns repeat throughout the code:

#### Pattern 1: `usleep(0)` — Timing Noise
```asm
mov    $0x0,%edi
call   usleep@plt
```
Calls `usleep(0)` hundreds of times. Zero-duration sleeps still incur syscall overhead but produce no visible delay. Pure noise.

#### Pattern 2: `getpid()` + Sign Check — Dead Code
```asm
call   getpid@plt
test   %eax,%eax
jns    <continue>           ; always taken (getpid returns positive PID)
mov    $0x1,%eax
jmp    0x282c1              ; exit(1) — never reached
```
`getpid()` always returns a positive integer on any normal system, so `jns` (jump if not negative) is always taken. The `exit(1)` branch is dead code designed to confuse static analysis.

#### Pattern 3: XOR with `0xDEADBEEF` — Junk Computation
```asm
mov    -0x88b0(%rbp),%rax
mov    $0xdeadbeef,%edx
xor    %rdx,%rax
mov    %rax,-0x88a8(%rbp)    ; aux = ptr ^ 0xDEADBEEF
```
The result is written to the `aux` variable which is never used for any meaningful computation. The XOR is pure obfuscation.

#### Pattern 4: `write(2, buf, 0)` — No-op Syscall
```asm
mov    $0x0,%edx              ; count = 0
lea    0x27da2(%rip),%rax     ; buffer address
mov    %rax,%rsi
mov    $0x2,%edi              ; fd = 2 (stderr)
call   write@plt              ; write(2, buf, 0) — writes nothing
```
Writing zero bytes is a complete no-op. Inserted to add more function calls and confuse analysis.

#### Pattern 5: Dummy Loops — Control Flow Noise
```asm
movl   $0x0,-0x930c(%rbp)    ; counter = 0
jmp    CHECK
BODY:
mov    -0x930c(%rbp),%eax
cltq
add    %rax,-0x88a8(%rbp)    ; aux += counter (always adds 0)
addl   $0x1,-0x930c(%rbp)    ; counter++
CHECK:
cmpl   $0x0,-0x930c(%rbp)
jle    BODY                   ; runs once: 0 <= 0, then 1 > 0 exits
```
This loop executes exactly once, adding 0 to `aux`. It exists solely to add loop-like control flow that complicates CFG recovery.

#### Pattern 6: Pointer Shuffling — Redundant Moves
```asm
mov    -0x88b0(%rbp),%rax    ; rax = ptr
mov    %rax,-0x8890(%rbp)    ; temp1 = ptr
mov    -0x8890(%rbp),%rax    ; rax = temp1
mov    %rax,-0x88b0(%rbp)    ; ptr = rax (no-op)
```
Copies the pointer through temporary stack variables and back again. No net effect.

#### Pattern 7: Null Pointer Wrap-Around
```asm
cmpq   $0x0,-0x88b0(%rbp)
jne    skip
lea    -0x7540(%rbp),%rax
mov    %rax,-0x88b0(%rbp)    ; if ptr == NULL, reset to buffer start
```
Safety check that resets the pointer to the buffer start if it becomes NULL. In normal execution, this never triggers.

### Step 4: Extracting Brainfuck Operations

After stripping away all obfuscation, the core operations map directly to Brainfuck instructions:

| x86-64 Pattern | Brainfuck | Description |
|---------------|-----------|-------------|
| `movzbl (%rax),%eax; lea 0x1(%rax),%edx; mov %dl,(%rax)` | `+` | Increment cell |
| `movzbl (%rax),%eax; lea -0x1(%rax),%edx; mov %dl,(%rax)` | `-` | Decrement cell |
| `addq $0x1,-0x88b0(%rbp)` | `>` | Move pointer right |
| `subq $0x1,-0x88b0(%rbp)` | `<` | Move pointer left |
| `call getchar@plt; mov %dl,(%rax)` | `,` | Read character |
| `movzbl (%rax),%eax; movzbl %al,%eax; mov %eax,%edi; call putchar@plt` | `.` | Output character |
| `test %al,%al; jne <backward>` | `]` | Loop end |

The extracted BF operation counts:
| Operation | Count |
|-----------|-------|
| `+` (increment) | 1504 |
| `-` (decrement) | 835 |
| `>` (move right) | 11 |
| `<` (move left) | 11 |
| `,` (input) | 8 |
| `.` (output) | 16 |
| `]` (loop end) | 42 |

### Step 5: Understanding the Loop Structure

The 42 loop ends form a consistent pattern. For each of the 8 input characters, there are 3 nested loops:

```
Loop type 1: [-]         — Zero out the current cell
Loop type 2: [-]         — Zero out the adjacent cell
Loop type 3: [--<>]      — Outer check loop (contains loops 1 & 2)
```

The outer loop (type 3) implements the password check logic:
- If `cell[1] == 0` after subtracting from the input character: the character matches, loop doesn't execute, `cell[0]` (flag) stays at 1
- If `cell[1] != 0`: the loop executes, zeroing both `cell[0]` (flag) and `cell[1]`, marking a mismatch

After all 8 characters are processed, if `cell[0]` is still 1, the program outputs the success message. If any character didn't match, `cell[0]` was zeroed and the program exits silently.

The final loop (loop 42) at the very end of main handles the output section, iterating through the success message characters.

### Step 6: Extracting the Password

The critical insight is: **for each input position, the correct character is the one where the total decrements equal the character's ASCII value**. When `input_char - total_decrements == 0`, the loop check finds the cell already zero and skips the loop body, preserving the match flag.

The key is counting only decrements that occur **outside loop bodies**, because:
- Loops only execute on mismatch
- On a correct password, loops are never entered
- The decrements inside `[-]` loops are irrelevant for the correct case

Counting decrements between each `getchar` call (excluding loop body addresses):

| Input # | Decrements | ASCII | Character |
|---------|-----------|-------|-----------|
| 1 | 98 | 98 | `b` |
| 2 | 114 | 114 | `r` |
| 3 | 117 | 117 | `u` |
| 4 | 104 | 104 | `h` |
| 5 | 32 | 32 | ` ` (space) |
| 6 | 119 | 119 | `w` |
| 7 | 116 | 116 | `t` |
| 8 | 102 | 102 | `f` |

**Password: `bruh wtf`**

### Step 7: Verification

```
$ echo -n "bruh wtf" | ./a.out
you made it hero
```

The program outputs `you made it hero` confirming the password is correct.

---
