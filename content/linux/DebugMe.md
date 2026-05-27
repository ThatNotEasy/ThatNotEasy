# DebugMe 

## TL;DR

- **Goal:** Pass three stages and print `Well done :)`.
- **Technique:** `LD_PRELOAD` library returns different fake `/proc/self/status` content on successive `fopen` calls so **TracerPid** matches what each stage expects; **`argv[1]` = `1`** satisfies the final check.

---

## 1. Overview

The binary uses intentional **division-by-zero** to trigger a **SIGFPE** handler. The handler re-checks tracer state and validates **`argv[1]`**. Stage 1 requires **`TracerPid: 0`** (fault path); stage 2 avoids a second fatal fault when **`TracerPid ≠ 0`**; stage 3 compares against the spoofed PID value. A small **`LD_PRELOAD`** shim feeds consistent fake procfs content across calls.

---

## 2. Initial reconnaissance

```
$ file DebugMe
ELF 64-bit LSB pie executable, x86-64, stripped, dynamically linked
```

Key strings extracted from `.rodata`:

| Address   | String                          |
|-----------|---------------------------------|
| `0x2006`  | `/proc/self/status`             |
| `0x2018`  | `TracerPid:`                    |
| `0x2023`  | `Pass`                          |
| `0x2070`  | `DebugMe stage 1: `             |
| `0x2028`  | `DebugMe stage 2: `             |
| `0x2042`  | `DebugMe stage 3: `             |
| `0x205c`  | `Well done :)`                  |
| `0x2069`  | `Fail`                          |

Imported symbols of note: `signal`, `fopen`, `fgets`, `strncmp`, `atoi`, `printf`, `puts`, `fflush`, `fclose`, `exit`, `__stack_chk_fail`.

The presence of `/proc/self/status` + `TracerPid:` + `signal` immediately flags classic anti-debugging techniques combined with arithmetic fault handling.

---

## 3. Disassembly — full control-flow analysis

The `.text` section is small (0x2D9 bytes) and contains three logical blocks: `main` (entry at `0x10e0`), a SIGFPE handler (at `0x1319`), and a `check_tracer_pid` helper (at `0x1259`). There is no custom code in `.init_array` or `.fini_array` — only standard CRT registration/deregistration stubs.

### 3.1 `main` — Entry Point (`0x10e0`)

```asm
10e0: push   rbp
10e1: mov    ebp, edi              ; argc
10e3: mov    edi, 0x8              ; SIGFPE = 8
10e8: push   rbx
10e9: mov    rbx, rsi              ; argv
10ec: lea    rsi, [rip+0x226]      ; -> 0x1319 (handler address)
10f4: call   signal                ; signal(SIGFPE, handler)
10f9: lea    rdi, [rip+0xf6e]      ; "DebugMe stage 1: "
1102: call   printf
1107: mov    rdi, [stdout]
110e: call   fflush                ; flush stage 1 prompt
1113: mov    eax, 0xffffffff        ; default = -1
1118: cmp    ebp, 0x2              ; argc == 2 ?
111b: jne    1126
111d: mov    rdi, [rbx+0x8]        ; argv[1]
1121: call   atoi                  ; eax = atoi(argv[1])
1126: mov    [rip+0x2f48], eax     ; global_var @ 0x4074 = eax
112c: call   1314                  ; -> check_tracer_pid()
1131: mov    ecx, eax              ; ecx = TracerPid value
1133: mov    eax, 0x43             ; eax = 67
1138: cdq                          ; sign-extend -> edx:eax = 0:67
1139: idiv   ecx                   ; eax = 67 / TracerPid
113b: cmp    eax, 0x43             ; quotient == 67 ?
113e: je     114c                  ; if yes, skip "Fail"
1140: lea    rdi, "Fail"
1147: call   puts                  ; print "Fail"
114c: xor    eax, eax
1151: ret                          ; return 0
```

**Logic:**

1. Register `SIGFPE` handler at `0x1319`.
2. Print the "stage 1" prompt and flush `stdout`.
3. Parse `argv[1]` via `atoi()` and store as a global at `0x4074`. If no argument is given, the global defaults to `-1`.
4. Call `check_tracer_pid()` which reads `/proc/self/status` and returns the integer value of `TracerPid`.
5. Compute `67 / TracerPid` (signed integer division).

| TracerPid | `67 / TracerPid` | `== 67`? | Outcome             |
|-----------|-------------------|----------|---------------------|
| 0         | Division by zero  | SIGFPE   | Handler invoked     |
| 1         | 67                | Yes      | Returns silently    |
| 2..66     | 0..33             | No       | Prints "Fail"       |
| 67        | 1                 | No       | Prints "Fail"       |
| > 67      | 0                 | No       | Prints "Fail"       |

**Key observation:** The only way to reach the SIGFPE handler (which prints "Pass" and advances to stages 2 & 3) is for `TracerPid` to be **0**. A value of 1 passes the arithmetic check in `main` but skips the handler entirely — no "Well done" message is ever printed.

### 3.2 SIGFPE Handler (`0x1319`)

```asm
; --- Entered on SIGFPE (stage 1 trigger) ---
1319: push   rbx
131a: xor    esi, esi              ; SIG_DFL = 0
131c: mov    edi, 0x8              ; SIGFPE
1321: call   signal                ; signal(SIGFPE, SIG_DFL) — reset!
1326: lea    rdi, "Pass"
132d: call   puts                  ; **"Pass"** (stage 1 cleared)
1332: lea    rdi, "DebugMe stage 2: "
133b: call   printf
1347: call   fflush                ; flush stage 2 prompt

; --- Stage 2 check ---
134c: call   1314                  ; first = check_tracer_pid()
1351: mov    ebx, eax              ; ebx = first
1353: call   1314                  ; second = check_tracer_pid()
1358: mov    ecx, eax              ; ecx = second
135a: mov    eax, ebx              ; eax = first
135c: cdq
135d: idiv   ecx                   ; eax = first / second
135f: test   eax, eax              ; result == 0 ?
1361: jne    136a                  ; if NON-ZERO -> stage 2 passes
1363: xor    edi, edi
1365: call   exit                  ; exit(0) — silent failure

; --- Stage 2 passed ---
136a: lea    rdi, "Pass"
1371: call   puts                  ; **"Pass"** (stage 2 cleared)
1376: lea    rdi, "DebugMe stage 3: "
137f: call   printf
138b: call   fflush                ; flush stage 3 prompt

; --- Stage 3 check ---
1390: cmp    DWORD [rip+0x2cde], ebx   ; global_var == first ?
1396: lea    rdi, "Fail"
139d: jne    13b2                        ; if NOT equal -> print "Fail"
139f: lea    rdi, "Pass"
13a6: call   puts                  ; **"Pass"** (stage 3 cleared)
13ab: lea    rdi, "Well done :)"
13b2: call   puts                  ; "Well done :)" or "Fail"
13b7: jmp    1363                  ; exit(0)
```

**Logic:**

1. **Immediately resets** `SIGFPE` to `SIG_DFL`. Any subsequent division-by-zero will **kill the process** (no second chance).
2. Prints "Pass" for stage 1.
3. Prints "DebugMe stage 2: " prompt.
4. Calls `check_tracer_pid()` **twice**. Let the two results be `first` and `second`.
5. Computes `first / second` (integer division). If the result is **non-zero**, stage 2 passes. If zero, the program exits silently.
6. Prints "Pass" for stage 2.
7. Prints "DebugMe stage 3: " prompt.
8. Compares the global variable (parsed from `argv[1]`) against `first` (the first TracerPid read inside the handler). If they match, prints "Pass" for stage 3 and then "Well done :)". Otherwise prints "Fail".

**The impossible constraint:** When running without a debugger, `TracerPid` is always `0`. In the handler, `first == 0` and `second == 0`, so `0 / 0` triggers a second SIGFPE — but the handler was already reset to `SIG_DFL`, so the process **crashes** with a core dump. Conversely, if `TracerPid` were non-zero from the start, the SIGFPE handler would never be invoked at all.

| State | Stage 1 | Stage 2 | Stage 3 |
|-------|---------|---------|---------|
| TracerPid = 0 throughout | SIGFPE → handler → 0/0 crash | Crash | Crash |
| TracerPid = 1 throughout | 67/1=67, no SIGFPE, silent return | Never reached | Never reached |
| TracerPid = 0, then N≠0 | SIGFPE → handler → N/N=1 ✓ | Passes | Requires argv[1]=N |

The solution demands that `TracerPid` be **0 for the first read** (in `main`) and **a consistent non-zero value for the next two reads** (in the handler). This is inherently contradictory for a normal process, since `/proc/self/status` is a kernel-generated virtual file.

### 3.3 `check_tracer_pid` Helper (`0x1259`)

```asm
1259: push   rbp
125a: lea    rdi, "/proc/self/status"
1262: sub    rsp, 0x128
1269: mov    rsi, fs:0x28           ; stack canary
1272: mov    [rsp+0x118], rsi
127a: lea    rsi, "r"
1281: call   fopen                  ; fopen("/proc/self/status", "r")
1286: test   rax, rax
1289: je     12eb                   ; if NULL -> return 1
128b: mov    rbp, rax               ; rbp = FILE*
129c: ...                           ; memset(buffer, 0, 265)
12a9: call   fgets                  ; read line
12b3: mov    edx, 0xa               ; 10
12b8: lea    rsi, "TracerPid:"
12c4: call   strncmp                ; line starts with "TracerPid:" ?
12c9: test   eax, eax
12cb: jne    129c                   ; if not, read next line
12cd: lea    rdi, [rsp+0x19]        ; buffer + 10 (past "TracerPid:")
12d2: call   atoi                   ; parse the PID value
12da: mov    ebx, eax
12dc: call   fclose
12eb: mov    ebx, 0x1               ; default return = 1 (file open failed)
1308: mov    eax, ebx
1313: ret
```

The function opens `/proc/self/status`, iterates over lines with `fgets`, matches the line beginning with `TracerPid:`, extracts the integer after it via `atoi`, and returns it. If `fopen` fails (returns `NULL`), it returns `1`.

---

## 4. Solution design

Since the binary calls `fopen` from `libc.so.6` through the PLT, we can intercept it with `LD_PRELOAD`. Our replacement `fopen` behaves as follows:

| Call # | Returned content | Effect on binary |
|--------|-----------------|------------------|
| 1st    | `TracerPid:\t0\n` | `check_tracer_pid()` returns 0 → `67/0` → SIGFPE → handler |
| 2nd+   | `TracerPid:\t1\n` | `check_tracer_pid()` returns 1 → `1/1=1≠0` → stage 2 passes |

For stage 3, `argv[1]` must equal the first handler-read TracerPid value. Since we chose `1`, the argument is `1`.

### Execution trace with the solution

```
$ LD_PRELOAD=./override_fopen.so ./DebugMe 1
```

1. `main`: `signal(SIGFPE, handler)` registers the fault handler.
2. `main`: `printf("DebugMe stage 1: ")`, `fflush(stdout)`.
3. `main`: `global_var = atoi("1") = 1`.
4. `main`: `check_tracer_pid()` → our `fopen` returns `TracerPid:\t0\n` → returns `0`.
5. `main`: `idiv` with divisor `0` → **SIGFPE raised**.
6. **Handler entered**: `signal(SIGFPE, SIG_DFL)` resets the handler (fatal on next fault).
7. Handler: `puts("Pass")` → **Stage 1 passed**.
8. Handler: `printf("DebugMe stage 2: ")`, `fflush(stdout)`.
9. Handler: `check_tracer_pid()` → our `fopen` returns `TracerPid:\t1\n` → `first = 1`.
10. Handler: `check_tracer_pid()` → our `fopen` returns `TracerPid:\t1\n` → `second = 1`.
11. Handler: `1 / 1 = 1 ≠ 0` → **Stage 2 passed**.
12. Handler: `puts("Pass")`, `printf("DebugMe stage 3: ")`, `fflush(stdout)`.
13. Handler: `cmp global_var, first` → `cmp 1, 1` → equal → **Stage 3 passed**.
14. Handler: `puts("Pass")`, `puts("Well done :)")`.
15. `exit(0)`.

**Output:**
```
DebugMe stage 1: Pass
Pass
DebugMe stage 2: Pass
DebugMe stage 3: Pass
Well done :)
```

---

## 5. Why other approaches fail

### Running under GDB / strace
If a debugger is attached, `TracerPid` is the debugger's PID (a large number like 123456). Then `67 / 123456 = 0 ≠ 67` → prints "Fail" immediately. The handler is never reached.

### PID namespace (TracerPid = 1)
Even if we could arrange `TracerPid = 1` (e.g., by tracing from PID 1 in a new namespace), then `67 / 1 = 67` which passes the arithmetic check in `main` **without** raising SIGFPE. The handler is never invoked, so stages 2 and 3 are never reached.

### No intervention (plain execution)
Without a debugger and without LD_PRELOAD, `TracerPid = 0`. The SIGFPE handler fires for stage 1, but then `0 / 0` crashes the process because the handler has been reset to `SIG_DFL`.

---

## 6. Exploit code

### 6.1 LD_PRELOAD Shared Library — `override_fopen.c`

This is the core of the exploit. It overrides `fopen()` from libc so that every time the binary opens `/proc/self/status`, we hand it a fake in-memory file instead. The first call returns `TracerPid: 0` (triggering the division-by-zero in `main`), and all subsequent calls return `TracerPid: 1` (allowing the handler's `1/1` division to succeed). We use `dlsym(RTLD_NEXT, "fopen")` to chain to the real `fopen` for any other file the program (or the C runtime) might open.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

static FILE *(*real_fopen)(const char *, const char *) = NULL;
static int call_count = 0;

FILE *fopen(const char *path, const char *mode) {
    if (real_fopen == NULL) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (strcmp(path, "/proc/self/status") == 0) {
        call_count++;
        if (call_count == 1) {
            /*
             * First call (from main): return TracerPid 0
             * This causes 67/0 = division by zero -> SIGFPE -> handler
             */
            return fmemopen("TracerPid:\t0\n", 14, "r");
        } else {
            /*
             * Subsequent calls (from handler): return TracerPid 1
             * In handler: first/second = 1/1 = 1 != 0 -> stage 2 passes
             * And global_var (argv[1]) == 1 -> stage 3 passes
             */
            return fmemopen("TracerPid:\t1\n", 14, "r");
        }
    }

    return real_fopen(path, mode);
}
```

**Compile:**
```bash
gcc -shared -fPIC -o override_fopen.so override_fopen.c -ldl
```

### 6.2 Python PoC — `poc.py`

This script automates the entire attack: it writes the C source to a temporary directory, compiles the shared library, runs `DebugMe` with `LD_PRELOAD` set, and verifies that `Well done :)` appears in the output. It cleans up temporary files afterward.

```python
#!/usr/bin/env python3
"""
DebugMe — PoC Exploit Script
=============================
Compiles an LD_PRELOAD shared library that overrides fopen() to return
different TracerPid values on successive calls, then runs the DebugMe
binary with the correct argv[1] to pass all three stages.

Usage:
    python3 poc.py [--binary path/to/DebugMe]

Solution:
    - Stage 1 needs TracerPid=0 (division by zero -> SIGFPE -> handler)
    - Stage 2 needs TracerPid!=0 (non-zero/non-zero division != 0)
    - Stage 3 needs atoi(argv[1]) == TracerPid from handler's first read

We override fopen() so that:
    Call 1  -> returns "TracerPid:\t0\n"  (triggers SIGFPE in main)
    Call 2+ -> returns "TracerPid:\t1\n"  (passes stages 2 & 3)

argv[1] = "1" matches the spoofed TracerPid in stage 3.
"""

import os
import sys
import subprocess
import tempfile
import argparse

# ---------------------------------------------------------------------------
# C source for the LD_PRELOAD shared library
# ---------------------------------------------------------------------------
PRELOAD_C_SOURCE = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

static FILE *(*real_fopen)(const char *, const char *) = NULL;
static int call_count = 0;

FILE *fopen(const char *path, const char *mode) {
    if (real_fopen == NULL) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (strcmp(path, "/proc/self/status") == 0) {
        call_count++;
        if (call_count == 1) {
            /* First call (from main): TracerPid 0 -> 67/0 -> SIGFPE */
            return fmemopen("TracerPid:\t0\n", 14, "r");
        } else {
            /* Subsequent calls (from handler): TracerPid 1 -> 1/1=1 != 0 */
            return fmemopen("TracerPid:\t1\n", 14, "r");
        }
    }

    return real_fopen(path, mode);
}
"""

# Spoofed TracerPid for stages 2 & 3 (must match argv[1])
SPOOFED_TRACERPID = 1


def compile_preload(output_dir: str) -> str:
    """Compile the LD_PRELOAD shared library and return its path."""
    src_path = os.path.join(output_dir, "override_fopen.c")
    so_path = os.path.join(output_dir, "override_fopen.so")

    with open(src_path, "w") as f:
        f.write(PRELOAD_C_SOURCE)

    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", so_path, src_path, "-ldl"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[!] Compilation failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Compiled preload library: {so_path}")
    return so_path


def run_exploit(binary_path: str, preload_path: str, argv1: str) -> None:
    """Run DebugMe with LD_PRELOAD set and capture output."""
    env = os.environ.copy()
    env["LD_PRELOAD"] = preload_path

    print(f"[+] Running: {binary_path} {argv1}")
    print(f"[+] LD_PRELOAD={preload_path}")
    print("---")

    result = subprocess.run(
        [binary_path, argv1],
        env=env,
        capture_output=True,
        text=True,
    )

    # Print combined stdout (binary outputs everything to stdout)
    output = result.stdout
    if output:
        print(output, end="")

    if result.stderr:
        print(f"[!] stderr: {result.stderr}", file=sys.stderr)

    print("---")

    if "Well done :)" in output:
        print("[+] SUCCESS: All stages passed — 'Well done :)' received!")
    else:
        print("[!] FAILED: 'Well done :)' not found in output.", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="DebugMe PoC — bypasses three anti-debug stages via LD_PRELOAD"
    )
    parser.add_argument(
        "--binary",
        default=os.path.join(os.path.dirname(__file__), "DebugMe"),
        help="Path to the DebugMe binary (default: ./DebugMe)",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temporary compilation directory",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        print(f"[!] Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    # Use a temporary directory for compilation artifacts
    tmpdir = tempfile.mkdtemp(prefix="debugme_poc_")
    print(f"[+] Working directory: {tmpdir}")

    try:
        so_path = compile_preload(tmpdir)
        run_exploit(binary_path, so_path, str(SPOOFED_TRACERPID))
    finally:
        if not args.keep_temp:
            os.remove(os.path.join(tmpdir, "override_fopen.c"))
            os.remove(so_path)
            os.rmdir(tmpdir)
            print(f"[+] Cleaned up temporary files")


if __name__ == "__main__":
    main()
```

---

