#!/usr/bin/env python3
"""
CFB3 VM reverse engineering + password solver.

VM architecture (from disassembly @ 0x140003780):
  - IP (rbx): program counter, advances by 3 per instruction
  - reg[0..3] (rbp-0x50 to rbp-0x4d): 4 one-byte registers
  - char_index (rbp-0x48): index into password string
  - flag (rbp-0x4c): comparison result flag
  - password_len (rbp-0x28): length of input password

Instructions (3 bytes each: opcode, dst/arg1, arg2):
  opcode = bytecode[IP] - 1  (decremented before dispatch)
  dst    = bytecode[IP+1]    (register index, 0-3)
  imm    = bytecode[IP+2]    (immediate byte)

Dispatch table (eax = opcode-1):
  0x00 (op=0x01): LOAD_CHAR  reg[dst] = password[char_index++]  (or 0 if OOB)
  0x01 (op=0x02): LOAD_IMM   reg[dst] = imm
  0x02 (op=0x03): ADD        reg[dst] = reg[dst] + reg[imm]
  0x03 (op=0x04): (not seen)
  0x04 (op=0x05): XOR_IMM    reg[dst] ^= imm
  0x05 (op=0x06): CMP_IMM    flag = (reg[dst] == imm)
  0x06 (op=0x07): JMP_FALSE  if not flag: IP = imm*3  (relative from start)
  0x07 (op=0x08): HALT_OK    success
  0x08 (op=0x09): HALT_FAIL  failure

Wait - let me re-read the disassembly more carefully:

From 0x14000379e:
  edx = bytecode[IP+1]  (operand a)
  r8d = bytecode[IP+2]  (operand b)
  eax = opcode - 1
  jmp via jump table [r9 + eax*4 + 0x3964]

Case 0 (op=1) @ 0x1400037bf: LOAD_CHAR
  if dst < 4 and char_index < password_len:
      reg[dst] = password[char_index]
  else:
      reg[dst] = 0
  char_index++
  IP += 3

Case 1 (op=2) @ 0x14000381f: LOAD_IMM (immediate store)
  if dst < 4: reg[dst] = imm (r8b)
  IP += 3

Case 2 (op=3) @ 0x14000382b: ADD_REG
  if dst < 4 and imm < 4: reg[dst] += reg[imm]
  IP += 3

Case 3 (op=4): (not in bytecode)

Case 4 (op=5) @ 0x140003865: XOR_IMM
  if dst < 4: reg[dst] ^= imm
  IP += 3

Case 5 (op=6) @ 0x140003874: CMP_EQ
  if dst < 4: flag = (reg[dst] == imm)
  IP += 3  (no char_index advance in CMP)

Case 6 (op=7) @ 0x140003887: JMP_IF_FLAG
  Actually: if flag == 0: IP = imm*3 (jump to instruction imm)
            else: IP += 3 (continue)
  Wait - re-read: cmp [flag], 0 / jne -> continue
                  if flag is 0: lea rbx, [r8 + r8*2]  then jmp to +3
  So: if NOT flag: IP = imm * 3

Case 7 (op=8) @ 0x1400037bf ... let me check HALT_OK/FAIL

Actually from the disasm:
  0x14000387e: sete [flag]  <- that's CMP_EQ setting flag
  0x140003887: cmp [flag],0 / jne -> continue (flag=1, step OK)
               if flag=0: IP = imm*3 (the jump_fail)

Let me re-read more carefully using the actual disassembly output:

0x1400037bf  cmp dl, 4   ; if dst >= 4: invalid
0x1400037c2  jae 0x1400037fb  (error branch)
0x1400037c4  mov r8, [char_index]
0x1400037c8  cmp r8, [password_len]
0x1400037cc  jae 0x140003818   (OOB: store 0)
0x1400037ce  lea rax, [rbp-0x38]  ; SSO string ptr
0x1400037d2  cmp [cap], 0xf
0x1400037d7  cmova rax, [heap_ptr]
0x1400037dc  movzx eax, byte [rax + r8]  ; eax = password[char_index]
0x1400037e1  mov [rbp + rdx - 0x50], al  ; reg[dst] = char
0x1400037e5  inc [char_index]
0x1400037e9  mov rbx, [IP_save]
0x1400037ed  add rbx, 3              ; IP += 3
0x1400037f1  mov [IP_save], rbx
0x1400037f5  cmp [flag_active], 0
0x1400037f9  jne 0x140003780  ; continue loop

Hmm - 0x1400037f5: cmp byte [rbp-0x40], 0 / jne -> back to loop
That [rbp-0x40] is checked each iteration - probably the HALT flag.

0x14000381f  (case 1, op=2): LOAD_IMM
  if dst < 4: reg[dst] = r8b
  then fallthrough to IP+=3

0x14000382b  (case 2, op=3): ADD_REG
  if dst < 4 and r8b < 4:
      reg[dst] += reg[r8b]
  IP+=3

0x140003848 .. wait that's skipped in our bytecode

0x140003865  (case 4, op=5): XOR_IMM
  if dst < 4:
      reg[dst] ^= r8b
  IP+=3

0x140003874  (case 5, op=6): CMP_EQ
  if dst < 4:
      flag = (reg[dst] == r8b)   ; sete
  IP+=3 (goes to 0x1400037ed)

0x140003887  (case 6, op=7): COND_JUMP
  if flag == 0:
      IP = r8b * 3   (jump to instruction r8b)
  else:
      IP += 3

0x140003891:  lea rbx, [r8 + r8*2]  ; rbx = r8*3
0x140003895:  jmp 0x1400037f1       ; store and continue

HALT: op=8 sets flag_active=0 -> loop exits at 0x1400037f9

"""

# ── Bytecode dump ─────────────────────────────────────────────────────────────
data = open('/home/user/uploads/CFB3.exe','rb').read()
BYTECODE_OFF = 0x1fdc0
bc = list(data[BYTECODE_OFF:BYTECODE_OFF+120])
n_instr = 40

print('=== Raw bytecode (40 × 3 bytes) ===')
for i in range(n_instr):
    op, a, b = bc[i*3], bc[i*3+1], bc[i*3+2]
    print(f'  [{i:2d}] op={op:#04x} a={a:#04x} b={b:#04x}')

# ── Disassembler ─────────────────────────────────────────────────────────────

OPCODES = {
    0x01: 'LOAD_CHAR',  # reg[a] = password[char_idx++]
    0x02: 'LOAD_IMM',   # reg[a] = b
    0x03: 'ADD_REG',    # reg[a] += reg[b]
    0x05: 'XOR_IMM',    # reg[a] ^= b
    0x06: 'CMP_EQ',     # flag = (reg[a] == b)
    0x07: 'JMP_NOFLAG', # if !flag: jump to instr b
    0x08: 'HALT_OK',
    0x09: 'HALT_FAIL',
}

print()
print('=== VM Disassembly ===')
for i in range(n_instr):
    op, a, b = bc[i*3], bc[i*3+1], bc[i*3+2]
    mnem = OPCODES.get(op, f'UNK_{op:#04x}')
    if op == 0x01:
        desc = f'reg[{a}] = password[char_idx++]'
    elif op == 0x02:
        desc = f'reg[{a}] = {b:#04x} ({b})'
    elif op == 0x03:
        desc = f'reg[{a}] += reg[{b}]'
    elif op == 0x05:
        desc = f'reg[{a}] ^= {b:#04x} ({b})'
    elif op == 0x06:
        desc = f'flag = (reg[{a}] == {b:#04x})'
    elif op == 0x07:
        desc = f'if !flag: goto [{b}]'
    elif op == 0x08:
        desc = 'HALT: ACCESS GRANTED'
    elif op == 0x09:
        desc = 'HALT: ACCESS DENIED'
    else:
        desc = ''
    print(f'  [{i:2d}] {mnem:12s} {desc}')

# ── Emulator + password solver ───────────────────────────────────────────────
print()
print('=== Solving for password ===')

# The bytecode reads one password char per LOAD_CHAR instruction.
# Each char is transformed then compared (CMP_EQ).
# We solve by running the VM with a "symbolic" password: for each LOAD_CHAR
# we capture what value is expected (from the preceding transforms) and invert.

# But it's simpler: just simulate with a known password and check,
# then brute-force each byte independently.

def vm_run(password_bytes):
    """Run the VM. Returns True if password is accepted."""
    regs = [0, 0, 0, 0]
    flag = 0
    char_idx = 0
    pw = list(password_bytes)
    pw_len = len(pw)
    IP = 0  # instruction index

    for _ in range(1000):  # safety cap
        if IP >= n_instr:
            return False
        op, a, b = bc[IP*3], bc[IP*3+1], bc[IP*3+2]

        if op == 0x01:   # LOAD_CHAR
            if a < 4:
                regs[a] = pw[char_idx] if char_idx < pw_len else 0
            char_idx += 1
            IP += 1

        elif op == 0x02:  # LOAD_IMM
            if a < 4:
                regs[a] = b
            IP += 1

        elif op == 0x03:  # ADD_REG
            if a < 4 and b < 4:
                regs[a] = (regs[a] + regs[b]) & 0xFF
            IP += 1

        elif op == 0x05:  # XOR_IMM
            if a < 4:
                regs[a] = (regs[a] ^ b) & 0xFF
            IP += 1

        elif op == 0x06:  # CMP_EQ
            if a < 4:
                flag = 1 if regs[a] == b else 0
            IP += 1

        elif op == 0x07:  # JMP_NOFLAG
            if flag == 0:
                IP = b   # jump to instruction b
            else:
                IP += 1

        elif op == 0x08:  # HALT_OK
            return True

        elif op == 0x09:  # HALT_FAIL
            return False

        else:
            return False

    return False

# Brute force each character (0x20..0x7e printable range)
# The VM processes chars sequentially - we can solve char-by-char
# by running with partial known prefix

print('Brute-forcing password (char by char)...')
password = []
for pos in range(20):  # try up to 20 chars
    found = False
    for c in range(0x20, 0x7f):
        trial = password + [c]
        # Pad with zeros to make it long enough
        trial_padded = trial + [0]*20
        result = vm_run(trial_padded)
        if result:
            password.append(c)
            found = True
            print(f'  char[{pos}] = {c:#04x} ({chr(c)!r}) -> ACCEPTED (full match!)')
            break
    if found and result:
        break
    # Need to check if partial prefix reaches the pos-th LOAD_CHAR correctly
    # Better approach: trace execution to find what value is expected at each position

# Better: trace the VM symbolically - find expected value for each char
print()
print('Tracing VM to find expected values per character position...')

# We run the VM providing known chars and observe what CMP_EQ checks each time
# For each LOAD_CHAR, we'll set that char to 0xFF and run to the next CMP_EQ
# to find what value is expected

def solve_symbolic():
    """
    Trace VM execution to determine what each password character must be.
    Strategy: inject one char at a time, track transformations, invert CMP target.
    """
    result_password = []
    char_idx = 0
    IP = 0
    regs = [0, 0, 0, 0]
    flag = 1  # start with flag=1 so no jumps taken
    pw = {}   # char_pos -> value (solved chars)

    # We'll run the VM with solved chars filled in,
    # and for the current unknown char, we try all 256 values

    # Run until HALT_OK, solving each char when we hit a CMP_EQ that fails
    for solve_attempt in range(30):
        # Build current password guess
        guess = [pw.get(i, 0x00) for i in range(max(pw.keys())+2 if pw else 1)]

        # Run and find which char position causes first failure
        regs2 = [0, 0, 0, 0]
        flag2 = 0
        cidx2 = 0
        IP2 = 0
        load_history = []  # (char_pos, reg_dst)

        for _ in range(2000):
            if IP2 >= n_instr: break
            op2, a2, b2 = bc[IP2*3], bc[IP2*3+1], bc[IP2*3+2]

            if op2 == 0x01:
                load_history.append((cidx2, a2))
                regs2[a2] = guess[cidx2] if cidx2 < len(guess) else 0
                cidx2 += 1
                IP2 += 1
            elif op2 == 0x02:
                regs2[a2] = b2; IP2 += 1
            elif op2 == 0x03:
                regs2[a2] = (regs2[a2] + regs2[b2]) & 0xFF; IP2 += 1
            elif op2 == 0x05:
                regs2[a2] ^= b2; regs2[a2] &= 0xFF; IP2 += 1
            elif op2 == 0x06:
                flag2 = 1 if regs2[a2] == b2 else 0; IP2 += 1
            elif op2 == 0x07:
                if flag2 == 0:
                    IP2 = b2
                else:
                    IP2 += 1
            elif op2 == 0x08:
                return ''.join(chr(pw[i]) for i in range(len(pw)))
            elif op2 == 0x09:
                break
            else:
                break

        break  # shouldn't reach here in normal flow

    return None

# Cleaner approach: run VM once for each char pos, trying all 256 values
def solve():
    # Run the full VM but for each char load, inject a test value
    # We solve greedily: fix chars 0..n-1, brute force char n

    solved = []
    for char_pos in range(20):
        found_char = None
        for c in range(0x20, 0x7f):
            test_pw = solved + [c] + [0]*20
            if vm_run(test_pw):
                # Full success already!
                solved.append(c)
                return ''.join(chr(x) for x in solved)

        # Char wasn't the last - need smarter approach
        # Find what value makes the VM proceed past char_pos's CMP
        for c in range(0x00, 0x100):
            test_pw = solved + [c] + [ord('A')]*20  # fill rest with 'A'
            # Run until we've processed char_pos+1 chars
            regs = [0,0,0,0]
            flag = 0
            cidx = 0
            IP = 0
            passed_this_char = False

            for _ in range(2000):
                if IP >= n_instr: break
                op, a, b = bc[IP*3], bc[IP*3+1], bc[IP*3+2]

                if op == 0x01:
                    regs[a] = (test_pw[cidx] if cidx < len(test_pw) else 0) if a < 4 else 0
                    cidx += 1
                    IP += 1
                elif op == 0x02:
                    if a < 4: regs[a] = b
                    IP += 1
                elif op == 0x03:
                    if a < 4 and b < 4: regs[a] = (regs[a]+regs[b])&0xFF
                    IP += 1
                elif op == 0x05:
                    if a < 4: regs[a] = (regs[a]^b)&0xFF
                    IP += 1
                elif op == 0x06:
                    if a < 4: flag = 1 if regs[a]==b else 0
                    IP += 1
                elif op == 0x07:
                    if flag == 0:
                        IP = b
                    else:
                        IP += 1
                elif op == 0x08:
                    # Full success with only char_pos+1 chars - password is shorter
                    solved.append(c)
                    return ''.join(chr(x) for x in solved)
                elif op == 0x09:
                    break
                else:
                    break

                # If we've loaded more chars than char_pos and are still running
                # and the vm hasn't jumped backwards, this char is valid
                if cidx == char_pos + 1 and IP > char_pos * 3:
                    passed_this_char = True

            if passed_this_char and flag == 1:
                # The char passed the CMP at this position
                found_char = c
                break

        if found_char is not None:
            solved.append(found_char)
            print(f'  char[{len(solved)-1}] = {found_char:#04x}  ({chr(found_char)!r})')
        else:
            print(f'  char[{char_pos}] = ??? (not found)')
            break

    return ''.join(chr(x) for x in solved)

# Actually let's do it the simple direct way:
# Simulate the VM and for each LOAD_CHAR + subsequent CMP_EQ pair,
# directly compute the required input by inverting all operations between them.

def solve_direct():
    """
    Directly solve by tracing the instruction sequence symbolically.
    For each LOAD_CHAR..CMP_EQ pair, invert the transforms.
    """
    password_chars = {}
    char_load_reg = {}  # which register holds which char (by char_pos)

    regs = [None]*4   # None = unknown, int = known
    flag = 1
    cidx = 0
    IP = 0
    solved_regs = [0]*4  # actual solved values

    print('Symbolic trace:')
    for step in range(500):
        if IP >= n_instr: break
        op, a, b = bc[IP*3], bc[IP*3+1], bc[IP*3+2]

        if op == 0x01:   # LOAD_CHAR
            regs[a] = f'pw[{cidx}]'
            char_load_reg[cidx] = a
            solved_regs[a] = 0  # placeholder
            print(f'  [{IP:2d}] LOAD_CHAR   reg[{a}] = pw[{cidx}]')
            cidx += 1
            IP += 1

        elif op == 0x02:  # LOAD_IMM
            regs[a] = b
            solved_regs[a] = b
            print(f'  [{IP:2d}] LOAD_IMM    reg[{a}] = {b:#04x}')
            IP += 1

        elif op == 0x03:  # ADD_REG: reg[a] += reg[b]
            if isinstance(regs[a], str):
                regs[a] = f'({regs[a]} + {regs[b]:#04x})'
            elif isinstance(regs[b], str):
                regs[a] = f'({regs[a]:#04x} + {regs[b]})'
            else:
                regs[a] = (solved_regs[a] + solved_regs[b]) & 0xFF
            solved_regs[a] = (solved_regs[a] + solved_regs[b]) & 0xFF
            print(f'  [{IP:2d}] ADD_REG     reg[{a}] += reg[{b}]  -> {regs[a]}')
            IP += 1

        elif op == 0x05:  # XOR_IMM
            if isinstance(regs[a], str):
                regs[a] = f'({regs[a]} ^ {b:#04x})'
            else:
                regs[a] = (solved_regs[a] ^ b) & 0xFF
            solved_regs[a] = (solved_regs[a] ^ b) & 0xFF
            print(f'  [{IP:2d}] XOR_IMM     reg[{a}] ^= {b:#04x}  -> {regs[a]}')
            IP += 1

        elif op == 0x06:  # CMP_EQ: flag = (reg[a] == b)
            print(f'  [{IP:2d}] CMP_EQ      flag = (reg[{a}] == {b:#04x})  // reg[{a}]={regs[a]}')
            IP += 1

        elif op == 0x07:  # JMP_NOFLAG: if !flag: IP=b
            print(f'  [{IP:2d}] JMP_NOFLAG  if !flag goto [{b}]  (flag=1, skip)')
            IP += 1  # assume flag=1 (CMP passed) for trace

        elif op == 0x08:
            print(f'  [{IP:2d}] HALT_OK')
            break
        elif op == 0x09:
            print(f'  [{IP:2d}] HALT_FAIL')
            break
        else:
            print(f'  [{IP:2d}] UNKNOWN op={op:#04x}')
            break

solve_direct()

# ── Now do the actual inversion ───────────────────────────────────────────────
print()
print('=== Solving each character by inversion ===')

# Parse the bytecode into per-char blocks:
# Each block: LOAD_CHAR [transforms...] CMP_EQ JMP_NOFLAG
# We need to invert the transforms to find what input produces the expected value.

def solve_inversion():
    password = []
    char_count = 0
    regs_solved = [0]*4   # track "current" solved register values
    IP = 0

    # We'll run "forward" but whenever we encounter LOAD_CHAR,
    # we note which reg is loaded. When we see CMP_EQ on that reg,
    # we can back-compute the original char value.

    # Track the chain of operations on each register after a LOAD_CHAR
    char_reg_ops = {}  # char_pos -> list of (op, *args)

    # Run through all instructions recording ops
    reg_source = [None]*4  # which char_pos loaded this reg (-1 = constant)
    reg_val = [0]*4

    char_expected = {}  # char_pos -> required reg value after all transforms

    IP = 0
    for _ in range(200):
        if IP >= n_instr: break
        op, a, b = bc[IP*3], bc[IP*3+1], bc[IP*3+2]

        if op == 0x01:   # LOAD_CHAR reg[a] = pw[char_count]
            reg_source[a] = char_count
            reg_val[a] = 0  # unknown
            if char_count not in char_reg_ops:
                char_reg_ops[char_count] = []
            char_count += 1
            IP += 1

        elif op == 0x02:  # LOAD_IMM reg[a] = b
            reg_source[a] = -1  # constant
            reg_val[a] = b
            IP += 1

        elif op == 0x03:  # ADD_REG reg[a] += reg[b]
            # This adds a KNOWN reg[b] to reg[a]
            # Record the operation for the source char
            src = reg_source[a]
            if src is not None and src >= 0:
                char_reg_ops[src].append(('add', reg_val[b]))
            reg_val[a] = (reg_val[a] + reg_val[b]) & 0xFF
            IP += 1

        elif op == 0x05:  # XOR_IMM reg[a] ^= b
            src = reg_source[a]
            if src is not None and src >= 0:
                char_reg_ops[src].append(('xor', b))
            reg_val[a] = (reg_val[a] ^ b) & 0xFF
            IP += 1

        elif op == 0x06:  # CMP_EQ flag = (reg[a] == b)
            src = reg_source[a]
            if src is not None and src >= 0:
                # The expected value after transforms is b
                char_expected[src] = b
            IP += 1

        elif op == 0x07:  # JMP_NOFLAG (assume flag=1, skip)
            IP += 1

        elif op in (0x08, 0x09):
            break
        else:
            break

    # Now invert each char's transform chain to find the required input
    print(f'  Found {char_count} password characters')
    print()

    password_chars = []
    for i in range(char_count):
        ops = char_reg_ops.get(i, [])
        expected = char_expected.get(i, None)

        if expected is None:
            # Special case: op=0x06 with reg[0]=0x00 -> LOAD_CHAR then CMP 0x00
            # Check if it's the last char with no transforms
            password_chars.append(0)
            print(f'  char[{i}]: no CMP found')
            continue

        # Invert: start from expected, apply inverse ops in reverse order
        val = expected
        for op_name, arg in reversed(ops):
            if op_name == 'xor':
                val = val ^ arg   # XOR is self-inverse
            elif op_name == 'add':
                val = (val - arg) & 0xFF  # subtract to invert add

        c = val & 0xFF
        password_chars.append(c)

        # Format
        ch_repr = chr(c) if 0x20 <= c <= 0x7e else f'\\x{c:02x}'
        ops_str = ' '.join(f'{o}({a:#04x})' for o,a in ops)
        print(f'  char[{i:2d}]: expected_after_transforms={expected:#04x}'
              f'  ops=[{ops_str}]'
              f'  -> input={c:#04x} ({ch_repr!r})')

    pw = ''.join(chr(c) if 0x20 <= c <= 0x7e else '?' for c in password_chars)
    return pw, password_chars

password, char_vals = solve_inversion()
print()
print(f'Password: {password!r}')
print(f'Hex:      {" ".join("%02x" % c for c in char_vals)}')

# Verify
print()
print(f'Verification: vm_run({password!r}) = {vm_run(char_vals)}')
