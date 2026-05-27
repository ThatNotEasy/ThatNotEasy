# CFB2 — Crackmes for Beginners #2


## TL;DR

- **Challenge:** Navigate a hidden 10×10 maze stored in `.rdata` — find the WASD path from `(0,0)` to `(9,9)`.
- **Solution:** `SDDSSASSDDSSDDDSSDDD` (20 steps, BFS shortest path).
- **Approach:** Static analysis — scan `.rdata` for the maze array, disassemble WASD dispatch, run BFS.

---

## 1. Overview

CFB2 is a maze-navigating crackme that drops the player into a hidden 10×10 grid stored in the binary's read-only data section. There are no dynamic string calculations or mathematical equations — the challenge is purely about extracting the maze layout, understanding the movement mechanics from the disassembly, and finding the correct sequence of `W`/`A`/`S`/`D` key presses that walks from the start position `(0,0)` to the finish at `(9,9)`. The maze is encoded as flat byte values in `.rdata`, making it recoverable through static analysis alone.

**Goal:** Find the correct sequence of `W`/`A`/`S`/`D` key presses that walks from `(0,0)` to `(9,9)` through a 10×10 maze hidden in `.rdata`.

---

## 2. Initial reconnaissance

### 2.1 File Identification

```
File      : CFB2.exe
Format    : PE32+ (x64)
Compiler  : MSVC C++ (iostream)
Packing   : None
ImageBase : 0x140000000
```

**Sections:**

| Name | VA | VSize | File Offset |
|---|---|---|---|
| `.text` | `0x140001000` | `0x29868` | `0x000400` |
| `.rdata` | `0x14002B000` | `0x129A6` | `0x029E00` |
| `.data` | `0x14003E000` | `0x002500` | `0x03C800` |
| `.pdata` | `0x140041000` | `0x00246C` | `0x03DC00` |

Key strings extracted immediately reveal the rules:

```
[*] Welcome to CFB2 - The Maze Runner.
[*] Enter your solution path (using W/A/S/D):
[-] Invalid move 'X' at step N
[-] Out of bounds at step N
[-] Hit a wall at step N
[-] You did not reach the finish point (9,9).
[+] ACCESS GRANTED! Congratulations!
```

Three important facts surface right away:
- Movement is **WASD** (no up/down arrows — pure ASCII input)
- The finish is at **(9, 9)** — confirmed by the error string
- Walls, bounds, and finish are all validated separately

---

## 3. Locating the maze in memory

### 3.1 Strategy

The maze is 10×10 = **100 cells**, stored in `.rdata`. Each cell should be one of a small number of distinct values (open / wall / finish). We scan `.rdata` with a sliding window of 100 bytes, looking for regions where:

- Exactly 2–4 **unique byte values** appear
- All values are **≤ 10** (no printable ASCII / floats / pointers)

### 3.2 Scan result

Running the scan on `.rdata` produces dozens of sliding-window matches for `{0, 1}` — those are false positives caused by boolean data and padding. The **key discriminator** is the presence of a third value `2` (the finish marker):

```
file_off=0x2A1C0  VA=0x14002B3C0  unique_vals=[0, 1, 2]
```

Only 6 candidates contain value `2`, and only one has `2` at position **[9][9]** (the last cell, matching the `(9,9)` finish string):

```
row 9:  1 1 1 1 1 1 0 0 0 2   ← value 2 at col 9
```

This is our maze. **Cell encoding:**

| Value | Meaning |
|---|---|
| `0` | Open passage |
| `1` | Wall |
| `2` | Finish (exit) |

The start is implicitly `(0, 0)` — confirmed by `maze[0][0] == 0`.

**Raw maze data** (`file offset 0x2A1C0`, 100 bytes):

```
0x2A1C0:  01 01 01 01 01 01 01 01 01
          00 00 01 00 00 00 00 00 01
          01 01 00 01 00 01 01 01 00 01
          01 00 00 00 00 01 00 00 00 01
          01 00 01 01 01 01 00 01 01 01
          01 00 00 00 01 00 00 00 00 01
          01 01 01 00 01 01 01 01 00 01
          01 00 00 00 00 00 00 01 00 01
          01 00 01 01 01 01 00 01 00 00
          01 01 01 01 01 01 00 00 00 02
```

---

## 4. Reversing the movement mechanics

### 4.1 WASD dispatch — disassembly @ `0x140006638`

The movement dispatcher is a simple if-else chain comparing each input character:

```asm
0x140006638  cmp  al, 0x41     ; 'A'
0x14000663a  je   0x140006658  ; → dec esi (col--)
0x14000663c  cmp  al, 0x44     ; 'D'
0x14000663e  je   0x140006654  ; → inc esi (col++)
0x140006640  cmp  al, 0x53     ; 'S'
0x140006642  je   0x140006650  ; → inc edi (row++)
0x140006644  cmp  al, 0x57     ; 'W'
0x140006646  jne  0x1400066eb  ; → invalid move error

; W branch:
0x14000664c  dec  edi          ; row--

; S branch:
0x140006650  inc  edi          ; row++

; D branch:
0x140006654  inc  esi          ; col++

; A branch:
0x140006658  dec  esi          ; col--
```

**Key → (Δrow, Δcol):**

| Key | Action | Δrow | Δcol |
|-----|--------|------|------|
| `W` | Up    | −1 | 0 |
| `S` | Down  | +1 | 0 |
| `D` | Right |  0 | +1 |
| `A` | Left  |  0 | −1 |

### 4.2 Bounds check

```asm
0x14000665a  cmp  esi, 9       ; col > 9?
0x14000665d  ja   out_of_bounds
0x140006663  cmp  edi, 9       ; row > 9?
0x140006666  ja   out_of_bounds
```

Unsigned comparison — negative values wrap to large unsigned → also caught.

### 4.3 Cell check

```asm
0x14000666c  lea  eax, [rdi + rdi*4]   ; eax = row * 5
0x14000666f  lea  eax, [rsi + eax*2]   ; eax = row*10 + col
0x140006672  cdqe
0x140006674  movzx edx, byte ptr [rax + r14]   ; r14 = maze base ptr
0x140006679  cmp  dl, r12b             ; r12b = 1 (wall value)
0x14000667c  je   hit_wall_error
0x140006682  cmp  dl, 2                ; finish cell?
0x140006689  jne  continue_loop
```

**Index formula:** `maze[row * 10 + col]` — standard row-major 2D array.

---

## 5. Extracting and rendering the maze

```
     0  1  2  3  4  5  6  7  8  9
  0: S  #  #  #  #  #  #  #  #  #
  1: .  .  .  #  .  .  .  .  .  #
  2: #  #  .  #  .  #  #  #  .  #
  3: #  .  .  .  .  #  .  .  .  #
  4: #  .  #  #  #  #  .  #  #  #
  5: #  .  .  .  #  .  .  .  .  #
  6: #  #  #  .  #  #  #  #  .  #
  7: #  .  .  .  .  .  .  #  .  #
  8: #  .  #  #  #  #  .  #  .  .
  9: #  #  #  #  #  #  .  .  .  E

  Legend:  S = start (0,0)   E = finish (9,9)
           # = wall (1)      . = open path (0)
```

---

## 6. BFS pathfinding

With the maze and movement rules confirmed, a standard **Breadth-First Search** finds the shortest path from `(0,0)` → `(9,9)`.

```python
from collections import deque

MOVES = {'W':(-1,0), 'S':(1,0), 'A':(0,-1), 'D':(0,1)}

def bfs(maze):
    queue   = deque([((0,0), [])])
    visited = {(0,0)}
    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == (9, 9):
            return path
        for key, (dr, dc) in MOVES.items():
            nr, nc = r+dr, c+dc
            if 0 <= nr < 10 and 0 <= nc < 10:
                if (nr,nc) not in visited and maze[nr][nc] != 1:
                    visited.add((nr, nc))
                    queue.append(((nr,nc), path+[key]))
    return None
```

---

## 7. The solution

**BFS result: 20 steps**

```
SDDSSASSDDSSDDDSSDDD
```

### 7.1 Step-by-step walkthrough

| Step | Key | From → To | Cell |
|------|-----|-----------|------|
| 1 | `S` | (0,0) → (1,0) | open |
| 2 | `D` | (1,0) → (1,1) | open |
| 3 | `D` | (1,1) → (1,2) | open |
| 4 | `S` | (1,2) → (2,2) | open |
| 5 | `S` | (2,2) → (3,2) | open |
| 6 | `A` | (3,2) → (3,1) | open |
| 7 | `S` | (3,1) → (4,1) | open |
| 8 | `S` | (4,1) → (5,1) | open |
| 9 | `D` | (5,1) → (5,2) | open |
| 10 | `D` | (5,2) → (5,3) | open |
| 11 | `S` | (5,3) → (6,3) | open |
| 12 | `S` | (6,3) → (7,3) | open |
| 13 | `D` | (7,3) → (7,4) | open |
| 14 | `D` | (7,4) → (7,5) | open |
| 15 | `D` | (7,5) → (7,6) | open |
| 16 | `S` | (7,6) → (8,6) | open |
| 17 | `S` | (8,6) → (9,6) | open |
| 18 | `D` | (9,6) → (9,7) | open |
| 19 | `D` | (9,7) → (9,8) | open |
| 20 | `D` | (9,8) → (9,9) | **FINISH** |

### 7.2 Solved maze (path marked `*`)

```
     0  1  2  3  4  5  6  7  8  9
  0: S  #  #  #  #  #  #  #  #  #
  1: *  *  *  #  .  .  .  .  .  #
  2: #  #  *  #  .  #  #  #  .  #
  3: #  *  *  .  .  #  .  .  .  #
  4: #  *  #  #  #  #  .  #  #  #
  5: #  *  *  *  #  .  .  .  .  #
  6: #  #  #  *  #  #  #  #  .  #
  7: #  .  .  *  *  *  *  #  .  #
  8: #  .  #  #  #  #  *  #  .  .
  9: #  #  #  #  #  #  *  *  *  E
```

---

## 8. Solver script

```python
#!/usr/bin/env python3
"""
CFB2 Maze Solver
Extracts the 10x10 maze from CFB2.exe .rdata and solves it with BFS.
"""
import struct
from collections import deque

data = open('CFB2.exe', 'rb').read()

# Maze located at file offset 0x2A1C0 in .rdata
# Encoding: 0=open, 1=wall, 2=finish
MAZE_OFF = 0x2A1C0
raw  = list(data[MAZE_OFF:MAZE_OFF+100])
maze = [raw[r*10:(r+1)*10] for r in range(10)]

MOVES = {'W':(-1,0), 'S':(1,0), 'A':(0,-1), 'D':(0,1)}

def bfs(maze):
    queue   = deque([((0,0), [])])
    visited = {(0,0)}
    while queue:
        (r,c), path = queue.popleft()
        if (r,c) == (9,9):
            return ''.join(path)
        for key,(dr,dc) in MOVES.items():
            nr,nc = r+dr, c+dc
            if 0<=nr<10 and 0<=nc<10 and (nr,nc) not in visited and maze[nr][nc]!=1:
                visited.add((nr,nc))
                queue.append(((nr,nc), path+[key]))

solution = bfs(maze)
print(f'[+] Solution ({len(solution)} steps): {solution}')
```

**Output:**
```
[+] Solution (20 steps): SDDSSASSDDSSDDDSSDDD
```

---

## 9. Conclusion

| Step | What we did |
|---|---|
| **Strings** | Identified finish coord `(9,9)`, WASD controls, and error messages |
| **Scan `.rdata`** | Slid a 100-byte window over `.rdata` looking for `{0,1,2}` unique-value regions |
| **Confirmed maze** | Only one candidate has `maze[9][9] == 2` — file offset `0x2A1C0` |
| **Disassembly** | Confirmed WASD → (Δrow, Δcol) mapping and row-major `maze[row*10+col]` index formula |
| **BFS** | Standard breadth-first search found the **unique shortest path in 20 moves** |

**Key insight:** No execution needed. The maze is stored as a flat array of `uint8` values in `.rdata`. Once you identify the encoding scheme (`0/1/2`) and map WASD to direction vectors from the disasm, the problem reduces to a textbook graph traversal.

**Solution:** `SDDSSASSDDSSDDDSSDDD`

*Solved with static analysis only — no debugger, no emulator, no execution.*
