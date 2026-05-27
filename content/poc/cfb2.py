import struct
from collections import deque

# ── Load binary & parse PE ────────────────────────────────────────────────────
data = open('/home/user/uploads/CFB2.exe','rb').read()
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
pe = e_lfanew
image_base   = struct.unpack_from('<Q', data, pe+48)[0]
num_sections = struct.unpack_from('<H', data, pe+6)[0]
opt_hdr_size = struct.unpack_from('<H', data, pe+20)[0]
sect_off = pe + 24 + opt_hdr_size
sections = []
for i in range(num_sections):
    s = sect_off + i*40
    name  = data[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    vsize = struct.unpack_from('<I', data, s+8)[0]
    vrva  = struct.unpack_from('<I', data, s+12)[0]
    rsize = struct.unpack_from('<I', data, s+16)[0]
    roff  = struct.unpack_from('<I', data, s+20)[0]
    sections.append((name, vrva, vsize, roff, rsize))

# ── Extract maze from .rdata ──────────────────────────────────────────────────
# Confirmed candidate: file offset 0x2a1c0, unique vals [0,1,2]
# 0 = open path, 1 = wall, 2 = finish (9,9)
MAZE_FILE_OFF = 0x2a1c0
maze_raw = list(data[MAZE_FILE_OFF:MAZE_FILE_OFF+100])
maze = [maze_raw[r*10:(r+1)*10] for r in range(10)]

# Confirm start and finish
assert maze[0][0] == 0,  "Start (0,0) must be open"
assert maze[9][9] == 2,  "Finish (9,9) must be value 2"

print("── Maze (0=open, 1=wall, 2=finish) ─────────────────────────────")
print("     col: 0  1  2  3  4  5  6  7  8  9")
for r, row in enumerate(maze):
    cells = '  '.join(str(v) for v in row)
    print(f"  row {r}:  {cells}")

print()

# Pretty ASCII art
SYMBOLS = {0: '.', 1: '#', 2: 'E'}
print("── ASCII maze (#=wall, .=open, S=start, E=finish) ─────────────")
for r, row in enumerate(maze):
    line = ''
    for c, v in enumerate(row):
        if r == 0 and c == 0:
            line += 'S '
        else:
            line += SYMBOLS[v] + ' '
    print('  ' + line)

print()

# ── BFS solver ───────────────────────────────────────────────────────────────
# WASD: W=up(row-1), S=down(row+1), A=left(col-1), D=right(col+1)
MOVES = {
    'W': (-1,  0),
    'S': ( 1,  0),
    'A': ( 0, -1),
    'D': ( 0,  1),
}

def bfs(maze):
    start  = (0, 0)
    finish = (9, 9)
    queue  = deque([(start, [])])
    visited = {start}

    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == finish:
            return path

        for key, (dr, dc) in MOVES.items():
            nr, nc = r+dr, c+dc
            if 0 <= nr < 10 and 0 <= nc < 10:
                if (nr, nc) not in visited and maze[nr][nc] != 1:
                    visited.add((nr, nc))
                    queue.append(((nr, nc), path + [key]))
    return None

path = bfs(maze)
solution = ''.join(path)

print(f"── BFS solution ({len(path)} steps) ──────────────────────────────────")
print(f"  Path: {solution}")
print()

# Walk-through verification
print("── Step-by-step verification ──────────────────────────────────")
r, c = 0, 0
print(f"  START → ({r},{c})")
for i, move in enumerate(path):
    dr, dc = MOVES[move]
    r2, c2 = r+dr, c+dc
    cell = maze[r2][c2]
    sym = {0:'open', 1:'WALL!', 2:'FINISH'}[cell]
    print(f"  step {i+1:2d}: {move} → ({r2},{c2}) [{sym}]")
    assert cell != 1, f"Hit a wall at step {i+1}!"
    r, c = r2, c2
assert (r, c) == (9, 9), f"Did not reach finish! At ({r},{c})"
print(f"\n  ✓ Reached FINISH at (9,9) in {len(path)} steps!")
print()

# Print path annotated on maze
print("── Solved maze (path marked with numbers) ──────────────────────")
visited_path = {}
rr, cc = 0, 0
visited_path[(rr, cc)] = 0
for i, move in enumerate(path):
    dr, dc = MOVES[move]
    rr += dr
    cc += dc
    visited_path[(rr, cc)] = i+1

for r2 in range(10):
    line = ''
    for c2 in range(10):
        if (r2, c2) in visited_path:
            step = visited_path[(r2, c2)]
            if step == 0:      line += 'S '
            elif (r2,c2)==(9,9): line += 'E '
            else:              line += '* '
        elif maze[r2][c2] == 1:
            line += '# '
        else:
            line += '. '
    print('  ' + line)

print()
print(f"  SOLUTION KEY: {solution}")
