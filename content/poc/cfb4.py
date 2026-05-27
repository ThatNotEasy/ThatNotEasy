#!/usr/bin/env python3
"""
CFB4 3-Rotor Cipher - CORRECTED SOLUTION

ENCRYPTED TARGET (13 bytes):
c6 b7 2b 6e 9e b7 fa 54 52 3f 35 98 df

POSITION OFFSETS (extracted from disassembly):
0x15, 0x15, 0x16, 0x18, 0x1b, 0x1f, 0x24, 0x2a, 0x31, 0x39, 0x42, 0x4c, 0x57
"""

def decrypt_byte_0(encrypted_val):
    """Reverse the encryption for byte 0"""
    val = encrypted_val
    val = val ^ 0xa5
    val = (val - 0x15) & 0xff
    val = val ^ 0x5c
    val = (val + 0x0d) & 0xff  # Initial subtract was 0x0d
    val = val ^ 0x7f
    val = (val - 0x13) & 0xff
    val = val ^ 0x3a
    val = (val - 0x05) & 0xff
    return val

def decrypt_byte_i(encrypted_val, r10, r11, offset):
    """Reverse the encryption for bytes 1-12"""
    val = encrypted_val
    val = val ^ 0xa5
    val = (val - offset) & 0xff
    val = val ^ 0x5c
    val = (val + r11) & 0xff
    val = val ^ 0x7f
    val = (val - 0x13) & 0xff
    val = val ^ 0x3a
    val = (val - r10) & 0xff
    return val

def decrypt_password():
    """Decrypt the complete 13-character password"""
    
    encrypted_target = [
        0xc6, 0xb7, 0x2b, 0x6e, 0x9e, 0xb7, 0xfa,
        0x54, 0x52, 0x3f, 0x35, 0x98, 0xdf
    ]
    
    # Position offsets from disassembly
    offsets = [0x15, 0x15, 0x16, 0x18, 0x1b, 0x1f, 0x24, 0x2a, 0x31, 0x39, 0x42, 0x4c, 0x57]
    
    plaintext = []
    
    # Decrypt byte 0
    byte_0 = decrypt_byte_0(encrypted_target[0])
    plaintext.append(chr(byte_0))
    print(f"Byte 0: 0x{encrypted_target[0]:02x} -> 0x{byte_0:02x} ('{chr(byte_0) if 32 <= byte_0 < 127 else '?'}')")
    
    # Initialize CFB states after byte 0
    # From disassembly analysis:
    # lea 0x5(%r9),%edx  -> r10 = r9 + 0x05
    # xor $0xd,%r9b -> r11 = r9 ^ 0x0d
    r9 = encrypted_target[0]
    r10 = (r9 + 0x05) & 0xff
    r11 = r9 ^ 0x0d
    
    print(f"Initial states: r10=0x{r10:02x}, r11=0x{r11:02x}")
    
    # Decrypt bytes 1-12
    for i in range(1, 13):
        byte_i = decrypt_byte_i(encrypted_target[i], r10, r11, offsets[i])
        plaintext.append(chr(byte_i))
        print(f"Byte {i:2d}: 0x{encrypted_target[i]:02x} -> 0x{byte_i:02x} ('{chr(byte_i) if 32 <= byte_i < 127 else '?'}') | r10=0x{r10:02x}, r11=0x{r11:02x}")
        
        # Update CFB states
        # add %encrypted_byte,%r10b
        # xor %encrypted_byte,%r11b
        r10 = (r10 + encrypted_target[i]) & 0xff
        r11 = r11 ^ encrypted_target[i]
    
    return ''.join(plaintext)

if __name__ == "__main__":
    print("="*70)
    print("CFB4 3-Rotor Cipher - FINAL DECRYPTION")
    print("="*70)
    print()
    
    password = decrypt_password()
    
    print()
    print("="*70)
    print(f"[+] DECRYPTED PASSWORD: {password}")
    print(f"[+] Length: {len(password)} characters")
    print()
    
    # Verify it's printable ASCII
    if all(32 <= ord(c) < 127 for c in password):
        print(f"[✓] All characters are printable ASCII")
    else:
        non_printable = [f"0x{ord(c):02x}" for c in password if ord(c) < 32 or ord(c) >= 127]
        print(f"[✗] Contains non-printable characters: {non_printable}")
    
    print()
    print(f"[*] Enter this password in CFB4.exe:")
    print(f"    >>> {password}")
    print("="*70)
