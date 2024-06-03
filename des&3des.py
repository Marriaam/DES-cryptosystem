import itertools
import base64

# Initial Permutation Table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation Table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Table
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Substitution Boxes
S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Permutation function
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# Permuted Choice 1
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Number of bit shifts
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    return [block[x-1] for x in table]

def left_shift(block, num_shifts):
    return block[num_shifts:] + block[:num_shifts]

def xor(t1, t2):
    return [i ^ j for i, j in zip(t1, t2)]

def sbox_substitution(bits):
    result = []
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = int(f"{block[0]}{block[5]}", 2)
        col = int("".join(str(x) for x in block[1:5]), 2)
        s_value = S_BOXES[i][row][col]
        bin_value = bin(s_value)[2:].zfill(4)
        result.extend([int(bit) for bit in bin_value])
    return result

def feistel_function(right, subkey):
    expanded_right = permute(right, E)
    xor_result = xor(expanded_right, subkey)
    substituted = sbox_substitution(xor_result)
    return permute(substituted, P)

def generate_keys(key):
    key = permute(key, PC1)
    left, right = key[:28], key[28:]
    keys = []
    for shift in SHIFT_SCHEDULE:
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        combined = left + right
        round_key = permute(combined, PC2)
        keys.append(round_key)
    return keys

def des_encrypt_block(block, keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for key in keys:
        new_right = xor(left, feistel_function(right, key))
        left = right
        right = new_right
    combined = right + left
    return permute(combined, FP)

def des_decrypt_block(block, keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for key in reversed(keys):
        new_right = xor(left, feistel_function(right, key))
        left = right
        right = new_right
    combined = right + left
    return permute(combined, FP)

def text_to_bits(text):
    bits = []
    for char in text:
        bin_value = bin(ord(char))[2:].zfill(8)
        bits.extend([int(bit) for bit in bin_value])
    return bits

def bits_to_text(bits):
    chars = []
    for b in range(0, len(bits), 8):
        byte = bits[b:b+8]
        chars.append(chr(int("".join(str(bit) for bit in byte), 2)))
    return "".join(chars)

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def bits_to_base64(bits):
    binary_string = ''.join(str(bit) for bit in bits)
    byte_array = bytearray()
    for i in range(0, len(binary_string), 8):
        byte_array.append(int(binary_string[i:i+8], 2))
    return base64.b64encode(byte_array).decode('utf-8')

def base64_to_bits(b64_str):
    byte_array = base64.b64decode(b64_str)
    bits = []
    for byte in byte_array:
        bits.extend([int(bit) for bit in bin(byte)[2:].zfill(8)])
    return bits

def des_encrypt(plain_text, key):
    key_bits = text_to_bits(key)
    keys = generate_keys(key_bits)
    plain_text = pad(plain_text)
    cipher_text_bits = []
    for i in range(0, len(plain_text), 8):
        block = plain_text[i:i+8]
        block_bits = text_to_bits(block)
        encrypted_bits = des_encrypt_block(block_bits, keys)
        cipher_text_bits.extend(encrypted_bits)
    return bits_to_base64(cipher_text_bits)

def des_decrypt(cipher_text, key):
    key_bits = text_to_bits(key)
    keys = generate_keys(key_bits)
    cipher_text_bits = base64_to_bits(cipher_text)
    plain_text_bits = []
    for i in range(0, len(cipher_text_bits), 64):
        block_bits = cipher_text_bits[i:i+64]
        decrypted_bits = des_decrypt_block(block_bits, keys)
        plain_text_bits.extend(decrypted_bits)
    return bits_to_text(plain_text_bits).rstrip()

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def des3_encrypt(plain_text, keys):
    key_bits = [text_to_bits(key) for key in keys]
    cipher_text_bits = text_to_bits(plain_text)
    cipher_text_bits = des_encrypt_block(cipher_text_bits, generate_keys(key_bits[0]))
    cipher_text_bits = des_decrypt_block(cipher_text_bits, generate_keys(key_bits[1]))
    cipher_text_bits = des_encrypt_block(cipher_text_bits, generate_keys(key_bits[2]))
    return bits_to_base64(cipher_text_bits)

def des3_decrypt(cipher_text, keys):
    key_bits = [text_to_bits(key) for key in keys]
    cipher_text_bits = base64_to_bits(cipher_text)
    plain_text_bits = des_decrypt_block(cipher_text_bits, generate_keys(key_bits[2]))
    plain_text_bits = des_encrypt_block(plain_text_bits, generate_keys(key_bits[1]))
    plain_text_bits = des_decrypt_block(plain_text_bits, generate_keys(key_bits[0]))
    return bits_to_text(plain_text_bits).rstrip()

if __name__ == "__main__":
    while True:
        action = input("What would you like to do? (1) DES Encrypt (2) DES Decrypt (3) 3DES Encrypt (4) 3DES Decrypt (5) Exit : ")
        if action == '1':
            key = input("Enter an 8-character DES key: ")
            plain_text = input("Enter the text to be encrypted: ")
            encrypted_text = des_encrypt(plain_text, key)
            print(f"Encrypted (DES): {encrypted_text}")
        elif action == '2':
            key = input("Enter an 8-character DES key: ")
            cipher_text = input("Enter the text to be decrypted: ")
            decrypted_text = des_decrypt(cipher_text, key)
            print(f"Decrypted (DES): {decrypted_text}")
        elif action == '3':
            keys = [input(f"Enter 8-character 3DES key {i+1}: ") for i in range(3)]
            plain_text = input("Enter the text to be encrypted: ")
            plain_text = pad(plain_text)
            encrypted_text = des3_encrypt(plain_text, keys)
            print(f"Encrypted (3DES): {encrypted_text}")
        elif action == '4':
            keys = [input(f"Enter 8-character 3DES key {i+1}: ") for i in range(3)]
            cipher_text = input("Enter the text to be decrypted: ")
            cipher_text = pad(cipher_text)
            decrypted_text = des3_decrypt(cipher_text, keys)
            print(f"Decrypted (3DES): {decrypted_text}")
        elif action == '5':
            break
        else:
            print("Invalid option selected.")