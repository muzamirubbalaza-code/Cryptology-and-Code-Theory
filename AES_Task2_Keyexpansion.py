
# AES-128 Key Expansion Algorithm

# AES finite-field multiplication
def gf_multiply(a, b):
    result = 0

    while b:
        if b & 1:
            result ^= a

        a <<= 1

        if a & 0x100:
            a ^= 0x11B

        b >>= 1

    return result & 0xFF


# Rotate an 8-bit byte left
def rotate_byte(value, n):
    return ((value << n) | (value >> (8 - n))) & 0xFF


# Generate AES S-box mathematically
def generate_sbox():
    sbox = []

    for value in range(256):

        if value == 0:
            inverse = 0
        else:
            inverse = 1
            base = value
            exponent = 254

            while exponent:
                if exponent & 1:
                    inverse = gf_multiply(inverse, base)

                base = gf_multiply(base, base)
                exponent >>= 1

        substituted = (
            inverse ^
            rotate_byte(inverse, 1) ^
            rotate_byte(inverse, 2) ^
            rotate_byte(inverse, 3) ^
            rotate_byte(inverse, 4) ^
            0x63
        )

        sbox.append(substituted)

    return sbox


SBOX = generate_sbox()


# AES-128 key expansion
def aes128_key_expansion(key):

    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")

    # Split key into four initial words
    words = [
        list(key[i:i+4])
        for i in range(0, 16, 4)
    ]

    # Round constants
    rcon = [
        0x00, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    ]

    # Generate 44 words
    for i in range(4, 44):

        temp = words[i - 1].copy()

        if i % 4 == 0:

            # RotWord
            temp = temp[1:] + temp[:1]

            # SubWord
            temp = [SBOX[b] for b in temp]

            # XOR with round constant
            temp[0] ^= rcon[i // 4]

        # XOR with word four positions earlier
        new_word = [
            words[i - 4][j] ^ temp[j]
            for j in range(4)
        ]

        words.append(new_word)

    # Combine four words to create each round key
    round_keys = []

    for round_number in range(11):

        round_key = []

        for word in words[round_number * 4:
                          round_number * 4 + 4]:

            round_key.extend(word)

        round_keys.append(bytes(round_key))

    return round_keys


# Standard test AES-128 key
key = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)

# Generate all round keys
round_keys = aes128_key_expansion(key)

# Display original key and first two rounds
for i in range(3):

    print(
        f"Round Key {i}:",
        round_keys[i].hex()
    )

# Display total number of round keys
print("\nTotal Round Keys:", len(round_keys))
