 # Implementing error detection and correction in Python
def introduce_error(codeword, position):
    # Convert codeword into a list
    bits = list(map(int, codeword))

    # Flip the specified bit (positions start at 1)
    bits[position - 1] ^= 1

    return ''.join(map(str, bits))


def hamming_decode(received):
    bits = list(map(int, received))

    # Calculate syndrome bits using even parity
    C1 = bits[0] ^ bits[2] ^ bits[4] ^ bits[6]
    C2 = bits[1] ^ bits[2] ^ bits[5] ^ bits[6]
    C4 = bits[3] ^ bits[4] ^ bits[5] ^ bits[6]

    # Construct syndrome C4C2C1
    syndrome = f"{C4}{C2}{C1}"

    # Convert syndrome to decimal
    error_position = int(syndrome, 2)

    # Correct the error if one is detected
    if error_position != 0:
        bits[error_position - 1] ^= 1

    corrected = ''.join(map(str, bits))

    # Extract original data bits
    data = ''.join(str(bits[i]) for i in [2, 4, 5, 6])

    return syndrome, error_position, corrected, data


# Original codeword
original = "0110011"

# Introduce error at position 6
received = introduce_error(original, 6)

# Decode and correct
syndrome, position, corrected, data = hamming_decode(received)

print("Original codeword:", original)
print("Received codeword:", received)
print("Syndrome C4C2C1:", syndrome)
print("Error position:", position)
print("Corrected codeword:", corrected)
print("Recovered data:", data)
