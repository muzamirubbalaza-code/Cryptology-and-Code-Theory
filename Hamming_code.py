
def hamming_encode(data):
    # Create an array of 7 bits
    code = [0] * 7

    # Insert the four data bits
    code[2] = int(data[0])
    code[4] = int(data[1])
    code[5] = int(data[2])
    code[6] = int(data[3])

    # Calculate parity bits using even parity
    code[0] = code[2] ^ code[4] ^ code[6]
    code[1] = code[2] ^ code[5] ^ code[6]
    code[3] = code[4] ^ code[5] ^ code[6]

    # Return the transmitted codeword
    return ''.join(map(str, code))


# Original data
data = "1011"

# Encode the data
codeword = hamming_encode(data)

print("Original data:", data)
print("Transmitted codeword:", codeword)
