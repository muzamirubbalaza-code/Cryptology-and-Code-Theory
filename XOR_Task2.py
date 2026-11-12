
# Simplified XOR-based block cipher

# Given plaintext and secret key
P = "10110110"
K = "11001010"

# Convert binary strings to integers
plaintext = int(P, 2)
key = int(K, 2)

# Perform XOR encryption
ciphertext = plaintext ^ key

# Convert result back to 8-bit binary
C = format(ciphertext, '08b')

# Display results
print("Plaintext:  ", P)
print("Key:        ", K)
print("Ciphertext: ", C)
