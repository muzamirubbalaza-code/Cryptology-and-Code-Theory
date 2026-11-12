
# RSA KEY GENERATION, ENCRYPTION AND DECRYPTION

# PART A: RSA KEY GENERATION

# Step 1: Choose two prime numbers
p = 11
q = 13

# Step 2: Calculate modulus n
n = p * q

# Step 3: Calculate Euler's Totient Function
phi_n = (p - 1) * (q - 1)

# Step 4: Choose public exponent e
e = 7

# Step 5: Calculate private exponent d
# d is the modular multiplicative inverse of e modulo phi_n
d = pow(e, -1, phi_n)

# Display generated keys
print("RSA KEY GENERATION")
print("-------------------")
print("Prime p:", p)
print("Prime q:", q)
print("Modulus n:", n)
print("Euler's Totient φ(n):", phi_n)
print("Public exponent e:", e)
print("Private exponent d:", d)

print("\nPublic Key:", (e, n))
print("Private Key:", (d, n))


# PART B: RSA ENCRYPTION

# Original message
M = 7

# Encrypt using public key
# C = M^e mod n
C = pow(M, e, n)

print("\nRSA ENCRYPTION")
print("--------------")
print("Original Message:", M)
print("Encrypted Ciphertext:", C)


# PART C: RSA DECRYPTION

# Decrypt using private key
# M = C^d mod n
decrypted_message = pow(C, d, n)

print("\nRSA DECRYPTION")
print("--------------")
print("Ciphertext:", C)
print("Decrypted Message:", decrypted_message)


# PART D: VERIFICATION

if decrypted_message == M:
    print("\nSUCCESS: RSA encryption and decryption verified!")
else:
    print("\nERROR: Decryption verification failed.")
