
"""
TASK 3(e): SIMPLIFIED DIFFIE-HELLMAN KEY EXCHANGE

This program implements the Diffie-Hellman key exchange
algorithm using the following public parameters:

Prime number (p) = 23
Generator (g) = 5

The program:
1. Defines public parameters.
2. Generates Alice's and Bob's private keys.
3. Calculates their public keys.
4. Exchanges the public keys.
5. Calculates the shared secret independently.
6. Verifies that both parties have the same shared secret.
"""

# ==========================================================
# STEP 1: DEFINE PUBLIC PARAMETERS
# ==========================================================

# A prime number agreed upon by Alice and Bob.
p = 23

# A generator agreed upon by Alice and Bob.
g = 5

print("=" * 55)
print("DIFFIE-HELLMAN KEY EXCHANGE")
print("=" * 55)

print("\nPUBLIC PARAMETERS")
print("-----------------")
print("Prime number (p):", p)
print("Generator (g):", g)


# ==========================================================
# STEP 2: GENERATE PRIVATE KEYS
# ==========================================================

# Alice selects her private key.
# This number must remain secret.
alice_private_key = 6

# Bob selects his private key.
# This number must also remain secret.
bob_private_key = 15

print("\nPRIVATE KEYS")
print("------------")
print("Alice's Private Key:", alice_private_key)
print("Bob's Private Key:", bob_private_key)


# ==========================================================
# STEP 3: CALCULATE PUBLIC KEYS
# ==========================================================

# Alice calculates her public key using:
# A = g^a mod p

alice_public_key = pow(g, alice_private_key, p)

# Bob calculates his public key using:
# B = g^b mod p

bob_public_key = pow(g, bob_private_key, p)

print("\nPUBLIC KEYS")
print("-----------")
print("Alice's Public Key (A):", alice_public_key)
print("Bob's Public Key (B):", bob_public_key)


# ==========================================================
# STEP 4: EXCHANGE PUBLIC KEYS
# ==========================================================

# Alice sends her public key to Bob.
# Bob sends his public key to Alice.
#
# The public keys can be transmitted over an insecure
# communication channel because they do not reveal
# the private keys directly.

print("\nPUBLIC KEY EXCHANGE")
print("-------------------")

print("Alice sends public key:", alice_public_key)
print("Bob sends public key:", bob_public_key)


# ==========================================================
# STEP 5: CALCULATE THE SHARED SECRET
# ==========================================================

# Alice uses Bob's public key and her private key.
#
# Shared Secret = B^a mod p

alice_shared_secret = pow(
    bob_public_key,
    alice_private_key,
    p
)

# Bob uses Alice's public key and his private key.
#
# Shared Secret = A^b mod p

bob_shared_secret = pow(
    alice_public_key,
    bob_private_key,
    p
)

print("\nSHARED SECRET GENERATION")
print("------------------------")

print("Alice's Shared Secret:", alice_shared_secret)
print("Bob's Shared Secret:", bob_shared_secret)


# ==========================================================
# STEP 6: VERIFY THE SHARED SECRET
# ==========================================================

print("\nVERIFICATION")
print("------------")

# Check whether both parties calculated the same secret.

if alice_shared_secret == bob_shared_secret:

    print("Alice and Bob have successfully established")
    print("the same shared secret key.")

    print("\nShared Secret Key:", alice_shared_secret)

    print("\nSUCCESS: DIFFIE-HELLMAN KEY EXCHANGE VERIFIED!")

else:

    print("ERROR: The shared secrets do not match.")


# ==========================================================
# END OF PROGRAM
# ==========================================================
