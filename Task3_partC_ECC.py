
"""
TASK 3(c): ELLIPTIC CURVE CRYPTOGRAPHY (ECC) AND ECIES

This program:
1. Generates an ECC key pair using the NIST P-256 curve.
2. Implements an ECIES-style encryption process.
3. Uses ECDH to establish a shared secret.
4. Uses HKDF to derive an AES encryption key.
5. Encrypts a message using AES-256-GCM.
6. Decrypts the ciphertext and verifies the original message.

Library: cryptography
Curve: SECP256R1 (NIST P-256)
"""

# Import ECC-related functions
from cryptography.hazmat.primitives.asymmetric import ec

# Import ECDH key exchange algorithm
from cryptography.hazmat.primitives import hashes

# Import HKDF for deriving a symmetric encryption key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Import AES-GCM for authenticated encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import secure random number generation
import os


# ==========================================================
# PART 1: ECC KEY GENERATION USING THE P-256 CURVE
# ==========================================================

print("=" * 60)
print("ELLIPTIC CURVE CRYPTOGRAPHY (ECC) KEY GENERATION")
print("=" * 60)

# Generate the receiver's private key using the P-256 curve.
# The private key is a randomly generated secret number.
receiver_private_key = ec.generate_private_key(ec.SECP256R1())

# Derive the corresponding public key.
# The public key can safely be shared with other parties.
receiver_public_key = receiver_private_key.public_key()

# Display the curve used
print("Elliptic Curve: NIST P-256 (SECP256R1)")

# Display the receiver's public key coordinates.
# We do not display the private key because it must remain secret.
public_numbers = receiver_public_key.public_numbers()

print("\nReceiver's Public Key:")
print("X coordinate:", hex(public_numbers.x))
print("Y coordinate:", hex(public_numbers.y))

print("\nECC key pair generated successfully!")


# ==========================================================
# PART 2: ECIES-STYLE ENCRYPTION
# ==========================================================

print("\n" + "=" * 60)
print("ECIES-STYLE MESSAGE ENCRYPTION")
print("=" * 60)

# Define the original message to be encrypted.
message = b"Hello, Cryptology!"

print("Original Message:", message.decode("utf-8"))

# STEP 1: Generate an ephemeral ECC key pair.
# An ephemeral key is a temporary key generated for one
# encryption operation. It provides forward secrecy when
# used correctly in this construction.

ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())

# Obtain the ephemeral public key.
ephemeral_public_key = ephemeral_private_key.public_key()

print("\nEphemeral ECC key pair generated.")


# STEP 2: Perform Elliptic Curve Diffie-Hellman (ECDH).
#
# The sender combines their ephemeral private key with
# the receiver's public key to obtain a shared secret.

sender_shared_secret = ephemeral_private_key.exchange(
    ec.ECDH(),
    receiver_public_key
)

print("Sender's shared secret generated using ECDH.")


# STEP 3: Generate a random salt for HKDF.
# The salt is not required to be secret.
# It helps derive a cryptographically secure AES key.

salt = os.urandom(16)

# Define context information for the key derivation process.
info = b"ECIES-P256-AES256GCM"

# Use HKDF with SHA-256 to derive a 32-byte AES key.
sender_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info
).derive(sender_shared_secret)

print("AES-256 encryption key derived using HKDF.")


# STEP 4: Generate a 12-byte random nonce for AES-GCM.
# A unique nonce must be used for every encryption with
# the same AES key.

nonce = os.urandom(12)

# Define associated authenticated data.
# This data is authenticated but is not encrypted.

associated_data = b"ECIES-P256-AES256GCM"


# STEP 5: Encrypt the original message using AES-256-GCM.
# AESGCM.encrypt() returns the ciphertext with its
# authentication tag appended.

aesgcm = AESGCM(sender_aes_key)

ciphertext = aesgcm.encrypt(
    nonce,
    message,
    associated_data
)

print("\nMessage encrypted successfully!")
print("Nonce:", nonce.hex())
print("Salt:", salt.hex())
print("Ciphertext:", ciphertext.hex())


# ==========================================================
# PART 3: ECIES-STYLE DECRYPTION
# ==========================================================

print("\n" + "=" * 60)
print("ECIES-STYLE MESSAGE DECRYPTION")
print("=" * 60)

# STEP 1: The receiver uses their private key and the
# sender's ephemeral public key to independently
# calculate the same ECDH shared secret.

receiver_shared_secret = receiver_private_key.exchange(
    ec.ECDH(),
    ephemeral_public_key
)

print("Receiver's shared secret generated using ECDH.")


# STEP 2: Derive the AES key using the same HKDF settings.
# The receiver must use the same salt and info values.

receiver_aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info
).derive(receiver_shared_secret)

print("Receiver's AES-256 key derived using HKDF.")


# STEP 3: Decrypt the ciphertext using AES-GCM.
# AES-GCM also verifies the authentication tag.
# If the ciphertext or authentication data is modified,
# decryption will fail.

receiver_aesgcm = AESGCM(receiver_aes_key)

decrypted_message = receiver_aesgcm.decrypt(
    nonce,
    ciphertext,
    associated_data
)

print("\nDecryption successful!")
print("Decrypted Message:", decrypted_message.decode("utf-8"))


# ==========================================================
# PART 4: VERIFICATION
# ==========================================================

print("\n" + "=" * 60)
print("ECC AND ECIES VERIFICATION")
print("=" * 60)

# Confirm that both parties derived the same shared secret.
print(
    "ECDH Shared Secrets Match:",
    sender_shared_secret == receiver_shared_secret
)

# Confirm that both parties derived the same AES key.
print(
    "AES Keys Match:",
    sender_aes_key == receiver_aes_key
)

# Confirm that the decrypted message matches the original.
if decrypted_message == message:
    print("Original and Decrypted Messages Match: True")
    print("\nSUCCESS: ECC AND ECIES IMPLEMENTATION VERIFIED!")
else:
    print("Original and Decrypted Messages Match: False")
    print("\nERROR: MESSAGE VERIFICATION FAILED!")
