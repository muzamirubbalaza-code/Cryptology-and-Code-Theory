
"""
TASK 4(a): SHA-256 HASHING AND AVALANCHE EFFECT

This program:
1. Defines an original message.
2. Creates a modified message by changing one character.
3. Computes the SHA-256 hash of each message.
4. Displays both hash values.
5. Compares the hashes to demonstrate the avalanche effect.
6. Counts the number of changed bits between the hashes.
"""

# Import hashlib to access the SHA-256 hashing algorithm.
import hashlib


# STEP 1: Define the original message.
original_message = "Patient: John Doe, Diagnosis: MCI"

# STEP 2: Modify the message by adding one full stop.
# This represents a change of only one character.
modified_message = "Patient: John Doe, Diagnosis: MCI."


# STEP 3: Convert each message into bytes and calculate
# its SHA-256 hash using hashlib.sha256().

original_hash = hashlib.sha256(
    original_message.encode("utf-8")
).hexdigest()

modified_hash = hashlib.sha256(
    modified_message.encode("utf-8")
).hexdigest()


# STEP 4: Display the original and modified messages
# together with their corresponding SHA-256 hashes.

print("=" * 65)
print("SHA-256 HASHING AND AVALANCHE EFFECT")
print("=" * 65)

print("\nORIGINAL MESSAGE:")
print(original_message)

print("\nSHA-256 HASH OF ORIGINAL MESSAGE:")
print(original_hash)

print("\nMODIFIED MESSAGE:")
print(modified_message)

print("\nSHA-256 HASH OF MODIFIED MESSAGE:")
print(modified_hash)


# STEP 5: Compare the two hash values.
# If they are different, the one-character change has
# produced a different hash output.

print("\nHASH COMPARISON")
print("----------------")

if original_hash != modified_hash:
    print("The two hash values are different.")
else:
    print("The two hash values are identical.")


# STEP 6: Demonstrate the avalanche effect by counting
# the number of bits that changed between the two hashes.
#
# Convert hexadecimal hashes into bytes, then use XOR
# to identify different bits in corresponding bytes.

original_bytes = bytes.fromhex(original_hash)
modified_bytes = bytes.fromhex(modified_hash)

# XOR produces 1 wherever corresponding bits differ.
# bit_count() counts the number of set bits in the result.

changed_bits = sum(
    (byte1 ^ byte2).bit_count()
    for byte1, byte2 in zip(original_bytes, modified_bytes)
)

# SHA-256 produces 256 bits in total.
total_bits = 256

# Calculate the percentage of changed bits.
percentage_changed = (changed_bits / total_bits) * 100

print("\nAVALANCHE EFFECT ANALYSIS")
print("------------------------")
print("Total hash bits:", total_bits)
print("Number of changed bits:", changed_bits)
print("Percentage of changed bits:", round(percentage_changed, 2), "%")

print("\nSUCCESS: SHA-256 HASHING COMPLETED!")
