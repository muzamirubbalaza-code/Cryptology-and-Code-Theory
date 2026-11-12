
"""
TASK 4(b): HMAC-SHA256 IMPLEMENTATION

This program:
1. Defines a message and a shared secret key.
2. Generates an HMAC-SHA256 authentication code.
3. Verifies the authenticity and integrity of the message.
4. Modifies the original message to simulate tampering.
5. Demonstrates that the modified message fails verification.

Libraries:
- hashlib: Provides SHA-256.
- hmac: Provides HMAC authentication.
"""

# Import hashlib for SHA-256 hashing.
import hashlib

# Import hmac for generating and verifying HMAC codes.
import hmac


# ==========================================================
# STEP 1: DEFINE THE MESSAGE AND SHARED SECRET KEY
# ==========================================================

# This is the original message to be authenticated.
message = b"Patient: John Doe, Diagnosis: MCI"

# This is the shared secret key known to both sender
# and receiver. In real systems, it must remain confidential.
secret_key = b"CryptologyCourseworkSharedSecret2026"


# ==========================================================
# STEP 2: GENERATE THE HMAC-SHA256 AUTHENTICATION CODE
# ==========================================================

# hmac.new() combines the secret key and message
# using the SHA-256 hashing algorithm.
#
# The result is an HMAC authentication object.
hmac_object = hmac.new(
    secret_key,
    message,
    hashlib.sha256
)

# Convert the generated HMAC into hexadecimal format.
authentication_code = hmac_object.hexdigest()


# ==========================================================
# STEP 3: DISPLAY THE ORIGINAL MESSAGE AND HMAC
# ==========================================================

print("=" * 65)
print("HMAC-SHA256 MESSAGE AUTHENTICATION")
print("=" * 65)

print("\nORIGINAL MESSAGE:")
print(message.decode("utf-8"))

print("\nSHARED SECRET KEY:")
print(secret_key.decode("utf-8"))

print("\nGENERATED HMAC-SHA256:")
print(authentication_code)


# ==========================================================
# STEP 4: VERIFY THE MESSAGE AUTHENTICITY
# ==========================================================

# The receiver independently generates an HMAC using
# the received message and the same shared secret key.

receiver_hmac = hmac.new(
    secret_key,
    message,
    hashlib.sha256
).hexdigest()

# compare_digest() safely compares the two authentication
# codes and helps prevent timing-based comparison attacks.

verification_result = hmac.compare_digest(
    authentication_code,
    receiver_hmac
)

print("\nMESSAGE AUTHENTICATION")
print("----------------------")

if verification_result:
    print("HMAC verification: SUCCESS")
    print("Message integrity is maintained.")
    print("The message was authenticated using the shared key.")
else:
    print("HMAC verification: FAILED")
    print("The message may have been modified.")


# ==========================================================
# STEP 5: SIMULATE MESSAGE TAMPERING
# ==========================================================

# Modify the original message by changing MCI to AD.
# This simulates an unauthorized modification.

modified_message = b"Patient: John Doe, Diagnosis: AD"

# The receiver calculates a new HMAC using the modified
# message and the same secret key.

modified_hmac = hmac.new(
    secret_key,
    modified_message,
    hashlib.sha256
).hexdigest()

print("\nTAMPERING SIMULATION")
print("--------------------")

print("Modified Message:")
print(modified_message.decode("utf-8"))

print("\nHMAC of Modified Message:")
print(modified_hmac)


# ==========================================================
# STEP 6: CHECK WHETHER THE MODIFIED MESSAGE IS AUTHENTIC
# ==========================================================

# Compare the original authentication code with the
# authentication code generated for the modified message.

tampering_detected = not hmac.compare_digest(
    authentication_code,
    modified_hmac
)

if tampering_detected:
    print("\nTAMPERING DETECTED!")
    print("The authentication codes do not match.")
    print("The modified message has failed verification.")
else:
    print("\nNo tampering detected.")


# ==========================================================
# END OF PROGRAM
# ==========================================================
