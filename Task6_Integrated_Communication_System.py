
"""
TASK 6: INTEGRATED SECURE COMMUNICATION SYSTEM
Course: BCS 2104 - Cryptology and Code Theory

Scenario:
A rural clinic sends an encrypted patient report to a regional
referral hospital over an unreliable 3G network.

Cryptographic techniques implemented:
1. AES-128-CBC encryption
2. HKDF-SHA256 key derivation
3. HMAC-SHA256 message authentication
4. SHA-256 message digest
5. RSA-2048 digital signature using RSA-PSS
6. Hamming (7,4) error detection and correction
7. Simulated noisy communication channel


EDUCATIONAL NOTE:
This is a coursework prototype, not a production medical system.
The simulation assumes the IV, salt, HMAC tag and signature arrive
intact. Hamming (7,4) protects the ciphertext bytes.
"""

# ============================================================
# 1. IMPORT REQUIRED LIBRARIES
# ============================================================

import os
import hmac
import hashlib

from dataclasses import dataclass

# AES encryption and padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)

from cryptography.hazmat.primitives import padding

# HKDF key derivation
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Hashing algorithms
from cryptography.hazmat.primitives import hashes

# RSA key generation and digital signatures
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding as asymmetric_padding,
    utils
)

# Serialization is useful when exporting public keys
from cryptography.hazmat.primitives import serialization


# ============================================================
# 2. CONFIGURATION AND SHARED SESSION SECRET
# ============================================================

# The clinic and hospital share this secret securely beforehand.
#
# In a real system, this secret must not be written directly
# inside source code. It should be securely provisioned.
#
# HKDF will derive separate AES and HMAC keys from this secret.

SHARED_SESSION_SECRET = (
    b"MMU_Cryptology_Shared_Session_Secret_2026"
)

# AES-128 uses a 16-byte encryption key.
AES_KEY_LENGTH = 16

# HMAC-SHA256 will use a 32-byte authentication key.
HMAC_KEY_LENGTH = 32

# AES has a block size of 128 bits = 16 bytes.
AES_BLOCK_SIZE = 128

# Random IV length for AES-CBC is 16 bytes.
IV_LENGTH = 16

# HKDF salt length used in this demonstration.
SALT_LENGTH = 16


# ============================================================
# 3. GENERATE RSA KEYS FOR DIGITAL SIGNATURES
# ============================================================

def generate_rsa_keys():
    """
    Generate an RSA-2048 key pair.

    The rural clinic keeps the private key secret and uses it
    to sign the message digest.

    The regional hospital receives the trusted public key and
    uses it to verify the digital signature.

    RSA-2048 is used here for educational demonstration.
    """

    print("\nGENERATING RSA DIGITAL SIGNATURE KEYS")
    print("--------------------------------------")

    # Generate the RSA private key.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract the corresponding public key.
    public_key = private_key.public_key()

    print("RSA key pair generated successfully.")
    print("RSA key size: 2048 bits")

    return private_key, public_key


# ============================================================
# 4. DERIVE AES AND HMAC KEYS USING HKDF
# ============================================================

def derive_session_keys(shared_secret, salt):
    """
    Derive two independent cryptographic keys from the
    shared session secret using HKDF-SHA256.

    First 16 bytes  -> AES-128 encryption key
    Next 32 bytes   -> HMAC-SHA256 authentication key

    Using separate derived keys avoids directly reusing the
    same key for encryption and authentication.
    """

    # Total bytes required: 16 + 32 = 48 bytes.
    total_length = AES_KEY_LENGTH + HMAC_KEY_LENGTH

    # HKDF performs cryptographic key derivation.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=total_length,
        salt=salt,
        info=b"MMU-Telemedicine-Secure-Communication"
    )

    # Derive the 48 bytes from the shared secret.
    derived_key_material = hkdf.derive(shared_secret)

    # Separate the derived material into two keys.
    aes_key = derived_key_material[:AES_KEY_LENGTH]

    hmac_key = derived_key_material[AES_KEY_LENGTH:]

    return aes_key, hmac_key


# ============================================================
# 5. AES-128-CBC ENCRYPTION
# ============================================================

def aes_encrypt(plaintext, aes_key):
    """
    Encrypt the clinical report using AES-128-CBC.

    AES-CBC requires:
    - A 16-byte AES key.
    - A random 16-byte initialization vector (IV).
    - Plaintext padded to a multiple of 16 bytes.

    PKCS7 padding is used to make the plaintext fit the
    required AES block size.
    """

    # Generate a cryptographically secure random IV.
    iv = os.urandom(IV_LENGTH)

    # Create a PKCS7 padder for the AES block size.
    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()

    # Add padding to the plaintext.
    padded_plaintext = (
        padder.update(plaintext) + padder.finalize()
    )

    # Create AES in CBC mode.
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )

    # Create the encryption operation.
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext.
    ciphertext = (
        encryptor.update(padded_plaintext)
        + encryptor.finalize()
    )

    return iv, ciphertext


# ============================================================
# 6. AES-128-CBC DECRYPTION
# ============================================================

def aes_decrypt(ciphertext, aes_key, iv):
    """
    Decrypt ciphertext using AES-128-CBC and remove PKCS7
    padding to recover the original clinical report.
    """

    # Recreate the AES-CBC cipher using the same key and IV.
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )

    # Create the decryption operation.
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext.
    padded_plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    # Remove the PKCS7 padding.
    unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()

    plaintext = (
        unpadder.update(padded_plaintext)
        + unpadder.finalize()
    )

    return plaintext


# ============================================================
# 7. GENERATE HMAC-SHA256 AUTHENTICATION TAG
# ============================================================

def generate_hmac(hmac_key, salt, iv, ciphertext):
    """
    Generate an HMAC-SHA256 authentication tag.

    HMAC provides:
    - Message integrity: detects unauthorized modification.
    - Shared-secret authentication: verifies that the sender
      knows the shared authentication key.

    The tag covers the salt, IV and ciphertext.
    """

    authenticated_data = salt + iv + ciphertext

    authentication_tag = hmac.new(
        hmac_key,
        authenticated_data,
        hashlib.sha256
    ).digest()

    return authentication_tag


# ============================================================
# 8. SHA-256 MESSAGE DIGEST
# ============================================================

def calculate_message_digest(salt, iv, ciphertext, tag):
    """
    Calculate a SHA-256 digest over the packet information.

    The digest covers:
    - HKDF salt
    - AES initialization vector
    - Encrypted ciphertext
    - HMAC authentication tag

    The digest will be digitally signed using RSA.
    """

    packet_data = salt + iv + ciphertext + tag

    digest = hashlib.sha256(packet_data).digest()

    return digest


# ============================================================
# 9. RSA DIGITAL SIGNATURE
# ============================================================

def sign_message_digest(digest, private_key):
    """
    Sign the SHA-256 digest using the sender's RSA private key.

    RSA-PSS is used as the signature padding scheme.
    Prehashed tells the library that the SHA-256 digest
    has already been calculated.
    """

    signature = private_key.sign(
        digest,
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )

    return signature


def verify_digital_signature(digest, signature, public_key):
    """
    Verify the RSA digital signature using the sender's
    public key.

    If verification succeeds, the signature corresponds
    to the digest and the trusted public key.
    """

    try:
        public_key.verify(
            signature,
            digest,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )

        return True

    except Exception:
        return False


# ============================================================
# 10. HAMMING (7,4) ENCODER
# ============================================================

def hamming_encode_nibble(data_bits):
    """
    Encode four data bits into seven bits using Hamming (7,4).

    Bit positions:

        Position:  1  2  3  4  5  6  7
        Contents:  P1 P2 D1 P4 D2 D3 D4

    P1, P2 and P4 are parity bits.

    Even parity is used.
    """

    d1, d2, d3, d4 = data_bits

    # Calculate the three parity bits using XOR.
    p1 = d1 ^ d2 ^ d4

    p2 = d1 ^ d3 ^ d4

    p4 = d2 ^ d3 ^ d4

    # Construct the seven-bit codeword.
    codeword = [
        p1, p2, d1, p4, d2, d3, d4
    ]

    return codeword


def hamming_encode_bytes(data):
    """
    Convert each byte into two four-bit nibbles.

    Each nibble is encoded into seven bits.

    Therefore:
        1 byte = 8 original bits
        2 nibbles = 14 encoded bits

    The result is a longer bit sequence containing
    error-correction redundancy.
    """

    encoded_bits = []

    for byte in data:

        # Convert the byte into eight binary digits.
        binary = format(byte, "08b")

        # Split into two four-bit nibbles.
        first_nibble = [int(bit) for bit in binary[:4]]

        second_nibble = [int(bit) for bit in binary[4:]]

        # Encode both nibbles independently.
        encoded_bits.extend(
            hamming_encode_nibble(first_nibble)
        )

        encoded_bits.extend(
            hamming_encode_nibble(second_nibble)
        )

    return encoded_bits


# ============================================================
# 11. HAMMING (7,4) DECODER AND ERROR CORRECTION
# ============================================================

def hamming_decode_nibble(codeword):
    """
    Decode one seven-bit Hamming codeword.

    The syndrome identifies the position of a single-bit
    error.

    Syndrome calculation:

        S1 = bit1 XOR bit3 XOR bit5 XOR bit7
        S2 = bit2 XOR bit3 XOR bit6 XOR bit7
        S4 = bit4 XOR bit5 XOR bit6 XOR bit7

    Error position = S1 + 2*S2 + 4*S4

    If the syndrome is non-zero, the bit at that position
    is flipped to correct the error.
    """

    # Calculate syndrome bits using one-based positions.
    s1 = (
        codeword[0] ^ codeword[2]
        ^ codeword[4] ^ codeword[6]
    )

    s2 = (
        codeword[1] ^ codeword[2]
        ^ codeword[5] ^ codeword[6]
    )

    s4 = (
        codeword[3] ^ codeword[4]
        ^ codeword[5] ^ codeword[6]
    )

    # Convert the syndrome into an error position.
    error_position = s1 + (2 * s2) + (4 * s4)

    corrected = False

    # A non-zero syndrome indicates a detected error.
    if error_position != 0:

        # Flip the bit at the indicated position.
        # Python indexes start from zero, hence -1.
        codeword[error_position - 1] ^= 1

        corrected = True

    # Extract the four original data bits.
    data_bits = [
        codeword[2],
        codeword[4],
        codeword[5],
        codeword[6]
    ]

    return data_bits, corrected, error_position


def hamming_decode_bytes(encoded_bits):
    """
    Decode the complete encoded bit sequence.

    Every seven bits represent one Hamming codeword.
    Two decoded nibbles are combined into one byte.
    """

    if len(encoded_bits) % 7 != 0:
        raise ValueError("Invalid Hamming encoded bit length.")

    decoded_nibbles = []

    corrected_count = 0

    detected_positions = []

    # Process each seven-bit codeword.
    for index in range(0, len(encoded_bits), 7):

        codeword = encoded_bits[index:index + 7]

        decoded, corrected, error_position = (
            hamming_decode_nibble(codeword)
        )

        decoded_nibbles.append(decoded)

        if corrected:
            corrected_count += 1
            detected_positions.append(
                (index // 7, error_position)
            )

    # Reconstruct the original bytes from pairs of nibbles.
    decoded_bytes = bytearray()

    for index in range(0, len(decoded_nibbles), 2):

        first = "".join(
            str(bit) for bit in decoded_nibbles[index]
        )

        second = "".join(
            str(bit) for bit in decoded_nibbles[index + 1]
        )

        combined = first + second

        decoded_bytes.append(int(combined, 2))

    return bytes(decoded_bytes), corrected_count, detected_positions


# ============================================================
# 12. SIMULATE THE UNRELIABLE 3G NETWORK
# ============================================================

def simulate_noisy_channel(encoded_bits, error_index=None):
    """
    Simulate transmission over an unreliable communication
    channel.

    If error_index is provided, one encoded bit is flipped.

    For example:
        error_index = 10

    This changes the bit at zero-based index 10.

    If error_index is None, no deliberate error is introduced.
    """

    # Copy the transmitted data to avoid modifying the sender's
    # original encoded bit sequence.
    received_bits = encoded_bits.copy()

    if error_index is not None:

        if not 0 <= error_index < len(received_bits):
            raise ValueError("Error index is outside the bit sequence.")

        # Simulate one transmission error using XOR.
        received_bits[error_index] ^= 1

        print("\nNETWORK ERROR SIMULATION")
        print("------------------------")
        print("A single bit was flipped during transmission.")
        print("Corrupted bit index:", error_index)

    else:

        print("\nNETWORK TRANSMISSION")
        print("--------------------")
        print("No deliberate transmission error was introduced.")

    return received_bits


# ============================================================
# 13. SENDER: PREPARE AND TRANSMIT A SECURE PACKET
# ============================================================

@dataclass
class SecurePacket:
    """
    Container holding the information transmitted from
    the rural clinic to the regional referral hospital.

    The ciphertext is Hamming encoded before transmission.
    """

    salt: bytes
    iv: bytes
    encoded_ciphertext: list
    hmac_tag: bytes
    signature: bytes


def sender_prepare_packet(
    plaintext,
    shared_secret,
    sender_private_key
):
    """
    Complete sender-side operations:

    1. Generate a random HKDF salt.
    2. Derive AES and HMAC keys.
    3. Encrypt plaintext with AES-128-CBC.
    4. Generate HMAC-SHA256.
    5. Calculate SHA-256 digest.
    6. Digitally sign the digest using RSA.
    7. Encode ciphertext using Hamming (7,4).
    8. Package the transmitted information.
    """

    print("\nSENDER: RURAL CLINIC")
    print("====================")

    # Step 1: Generate a random salt.
    salt = os.urandom(SALT_LENGTH)

    # Step 2: Derive separate encryption and authentication keys.
    aes_key, hmac_key = derive_session_keys(
        shared_secret,
        salt
    )

    print("AES-128 key derived successfully.")
    print("HMAC-SHA256 key derived successfully.")

    # Step 3: Encrypt the clinical report.
    iv, ciphertext = aes_encrypt(
        plaintext,
        aes_key
    )

    print("Clinical report encrypted using AES-128-CBC.")

    # Step 4: Generate an HMAC authentication tag.
    tag = generate_hmac(
        hmac_key,
        salt,
        iv,
        ciphertext
    )

    print("HMAC-SHA256 authentication tag generated.")

    # Step 5: Calculate the SHA-256 digest.
    digest = calculate_message_digest(
        salt,
        iv,
        ciphertext,
        tag
    )

    print("SHA-256 message digest calculated.")

    # Step 6: Sign the digest using the RSA private key.
    signature = sign_message_digest(
        digest,
        sender_private_key
    )

    print("RSA digital signature generated.")

    # Step 7: Encode ciphertext using Hamming (7,4).
    encoded_ciphertext = hamming_encode_bytes(ciphertext)

    print("Ciphertext encoded using Hamming (7,4).")

    print("Original ciphertext size:", len(ciphertext), "bytes")
    print("Hamming encoded size:", len(encoded_ciphertext), "bits")

    # Step 8: Package the data for transmission.
    packet = SecurePacket(
        salt=salt,
        iv=iv,
        encoded_ciphertext=encoded_ciphertext,
        hmac_tag=tag,
        signature=signature
    )

    return packet


# ============================================================
# 14. RECEIVER: RECEIVE, VERIFY AND DECRYPT
# ============================================================

def receiver_process_packet(
    packet,
    shared_secret,
    sender_public_key,
    error_index=None
):
    """
    Complete receiver-side operations:

    1. Receive encoded ciphertext.
    2. Simulate the network.
    3. Decode and correct Hamming errors.
    4. Derive the same AES and HMAC keys.
    5. Verify the RSA digital signature.
    6. Verify HMAC-SHA256.
    7. Decrypt the ciphertext.
    8. Recover the original clinical report.

    The receiver stops if signature or HMAC verification fails.
    """

    print("\nRECEIVER: REGIONAL REFERRAL HOSPITAL")
    print("====================================")

    # Step 1 and 2: Receive the encoded ciphertext and simulate
    # transmission over the network.
    received_bits = simulate_noisy_channel(
        packet.encoded_ciphertext,
        error_index
    )

    # Step 3: Decode and correct transmission errors.
    recovered_ciphertext, corrected_count, positions = (
        hamming_decode_bytes(received_bits)
    )

    print("\nHAMMING ERROR CORRECTION")
    print("------------------------")
    print("Number of corrected codeword errors:", corrected_count)

    if corrected_count > 0:
        print("Corrected codeword positions:", positions)
    else:
        print("No Hamming errors detected.")

    # Step 4: Derive the same keys using the shared secret
    # and the salt received in the packet.
    aes_key, hmac_key = derive_session_keys(
        shared_secret,
        packet.salt
    )

    print("\nSession keys successfully derived at receiver.")

    # Step 5: Recalculate the digest using the recovered
    # ciphertext and the received authentication tag.
    received_digest = calculate_message_digest(
        packet.salt,
        packet.iv,
        recovered_ciphertext,
        packet.hmac_tag
    )

    # Verify the digital signature using the trusted public key.
    signature_valid = verify_digital_signature(
        received_digest,
        packet.signature,
        sender_public_key
    )

    print("\nDIGITAL SIGNATURE VERIFICATION")
    print("------------------------------")

    if not signature_valid:

        print("RSA signature verification FAILED.")
        print("Message rejected. Decryption will not continue.")

        return None

    print("RSA signature verification SUCCESSFUL.")

    # Step 6: Recalculate the HMAC using the recovered data.
    expected_tag = generate_hmac(
        hmac_key,
        packet.salt,
        packet.iv,
        recovered_ciphertext
    )

    # Compare authentication tags safely.
    hmac_valid = hmac.compare_digest(
        expected_tag,
        packet.hmac_tag
    )

    print("\nHMAC AUTHENTICATION")
    print("-------------------")

    if not hmac_valid:

        print("HMAC verification FAILED.")
        print("Message integrity could not be established.")

        return None

    print("HMAC-SHA256 verification SUCCESSFUL.")
    print("Message integrity and shared-secret authentication verified.")

    # Step 7: Decrypt only after the security checks succeed.
    try:

        plaintext = aes_decrypt(
            recovered_ciphertext,
            aes_key,
            packet.iv
        )

    except Exception as error:

        print("Decryption failed:", error)

        return None

    # Step 8: Display the recovered clinical report.
    print("\nDECRYPTED CLINICAL REPORT")
    print("------------------------")
    print(plaintext.decode("utf-8"))

    print("\nTRANSMISSION SUCCESSFUL.")
    print("The hospital recovered the original clinical report.")

    return plaintext


# ============================================================
# 15. MAIN PROGRAM: TEST THE COMPLETE SYSTEM
# ============================================================

def main():

    print("=" * 65)
    print("INTEGRATED SECURE TELEMEDICINE COMMUNICATION SYSTEM")
    print("BCS 2104 - CRYPTOLOGY AND CODE THEORY")
    print("=" * 65)

    # Sample clinical report.
    #
    # This is fictional demonstration data, not a real patient record.
    clinical_report = (
        "Patient ID: PATIENT001\n"
        "Diagnosis: MCI\n"
        "Clinic: Rural Health Centre\n"
        "Referral: MRI review required"
    )

    plaintext = clinical_report.encode("utf-8")

    print("\nORIGINAL CLINICAL REPORT")
    print("------------------------")
    print(clinical_report)

    # Generate RSA keys for the clinic.
    sender_private_key, sender_public_key = generate_rsa_keys()

    # --------------------------------------------------------
    # TEST 1: SUCCESSFUL TRANSMISSION WITHOUT A BIT ERROR
    # --------------------------------------------------------

    print("\n\n")
    print("#" * 65)
    print("TEST 1: NORMAL SECURE TRANSMISSION")
    print("#" * 65)

    # The sender encrypts, authenticates, signs and encodes
    # the clinical report.
    packet1 = sender_prepare_packet(
        plaintext,
        SHARED_SESSION_SECRET,
        sender_private_key
    )

    # The receiver processes the packet without a deliberate
    # transmission error.
    recovered1 = receiver_process_packet(
        packet1,
        SHARED_SESSION_SECRET,
        sender_public_key,
        error_index=None
    )

    # Confirm that the received message matches the original.
    print("\nTEST 1 RESULT")
    print("-------------")

    if recovered1 == plaintext:

        print("PASS: Original message successfully recovered.")

    else:

        print("FAIL: Recovered message does not match original.")

    # --------------------------------------------------------
    # TEST 2: TRANSMISSION WITH A SINGLE-BIT ERROR
    # --------------------------------------------------------

    print("\n\n")
    print("#" * 65)
    print("TEST 2: TRANSMISSION WITH A SINGLE-BIT ERROR")
    print("#" * 65)

    # Prepare another secure packet.
    #
    # A new salt and IV are generated, so this is a new
    # encryption operation.
    packet2 = sender_prepare_packet(
        plaintext,
        SHARED_SESSION_SECRET,
        sender_private_key
    )

    # Choose a bit position in the encoded ciphertext.
    # The network will flip exactly one bit at this position.
    deliberate_error_index = 17

    # The receiver corrects the single-bit error using Hamming
    # (7,4), verifies the signature and HMAC, and decrypts.
    recovered2 = receiver_process_packet(
        packet2,
        SHARED_SESSION_SECRET,
        sender_public_key,
        error_index=deliberate_error_index
    )

    # Confirm that error correction recovered the original.
    print("\nTEST 2 RESULT")
    print("-------------")

    if recovered2 == plaintext:

        print("PASS: Single-bit error corrected successfully.")
        print("PASS: Original clinical report recovered.")

    else:

        print("FAIL: The original message was not recovered.")

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n\n")
    print("=" * 65)
    print("FINAL SYSTEM TEST SUMMARY")
    print("=" * 65)

    print("AES-128-CBC encryption: Implemented")
    print("Random initialization vector: Implemented")
    print("HKDF-SHA256 key derivation: Implemented")
    print("HMAC-SHA256 authentication: Implemented")
    print("SHA-256 message digest: Implemented")
    print("RSA-2048 digital signature: Implemented")
    print("Hamming (7,4) encoding: Implemented")
    print("Hamming single-bit correction: Implemented")
    print("Simulated noisy network: Implemented")

    print("\nNormal transmission:", 
          "SUCCESS" if recovered1 == plaintext else "FAILED")

    print("Single-bit error transmission:",
          "SUCCESS" if recovered2 == plaintext else "FAILED")

    print("\nEND OF TASK 6 DEMONSTRATION")
    print("=" * 65)


# ============================================================
# 16. EXECUTE THE PROGRAM
# ============================================================

if __name__ == "__main__":
    main()
