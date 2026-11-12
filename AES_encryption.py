
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate a 128-bit (16-byte) AES key
key = get_random_bytes(16)

# Generate a 128-bit (16-byte) initialization vector
iv = get_random_bytes(16)

# Patient record (exactly 16 bytes)
patient_record = b"PATIENT123456789"

# Display original patient record
print("Original Patient Record:", patient_record)
print("Patient Record Length:", len(patient_record) * 8, "bits")

# Create AES-128 cipher in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the patient record
ciphertext = cipher.encrypt(pad(patient_record, AES.block_size))

# Display encryption results
print("\nAES-128 ENCRYPTION RESULTS")
print("Secret Key:", key.hex())
print("Initialization Vector:", iv.hex())
print("Ciphertext:", ciphertext.hex())

# Decryption
decipher = AES.new(key, AES.MODE_CBC, iv)

decrypted_record = unpad(
    decipher.decrypt(ciphertext),
    AES.block_size
)

print("\nDECRYPTION RESULTS")
print("Decrypted Patient Record:", decrypted_record)
