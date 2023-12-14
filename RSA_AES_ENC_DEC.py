from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# =========================================================================
# RSA keys generation
# =========================================================================

# Generate an RSA key pair for sender
rsa_key_s = RSA.generate(2048)

# Get the public key and private key for RSA for sender
public_key_s = rsa_key_s.publickey()
private_key_s = rsa_key_s.export_key()

# Generate an RSA key pair for reciever
rsa_key_r = RSA.generate(2048)

# Get the public key and private key for RSA for reciever
public_key_r = rsa_key_r.publickey()
private_key_r = rsa_key_r.export_key()

# =========================================================================
# AES key exchange
# =========================================================================

# Get AES key from the user
print("")
aes_key = input("Enter your AES-key (16 bytes): ").encode('utf-8')
if len(aes_key) != 16:
    raise ValueError("Key must be 16 bytes long.")

# Create an RSA cipher object for encryption of the AES key
cipher_rsa_s_key = PKCS1_OAEP.new(public_key_r)

# Encrypt the AES key with RSA
encrypted_aes_key = cipher_rsa_s_key.encrypt(aes_key)
print("")
print("Encrypted AES key:")
print(encrypted_aes_key)
print("")

# Create an RSA cipher object for decryption of the AES key
cipher_rsa_r_key = PKCS1_OAEP.new(RSA.import_key(private_key_r))

# Decrypt the AES key with RSA
decrypted_aes_key = cipher_rsa_r_key.decrypt(encrypted_aes_key)
print("Decrypted AES key:", decrypted_aes_key.decode('utf-8'))
print("")

# =========================================================================
# get plaintext from the user and paths for required files
# =========================================================================

data_path = input("Enter the path of the file of your data: ")
print("")
if data_path[0] == '"' and data_path[-1] == '"':
    data_path = data_path[1:-1]

enc_path = input("Enter the path of the encrypted file: ")
print("")
if enc_path[0] == '"' and enc_path[-1] == '"':
    enc_path = enc_path[1:-1]

dec_path = input("Enter the path of the decrypted file: ")
print("")
if dec_path[0] == '"' and dec_path[-1] == '"':
    dec_path = dec_path[1:-1]

# =========================================================================
# sending the data
# =========================================================================

# Encrypt the plaintext with RSA

# Open a file for reading
with open(data_path, 'r') as file:
    # Read the entire file content
    plaintext = file.read()

print("Your entered data:")
print(plaintext)
print("")

# Create an RSA cipher object for encryption of the plaintext
cipher_rsa_s_plain = PKCS1_OAEP.new(public_key_r)

# Encrypt the plaintext with RSA
encrypted_aes_plain = cipher_rsa_s_plain.encrypt(plaintext.encode('utf-8'))
print("Encrypted data with RSA:")
print(encrypted_aes_plain)
print("")

# Encrypt with AES the plaintext encrypted by RSA

# Create an AES cipher object
cipher_aes_s_plain = AES.new(decrypted_aes_key, AES.MODE_EAX)

# Encrypt the plaintext
ciphertext_ENC, tag = cipher_aes_s_plain.encrypt_and_digest(encrypted_aes_plain)
nonce = cipher_aes_s_plain.nonce

# Open a file for writing
with open(enc_path, 'w') as file:
    # Write content to the file
    file.write(ciphertext_ENC.hex())

print("Encrypted data with AES:")
print(ciphertext_ENC)
print("")

# =========================================================================
# receiving the data
# =========================================================================

# Create another AES cipher object for decryption
cipher_aes_r_plain = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce)

# Decrypt the data
ciphertext_DEC = cipher_aes_r_plain.decrypt_and_verify(ciphertext_ENC, tag)
print("Decrypted data with AES:")
print(ciphertext_DEC)
print("")

# Create an RSA cipher object for decryption of the AES plaintext
cipher_rsa_r_plain = PKCS1_OAEP.new(RSA.import_key(private_key_r))

# Decrypt the plaintext with RSA
decrypted_plain = cipher_rsa_r_plain.decrypt(ciphertext_DEC)

# Open a file for writing
with open(dec_path, 'w') as file:
    # Write content to the file
    file.write(decrypted_plain.decode('utf-8'))

print("Decrypted data with RSA (your original data):")
print("")
print(decrypted_plain.decode('utf-8'))
print("")
