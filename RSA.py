from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

#Generate private key (n, d) and public key (n, e) of size 1024 bits
#Public exponent, e = 65537
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)
public_key = private_key.public_key()

print("RSA Key Generation")
print("Public exponent (e):", 65537)
print("Key size (bits):", public_key.key_size)

public_numbers = public_key.public_numbers()
private_numbers = private_key.private_numbers()

n = public_numbers.n #modulus n = p * q
e = public_numbers.e #public exponent, e
d = private_numbers.d #private exponent, d
p = private_numbers.p #first prime number
q = private_numbers.q #second prime number

#Compute totient
totient = (p - 1) * (q - 1)

print("\nInternal RSA Parameters")
print(f"p (prime 1): {p}")
print(f"q (prime 2): {q}")
print(f"n = p * q (modulus): {n}")
print(f"Phi(n) = (p-1)*(q-1): {totient}")
print(f"e (public exponent): {e}")
print(f"d (private exponent): {d}")
print(f"e * d mod Phi(n): {(e * d) % totient}")

message = b"Hello SC4010"

#Encryption
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), # mask generation function
        algorithm=hashes.SHA256(), # hash algorithm
        label=None
    )
)

print("\nEncryption")
print("Plaintext (bytes):", message)
print("Plaintext (hex):", message.hex())
print("Ciphertext (bytes):", ciphertext)
print("Ciphertext (hex):", ciphertext.hex())

#Decryption
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\nDecryption")
print("Recovered plaintext (bytes):", plaintext)
print("Recovered plaintext (hex):", plaintext.hex())
print("Decoded message (string):", plaintext.decode())
