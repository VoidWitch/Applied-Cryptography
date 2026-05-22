import json
from pathlib import Path
import importlib.util, sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# RSA
def rsa_keygen(pub_path: str, priv_path: str, bits: int = 1024):
    print("\n [STEP 1] RSA Key Generation")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    public_numbers = public_key.public_numbers()
    private_numbers = private_key.private_numbers()

    p, q = private_numbers.p, private_numbers.q
    n = public_numbers.n
    e = public_numbers.e
    d = private_numbers.d
    phi_n = (p - 1) * (q - 1)

    print(f"   Prime 1, p: {p}")
    print(f"   Prime 2, q: {q}")
    print(f"   Modulus, n = p * q: {n}")
    print(f"   Euler's totient, φ(n) = (p−1)(q−1): {phi_n}")
    print(f"   Public exponent, e: {e}")
    print(f"   Private exponent, d: {d}")
    print(f"   Check: e * d mod φ(n) = {(e*d) % phi_n}")

    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(priv_path).write_bytes(pem_priv)
    Path(pub_path).write_bytes(pem_pub)
    print("   RSA key pair generated and saved.\n")


def rsa_encrypt(pub_path: str, plaintext: bytes) -> bytes:
    print("\n [STEP 2] RSA Encryption Process")
    pub = serialization.load_pem_public_key(Path(pub_path).read_bytes())
    print(f"   Plaintext (ASCII): {plaintext.decode()}")
    print(f"   Plaintext (hex): {plaintext.hex()}")

    ciphertext = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print(f"   Ciphertext (hex): {ciphertext.hex()}")
    return ciphertext


def rsa_decrypt(priv_path: str, ciphertext: bytes) -> bytes:
    print("\n [STEP 3] RSA Decryption Process (Detailed)")
    priv = serialization.load_pem_private_key(Path(priv_path).read_bytes(), password=None)
    priv_numbers = priv.private_numbers()
    pub_numbers = priv_numbers.public_numbers

    n = pub_numbers.n
    d = priv_numbers.d

    # Convert ciphertext bytes → integer
    c_int = int.from_bytes(ciphertext, byteorder='big')
    print(f"   Ciphertext as integer C = {c_int}")

    # Modular exponentiation M = C^d mod n
    m_int = pow(c_int, d, n)
    print(f"   Step: M = C^d mod n = {m_int}")

    # Convert back to bytes
    recovered = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')
    print(f"   Step: Convert integer → bytes: {recovered}")
    try:
        print(f"   Step: Decode bytes → ASCII string: {recovered.decode()}")
    except:
        print("   Step: Message not ASCII-decodable (binary data).")

    # For OAEP padding (already done internally by library)
    # We'll show the "library-verified" final decryption
    verified_plain = priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    print(f"\n Verified OAEP decryption result: {verified_plain.decode(errors='ignore')}")
    return verified_plain


# Kyber
def _import_kyber():
    kyber_path = Path(__file__).parent / "Kyber.py"
    if not kyber_path.exists():
        kyber_path = Path.cwd() / "Kyber.py"
    spec = importlib.util.spec_from_file_location("KyberModule", str(kyber_path))
    kyber = importlib.util.module_from_spec(spec)
    sys.modules["KyberModule"] = kyber
    spec.loader.exec_module(kyber)
    return kyber


Kyber = _import_kyber()


def _bits_from_bytes(data: bytes) -> list[int]:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _bytes_from_bits(bits: list[int]) -> bytes:
    pad = (-len(bits)) % 8
    bits += [0] * pad
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i + j]
        out.append(val)
    return bytes(out)


def kyber_keygen(pub_path: str, priv_path: str):
    print("\n [STEP 1] Kyber Key Generation")
    (A, t), s = Kyber.keygen()
    print(f"   Parameter n (poly degree): {Kyber.n}")
    print(f"   Modulus q: {Kyber.q}")
    print(f"   Matrix rank k: {Kyber.k}")
    print(f"   Public matrix A:\n{A}")
    print(f"   Secret vector s:\n{s}")
    print(f"   Noise vector e added during keygen.")
    print(f"   Public key t = A·s + e:\n{t}")

    pub = {"A": A, "t": t, "n": Kyber.n, "q": Kyber.q, "k": Kyber.k}
    prv = {"s": s, "n": Kyber.n, "q": Kyber.q, "k": Kyber.k}
    Path(pub_path).write_text(json.dumps(pub))
    Path(priv_path).write_text(json.dumps(prv))
    print("   Kyber key pair generated and saved.\n")


def kyber_encrypt(pub_path: str, plaintext: bytes):
    print("\n [STEP 2] Kyber Encryption Process")
    pub = json.loads(Path(pub_path).read_text())
    A, t, n = pub["A"], pub["t"], pub["n"]
    Kyber.n = n
    bits = _bits_from_bytes(plaintext)
    blocks = [bits[i:i + n] for i in range(0, len(bits), n)]
    print(f"   Message converted into {len(blocks)} polynomial block(s).")

    ciphertexts = []
    for idx, block in enumerate(blocks):
        print(f"\n   ▪ Encrypting block {idx+1}: {block}")
        u, v = Kyber.encrypt((A, t), block)
        print(f"     → Ephemeral secret r, noise e₁,e₂ sampled internally.")
        print(f"     → Ciphertext component u = Aᵗ·r + e₁: {u}")
        print(f"     → Ciphertext component v = tᵗ·r + e₂ + μ: {v}")
        ciphertexts.append((u, v))

    print("\n Kyber encryption complete.")
    return ciphertexts


def kyber_decrypt(priv_path: str, ciphertexts):
    print("\n [STEP 3] Kyber Decryption Process (Detailed)")
    prv = json.loads(Path(priv_path).read_text())
    s, n = prv["s"], prv["n"]
    Kyber.n = n
    bits_out = []

    for idx, ct in enumerate(ciphertexts):
        print(f"\n   ▪ Decrypting ciphertext block {idx+1}")
        u, v = ct
        print(f"     → Input ciphertext components:")
        print(f"         u = {u}")
        print(f"         v = {v}")

        # Step 1: Compute sᵗ · u
        w = Kyber.vec_dot(s, u)
        print(f"     [1] Compute w = sᵗ·u = {w}")

        # Step 2: Subtract to isolate encoded message
        diff = Kyber.poly_sub(v, w)
        print(f"     [2] Compute v - sᵗu = {diff}")

        # Step 3: Decode bits from coefficients
        print(f"     [3] Decode each coefficient:")
        decoded_bits = []
        for i, coeff in enumerate(diff):
            bit = 1 if Kyber.circdist(coeff, Kyber.q // 2) < Kyber.circdist(coeff, 0) else 0
            print(f"         coeff[{i}] = {coeff} → bit = {bit}")
            decoded_bits.append(bit)

        bits_out.extend(decoded_bits)
        print(f"     [4] Decoded bits: {decoded_bits}")

    plaintext = _bytes_from_bits(bits_out)
    print("\n Reconstructed plaintext bytes:", plaintext)
    try:
        print(" Decoded message (ASCII):", plaintext.decode())
    except:
        print(" Message not ASCII-decodable (binary data).")

    print(" Kyber decryption complete.\n")
    return plaintext


# main
def main():
    print("===  Public Key Encryption Demonstration ===")
    print("Choose which system to use:")
    print("1. RSA")
    print("2. CRYSTALS-Kyber")
    choice = input("Enter choice (1/2): ").strip()
    algorithm = "RSA" if choice == "1" else "Kyber"
    print(f"\nYou selected: {algorithm}")

    # Generate keys
    if algorithm == "RSA":
        rsa_keygen("rsa_public.pem", "rsa_private.pem")
    else:
        kyber_keygen("kyber_public.json", "kyber_private.json")

    message = input("\nEnter a message to encrypt: ").encode()

    if algorithm == "RSA":
        ciphertext = rsa_encrypt("rsa_public.pem", message)
        recovered = rsa_decrypt("rsa_private.pem", ciphertext)
    else:
        ciphertext = kyber_encrypt("kyber_public.json", message)
        recovered = kyber_decrypt("kyber_private.json", ciphertext)

    print("\n\n✅ Demonstration complete.")
    print(f"Original message: {message.decode()}")
    print(f"Recovered message: {recovered.decode()}")


if __name__ == "__main__":
    main()
