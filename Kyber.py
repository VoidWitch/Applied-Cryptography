# Toy implementation with baby params
import random

## Baby params
n = 10        # degree (default Kyber uses 256) so polynomial degree of n-1
q = 3329      # modulo for coefficient of polynomial terms
k = 2         # module rank (default Kyber uses 2)
width = 1     # width of centered-binomial sampling for small coeffns (secret s/r, noise e/e1/e2 )

# instantiates an empty polynomial
def zero_poly(): return [0]*n

# polynomial coeffns stored as list of length n, [x^0, ..., x^n-1]
def poly_add(a, b): return [(a[i] + b[i]) % q for i in range(n)]
def poly_sub(a, b): return [(a[i] - b[i]) % q for i in range(n)] 

def poly_mul(a, b):
    # integer convolution, then fold with (X^n + 1) and mod q reduction
    tmp = [0]*(2*n - 1) # each index represents coeffn of x^i for i in [0,2n-1]
    for i in range(n):
        poly_a_val = a[i]
        if poly_a_val == 0: continue
        for j in range(n):
            tmp[i + j] += poly_a_val*b[j]
    result = [0]*n
    for i in range(n): result[i] = tmp[i]
    for i in range(n, 2*n - 1): result[i - n] -= tmp[i] # fold + sign flip cuz negacyclic
    return [x % q for x in result] # mod q reduction, returns a polynomial represented using a list

# compute A*v, rank k matrix A and secret vector/ephemeral secret v
def mat_vec_mul(M, v):
    out = [zero_poly() for _ in range(k)] # initiates empty list of lists
    for i in range(k):
        tmp = zero_poly()
        for j in range(k):
            tmp = poly_add(tmp, poly_mul(M[i][j], v[j])) # row, col matrix operation
        out[i] = tmp
    return out

def mat_transpose(M): return [[M[j][i] for j in range(k)] for i in range(k)]

# compute second ciphertext piece v that requires vector product
def vec_dot(u, v):
    tmp = zero_poly()
    for i in range(k):
        tmp = poly_add(tmp, poly_mul(u[i], v[i]))
    return tmp

# Sampling 
def sample_cbd(width):
    s1 = sum(random.getrandbits(1) for _ in range(width))
    s2 = sum(random.getrandbits(1) for _ in range(width))
    return s1 - s2 # to make the noise centered at 0 so there will be lesser decryption errors

def sample_poly_cbd(width): return [sample_cbd(width) % q for _ in range(n)] # for small secret/noise coeffn of len(n), with coeffn modq
def sample_uniform_poly(): return [random.randrange(q) for _ in range(n)] # for matrix polynomial coeffn of len(n)

# Bit message encoding/decoding
def encode_bits(bits):
    out = [0]*n
    half = q // 2 # floored
    L = min(n, len(bits)) # encryption of msg length bounded by degree of polynomial
    for i in range(L): 
        out[i] = half if bits[i] else 0 # bit 1 encrypted as q//2, bit 0 encrypted as 0
    return out

def circdist(x, c):  # used for decoding to compute closest distance after coeffn mod q
    d = (x - c) % q
    return min(d, q - d)

def decode_bits(poly):
    half = q // 2
    out = []
    for x in poly:
        x %= q
        # decode as 1 if coeffn lies closer to q/2, since bit 1 is encoded as q/2, likewise for 0   
        out.append(1 if circdist(x, half) < circdist(x, 0) else 0)
    return out

# Public key generation / Encryption / Decryption
def keygen():
    # A is 1x1 matrix here: rank 1 with a single polynomial entry of degree 7 (8 coefficients)
    A = [[sample_uniform_poly() for _ in range(k)] for __ in range(k)]
    # secret s and noise e are also 1x1 with a single polynomial entry
    s = [sample_poly_cbd(width) for _ in range(k)]
    e = [sample_poly_cbd(width) for _ in range(k)]
    # public vector t = As + e, where As and e are of rank k
    t = [poly_add(mat_vec_mul(A, s)[i], e[i]) for i in range(k)]  # vector length k
    return (A, t), s

# sender encryption with args(public key, bit-string message)
def encrypt(pk, bits):
    A, t = pk
    mu = encode_bits(bits)
    r  = [sample_poly_cbd(width) for _ in range(k)] # ephemeral secret vector
    e1 = [sample_poly_cbd(width) for _ in range(k)] # noise vector 1 for first ciphertext piece
    e2 = sample_poly_cbd(width) # noise polynomial for second ciphertext piece
    AT = mat_transpose(A)
    # computing first ciphertext piece: u = A^Tr + e'
    u  = mat_vec_mul(AT, r)
    u  = [poly_add(u[i], e1[i]) for i in range(k)]
    # computing second ciphertext piece: v = t^Tr + e'' + mu
    v  = vec_dot(t, r)
    v  = poly_add(v, e2)
    v  = poly_add(v, mu)
    return (u, v)

# receiver decryption with args(own secret key, both ciphertext pieces)
def decrypt(sk, ct):
    u, v = ct
    # compute prediction using secret: w = s^Tu
    w = vec_dot(sk, u)
    # subtract w from v to get encoded msg mu + some combined noise: v-w = mu + (e'' - s^Te' + r^Te)
    diff = poly_sub(v, w)
    return decode_bits(diff) # decoding back to bit-string based on coeffn distance to 0 or q/2

# Demo
if __name__ == "__main__":
    msg = [random.getrandbits(1) for _ in range(n)]  # 1 polynomial = n bits, degree n-1
    pk, sk = keygen()
    ct = encrypt(pk, msg)
    dec = decrypt(sk, ct)
    print("Decryption:", msg == dec)
    print("msg:", msg)
    print("dec:", dec)
