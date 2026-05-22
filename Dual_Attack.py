## Demonstration of Dual Attack without Secret via fpylll
## Toy Kyber implementation is the same as Kyber.py - use functions implemented in Kyber.py
from fpylll import IntegerMatrix, LLL
import random
import Kyber as kyber

# Parameters (to rest strength of different params)
n = kyber.n      # default 256
q = kyber.q
k = kyber.k      # default 2
width = kyber.width
N = kyber.k*kyber.n    # flattened dimension of polynomial matrix/vectors

# Flatten polynomial p in matrix A into n x n negacyclic matrix
def conv_matrix_negacyclic(a, n, q):
    # empty list to store columns of each flattened polynomial
    cols = []
    for j in range(n):
        # creates an empty polynomial
        ej = kyber.zero_poly()
        # sets coeffn of jth degree term in empty polynomial to 1 - identity polynomial
        ej[j] = 1
        # shifts subsequent columns down by 1 index - accounts for negacyclic wraparound
        prod = kyber.poly_mul(a, ej)
        # represent coeffn as positive integers
        cols.append([p % q for p in prod])
    # transpose the negacyclic matrix cols[] as the cols were represented as rows during construction
    return [[cols[c][r] for c in range(n)] for r in range(n)]

# combine all negacyclic matrices from flattened polynomials into block n*k x n*k matrix
def block_conv_matrix(A, n, k, q):
    N = k*n
    Cbig = [[0]*N for _ in range(N)]
    for i in range(k):          
        for j in range(k):
            # get each flattened polynomial in matrix A
            Cij = conv_matrix_negacyclic(A[i][j], n, q)
            for r in range(n):
                for c in range(n):
                    # insert flattened poly into flattened matrix C(A)
                    Cbig[i*n + r][j*n + c] = Cij[r][c]
    return Cbig

# flatten vector into rank k*n
def flatten_vec_k_polys(vec_k, k):
    out = []
    # appending n terms of k polynomials - vector dims n*k x 1
    for j in range(k):
        out.extend(int(x) for x in vec_k[j])
    return out

# unflatten n*k rank vector back to polynomial vector
def unflatten_to_k_polys(vecN, n, k):
    return [[int(x) for x in vecN[j*n : (j + 1)*n]] for j in range(k)]


# Extended-dual lattice
# requires C(A), -(compressed t vector), identity matrix N, q*(identity matrix N)
def build_B_dual_rows(A, t, n, k, q):
    N = k*n
    Cbig = block_conv_matrix(A, n, k, q)   # N × N
    tflat = flatten_vec_k_polys(t, k)      # length N

    B = []
    # short vector y row - compute first row of dual lattice [IN, 0, C(A)^T]
    for i in range(N):
        row = [0]*(2*N + 1)
        row[i] = 1
        for j in range(N):
            row[N + 1 + j] = Cbig[j][i]
        B.append(row)

    # short vector α row - compute second row of dual lattice [0, 1, -tflat^T]
    row_alpha = [0]*(2*N + 1)
    row_alpha[N] = 1
    for j in range(N):
        row_alpha[N + 1 + j] = -tflat[j]
    B.append(row_alpha)

    # qI rows for z
    for j in range(N):
        row = [0]*(2*N + 1)
        row[N + 1 + j] = q
        B.append(row)

    return B, Cbig, tflat

def yT_u_polynomial(y_vec, u, n, k):
    y_polys = unflatten_to_k_polys(y_vec, n, k)
    out = kyber.vec_dot(y_polys, u)
    return out

# find shortest circular (mod q) signed distance from 0
def center_mod_vec(vec, q):
    half = q // 2
    return [((int(x) + half) % q) - half for x in vec]


# Extended Euclid Algorithm
# a = b*(a // b) + r1
# b = r1*(b // r1) + r2
# r1 = r2*(r1 // r2) + 0
# gcd = r2
def extended_euclid(a, b):
    r = a % b
    return b if r == 0 else extended_euclid(b, r)


def dual_attack_decrypt_fpylll(pk, ct, n, k, q,
                               deltas=(0.99, 0.999, 0.9995),    # stronger reduction the closer to 1
                               return_debug=False):
    
    (A, t) = pk
    (u, v) = ct
    N = k*n
    half = q // 2

    best_bits, best_score, best_dbg = None, None, None

    def try_with_rows(B_rows):
        nonlocal best_bits, best_score, best_dbg
        # copies B into fpylll’s internal integer matrix to run LLL
        M = IntegerMatrix.from_matrix(B_rows)

        # reduce
        for delt in deltas:
            LLL.reduction(M, delta=delt)

            # scan rows - each row corresponds to a lattice basis vector (y, α, z)
            # y is first N terms, alpha is the (N+1) term
            for r in range(M.nrows):
                vec = [int(M[r, c]) for c in range(M.ncols)]
                y_vec  = vec[0 : N]
                # check condition for suitable alpha value - must not be equals to 0 if modq
                alpha = int(vec[N]) % q
                if alpha == 0:
                    continue

                # residual rho = Cy − αt is the error term of the congruence Cy = αt
                # if LLL found suitable α, y vectors, rho will be small
                rho = [(sum(Cbig[i][j]*y_vec[j] for j in range(N)) - alpha*flatten_vec_k_polys(t, k)[i]) % q for i in range(N)]
                rho_c = center_mod_vec(rho, q)
                worst_case_rho = max(abs(x) for x in rho_c) if rho_c else 0

                # ||y||^2
                y_norm = sum(xx**2 for xx in y_vec)

                # Compute W = αv − y^Tu, with constant alpha and unflattened vector v, u, and y
                W = [(alpha*vi) % q for vi in v]
                yTu = yT_u_polynomial(y_vec, u, n, k)
                W = kyber.poly_sub(W, yTu)

                # Decoding using inv(α) for W = α*mu + noise, where W*inv(α) = mu + small noise
                ainv = pow(alpha, -1, q) if extended_euclid(alpha, q) == 1 else None
                if ainv is not None:
                    Wn = [(ainv*wi) % q for wi in W]
                    bits = [1 if kyber.circdist(x % q, half) < kyber.circdist(x % q, 0) else 0 for x in Wn]
                # best effort decoding if no inv(α)
                else:
                    # normalize decoding of coeffn since combiner w is scaled with α
                    norm_half = (alpha*half) % q
                    bits = [1 if kyber.circdist(x % q, norm_half) < kyber.circdist(x % q, 0) else 0 for x in W]

                score = (worst_case_rho, y_norm)
                if (best_bits is None) or (score < best_score):
                    best_bits = bits
                    best_score = score
                    best_dbg = {
                        "alpha_mod_q": alpha,
                        "rho_inf": worst_case_rho,
                        "y_norm": y_norm,
                        "row_index": r,
                        "delta_used": delt,
                    }

            if best_bits is not None:   # # suitable vals found
                break

    # base basis
    B_rows, Cbig, tflat = build_B_dual_rows(A, t, n, k, q)
    try_with_rows(B_rows)

    if best_bits is None:
        raise RuntimeError("Dual attack: no usable (y, alpha)")

    return (best_bits, best_dbg) if return_debug else best_bits

# Demo
if __name__ == "__main__":
    msg = [random.getrandbits(1) for _ in range(n)]
    pk, sk = kyber.keygen()
    ct = kyber.encrypt(pk, msg)

    print("Receiver decryption correct? ", kyber.decrypt(sk, ct) == msg)

    bits, dbg = dual_attack_decrypt_fpylll(
        pk, ct, n=n, k=k, q=q,
        deltas=(0.99, 0.999, 0.9995),
        return_debug=True
    )

    print("Dual attack correct?         ", bits == msg)
    print("msg:                         ", msg)
    print("Recovered bits:              ", bits)
    print("alpha (mod q):               ", dbg["alpha_mod_q"])
    print("worst-case rho, ||y||^2:     ", dbg["rho_inf"], dbg["y_norm"])
    print("row index, delta:            ", dbg["row_index"], dbg["delta_used"])
