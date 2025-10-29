import math, random
import hashlib

def is_probable_prime(n, k=8):
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n % p == 0:
            return n == p
    s, d_val = 0, n-1 
    while d_val % 2 == 0:
        d_val //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d_val, n)
        if x in (1, n-1): continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1: break
        else: return False
    return True

def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_probable_prime(p):
            return p

def lcm(a,b): 
    return a // math.gcd(a,b) * b

class Pub:
    def __init__(self, n, g, n2, e): 
        self.n, self.g, self.n2, self.e = n, g, n2, e

class Priv:
    def __init__(self, lam, mu, pub: Pub, d): 
        self.lam, self.mu, self.pub, self.d = lam, mu, pub, d

def paillier_keygen(bits=1024):
    p = gen_prime(bits//2); q = gen_prime(bits//2)
    while q == p: q = gen_prime(bits//2)
    n = p * q
    n2 = n * n
    lam = lcm(p-1, q-1)
    g = n + 1

    e = 65537 
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)

    def L(u): return (u - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    return Pub(n, g, n2, e), Priv(lam, mu, Pub(n, g, n2, e), d) # Passa 'e' e 'd'

def paillier_encrypt(pub: Pub, m: int):
    if not (0 <= m < pub.n):
        raise ValueError("m out of range")
    r = random.randrange(1, pub.n)
    while math.gcd(r, pub.n) != 1:
        r = random.randrange(1, pub.n)
    return (pow(pub.g, m, pub.n2) * pow(r, pub.n, pub.n2)) % pub.n2

def paillier_decrypt(priv: Priv, c: int):
    n = priv.pub.n; n2 = priv.pub.n2
    def L(u): return (u - 1) // n
    return (L(pow(c, priv.lam, n2)) * priv.mu) % n

def _hash_message_to_int(m_bytes: bytes) -> int:
    h = hashlib.sha256(m_bytes).digest()
    return int.from_bytes(h, 'big')

def paillier_sign(priv: Priv, m_bytes: bytes) -> str:
    H = _hash_message_to_int(m_bytes)
    S = pow(H, priv.d, priv.pub.n)
    return str(S)


def paillier_verify(pub: Pub, S: str, m_bytes: bytes) -> bool:
    H = _hash_message_to_int(m_bytes)
    
    try:
        S_int = int(S)
    except ValueError:
        return False 

    H_prime = pow(S_int, pub.e, pub.n)
    return H_prime == H
