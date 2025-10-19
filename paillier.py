# paillier.py
import math, random

def is_probable_prime(n, k=8):
    if n < 2: return False
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
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
    def __init__(self, n, g, n2):
        self.n, self.g, self.n2 = n, g, n2

class Priv:
    def __init__(self, lam, mu, pub: Pub):
        self.lam, self.mu, self.pub = lam, mu, pub

def paillier_keygen(bits=1024):
    p = gen_prime(bits//2); q = gen_prime(bits//2)
    while q == p: q = gen_prime(bits//2)
    n = p * q
    n2 = n * n
    lam = lcm(p-1, q-1)
    g = n + 1
    def L(u): return (u - 1) // n
    mu = pow(L(pow(g, lam, n2)), -1, n)
    return Pub(n, g, n2), Priv(lam, mu, Pub(n, g, n2))

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
