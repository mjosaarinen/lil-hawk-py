#   poly_ntt.py
#   2023-07-12  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE
#   Implementations of basic ring and NTT arithmetic.

from random import randrange

#   generic polynomial functions

def f_str(f):
    """Create a string representation for resultant polynomial f(x)."""
    s = f'{f[0]:+d}'
    for i in range(1,len(f)):
        if f[i] != 0:
            s += f'{f[i]:+d}*x'
            if i > 1:
                s += f'^{i}'
    return s

def f_add(f, g):
    """Add polynomials: return f + g."""
    return [ (fi + gi) for fi,gi in zip(f,g) ]

def f_sub(f, g):
    """Add polynomials: return f - g."""
    return [ (fi - gi) for fi,gi in zip(f,g) ]

def f_adj(f):
    """Hermitian adjoint f*."""
    return [ f[0] ] + [ -x for x in reversed(f[1:]) ]

def f_scale(f, c):
    """Scale all coefficients: c*f."""
    return [ c * fi for fi in f ]

def f_mul(f, g):
    """Multiply polynomials f*g  mod x^n+1."""
    n   = len(f)
    assert len(g) == n
    t   = [0] * (2*n)
    for i in range(n):
        for j in range(n):
            t[i + j] += f[i] * g[j]
    return [ t[i] - t[i + n] for i in range(n) ]

def f_even(f):
    """Polynomial with even coefficients."""
    return [ f[i] for i in range(0, len(f), 2) ]

def f_odd(f):
    """Polynomial with odd coefficients."""
    return [ f[i] for i in range(1, len(f), 2) ]

def f_x2(f):
    """Double-degree polynomial f(x^2)."""
    r = []
    for x in f:
        r += [x, 0]
    return r

def f_nx(f):
    """Polynomial f(-x)."""
    r = f.copy()
    for i in range(1, len(f), 2):
        r[i] = -r[i];
    return r

def f_mulx(f):
    """Return x*f mod x^n+1."""
    return [ -f[-1] ] + f[:-1]

def f_shr(f, sh):
    """Right-shift each coefficient; floor divide by 2**sh."""
    return [ x >> sh for x in f ]

def f_ninf(f):
    """Infinity norm."""
    d = 0
    for x in f:
        d = max(d, abs(x))
    return d

def f_nsqe(f):
    """Squared euclidian norm."""
    d = 0
    for x in f:
        d += x*x
    return d

def f_nbit(f):
    """Bits in biggest element: ceil(log2( ||f||inf )) or 0 if all zeros."""
    d = 0
    for x in f:
        d = max(d, int(x).bit_length())
    return d

def f_nn(f):
    """Field norm (slow). Result is mod x^(n/2)+1."""
    t0 = f_even(f)
    t1 = f_odd(f)
    return f_sub( f_mul(t0,t0), f_mulx(f_mul(t1,t1)) )

def f_rand(n, p):
    """Random coefficients in [0,p-1] for p > 0 or [2p,-p-1] for p < 0."""
    if p >= 0:
        return [ randrange(p) for _ in range(n) ]
    else:
        return [ randrange(-2*p)+p for _ in range(n) ]

#   some number-theoretic helpers

def n_rdiv(a, b):
    """Integer rounding division round(a/b) = floor(a/b+1/2)."""
    return (a + (b >> 1)) // b

def n_modexp(x, e, n):
    """Modular exponentiation: Compute x**e (mod n)."""
    y = 1
    while e > 0:
        if e & 1 == 1:
            y = (y * x) % n
        x = (x * x) % n
        e >>= 1
    return y

def n_bitrev(x, l):
    """Reverse "l" bits of x."""
    y = 0
    for i in range(l):
        y |= ((x >> i) & 1) << (l - i - 1)
    return y

def n_gcd(a, b):
    """Given a and b, return r = gcd(a,b)."""
    (r0, r1) = (a, b)
    while r1 != 0:
        (r0, r1) = (r1, r0 % r1)
    return r0

def n_inv(a, n):
    """Given a and n, return a^-1 (mod n) -- if exists."""
    (r0, r1) = (a, n)
    (s0, s1) = (1, 0)
    while r1 != 0:
        q = r0 // r1
        (r0, r1) = (r1, r0 - q * r1)
        (s0, s1) = (s1, s0 - q * s1)
    return s0 % n

def n_egcd(a, b):
    """Given a and b, return (s,t,r) such that a*s + b*t = r = gcd(a,b)."""
    (r0, r1) = (a, b)
    (s0, s1) = (1, 0)
    (t0, t1) = (0, 1)
    while r1 != 0:
        q = r0 // r1
        (r0, r1) = (r1, r0 - q * r1)
        (s0, s1) = (s1, s0 - q * s1)
        (t0, t1) = (t1, t0 - q * t1)
    return (s0, t0, r0)

#   NTT (mod p) functions

def p_mod(f, p):
    """Reduce coefficients: return f (mod p)."""
    return [ (fi % p) for fi in f ]

def p_ntt(f, par):
    """Forward NTT (negacyclic - x^n+1.) Note: Transforms f in place."""
    (n, w, ni, p) = par
    l = n // 2
    wi = 0
    while l > 0:
        for i in range(0, n, 2 * l):
            wi += 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = (f[j + l] * z) % p
                f[j] = (x + y) % p
                f[j + l] = (x - y) % p
        l >>= 1
    return f

def p_intt(f, par):
    """Inverse NTT (negacyclic - x^n+1.) Note: Transforms f in place."""
    (n, w, ni, p) = par
    l = 1
    wi = n
    while l < n:
        for i in range(0, n, 2 * l):
            wi -= 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = f[j + l]
                f[j] = (x + y) % p
                f[j + l] = (z * (y - x)) % p
        l <<= 1
    for i in range(n):
        f[i] = (f[i] * ni) % p
    return f

def p_ntt_adj(ft):
    """Return ft* (adjunct with input and output in NTT domain.)"""
    fat = ft.copy()
    fat.reverse()
    return fat

def p_ntt_mul(ft, gt, p):
    """Multiplication of two polynomials (NTT domain.)"""
    return [(fi * gi) % p for fi,gi in zip(ft,gt)]

def p_ntt_inv(ft, p):
    """Invert all coefficients of f (mod p)."""
    rt = []
    for x in ft:
        if x == 0:
            return None
        rt += [ n_inv(x, p) ]
    return rt

def p_mul(f, g, par):
    """NTT negacyclic convolution h = f*g (mod x^n+1)."""
    (n, w, ni, p) = par
    ft = p_ntt(f.copy(), par)
    gt = p_ntt(g.copy(), par)
    ht = p_ntt_mul(ft, gt, p);
    ht = p_intt(ht, par)
    return ht

def p_ntt_find_h(n, p):
    """Find a generator h of order 2*n."""
    assert p % (2*n) == 1
    r = (p - 1) // (2*n)
    for x in range(2, p-1):
        y = n_modexp(x, r, p)
        z = n_modexp(y, n, p)
        if z == p - 1:
            return y
    return None

def p_ntt_calc_w(logn, h, p):
    """Generate a NTT "tweak" table."""
    n   = 1 << logn
    w   = []
    for i in range(n):
        j = n_bitrev(i, logn)
        x = n_modexp(h, j, p)
        w.append(x)
    return w

def p_param(logn, p):
    """Compute NTT Parameters."""
    n = 1 << logn
    ni  = n_inv(n, p)
    h   = p_ntt_find_h(n, p)
    w   = p_ntt_calc_w(logn, h, p)
    return (n, w, ni, p)

if (__name__ == "__main__"):
    #   self-test
    v = [ 12289, 18433, 40961, 59393, 61441, 65537, 79873, 83969, 86017 ]
    logn = 10
    n = 1 << logn
    for p in v:
        par = p_param(logn, p)
        f   = f_rand(n, p)
        g   = f_rand(n, p)
        h1  = p_mod( f_mul(f, g), p )
        h2  = p_mul(f, g, par)
        print(h1==h2)

