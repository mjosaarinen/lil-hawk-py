#   ntru_fft.py
#   2023-07-12  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE
#   Implementations of ntru_solve() and related functions.

import math
from poly_ntt import *

MAX_LOGN = 10

def c_fft_calc_w(logn):
    """Generate a FFT tweak table."""
    n   = 1 << logn
    w   = []
    b   = math.pi / n
    for i in range(n):
        j = n_bitrev(i, logn)
        a = j * b
        x = complex(math.cos(a), math.sin(a))
        w.append(x)
    return w

#   global table
C_FFT_W = c_fft_calc_w(MAX_LOGN)

def c_fft(f, w=C_FFT_W):
    """Forward FFT. Note: Transforms f in place."""
    n = len(f)
    l = n // 2
    wi = 0
    while l > 0:
        for i in range(0, n, 2 * l):
            wi += 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = f[j + l] * z
                f[j] = x + y
                f[j + l] = x - y
        l >>= 1
    return f

def c_ifft(f, w=C_FFT_W):
    """Inverse FFT. Note: Transforms f in place."""
    n = len(f)
    l = 1
    wi = n
    while l < n:
        for i in range(0, n, 2 * l):
            wi -= 1
            z = w[wi]
            for j in range(i, i + l):
                x = f[j]
                y = f[j + l]
                f[j] = x + y
                f[j + l] = z * (y - x)
        l <<= 1
    for i in range(n):
        f[i] = f[i] / n
    return f

def c_inv(ft):
    """Invert coefficients (FFT domain.)"""
    return [(1.0 / fi) for fi in ft]

def c_mul(ft, gt):
    """Multiplication of two polynomials (FFT domain.)"""
    return [(fi * gi) for fi,gi in zip(ft,gt)]

def f_reduce_k(f, g, F, G):
    """Compute k <- round( (Ff* + Gg*) / (ff* + gg*) )."""
    n = len(f)
    if n == 2:
        #   divisor (ff* + gg*) is just a degree-0 constant
        #   d = (f0^2 + f1^2 + g0^2 + g1^2)  mod x^2+1
        d = f[0]**2 + f[1]**2 + g[0]**2 + g[1]**2
        k = f_add( f_mul( F, f_adj(f) ), f_mul( G, f_adj(g) ) )
        k = [ n_rdiv( x, d ) for x in k ]
        return  k
    elif n == 4:
        #   divisor (ff* + gg*) is ( a - b*x + b*x^3 ) / ( a^2 - 2*b^2 )
        #   where a and b are:
        a = (f[0]**2 + f[1]**2 + f[2]**2 + f[3]**2 +
             g[0]**2 + g[1]**2 + g[2]**2 + g[3]**2)
        b = (f[1]*(f[0] + f[2]) + f[3]*(f[2] - f[0]) +
             g[1]*(g[0] + g[2]) + g[3]*(g[2] - g[0]))
        d = a**2 - 2*b**2
        k = f_add( f_mul( F, f_adj(f) ), f_mul( G, f_adj(g) ) )
        k = f_mul( k, [ a, -b, 0, b ] )
        k = [ n_rdiv( x, d ) for x in k ]
        return k

    #   take the high bits
    s1 = max(0, max( f_nbit(f), f_nbit(g) ) - 100)
    s2 = max(0, max( f_nbit(F), f_nbit(G) ) - 100)
    (fn, gn) = ( f_shr(f, s1), f_shr(g, s1) )
    (Fn, Gn) = ( f_shr(F, s2), f_shr(G, s2) )

    #   k = (Ff* + Gg*) / (ff* + gg*)
    fat = c_fft(f_adj(fn))
    gat = c_fft(f_adj(gn))
    k1t = f_add( c_mul( c_fft(Fn), fat ), c_mul( c_fft(Gn), gat ) )
    k2t = f_add( c_mul( c_fft(fn), fat ), c_mul( c_fft(gn), gat ) )
    k = c_ifft( c_mul( k1t, c_inv( k2t ) ) )

    #   round and scale k
    sh = max(0, s2 - s1)

    #print(f'n= {len(f)}  s1= {s1}  s2= {s2}  sh= {sh}')
    return [ round(x.real) << sh for x in k ]

def ntru_solve(f, g):
    """NTRUSolve(f, g): (F,G) with f*G-g*F=1 mod x^n+1. n power of two."""
    n = len(f)
    if n == 1:
        (s, t, r) = n_egcd(f[0], g[0])
        if r == 1:
            return ([-t], [s])
        else:
            return None
    else:
        fp = f_nn(f)
        gp = f_nn(g)
        r = ntru_solve(fp, gp)
        if r == None:
            return r
        (F,G) = r
        F = f_mul( f_x2( F ), f_nx( g ) )
        G = f_mul( f_x2( G ), f_nx( f ) )

        while True:
            k = f_reduce_k(f, g, F, G)
            l = f_nbit(k)
            #print(f'n= {n:4}  l= {l:4} |F|= {f_nbit(F):4}  |G|= {f_nbit(G):4}')
            if l == 0:
                break

            F = f_sub( F, f_mul(k, f) )
            G = f_sub( G, f_mul(k, g) )

        # check that the equation is valid
        #print(f_sub(f_mul(f, G), f_mul(g, F)) == [ 1 ] + ([0] * (n-1)))
        return (F, G)

if (__name__ == "__main__"):
    #   simple self-test
    n   =   512
    f   = f_rand(n, -10)
    g   = f_rand(n, -10)

    print("f=", f_str(f))
    print("g=", f_str(g))
    r = ntru_solve(f, g)
    if r == None:
        print(r)
    else:
        (F,G) = r
        print("F=", f_str(F))
        print("G=", f_str(G))
        r = f_sub( f_mul(f, G), f_mul(g, F) )
        print("r=", f_str(r))

