#   hawk.py
#   2023-07-12  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE
#   Experimental mplementation of Hawk -- not for production use.

import os
from Crypto.Hash import SHAKE256
from poly_ntt import *
from ntru_fft import *

class Hawk:

    #   initialize
    def __init__(self, logn=9, rnd=os.urandom):
        """Intialize a parametrized instance of Hawk."""
        n               =   1 << logn
        self.algname    =   f'Hawk-{n}'
        self.logn       =   logn
        self.rnd        =   rnd
        if logn == 8:
            self.privlen    =   96
            self.publen     =   450
            self.siglen     =   249
            self.dev_sign   =   1.010
            self.dev_verify =   1.042
            self.dev_krsec  =   1.042
            self.saltlen    =   112 // 8
            self.kgseedlen  =   128 // 8
            self.hpublen    =   128 // 8
            self.low_00     =   5
            self.high_00    =   9
            self.low_01     =   8
            self.high_01    =   11
            self.high_11    =   13
            self.high_s0    =   12
            self.low_s1     =   5
            self.high_s1    =   9
            self.beta_0     =   1.0 / 253 # (256)  Hawk-256 KAT 25 approx
        elif logn == 9:
            self.privlen    =   184
            self.publen     =   1024
            self.siglen     =   555
            self.dev_sign   =   1.278
            self.dev_verify =   1.425
            self.dev_krsec  =   1.425
            self.saltlen    =   192 // 8
            self.kgseedlen  =   192 // 8
            self.hpublen    =   256 // 8
            self.low_00     =   5
            self.high_00    =   9
            self.low_01     =   9
            self.high_01    =   12
            self.high_11    =   15
            self.high_s0    =   13
            self.low_s1     =   5
            self.high_s1    =   9
            self.beta_0     =   1.0 / 1000
        elif logn == 10:
            self.privlen    =   360
            self.publen     =   2440
            self.siglen     =   1221
            self.dev_sign   =   1.299
            self.dev_verify =   1.571
            self.dev_krsec  =   1.974
            self.saltlen    =   320 // 8
            self.kgseedlen  =   320 // 8
            self.hpublen    =   512 // 8
            self.low_00     =   6
            self.high_00    =   10
            self.low_01     =   10
            self.high_01    =   14
            self.high_11    =   17
            self.high_s0    =   17
            self.low_s1     =   6
            self.high_s1    =   10
            self.beta_0     =   1.0 / 3000

        #   calculate tables (which are actually constant)
        self.p1     =   2147473409
        self.p2     =   2147389441
        self.par1   =   p_param(logn, self.p1);
        self.par2   =   p_param(logn, self.p2);

    #   --- public functions
    def set_random(self, rnd):
        """Set the key material RBG."""
        self.rnd   =   rnd

    def keygen(self):
        """Generate a public-private key pair."""
        r = None
        while r == None:
            kgseed = self.rnd(self.kgseedlen)
            r = self.hawk_keygen(kgseed)
        return r

    def sign(self, msg, sk):
        """Create a NIST-style signed message envelope."""
        sig = self.hawk_sign(msg, sk)
        return msg + sig

    def open(self, sm, pk):
        """Verify a NIST-style signed message envelope."""
        if len(sm) < self.siglen:
            return (False, b'')
        msg = sm[:-self.siglen]
        sig = sm[-self.siglen:]
        r = self.hawk_verify(pk, msg, sig)
        if r == True:
            return (r, msg)
        else:
            return (False, b'')

    #   --- private functions

    def _shake256x4(self, seed, out_sz):
        """SHAKE256x4 Interleaved XOF."""
        xof0 = SHAKE256.new(seed + bytes([0]))
        xof1 = SHAKE256.new(seed + bytes([1]))
        xof2 = SHAKE256.new(seed + bytes([2]))
        xof3 = SHAKE256.new(seed + bytes([3]))
        z   = b''
        for i in range(out_sz // 32):
            z   +=  xof0.read(8) + xof1.read(8) + xof2.read(8) + xof3.read(8)
        return  z

    def _isinvertible(self, u, p):
        """Check if polynomial u is invertible module x^n+1."""
        if p == 2:
            w = 0
            for x in u:
                w += x
            return w % p != 0
        return False

    def _encode_int(self, x, k):
        """Encode x as a little-endian k-bit vector."""
        return [ (x >> i) & 1 for i in range(k) ]

    def _decode_int(self, v, k):
        """Decode k-bit bit vector v as a little-endian vector."""
        x = 0
        for i in range(k):
            x += (v[i] & 1) << i
        return x

    def _bits2bytes(self, v):
        """Convert a bit vector to bytes."""
        b = b''
        for i in range(0, len(v), 8):
            b += bytes([self._decode_int(v[i:], 8)])
        return b

    def _bytes2bits(self, b):
        """Convert bytes to a bit vector."""
        v = []
        for x in b:
            v += self._encode_int(x, 8)
        return v

    def _encode_private(self, kgseed, F, G, hpub):
        """(Alg 4) EncodePrivate: Private key encoding."""
        return kgseed + self._bits2bytes(F) + self._bits2bytes(G) + hpub

    def _decode_private(self, priv):
        """(Alg 5) DecodePrivate: Private key decoding."""
        if len(priv) != self.privlen:
            return None
        kgseed = priv[0:self.kgseedlen]
        nb = (1 << self.logn) // 8
        F = self._bytes2bits(priv[self.kgseedlen:self.kgseedlen + nb])
        G = self._bytes2bits(priv[self.kgseedlen + nb:self.kgseedlen + 2*nb])
        hpub = priv[self.kgseedlen + 2*nb:self.kgseedlen + 2*nb + self.hpublen]
        return (kgseed, F, G, hpub)

    def _compress_gr(self, f, low, high):
        """(Alg 6) CompressGR: Colomb-Rice compression."""
        ys = []
        yl = []
        yh = []
        for x in f:
            if x < 0:
                s = 1
            else:
                s = 0
            ys += [ s ]
            v = x - s * (2 * x + 1)
            if v >= (1 << high):
                return None
            yl += self._encode_int( v, low )
            yh += self._encode_int( 0, v >> low ) + [ 1 ]
        return ys + yl + yh

    def _decompress_gr(self, y, k, low, high):
        """(Alg 7) DecompressGR: Golomb-Rice decompression."""
        ys = y[:k]
        yl = y[k:]
        f = []
        j = k*(low + 1)
        for i in range(k):
            z = 0
            if j >= len(y):
                return None
            while y[j] != 1:
                z += 1
                j += 1
                if j >= len(y) or z >= (1 << (high-low)):
                    return None
            x = self._decode_int(yl[i*low:], low)
            x += z << low
            x = x - ys[i]*(2*x + 1)
            f += [x]
            j += 1
        return (f, j)

    def _encode_public(self, q00, q01):
        """(Alg 8) EncodePublic: Public key encoding."""
        n = 1 << self.logn
        if q00[0] < -2**15 or q00[0] >= 2**15:
            return None
        v = 16 - self.high_00
        qp00 = q00.copy()
        qp00[0] = q00[0] >> v
        y00 = self._compress_gr(qp00[0:n//2], self.low_00, self.high_00)
        if y00 == None:
            return None
        y00 += self._encode_int(q00[0], v)
        y00 += [0] * ((-len(y00)) & 7)
        y01 = self._compress_gr(q01, self.low_01, self.high_01)
        if y01 == None:
            return None
        y = y00 + y01
        if len(y) > 8 * self.publen:
            return None
        y += [0] * (8 * self.publen - len(y))
        return self._bits2bytes(y)

    def _decode_public(self, pub):
        """(Alg 9) DecodePublic: Public key decoding."""
        n = 1 << self.logn
        if len(pub) != self.publen:
            return None
        y = self._bytes2bits(pub)
        v = 16 - self.high_00
        r = self._decompress_gr(y, n//2, self.low_00, self.high_00)
        if r == None:
            return None
        (q00, j) = r
        if len(y) < j + v:
            return None
        q00[0] = (q00[0] << v) + self._decode_int(y[j:j+v],v)
        j += v
        while (j % 8) != 0:
            if j >= len(y) or y[j] != 0:
                return None
            j += 1
        q00 += [ 0 ]
        for i in range(n // 2 + 1, n):
            q00 += [ -q00[n - i] ]
        r = self._decompress_gr(y[j:], n, self.low_01, self.high_01)
        if r == None:
            return None
        (q01, jp) = r
        j += jp
        while (j % 8) != 0:
            if j >= len(y) or y[j] != 0:
                return None
            j += 1
        return (q00, q01)

    def _encode_signature(self, salt, s1):
        """(Alg 10) EncodeSignature: Signature encoding."""
        y = self._compress_gr(s1, self.low_s1, self.high_s1)
        if y == None or len(y) > 8*(self.siglen - self.saltlen):
            return None
        y += [ 0 ] * ( 8*(self.siglen - self.saltlen) - len(y) )
        return salt + self._bits2bytes(y)

    def _decode_signature(self, sig):
        """(Alg 11) DecodeSignature: Signature decoding."""
        n = 1 << self.logn
        if len(sig) != self.siglen:
            return None
        salt = sig[0:self.saltlen]
        y = self._bytes2bits(sig[self.saltlen:])
        r = self._decompress_gr(y, n, self.low_s1, self.high_s1)
        if r == None:
            return None
        s1, j = r
        for x in y[j:]:
            if x != 0:
                return None
        return (salt, s1)

    def _regenerate_fg(self, kgseed):
        """(Alg 12) Regeneratefg: Regenerate (f,g)."""
        n   = 1 << self.logn
        b   = n // 64
        y   = self._shake256x4(kgseed, 2 * b * n // 8)
        f   = []
        for i in range(2 * n):
            w   = 0
            for j in range(b):
                k   =   i*b + j
                w   +=  (y[k >> 3] >> (k & 7)) & 1
            f   +=  [ w - (b // 2) ]
        g   =   f[n:]
        f   =   f[:n]
        return  (f, g)

    def hawk_keygen(self, kgseed):
        """(Alg 13) HawkKeyGen: HAWK key pair generation."""
        #   (local init)
        n   = 1 << self.logn
        #   --- 1:  kgseed <- Rnd(kgseedlen_bits) [ external ]

        #   --- 2:  (f, g) <- Regeneratefg(kgseed)
        (f, g) = self._regenerate_fg(kgseed)

        #   --- 3:  if  IsInvertible(f, 2) != true or
        #               IsInvertible(g, 2) != true then restart
        if not self._isinvertible(f, 2) or not self._isinvertible(g, 2):
            return None

        #   --- 5:  if ||(f, g)||2 <= 2 * n * sig2_krsec then restart
        l2 = 0
        for i in range(n):
            l2 += f[i]**2 + g[i]**2
        if l2 <= 2 * n * (self.dev_krsec**2):
            return None

        #   --- 7:  q00 <- ff* + gg*
        q00 = f_add( f_mul(f, f_adj(f)), f_mul(g, f_adj(g)) )

        #   --- 9:  if  IsInvertible(q00, p1 ) != true or
        #               IsInvertible(q00, p2 ) != true then restart
        q00_t   = p_ntt(q00.copy(), self.par1)

        for x in q00_t:
            if x == 0:
                return None
        q00_t   = p_ntt(q00.copy(), self.par2)
        for x in q00_t:
            if x == 0:
                return None

        #   --- 11: if (1/q00)[0] >= beta_0 then restart
        q00_t   =  c_ifft( c_inv( c_fft( q00.copy() ) ) )
        if q00_t[0].real >= self.beta_0:
            return None

        #   --- 13: r <- NTRUSolve(f, g, 1)
        r = ntru_solve(f, g)

        #   --- 14: if r == None then restart
        if r == None:
            return None

        #   --- 16: (F, G) <- r
        (F, G) = r

        #   --- 17: if ||F, G)||inf > 127 then  restart
        if f_ninf(F) > 127 or f_ninf(G) > 127:
            return None

        #   --- 19: q01 <- Ff* + Gg*
        q01 = f_add( f_mul(F, f_adj(f)), f_mul(G, f_adj(g)) )

        #   --- 20: q11 <- FF* + GG*
        q11 = f_add( f_mul(F, f_adj(F)), f_mul(G, f_adj(G)) )

        #   --- 21: if |q11[i]| >= 2^high_11 for any i > 0 then restart
        if f_nbit( q11[1:] ) > self.high_11:
            return None

        #   --- 23: pub <- EncodePublic(q00, q01)
        pub = self._encode_public(q00, q01)

        #   --- 24: if pub == None then Restart
        if pub == None:
            return None

        #   --- 26: hpub <- SHAKE256(pub)
        hpub = SHAKE256.new(pub).read(self.hpublen)

        #   --- 27: priv <- EncodePrivate(kgseed, F mod 2, G mod 2, hpub)
        for i in range(n):
            F[i] &= 1
            G[i] &= 1
        priv = self._encode_private(kgseed, F, G, hpub)

        #   --- 28: return (priv, pub) <- NOTE! we flip order here
        return (pub, priv)

    def _sampler_sign(self, seed, t):
        """(Alg 14) SamplerSign: Gaussian sampling in HAWK signature."""
        #   Cumulative distribution tables for sampling
        _CDF_T0T1 = [
            [   [   #   Hawk-256 T0
                    0x26B871FBD58485D45050, 0x07C054114F1DC2FA7AC9,
                    0x00A242F74ADDA0B5AE61, 0x0005252E2152AB5D758B,
                    0x00000FDE62196C1718FC, 0x000000127325DDF8CEBA,
                    0x0000000008100822C548, 0x00000000000152A6E9AE,
                    0x0000000000000014DA4A, 0x0000000000000000007B,
                    0x00000000000000000000  ],
                [   #   Hawk-256 T1
                    0x13459408A4B181C718B1, 0x027D614569CC54722DC9,
                    0x0020951C5CDCBAFF49A3, 0x0000A3460C30AC398322,
                    0x000001355A8330C44097, 0x00000000DC8DE401FD12,
                    0x00000000003B0FFB28F0, 0x00000000000005EFCD99,
                    0x00000000000000003953, 0x00000000000000000000, ]   ],
            [   [   #   Hawk-512 T0
                    0x2C058C27920A04F8F267, 0x0E9A1C4FF17C204AA058,
                    0x02DBDE63263BE0098FFD, 0x005156AEDFB0876A3BD8,
                    0x0005061E21D588CC61CC, 0x00002BA568D92EEC18E7,
                    0x000000CF0F8687D3B009, 0x0000000216A0C344EB45,
                    0x0000000002EDF0B98A84, 0x0000000000023AF3B2E7,
                    0x00000000000000EBCC6A, 0x000000000000000034CF,
                    0x00000000000000000006, 0x00000000000000000000  ],
                [   #   Hawk-512 T1
                    0x1AFCBC689D9213449DC9, 0x06EBFB908C81FCE3524F,
                    0x01064EBEFD8FF4F07378, 0x0015C628BC6B23887196,
                    0x0000FF769211F07B326F, 0x00000668F461693DFF8F,
                    0x0000001670DB65964485, 0x000000002AB6E11C2552,
                    0x00000000002C253C7E81, 0x00000000000018C14ABF,
                    0x0000000000000007876E, 0x0000000000000000013D,
                    0x00000000000000000000  ]   ],
            [   [   #   Hawk-1024 T0
                    0x2C583AAA2EB76504E560, 0x0F1D70E1C03E49BB683E,
                    0x031955CDA662EF2D1C48, 0x005E31E874B355421BB7,
                    0x000657C0676C029895A7, 0x00003D4D67696E51F820,
                    0x0000014A1A8A93F20738, 0x00000003DAF47E8DFB21,
                    0x0000000006634617B3FF, 0x000000000005DBEFB646,
                    0x00000000000002F93038, 0x0000000000000000D5A7,
                    0x00000000000000000021, 0],
                [   #   Hawk-1024 T1
                    0x1B7F01AE2B17728DF2DE, 0x07506A00B82C69624C93,
                    0x01252685DB30348656A4, 0x001A430192770E205503,
                    0x00015353BD4091AA96DB, 0x000009915A53D8667BEE,
                    0x00000026670030160D5F, 0x00000000557CD1C5F797,
                    0x00000000006965E15B13, 0x00000000000047E9AB38,
                    0x000000000000001B2445, 0x000000000000000005AA,
                    0x00000000000000000000  ]   ]   ]

        #   intialize
        n = 1 << self.logn
        T0 = _CDF_T0T1[self.logn - 8][0]
        T1 = _CDF_T0T1[self.logn - 8][1]
        yb = self._shake256x4(seed, n * 8 * 5 // 2)
        y = [ int.from_bytes(yb[i:i+8], byteorder='little')
                for i in range(0, len(yb), 8) ]
        d = []
        for i in range(n // 8):
            for j in range(4):
                for k in range(4):
                    r = 16*i + 4*j + k
                    a = y[j + 4*(5*i + k)]
                    b = (y[j + 4*(5*i + 4)] >> (16 * k)) & 0x7FFF
                    c = (a & 0x7FFFFFFFFFFFFFFF) + (b << 63)
                    v = 0
                    if t[r] == 0:
                        while c < T0[v]:
                            v += 1
                        v = 2*v
                    else:
                        while c < T1[v]:
                            v += 1
                        v = 2*v + 1
                    if a >= (1 << 63):
                        v = -v
                    d += [ v ]

        return (d[:n], d[n:])

    def hawk_sign(self, msg, priv):
        """(Alg 15) HawkSign: HAWK signature generation."""

        #   (-- 0: Initialize)
        n = 1 << self.logn

        #   --- 1: (kgseed, F mod 2, G mod 2, hpub) <- DecodePrivate(priv)
        (kgseed, F, G, hpub) = self._decode_private(priv)

        #   --- 2: (f, g) <- Regeneratefg(kgseed)
        (f, g) = self._regenerate_fg(kgseed)

        #   --- 3: M <- SHAKE256(m | hpub)[0 : 512]
        hm = SHAKE256.new(msg + hpub).read(64)

        #   --- 4: a <- 0
        a = 0

        #   --- 5: loop
        while True:

            #   --- 6:  salt <- SHAKE256(M | kgseed | EncodeInt(a, 32) |
            #                            Rnd(saltlen))[0 : saltlen ]
            salt = (hm + kgseed +
                    (a).to_bytes(4, byteorder='little') +
                    self.rnd(self.saltlen))
            salt = SHAKE256.new(salt).read(self.saltlen)

            #   --- 7:  (h0, h1) <- SHAKE256(M | salt)[0:2n]
            h = SHAKE256.new(hm + salt).read(2*n // 8)
            h0 = self._bytes2bits(h[:n//8])
            h1 = self._bytes2bits(h[n//8:])

            #   --- 8:  (t0, t1) <- ((h_0f + h_1F) mod 2, (h_0g + h_1G) mod 2)
            t0 = f_add( f_mul(h0, f), f_mul(h1, F) )
            t0 = [ x & 1 for x in t0 ]
            t1 = f_add( f_mul(h0, g), f_mul(h1, G) )
            t1 = [ x & 1 for x in t1 ]

            #   --- 9:  seed <- M | kgseed | EncodeInt(a + 1, 32) | Rnd(320)
            seed = (hm + kgseed +
                    (a + 1).to_bytes(4, byteorder='little') +
                    self.rnd(320 // 8))

            #   --- 10: (x0, x1) <- SamplerSign(seed, (t0, t1))
            (x0, x1) = self._sampler_sign(seed, t0 + t1)

            #   --- 11: a <- a + 2
            a += 2

            #   --- 12: if |(x0,x1)|2 > 8*n*sigma_verify^2 then continue
            if f_nsqe(x0) + f_nsqe(x1) > 8 * n * (self.dev_verify**2):
                continue

            #   --- 14: w1 <- f d1 - g d0
            w1 = f_sub( f_mul(f, x1), f_mul(g, x0) )

            #   --- 15: if sym-break(w1) = false then w1 <- -w1
            if self._sym_break(w1) == False:
                w1 = [ -x for x in w1 ]

            #   --- 17: s1 <- (h1 - w1) / 2
            s1 = f_shr( f_sub(h1, w1), 1 )

            #   --- 18: sig <- EncodeSignature(salt, s1)
            sig = self._encode_signature(salt, s1)

            #   --- 19: if sig != None then return sig
            if  sig != None:
                return sig

    def _sym_break(self, w):
        """sym-break: first non-zero coefficient is positive."""
        for x in w:
            if x > 0:
                return True
            if x < 0:
                return False
        return False


    def _rebuild_s0(self, q00, q01, w1, h0):
        """(Alg 18) RebuildS0: Rebuild s0 from public key and signature."""
        #   since w1 = h1-2s1  we have for  2s0 = 2(q01/q00) * (h1/2 - s1)
        q00t = c_fft(q00.copy())
        q01t = c_fft(q01.copy())
        w1t  = c_fft(w1.copy())
        f2s0 = c_ifft(c_mul(c_mul(q01t, c_inv(q00t)), w1t))
        w0 = []
        for i in range(len(h0)):
            w0 += [ h0[i] - 2 * round( (h0[i] - f2s0[i].real ) / 2 ) ]
        return w0

    def _poly_qnorm(self, q00, q01, w0, w1, par):
        """(Alg 19) PolyQnorm: polynomial Q-norm evaluation (modular)."""
        (n, w, ni, p) = par

        w0 = [ -x for x in w0 ]

        q00t = p_ntt(q00.copy(), par)
        q01t = p_ntt(q01.copy(), par)
        w0t = p_ntt(w0.copy(), par)
        w1t = p_ntt(w1.copy(), par)
        dt  = p_ntt_mul(w1t, p_ntt_inv( q00t, p), p)
        et  = f_add(w0t, p_ntt_mul( dt, q01t, p))
        ct  = f_add(p_ntt_mul(q00t, p_ntt_mul( et, p_ntt_adj(et), p ), p),
                    p_ntt_mul(dt, p_ntt_adj(w1t), p))
        r   = 0
        for x in ct:
            r += x
        return r % p

    def hawk_verify(self, pub, msg, sig):
        """(Alg 20) HawkVerify: HAWK signature verification."""
        #   (-- 0:  local init )
        n   =   1 << self.logn

        #   --- 1:  r <- DecodeSignature(sig)
        r = self._decode_signature(sig)

        #   --- 2:  if r == None then return false
        if r == None:
            return False

        #   --- 4:  (salt, s1) <- r
        (salt, s1) = r

        #   --- 5:  r = DecodePublic(pub)
        r = self._decode_public(pub)

        #   --- 6:  if r == None then return false
        if r == None:
            return False

        #   --- 8:  (q00, q01) <- r
        (q00, q01) = r

        #   --- 9:  hpub <- SHAKE256(pub)
        hpub = SHAKE256.new(pub).read(self.hpublen)

        #   --- 10: M <- SHAKE256(m | hpub)
        hm = SHAKE256.new(msg + hpub).read(64)

        #   --- 11: (h0, h1) <- SHAKE256(M | salt)[0:2n]
        h = SHAKE256.new(hm + salt).read(2*n // 8)
        h0 = self._bytes2bits(h[:n//8])
        h1 = self._bytes2bits(h[n//8:])

        #   --- 12: w1 <- h1 - 2 * s1
        w1 = f_sub(h1, f_scale(s1, 2))

        #   --- 13: if sym-break(w1) = false then return false
        if self._sym_break(w1) == False:
            return False

        #   --- 15: w0 <- RebuildS0(q00, q01, w1, h0 )
        w0 = self._rebuild_s0(q00, q01, w1, h0)

        #   --- 18: r1 <- PolyQnorm(q00  q01, w0, w1, p1)
        r1 = self._poly_qnorm(q00, q01, w0, w1, self.par1 )

        #   --- 19: r2 <- PolyQnorm(q00  q01, w0, w1, p1)
        r2 = self._poly_qnorm(q00, q01, w0, w1, self.par2 )

        #   --- 20: if r1 != r2 or r1 != 0 mod n then return false
        if r1 != r2 or r1 % n != 0:
            return False

        #   --- 22: r1 <- r1 / n
        r1 = r1 // n

        #   --- 23: if r1 >  > 8*n*sigma_verify^2 then return false
        if r1 > 8 * n * (self.dev_verify**2):
            return False

        #   --- 25: return true
        return True

if __name__ == '__main__':
    #   Testing instance
    iut = Hawk(9)
    msg = b'abc'
    (pub,priv) = iut.keygen()
    print("pub =", pub.hex())
    print("priv =", priv.hex())
    print("msg =", msg.hex())
    sig = iut.hawk_sign(msg, priv)
    print("sig =", sig.hex())
    r = iut.hawk_verify(pub, msg, sig)
    print("vrfy =", r)

