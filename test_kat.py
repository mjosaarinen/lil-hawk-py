#   test_kat.py
#   2023-07-12  Markku-Juhani O. Saarinen <mjos@pqshield.com>. See LICENSE
#   Generate NIST test vectors (takes a while)

from Crypto.Cipher import AES
from hawk import Hawk

class NIST_KAT_DRBG:
    """AES-256 CTR to extract "fake" DRBG outputs that are compatible with
        the randombutes() call in the NIST KAT testing suite."""

    def __init__(self, seed):
        self.seed_length = 48
        assert len(seed) == self.seed_length
        self.key = bytes([0])*32
        self.ctr = bytes([0])*16
        update = self.get_bytes(self.seed_length)
        update = bytes(a^b for a,b in zip(update,seed))
        self.key = update[:32]
        self.ctr = update[32:]

    def __increment_ctr(self):
        x = int.from_bytes(self.ctr, 'big') + 1
        self.ctr = x.to_bytes(16, byteorder='big')

    def get_bytes(self, num_bytes):
        tmp = b""
        cipher = AES.new(self.key, AES.MODE_ECB)
        while len(tmp) < num_bytes:
            self.__increment_ctr()
            tmp  += cipher.encrypt(self.ctr)
        return tmp[:num_bytes]

    def random_bytes(self, num_bytes):
        output_bytes = self.get_bytes(num_bytes)
        update = self.get_bytes(48)
        self.key = update[:32]
        self.ctr = update[32:]
        return output_bytes

def reduce_error_kgseed(kgseed):
    """
    Return true if kgseed is invalid due to internal reduction errors
    in the reference implementation of NTRUSolve (SOLVE_ERR_REDUCE).
    """
    katfail = {
        (0x0C555E1E0F591E20, 16),   # Hawk-256   count= 19 / 125
        (0xC45A0E5E93DDFE17, 16),   # Hawk-256   count= 41 / 68
        (0x62FCE7094591D05F, 16),   # Hawk-256   count= 42 / 150
        (0x714D0C6AB71937E5, 24),   # Hawk-512   count=  0 / 15
        (0xC9D809E8C6B99A90, 24),   # Hawk-512   count=  2 / 2
        (0x4E0DB1FBA2443007, 24),   # Hawk-512   count= 11 / 26
        (0x5E362FCAA77B3FA0, 24),   # Hawk-512   count= 15 / 2
        (0xF29EC0F0BE074E6B, 24),   # Hawk-512   count= 21 / 39
        (0x92C350D19955474B, 24),   # Hawk-512   count= 33 / 26
        (0xE2C10EF68B795310, 24),   # Hawk-512   count= 36 / 45
        (0x3161196D21647367, 24),   # Hawk-512   count= 38 / 4
        (0x256939479F9B43BD, 24),   # Hawk-512   count= 40 / 20
        (0x6F0C9E3E450AA62E, 24),   # Hawk-512   count= 52 / 14
        (0x88587508B5EEAE2F, 24),   # Hawk-512   count= 52 / 19
        (0x5DDD9BEEFA221D76, 24),   # Hawk-512   count= 58 / 15
        (0x4239CE4FB85129AD, 24),   # Hawk-512   count= 65 / 6
        (0x0D11A5AFD3241F11, 24),   # Hawk-512   count= 84 / 7
        (0xD5AC3223B7D96459, 24),   # Hawk-512   count= 94 / 14
        (0x5C77A5C9BB52F4A2, 24),   # Hawk-512   count= 98 / 7
        (0xEB69AA98068AE1FF, 40),   # Hawk-1024  count=  3 / 4
        (0xEC1006679B2DDF6E, 40),   # Hawk-1024  count=  3 / 6
        (0x03CC79C3F8476F77, 40),   # Hawk-1024  count=  3 / 8
        (0x4C79880E120866C5, 40),   # Hawk-1024  count=  3 / 19
        (0xB4702B52B96CF0EC, 40),   # Hawk-1024  count=  3 / 26
        (0xE2228A1F1EA10959, 40),   # Hawk-1024  count=  3 / 27
        (0xF11C3589F6138D03, 40),   # Hawk-1024  count=  9 / 3
        (0xFE2317C0B0EFD1AD, 40),   # Hawk-1024  count= 11 / 3
        (0xA844378616A654C2, 40),   # Hawk-1024  count= 12 / 16
        (0x61CD090027D2AF37, 40),   # Hawk-1024  count= 12 / 18
        (0xA5AA6BEEF2AA4F11, 40),   # Hawk-1024  count= 12 / 23
        (0xA2B78121414CD88B, 40),   # Hawk-1024  count= 12 / 26
        (0x9D53E3DA4F4DC7C9, 40),   # Hawk-1024  count= 13 / 8
        (0xCB6F332422B7629B, 40),   # Hawk-1024  count= 16 / 2
        (0xCE881ED5C4F7839D, 40),   # Hawk-1024  count= 16 / 17
        (0x89F378A3BF7B353A, 40),   # Hawk-1024  count= 20 / 5
        (0x15583C6ADBB03153, 40),   # Hawk-1024  count= 20 / 7
        (0xB46867182F212D81, 40),   # Hawk-1024  count= 20 / 9
        (0x6F9ECCAB4A600B2A, 40),   # Hawk-1024  count= 21 / 2
        (0x0B64DBCA7917B1C0, 40),   # Hawk-1024  count= 21 / 11
        (0x950226D6AB0B774C, 40),   # Hawk-1024  count= 23 / 0
        (0x97A0E64FD82F3B0E, 40),   # Hawk-1024  count= 23 / 4
        (0x48A6F1129500C9C6, 40),   # Hawk-1024  count= 24 / 2
        (0xC9DFBE7E5C0D5115, 40),   # Hawk-1024  count= 25 / 8
        (0xB5E6F6695F2C209A, 40),   # Hawk-1024  count= 27 / 1
        (0x14605C352F895845, 40),   # Hawk-1024  count= 27 / 10
        (0xD8EF601F4C760883, 40),   # Hawk-1024  count= 27 / 17
        (0xD53B8D1FE57470A1, 40),   # Hawk-1024  count= 27 / 21
        (0x52F81ECAE58B7EA8, 40),   # Hawk-1024  count= 27 / 26
        (0x04D377DDCBE862F9, 40),   # Hawk-1024  count= 28 / 3
        (0x3A3A9C0EA09DF32A, 40),   # Hawk-1024  count= 29 / 22
        (0x3A7A7A580CCEFB37, 40),   # Hawk-1024  count= 29 / 38
        (0xA900C1E737918030, 40),   # Hawk-1024  count= 31 / 7
        (0x22420FA58BF0D179, 40),   # Hawk-1024  count= 31 / 13
        (0x86734218879D5A67, 40),   # Hawk-1024  count= 32 / 1
        (0xB2B6104233BC4D6D, 40),   # Hawk-1024  count= 36 / 1
        (0x078FBB0D10822B36, 40),   # Hawk-1024  count= 39 / 3
        (0xBD6E6021669A6E81, 40),   # Hawk-1024  count= 45 / 1
        (0x06884CBF437CDB0F, 40),   # Hawk-1024  count= 53 / 2
        (0xAA49697D2C3CD7F9, 40),   # Hawk-1024  count= 55 / 1
        (0xE1C731DEB049B6C5, 40),   # Hawk-1024  count= 58 / 2
        (0x94CA2616827FBC14, 40),   # Hawk-1024  count= 58 / 5
        (0x751DC5E1E28B2911, 40),   # Hawk-1024  count= 58 / 15
        (0x7F8515AA82DBC9EC, 40),   # Hawk-1024  count= 59 / 0
        (0x4C0F0EF1CA8073A5, 40),   # Hawk-1024  count= 64 / 0
        (0x13F55E4C5A3AE248, 40),   # Hawk-1024  count= 64 / 8
        (0x1B88712B41FB6662, 40),   # Hawk-1024  count= 64 / 14
        (0x9E0116FD18098FB1, 40),   # Hawk-1024  count= 66 / 4
        (0x1C5CBE3A32795B76, 40),   # Hawk-1024  count= 67 / 6
        (0x4DEBEF6D99728AA1, 40),   # Hawk-1024  count= 68 / 9
        (0xE8AED3951951AE6E, 40),   # Hawk-1024  count= 68 / 10
        (0xC220A03866EBE147, 40),   # Hawk-1024  count= 68 / 21
        (0x6A27B1666AB6FC44, 40),   # Hawk-1024  count= 69 / 0
        (0xE2CC94E50CCF6DE7, 40),   # Hawk-1024  count= 69 / 5
        (0x295CC66B860B6834, 40),   # Hawk-1024  count= 69 / 7
        (0x4E011218E4339033, 40),   # Hawk-1024  count= 69 / 13
        (0xF69E0A6E321FDC43, 40),   # Hawk-1024  count= 69 / 14
        (0x97B05CFB668E985F, 40),   # Hawk-1024  count= 69 / 16
        (0xE6A6AFC8F9AF04A9, 40),   # Hawk-1024  count= 69 / 23
        (0xCFFCEC91FEFD6FDE, 40),   # Hawk-1024  count= 69 / 27
        (0x0687C4DC74E75625, 40),   # Hawk-1024  count= 69 / 30
        (0x1D75CEEECDFA9E15, 40),   # Hawk-1024  count= 69 / 37
        (0x39F2C30676BC0FE0, 40),   # Hawk-1024  count= 69 / 44
        (0xD1934B8A71D28B44, 40),   # Hawk-1024  count= 71 / 2
        (0x56C4F111DFE3A3A6, 40),   # Hawk-1024  count= 79 / 2
        (0x1CDA70CF7046324C, 40),   # Hawk-1024  count= 92 / 3
        (0x7A652746F9B248CD, 40),   # Hawk-1024  count= 96 / 1
        (0x37519A02E8021F22, 40),   # Hawk-1024  count= 98 / 0
        (0x4E72095EB17BB89B, 40),   # Hawk-1024  count= 98 / 1
    }
    #   compare only first 8 bytes and the length
    x = int.from_bytes(kgseed[0:8], byteorder='big')
    return (x, len(kgseed)) in katfail

def kat_keygen(iut):
    """Generate a public-private key pair filtered for NTRUSolve failure."""
    r = None
    while r == None:
        kgseed = iut.rnd(iut.kgseedlen)
        if reduce_error_kgseed(kgseed):
            continue
        r = iut.hawk_keygen(kgseed)
    return r

#   This is intended to match the .rsp output from NIST PQCgenKAT_sign.c

def nist_kat_rsp(iut, katnum=100):
    """Create a test vector string matching official NIST KATs."""

    def _fmt_int(fh, label, n):
        fh.write(f"{label} = {n}\n")

    def _fmt_hex(fh, label, data):
        fh.write(f"{label} = {data.hex().upper()}\n")

    #   kat files are named based on secret key length in the nist suite
    fn = f"PQCsignKAT_{iut.privlen}.rsp"
    with open(fn, "w") as fh:

        #   KAT response file (no need for the request file here)
        fh.write(f"# {iut.algname}\n\n")

        entropy_input = bytes([i for i in range(48)])
        drbg = NIST_KAT_DRBG(entropy_input)

        for count in range(katnum):

            print(f"{iut.algname}: {fn} writing {count+1}/{katnum}.")

            _fmt_int(fh, "count", count)
            seed = drbg.random_bytes(48)
            _fmt_hex(fh, "seed", seed)
            mlen = 33 * (count + 1)
            _fmt_int(fh, "mlen", mlen)
            msg = drbg.random_bytes(mlen)
            _fmt_hex(fh, "msg", msg)

            #   force deterministic
            iut.set_random(NIST_KAT_DRBG(seed).random_bytes)

            #   filter iut.keygen()
            pk, sk = kat_keygen(iut)
            _fmt_hex(fh, "pk", pk)
            _fmt_hex(fh, "sk", sk)

            #   create signature
            sm = iut.sign(msg, sk)
            _fmt_int(fh, "smlen", len(sm))
            _fmt_hex(fh, "sm", sm)
            fh.write('\n')
            assert iut.open(sm, pk) == (True, msg)

if (__name__ == "__main__"):
    for i in range(3):
        iut = Hawk(8 + i)
        nist_kat_rsp(iut)
