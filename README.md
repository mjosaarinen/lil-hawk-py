#	lil-hawk-py

2023-07-12  Markku-Juhani O. Saarinen  mjos@pqshield.com

A (self-)educational re-implementation of the [Hawk](https://hawk-sign.info/) signature scheme. NOT FOR PRODUCTION USE.

This is not a speed optimized version; it doesn't even use the NTT functions unless it has to (in verification.) You'll note that the code follows the pseudocode of the [Hawk 1.0 spec](https://hawk-sign.info/hawk-spec.pdf) line-by-line.

After working on this for a few days, I realized there already is a [python implementation](https://github.com/hawk-sign/hawk-py). However, this implementation is smaller (1300 LOC vs 4318 LOC) and checks against the submission package KAT test vectors.

You can generate KAT vectors with `python3 test_kat.py`. The official KAT response files are contained in the Hawk submission package (see the official site above), but you can check the contents with `sha256sum *.rsp` against:
```
be01e169ac0621bf27c8feee6b19b10ab9c99ec8f3d882101b0a25e048822d45  PQCsignKAT_96.rsp
9ce26b957bf9995c8f07b8bf25831a61a8bd415901e713c66e4e2c768c505f83  PQCsignKAT_184.rsp
a9331558b5ac22322c2163293327481d983f3e783f86a86d9a703fb3f6d0c5e8  PQCsignKAT_360.rsp
```

###	On NTRUSolve and key generation, "invalid key list"

Note that the Hawk specification does not describe the *NTRUSolve* function that the key generation relies on to find small-coefficient solutions to the NTRU equation fG-gF=q -- only a pointer to reference [PP19](https://eprint.iacr.org/2019/015.pdf) is provided. The reference implementation uses a fast but approximate/heuristic method that sometimes fails even if a solution exists, and the simple NTRUSolve in this little implementation finds it.

To match the KAT files exactly, the KAT test code in `test_kat.py` has a list of `kgseed` instances where a solution exists, but the reference NTRUSolve can't find it. These candidates are simply skipped. These are all cases of the reference NTRUSolve arriving at an internal error [`SOLVE_ERR_REDUCE`](https://github.com/hawk-sign/dev/blob/ac3a98c3107ea030cc18fb2afef7f5655c588138/src/ng_ntru.c#L1047).

Note that this is not a security issue since there is no indication that the keys that pass the "approximate NTRUSolve filter" of the reference implementation are weaker than random keys. However, this is problematic for testing.

