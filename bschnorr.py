# based on Joseph Birr-Pixton's https://github.com/ctz/u2f-secret-storage

"""
Comedy blinded Schnorr signing and verification.
Don't use this for anything important.
Not intended to be interoperable.

!!! broken !!! check out https://eprint.iacr.org/2020/945.pdf Section 5.1
"""

import ec
from schnorr import _hash_message, verify

def bank_init(curve):
    return curve.generate_key()

def user_blind(curve, hash, pub, message, R):
    a = curve.rand_scalar()
    b = curve.rand_scalar()

    p1 = curve.base_mul(int(a))
    p2 = curve.point_mul(int(b), pub)

    Rp = curve.point_add(R, p1)
    Rp = curve.point_add(Rp, p2)

    xrp = curve.fe2i(Rp.x)

    # XXX: properly serialize inputs to hash function
    # XXX: add public key into hash input
    ep = _hash_message(curve, hash, hex(xrp) + message)
    e = ec.modp(curve.n, ep - b)[0]
    return a, xrp, ep, e

def bank_sign(curve, k, e, priv):
    e, priv, k = ec.modp(curve.n, int(e), int(priv), int(k))
    s = k - e*priv
    return s

def user_unblind(curve, s, a):
    # XXX: check s is consistent as sG ?= R + cX (ie signer didn't cheat)
    sp = ec.modp(curve.n, int(s)+int(a))
    return int(sp[0])

import hashlib
H = hashlib.sha256

def small_test():
    # bank generates Schnorr key pair
    priv, Q = ec.nistp256.generate_key()

    # step 1: bank prepares a Schnorr nonce and commits to it
    # bank keeps: k 
    # bank -> user: R
    k, R = bank_init(ec.nistp256)

    # step 2: user prepares blinding factors
    # user keeps:  (a, rp) 
    # user -> bank: e
    msg = 'hello world'
    a, rp, ep, e = user_blind(ec.nistp256, H, Q, msg, R)

    # step 3: bank actually signs
    # bank -> user: s
    s = bank_sign(ec.nistp256, k, e, priv)

    # step 4: user computes, verifies and releases signature (rp, sp)
    sp = user_unblind(ec.nistp256, s, a)

    print "blinded sig (r,s) ", (rp, sp)
    verify(ec.nistp256, H, Q, msg, (rp, sp))

if __name__ == "__main__":
    while True:
        small_test()
