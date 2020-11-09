# based on Joseph Birr-Pixton's https://github.com/ctz/u2f-secret-storage

"""
Comedy Schnorr signing and verification.
Don't use this for anything important.
Not intended to be interoperable.
"""

import ec
from ecdsa import _hash_message

def sign(curve, hash, priv, message, nonce=None):
    """
    Sign given message, hashing it with hash.
    Use the given private key (a scalar), on given curve.
    """

    while True:
        if nonce == None:
            k, R = curve.generate_key()
            #k = 38642705407899615353112568654350726618181305661874559450207851549217158808738
            #R = curve.base_mul(int(k))
            #print "R: ", R
        else:
            k, R = nonce
        #print "nonce k:", k
        xr = curve.fe2i(R.x)
        pub = curve.fe2i(curve.base_mul(int(priv)).x)
        # XXX use tight serialization
        #e = _hash_message(curve, hash, hex(pub) + hex(xr) + message)
        e = _hash_message(curve, hash, hex(xr) + message)
        print "e: ", e
        e, d, k, xr = ec.modp(curve.n, e, priv, k, xr) #
        s = (k - e*d)
        if int(xr) != 0 and int(s) != 0:
            return int(xr), int(s)

def verify(curve, hash, pub, message, sig):
    """
    Verify given signature on message (hashed with given
    hash function).  Public key is on the curve.

    Returns nothing on success, raises on error.
    """
    r, s = sig
    error = ValueError('invalid signature')

    if r < 1 or r >= curve.n or s < 1 or s >= curve.n or not curve.point_on_curve(pub):
        raise error

    # XXX: proper serialization of hash inputs
    #e = _hash_message(curve, hash, hex(curve.fe2i(pub.x)) + hex(r) + message)
    e = _hash_message(curve, hash, hex(r) + message)
    e, r, s = ec.modp(curve.n, e, r, s)

    p1 = curve.base_mul(int(s))
    p2 = curve.point_mul(int(e), pub)
    R = curve.point_add(p1, p2)
    if R.at_inf:
        raise error

    xr = curve.fe2i(R.x)
    v, = ec.modp(curve.n, xr)
    if v != r:
        raise error


def test_small():
    import hashlib
    H = hashlib.sha256

    k, Q = ec.nistp256.generate_key()
    #k = 94306422727956111492527276612919538250253517123717504295942571995000690042457
    #Q = ec.nistp256.base_mul(int(k))
    print 'pub', Q
    print 'priv', k
    msg = 'hello world'
    sig = sign(ec.nistp256, H, k, msg)
    print 'r', sig[0]
    print 's', sig[1]
    verify(ec.nistp256, H, Q, msg, sig)

    try:
        verify(ec.nistp256, H, Q, msg + 'foo', sig)
        assert False, 'signature was invalid'
    except ValueError:
        pass


if __name__ == '__main__':
    while True:
        test_small()
