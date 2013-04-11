# -*- encoding: utf-8 -*-

"""HKDF Implementation as per RFC 5869
(http://tools.ietf.org/html/rfc5869)"""

import hashlib
import hmac

def extract(IKM, salt=None, H=hashlib.sha256):
    h = H()
    if salt is None:
        salt = "\x00"*h.digest_size
    return hmac.HMAC(salt, IKM, H).digest()

def expand(PRK, L, info="", H=hashlib.sha256):
    h = H()
    N = (L+h.digest_size-1)/h.digest_size
    assert(N<254)
    T = ""
    for i in xrange(N+1):
        T += hmac.HMAC(PRK, T[:h.digest_size] + info + chr(i+1), H).digest()

    return T[:L]

def genkey(IKM, L, info="", salt=None, H=hashlib.sha256):
    return expand(extract(IKM, salt, H), L, info, H)
