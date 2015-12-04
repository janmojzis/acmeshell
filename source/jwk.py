from tobase64 import tobase64
from tobytes import tobytes
import hashlib


def jwk(e, n):
        """
        Create JSON Web Key from RSA exponent end modulus
        """

        return { "e": tobase64(e), "kty": "RSA", "n": tobase64(n) }


def jwkthumb(e, n):
        """
        JSON Web Key Thumbprint SHA256 from RSA exponent end modulus
        """

        js = '{"e":"%s","kty":"RSA","n":"%s"}' % (tobase64(e), tobase64(n))
        return tobase64(hashlib.sha256(tobytes(js)).digest())
