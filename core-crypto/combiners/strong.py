"""
Bindel et al. Strong Nested Combiner.
Binds message, inner signature, and inner public key:
sigma_1 = Sign_1(sk1, m)
sigma_2 = Sign_2(sk2, H(m || sigma_1 || pk_1))
"""

import hashlib
from typing import Tuple, Any

class StrongNestedCombiner:
    COMBINER_NAME = "Bindel-StrongNested"

    def __init__(self, inner_scheme: Any, outer_scheme: Any):
        self.inner = inner_scheme
        self.outer = outer_scheme

    @staticmethod
    def compute_intermediate_hash(message: bytes, sig_inner: bytes, pk_inner: bytes) -> bytes:
        return hashlib.sha256(message + sig_inner + pk_inner).digest()

    def sign(self, sk_inner: bytes, sk_outer: bytes, pk_inner: bytes, message: bytes) -> Tuple[bytes, bytes]:
        """
        Produce strong nested hybrid signature.
        """
        sig_inner = self.inner.sign(sk_inner, message)
        h_outer = self.compute_intermediate_hash(message, sig_inner, pk_inner)
        sig_outer = self.outer.sign(sk_outer, h_outer)
        return sig_inner, sig_outer

    def verify(
        self, pk_inner: bytes, pk_outer: bytes, message: bytes, sig_inner: bytes, sig_outer: bytes
    ) -> bool:
        """
        Verify strong nested hybrid signature.
        """
        h_outer = self.compute_intermediate_hash(message, sig_inner, pk_inner)
        v_outer = self.outer.verify(pk_outer, h_outer, sig_outer)
        if not v_outer:
            return False
        return self.inner.verify(pk_inner, message, sig_inner)
