"""
Bindel et al. Weak Nested Combiner.
Outer scheme signs inner signature:
sigma_1 = Sign_1(sk1, m)
sigma_2 = Sign_2(sk2, sigma_1)
"""

from typing import Tuple, Any

class WeakNestedCombiner:
    COMBINER_NAME = "Bindel-WeakNested"

    def __init__(self, inner_scheme: Any, outer_scheme: Any):
        self.inner = inner_scheme
        self.outer = outer_scheme

    def sign(self, sk_inner: bytes, sk_outer: bytes, message: bytes) -> Tuple[bytes, bytes]:
        """
        Produce weak nested hybrid signature:
        sig_inner signs message, sig_outer signs sig_inner.
        """
        sig_inner = self.inner.sign(sk_inner, message)
        sig_outer = self.outer.sign(sk_outer, sig_inner)
        return sig_inner, sig_outer

    def verify(
        self, pk_inner: bytes, pk_outer: bytes, message: bytes, sig_inner: bytes, sig_outer: bytes
    ) -> bool:
        """
        Verify that outer signature signs inner signature, and inner signs message.
        """
        v_outer = self.outer.verify(pk_outer, sig_inner, sig_outer)
        if not v_outer:
            return False
        return self.inner.verify(pk_inner, message, sig_inner)
