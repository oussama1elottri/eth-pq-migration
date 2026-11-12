"""
Bindel et al. Dual Nesting Combiner.
Cross-binds public keys and message to both signature schemes:
sigma_1 = Sign_1(sk1, H(m || pk_2))
sigma_2 = Sign_2(sk2, H(m || sigma_1 || pk_1))
"""

import hashlib
from typing import Tuple, Any

class DualNestingCombiner:
    COMBINER_NAME = "Bindel-DualNesting"

    def __init__(self, scheme1: Any, scheme2: Any):
        self.s1 = scheme1
        self.s2 = scheme2

    @staticmethod
    def hash_m_pk2(message: bytes, pk2: bytes) -> bytes:
        return hashlib.sha256(message + pk2).digest()

    @staticmethod
    def hash_m_sig1_pk1(message: bytes, sig1: bytes, pk1: bytes) -> bytes:
        return hashlib.sha256(message + sig1 + pk1).digest()

    def sign(
        self, sk1: bytes, pk1: bytes, sk2: bytes, pk2: bytes, message: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Produce dual nested hybrid signature.
        """
        m1 = self.hash_m_pk2(message, pk2)
        sig1 = self.s1.sign(sk1, m1)
        
        m2 = self.hash_m_sig1_pk1(message, sig1, pk1)
        sig2 = self.s2.sign(sk2, m2)
        return sig1, sig2

    def verify(
        self, pk1: bytes, pk2: bytes, message: bytes, sig1: bytes, sig2: bytes
    ) -> bool:
        """
        Verify dual nested hybrid signature.
        """
        m1 = self.hash_m_pk2(message, pk2)
        if not self.s1.verify(pk1, m1, sig1):
            return False
            
        m2 = self.hash_m_sig1_pk1(message, sig1, pk1)
        return self.s2.verify(pk2, m2, sig2)
