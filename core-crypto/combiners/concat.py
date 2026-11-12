"""
Bindel et al. Concatenation Combiner.
Combines two signatures independently over the original message:
sigma = (sigma_1, sigma_2)
"""

from typing import Tuple, Any

class ConcatCombiner:
    COMBINER_NAME = "Bindel-Concat"

    def __init__(self, scheme1: Any, scheme2: Any):
        self.s1 = scheme1
        self.s2 = scheme2

    def sign(self, sk1: bytes, sk2: bytes, message: bytes) -> Tuple[bytes, bytes]:
        """
        Produce hybrid concatenation signature (sig1, sig2).
        """
        sig1 = self.s1.sign(sk1, message)
        sig2 = self.s2.sign(sk2, message)
        return sig1, sig2

    def verify(self, pk1: bytes, pk2: bytes, message: bytes, sig1: bytes, sig2: bytes) -> bool:
        """
        Verify both signatures against message m.
        """
        v1 = self.s1.verify(pk1, message, sig1)
        v2 = self.s2.verify(pk2, message, sig2)
        return v1 and v2
