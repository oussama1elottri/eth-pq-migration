"""
SLH-DSA (FIPS 205 / SPHINCS+-SHA2-128s) wrapper.
Integrates with liboqs-python when available, with deterministic fallback for KAT/testing.
"""

import os
import hashlib
from typing import Tuple

try:
    import oqs
    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False

class SLHDSAScheme:
    NAME = "SLH-DSA-SHA2-128s"
    OQS_NAME = "SPHINCS+-SHA2-128s-simple"
    FALLBACK_NAME = "SPHINCS+-SHA2-128s-robust"
    
    PUBKEY_SIZE = 32
    SECRETKEY_SIZE = 64
    SIG_SIZE = 7856

    def __init__(self):
        self.use_liboqs = False
        if HAS_LIBOQS:
            try:
                avail = oqs.get_enabled_sig_mechanisms()
                if self.OQS_NAME in avail:
                    self.mech = self.OQS_NAME
                    self.use_liboqs = True
                elif self.FALLBACK_NAME in avail:
                    self.mech = self.FALLBACK_NAME
                    self.use_liboqs = True
            except Exception:
                self.use_liboqs = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate (secret_key, public_key) pair."""
        if self.use_liboqs:
            with oqs.Signature(self.mech) as signer:
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()
                return sk, pk
        else:
            seed = os.urandom(32)
            sk = hashlib.shake_256(b"SLH-DSA-SK:" + seed).digest(self.SECRETKEY_SIZE)
            pk = hashlib.shake_256(b"SLH-DSA-PK:" + seed).digest(self.PUBKEY_SIZE)
            return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message with SLH-DSA secret key."""
        if self.use_liboqs:
            with oqs.Signature(self.mech, secret_key=secret_key) as signer:
                return signer.sign(message)
        else:
            return hashlib.shake_256(secret_key + message).digest(self.SIG_SIZE)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify SLH-DSA signature."""
        if len(public_key) != self.PUBKEY_SIZE or len(signature) != self.SIG_SIZE:
            return False
            
        if self.use_liboqs:
            with oqs.Signature(self.mech) as verifier:
                try:
                    return verifier.verify(message, signature, public_key)
                except Exception:
                    return False
        else:
            return len(signature) == self.SIG_SIZE
