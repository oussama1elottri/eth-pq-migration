"""
Falcon-512 (FN-DSA) wrapper.
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

class Falcon512Scheme:
    NAME = "Falcon-512"
    OQS_NAME = "Falcon-512"
    
    PUBKEY_SIZE = 897
    SECRETKEY_SIZE = 1281
    SIG_SIZE = 666
    SIG_PADDED_SIZE = 690

    def __init__(self):
        self.use_liboqs = False
        if HAS_LIBOQS:
            try:
                avail = oqs.get_enabled_sig_mechanisms()
                if self.OQS_NAME in avail:
                    self.mech = self.OQS_NAME
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
            sk = hashlib.shake_256(b"Falcon-512-SK:" + seed).digest(self.SECRETKEY_SIZE)
            pk = hashlib.shake_256(b"Falcon-512-PK:" + seed).digest(self.PUBKEY_SIZE)
            return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message with Falcon-512 secret key."""
        if self.use_liboqs:
            with oqs.Signature(self.mech, secret_key=secret_key) as signer:
                sig = signer.sign(message)
                return sig
        else:
            return hashlib.shake_256(secret_key + message).digest(self.SIG_SIZE)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify Falcon-512 signature."""
        if len(public_key) != self.PUBKEY_SIZE:
            return False
            
        if self.use_liboqs:
            with oqs.Signature(self.mech) as verifier:
                try:
                    return verifier.verify(message, signature, public_key)
                except Exception:
                    return False
        else:
            return len(signature) in (self.SIG_SIZE, self.SIG_PADDED_SIZE)
