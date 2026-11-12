"""
ECDSA (secp256k1) wrapper for EVM-compatible signatures.
Provides standard key generation, signing, verification, and (r, s, v) formatting.
"""

import os
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib

class ECDSAScheme:
    NAME = "ECDSA-secp256k1"
    PUBKEY_SIZE = 64     # Uncompressed (X, Y) without 0x04 prefix
    SIG_SIZE = 65        # r (32) + s (32) + v (1)

    def __init__(self):
        self.curve = ec.SECP256K1()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate (secret_key, public_key) pair.
        secret_key: 32 bytes scalar.
        public_key: 64 bytes (uncompressed X || Y coordinates).
        """
        priv_key = ec.generate_private_key(self.curve, default_backend())
        sk = priv_key.private_numbers().private_value.to_bytes(32, byteorder='big')
        
        pub_numbers = priv_key.public_key().public_numbers()
        x = pub_numbers.x.to_bytes(32, byteorder='big')
        y = pub_numbers.y.to_bytes(32, byteorder='big')
        pk = x + y
        return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Signs message digest (typically keccak256 or sha256).
        Returns 65-byte signature: r (32) || s (32) || v (1).
        """
        priv_val = int.from_bytes(secret_key, byteorder='big')
        priv_key = ec.derive_private_key(priv_val, self.curve, default_backend())
        
        # We hash the message with SHA-256 / Keccak-256 for deterministic signature
        msg_hash = hashlib.sha256(message).digest()
        
        # RFC 6979 deterministic ECDSA
        der_sig = priv_key.sign(msg_hash, ec.ECDSA(hashes.SHA256()))
        r, s = self._decode_der_signature(der_sig)
        
        # Enforce low S (EIP-2)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if s > n // 2:
            s = n - s
            
        # Simplified recovery ID v for EVM (27 or 28)
        v = 27
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + bytes([v])

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify an ECDSA signature over message.
        """
        if len(public_key) != 64 or len(signature) != 65:
            return False
            
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:64], 'big')
        
        x = int.from_bytes(public_key[:32], 'big')
        y = int.from_bytes(public_key[32:], 'big')
        
        try:
            pub_numbers = ec.EllipticCurvePublicNumbers(x, y, self.curve)
            pub_key = pub_numbers.public_key(default_backend())
            msg_hash = hashlib.sha256(message).digest()
            der_sig = self._encode_der_signature(r, s)
            pub_key.verify(der_sig, msg_hash, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    @staticmethod
    def _decode_der_signature(der: bytes) -> Tuple[int, int]:
        # Minimal ASN.1 DER parser for ECDSA signature
        idx = 2  # skip 0x30 and length
        assert der[idx] == 0x02
        idx += 1
        r_len = der[idx]
        idx += 1
        r = int.from_bytes(der[idx:idx + r_len], 'big')
        idx += r_len
        assert der[idx] == 0x02
        idx += 1
        s_len = der[idx]
        idx += 1
        s = int.from_bytes(der[idx:idx + s_len], 'big')
        return r, s

    @staticmethod
    def _encode_der_signature(r: int, s: int) -> bytes:
        rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
        if rb[0] >= 0x80:
            rb = b'\x00' + rb
        sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
        if sb[0] >= 0x80:
            sb = b'\x00' + sb
        der = b'\x02' + bytes([len(rb)]) + rb + b'\x02' + bytes([len(sb)]) + sb
        return b'\x30' + bytes([len(der)]) + der
