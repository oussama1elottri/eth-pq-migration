#!/usr/bin/env python3
"""
Known Answer Test (KAT) Generator.
Generates reproducible test vectors for classical (ECDSA), post-quantum (ML-DSA-44, Falcon-512, SLH-DSA),
and Bindel et al. hybrid combiners (Concat, Weak, Strong, Dual Nesting).
Outputs deterministic JSON test vectors for Python and Solidity verifiers.
"""

import json
import os
import sys
import hashlib

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemes.ecdsa import ECDSAScheme
from schemes.mldsa44 import MLDSA44Scheme
from schemes.falcon512 import Falcon512Scheme
from schemes.slhdsa import SLHDSAScheme
from combiners.concat import ConcatCombiner
from combiners.weak import WeakNestedCombiner
from combiners.strong import StrongNestedCombiner
from combiners.dual_nesting import DualNestingCombiner

def generate_kats():
    print("[*] Initializing schemes...")
    ecdsa = ECDSAScheme()
    mldsa = MLDSA44Scheme()
    falcon = Falcon512Scheme()
    slhdsa = SLHDSAScheme()

    msg = b"EVM-PQC-Bench: Deterministic KAT Benchmark Payload v1.0"
    msg_hash = hashlib.sha256(msg).digest()

    print("[*] Generating Keypairs...")
    ecdsa_sk, ecdsa_pk = ecdsa.generate_keypair()
    mldsa_sk, mldsa_pk = mldsa.generate_keypair()
    falcon_sk, falcon_pk = falcon.generate_keypair()
    slhdsa_sk, slhdsa_pk = slhdsa.generate_keypair()

    print("[*] Generating Standalone Scheme Signatures...")
    ecdsa_sig = ecdsa.sign(ecdsa_sk, msg)
    mldsa_sig = mldsa.sign(mldsa_sk, msg)
    falcon_sig = falcon.sign(falcon_sk, msg)
    slhdsa_sig = slhdsa.sign(slhdsa_sk, msg)

    print("[*] Generating Bindel Combiner Signatures (ECDSA + Falcon-512)...")
    concat_falcon = ConcatCombiner(ecdsa, falcon)
    concat_sig1, concat_sig2 = concat_falcon.sign(ecdsa_sk, falcon_sk, msg)

    weak_falcon = WeakNestedCombiner(ecdsa, falcon)
    weak_sig1, weak_sig2 = weak_falcon.sign(ecdsa_sk, falcon_sk, msg)

    strong_falcon = StrongNestedCombiner(ecdsa, falcon)
    strong_sig1, strong_sig2 = strong_falcon.sign(ecdsa_sk, falcon_sk, ecdsa_pk, msg)

    dual_falcon = DualNestingCombiner(ecdsa, falcon)
    dual_sig1, dual_sig2 = dual_falcon.sign(ecdsa_sk, ecdsa_pk, falcon_sk, falcon_pk, msg)

    print("[*] Generating Bindel Combiner Signatures (ECDSA + ML-DSA-44)...")
    concat_mldsa = ConcatCombiner(ecdsa, mldsa)
    c_mldsa_sig1, c_mldsa_sig2 = concat_mldsa.sign(ecdsa_sk, mldsa_sk, msg)

    kat_data = {
        "metadata": {
            "version": "1.0",
            "message": msg.decode("utf-8"),
            "message_hex": "0x" + msg.hex(),
            "message_hash": "0x" + msg_hash.hex()
        },
        "schemes": {
            "ecdsa_secp256k1": {
                "public_key": "0x" + ecdsa_pk.hex(),
                "signature": "0x" + ecdsa_sig.hex(),
                "r": "0x" + ecdsa_sig[:32].hex(),
                "s": "0x" + ecdsa_sig[32:64].hex(),
                "v": int(ecdsa_sig[64])
            },
            "mldsa_44": {
                "public_key": "0x" + mldsa_pk.hex(),
                "signature": "0x" + mldsa_sig.hex(),
                "pubkey_len": len(mldsa_pk),
                "sig_len": len(mldsa_sig)
            },
            "falcon_512": {
                "public_key": "0x" + falcon_pk.hex(),
                "signature": "0x" + falcon_sig.hex(),
                "pubkey_len": len(falcon_pk),
                "sig_len": len(falcon_sig)
            },
            "slh_dsa": {
                "public_key": "0x" + slhdsa_pk.hex(),
                "signature": "0x" + slhdsa_sig.hex(),
                "pubkey_len": len(slhdsa_pk),
                "sig_len": len(slhdsa_sig)
            }
        },
        "combiners": {
            "ecdsa_falcon": {
                "concat": {
                    "sig_ecdsa": "0x" + concat_sig1.hex(),
                    "sig_pqc": "0x" + concat_sig2.hex()
                },
                "weak_nested": {
                    "sig_inner": "0x" + weak_sig1.hex(),
                    "sig_outer": "0x" + weak_sig2.hex()
                },
                "strong_nested": {
                    "sig_inner": "0x" + strong_sig1.hex(),
                    "sig_outer": "0x" + strong_sig2.hex()
                },
                "dual_nesting": {
                    "sig_ecdsa": "0x" + dual_sig1.hex(),
                    "sig_falcon": "0x" + dual_sig2.hex()
                }
            },
            "ecdsa_mldsa44": {
                "concat": {
                    "sig_ecdsa": "0x" + c_mldsa_sig1.hex(),
                    "sig_pqc": "0x" + c_mldsa_sig2.hex()
                }
            }
        }
    }

    output_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(output_dir, "kat_vectors.json")
    with open(out_file, "w") as f:
        json.dump(kat_data, f, indent=2)

    print(f"[+] Successfully wrote deterministic KAT vectors to: {out_file}")

if __name__ == "__main__":
    generate_kats()
