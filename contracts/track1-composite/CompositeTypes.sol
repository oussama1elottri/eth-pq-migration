// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CompositeTypes
 * @notice Data structures for Bindel et al. composite signatures and calldata modes.
 */
library CompositeTypes {
    enum PQCAlgorithm {
        FALCON_512,
        ML_DSA_44,
        SLH_DSA
    }

    enum VerificationMode {
        INLINE,       // Full signature & public key in calldata
        SEGWIT,       // Stripped signature verified against commitment / DA
        STATE_LOOKUP  // Public key stored in state; calldata has signature only
    }

    struct ECDSASignature {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct CompositePublicKey {
        address classicalAddress;
        bytes pqcPublicKey;
        PQCAlgorithm algorithm;
    }

    struct ConcatSignature {
        ECDSASignature classicalSig;
        bytes pqcSig;
    }

    struct NestedSignature {
        bytes innerSig; // E.g., ECDSA bytes or PQC bytes
        bytes outerSig; // Outer signature wrapping the inner signature or intermediate hash
    }

    struct SegWitWitnessProof {
        bytes32 witnessRoot;
        bytes32 leafHash;
        bytes32[] merkleBranch;
    }
}
