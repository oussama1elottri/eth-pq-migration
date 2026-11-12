// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CompositeTypes.sol";
import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";
import "../verifiers/IMLDSA44Verifier.sol";

/**
 * @title ConcatCombinerVerifier
 * @notice Table XV: Bindel et al. Concatenation Combiner (C_concat).
 * @dev Verifies sigma = (sigma_classical, sigma_pqc) over message m.
 */
contract ConcatCombinerVerifier {
    IECDSAVerifier public immutable ecdsaVerifier;
    IFalconVerifier public immutable falconVerifier;
    IMLDSA44Verifier public immutable mldsaVerifier;

    event VerificationResult(
        address indexed caller,
        bool success,
        uint256 gasUsed,
        uint256 calldataBytes
    );

    constructor(
        address _ecdsaVerifier,
        address _falconVerifier,
        address _mldsaVerifier
    ) {
        ecdsaVerifier = IECDSAVerifier(_ecdsaVerifier);
        falconVerifier = IFalconVerifier(_falconVerifier);
        mldsaVerifier = IMLDSA44Verifier(_mldsaVerifier);
    }

    /**
     * @notice Verify concatenation signature (ECDSA + Falcon-512)
     */
    function verifyConcatFalcon(
        bytes32 messageHash,
        address classicalSigner,
        CompositeTypes.ECDSASignature calldata classicalSig,
        bytes calldata falconPubKey,
        bytes calldata falconSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // 1. Classical Verification
        bool ecdsaValid = ecdsaVerifier.verify(
            messageHash,
            classicalSig.r,
            classicalSig.s,
            classicalSig.v,
            classicalSigner
        );
        if (!ecdsaValid) {
            emit VerificationResult(msg.sender, false, gasStart - gasleft(), msg.data.length);
            return false;
        }

        // 2. Post-Quantum Verification
        bool pqcValid = falconVerifier.verifyPrehashed(messageHash, falconSig, falconPubKey);
        uint256 gasUsed = gasStart - gasleft();

        emit VerificationResult(msg.sender, pqcValid, gasUsed, msg.data.length);
        return pqcValid;
    }

    /**
     * @notice Verify concatenation signature (ECDSA + ML-DSA-44)
     */
    function verifyConcatMLDSA(
        bytes32 messageHash,
        address classicalSigner,
        CompositeTypes.ECDSASignature calldata classicalSig,
        bytes calldata mldsaPubKey,
        bytes calldata mldsaSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        bool ecdsaValid = ecdsaVerifier.verify(
            messageHash,
            classicalSig.r,
            classicalSig.s,
            classicalSig.v,
            classicalSigner
        );
        if (!ecdsaValid) {
            emit VerificationResult(msg.sender, false, gasStart - gasleft(), msg.data.length);
            return false;
        }

        bool pqcValid = mldsaVerifier.verifyPrehashed(messageHash, mldsaSig, mldsaPubKey);
        uint256 gasUsed = gasStart - gasleft();

        emit VerificationResult(msg.sender, pqcValid, gasUsed, msg.data.length);
        return pqcValid;
    }
}
