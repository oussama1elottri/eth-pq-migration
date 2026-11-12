// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CompositeTypes.sol";
import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";

/**
 * @title DualNestingVerifier
 * @notice Table XV: Bindel et al. Dual Nesting Combiner (C_dual).
 * @dev Mutual binding: sigma_1 signs H(m || pk_2), sigma_2 signs H(m || sigma_1 || pk_1).
 */
contract DualNestingVerifier {
    IECDSAVerifier public immutable ecdsaVerifier;
    IFalconVerifier public immutable falconVerifier;

    event VerificationResult(
        address indexed caller,
        bool success,
        uint256 gasUsed,
        uint256 calldataBytes
    );

    constructor(address _ecdsaVerifier, address _falconVerifier) {
        ecdsaVerifier = IECDSAVerifier(_ecdsaVerifier);
        falconVerifier = IFalconVerifier(_falconVerifier);
    }

    function verifyDualNesting(
        bytes32 messageHash,
        address ecdsaSigner,
        CompositeTypes.ECDSASignature calldata ecdsaSig,
        bytes calldata falconPubKey,
        bytes calldata falconSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // 1. Classical signature binds message and PQC public key
        bytes32 m1 = keccak256(abi.encodePacked(messageHash, falconPubKey));
        bool ecdsaValid = ecdsaVerifier.verify(
            m1,
            ecdsaSig.r,
            ecdsaSig.s,
            ecdsaSig.v,
            ecdsaSigner
        );
        if (!ecdsaValid) {
            emit VerificationResult(msg.sender, false, gasStart - gasleft(), msg.data.length);
            return false;
        }

        // 2. Post-quantum signature binds message, classical signature, and classical address
        bytes32 m2 = keccak256(
            abi.encodePacked(
                messageHash,
                ecdsaSig.r,
                ecdsaSig.s,
                ecdsaSig.v,
                ecdsaSigner
            )
        );
        bool falconValid = falconVerifier.verifyPrehashed(m2, falconSig, falconPubKey);
        uint256 gasUsed = gasStart - gasleft();

        emit VerificationResult(msg.sender, falconValid, gasUsed, msg.data.length);
        return falconValid;
    }
}
