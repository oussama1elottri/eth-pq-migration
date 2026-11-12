// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CompositeTypes.sol";
import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";

/**
 * @title WeakNestedCombinerVerifier
 * @notice Table XV: Bindel et al. Weak Nested Combiner (C_weak).
 * @dev Outer signature signs inner signature: sigma_outer = Sign_outer(sigma_inner).
 */
contract WeakNestedCombinerVerifier {
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

    /**
     * @notice Mode A: Inner = ECDSA (signs message), Outer = Falcon-512 (signs serialized ECDSA sig)
     */
    function verifyInnerECDSAOuterFalcon(
        bytes32 messageHash,
        address innerSigner,
        CompositeTypes.ECDSASignature calldata innerSig,
        bytes calldata outerFalconPubKey,
        bytes calldata outerFalconSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // 1. Verify inner signature over message
        bool innerValid = ecdsaVerifier.verify(
            messageHash,
            innerSig.r,
            innerSig.s,
            innerSig.v,
            innerSigner
        );
        if (!innerValid) {
            emit VerificationResult(msg.sender, false, gasStart - gasleft(), msg.data.length);
            return false;
        }

        // 2. Hash of the inner signature is target for outer signature
        bytes32 innerSigHash = keccak256(abi.encodePacked(innerSig.r, innerSig.s, innerSig.v));

        // 3. Verify outer signature over inner signature
        bool outerValid = falconVerifier.verifyPrehashed(
            innerSigHash,
            outerFalconSig,
            outerFalconPubKey
        );
        uint256 gasUsed = gasStart - gasleft();

        emit VerificationResult(msg.sender, outerValid, gasUsed, msg.data.length);
        return outerValid;
    }
}
