// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CompositeTypes.sol";
import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";

/**
 * @title StrongNestedCombinerVerifier
 * @notice Table XV: Bindel et al. Strong Nested Combiner (C_strong).
 * @dev Outer signs H(m || sigma_inner || pk_inner) to prevent re-binding.
 */
contract StrongNestedCombinerVerifier {
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
     * @notice Verifies strong nested composite signature (ECDSA inner, Falcon outer)
     */
    function verifyStrongNested(
        bytes32 messageHash,
        address innerSigner,
        CompositeTypes.ECDSASignature calldata innerSig,
        bytes calldata outerFalconPubKey,
        bytes calldata outerFalconSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // 1. Verify inner ECDSA signature over original message
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

        // 2. Compute Strong Bindel intermediate hash H(m || sigma_inner || pk_inner)
        bytes32 intermediateHash = keccak256(
            abi.encodePacked(
                messageHash,
                innerSig.r,
                innerSig.s,
                innerSig.v,
                innerSigner
            )
        );

        // 3. Verify outer Falcon-512 signature over intermediateHash
        bool outerValid = falconVerifier.verifyPrehashed(
            intermediateHash,
            outerFalconSig,
            outerFalconPubKey
        );
        uint256 gasUsed = gasStart - gasleft();

        emit VerificationResult(msg.sender, outerValid, gasUsed, msg.data.length);
        return outerValid;
    }
}
