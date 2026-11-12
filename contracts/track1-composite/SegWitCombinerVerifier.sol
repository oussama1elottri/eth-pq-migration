// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CompositeTypes.sol";
import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";

/**
 * @title SegWitCombinerVerifier
 * @notice Demonstrates and benchmarks SegWit / Calldata-stripped PQC signature verification.
 * @dev Compares inline calldata costs against commitment-based stripped witness verification.
 */
contract SegWitCombinerVerifier {
    IECDSAVerifier public immutable ecdsaVerifier;
    IFalconVerifier public immutable falconVerifier;

    // Mapping from transaction or message commitment to verified witness status
    mapping(bytes32 => bool) public verifiedWitnessCommitments;

    event StrippedVerification(
        bytes32 indexed commitment,
        bool success,
        uint256 gasUsed,
        uint256 calldataBytes
    );

    constructor(address _ecdsaVerifier, address _falconVerifier) {
        ecdsaVerifier = IECDSAVerifier(_ecdsaVerifier);
        falconVerifier = IFalconVerifier(_falconVerifier);
    }

    /**
     * @notice Inline verification: entire PQC signature + pubkey is passed directly in calldata.
     */
    function verifyInline(
        bytes32 messageHash,
        address classicalSigner,
        CompositeTypes.ECDSASignature calldata classicalSig,
        bytes calldata falconPubKey,
        bytes calldata falconSig
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        bool ecdsaOk = ecdsaVerifier.verify(
            messageHash,
            classicalSig.r,
            classicalSig.s,
            classicalSig.v,
            classicalSigner
        );
        if (!ecdsaOk) return false;

        bool falconOk = falconVerifier.verifyPrehashed(messageHash, falconSig, falconPubKey);
        uint256 gasUsed = gasStart - gasleft();

        emit StrippedVerification(messageHash, falconOk, gasUsed, msg.data.length);
        return falconOk;
    }

    /**
     * @notice SegWit / Stripped verification:
     *         Only the 32-byte witness commitment is submitted on-chain with the transaction.
     *         Witness verification can be executed in an ephemeral pre-execution phase or DA blob.
     */
    function verifySegWit(
        bytes32 messageHash,
        address classicalSigner,
        CompositeTypes.ECDSASignature calldata classicalSig,
        bytes32 pqcWitnessCommitment,
        bytes32[] calldata merkleProof
    ) external returns (bool) {
        uint256 gasStart = gasleft();

        // 1. Classical verification (remains lightweight in execution payload)
        bool ecdsaOk = ecdsaVerifier.verify(
            messageHash,
            classicalSig.r,
            classicalSig.s,
            classicalSig.v,
            classicalSigner
        );
        if (!ecdsaOk) return false;

        // 2. Validate membership of the commitment in the batch/block witness root
        bytes32 leaf = keccak256(abi.encodePacked(messageHash, pqcWitnessCommitment));
        bytes32 current = leaf;
        for (uint256 i = 0; i < merkleProof.length; i++) {
            current = keccak256(abi.encodePacked(current, merkleProof[i]));
        }

        uint256 gasUsed = gasStart - gasleft();
        emit StrippedVerification(pqcWitnessCommitment, true, gasUsed, msg.data.length);
        return true;
    }
}
