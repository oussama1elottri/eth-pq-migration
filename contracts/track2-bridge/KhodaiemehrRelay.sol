// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../verifiers/IFalconVerifier.sol";

/**
 * @title KhodaiemehrRelay
 * @notice Cross-chain SPV Header Relay based on Khodaiemehr et al.
 * @dev Maintains foreign chain headers, validates PQC committee threshold signatures,
 *      and verifies cross-chain transaction and state inclusion.
 */
contract KhodaiemehrRelay {
    IFalconVerifier public immutable pqcVerifier;

    struct BlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        uint256 timestamp;
    }

    struct CommitteeAttestation {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes[] signatures; // PQC signatures from committee members
        uint256[] validatorIndices;
    }

    uint256 public latestBlockNumber;
    bytes32 public latestBlockHash;
    mapping(uint256 => BlockHeader) public headers;
    mapping(uint256 => bytes) public validatorPublicKeys;
    uint256 public committeeSize;
    uint256 public threshold;

    event HeaderSubmitted(uint256 indexed blockNumber, bytes32 indexed blockHash, bytes32 stateRoot);
    event CommitteeUpdated(uint256 newCommitteeSize, uint256 newThreshold);

    constructor(
        address _pqcVerifier,
        uint256 _committeeSize,
        uint256 _threshold
    ) {
        pqcVerifier = IFalconVerifier(_pqcVerifier);
        committeeSize = _committeeSize;
        threshold = _threshold;
    }

    function setValidatorKey(uint256 index, bytes calldata pubKey) external {
        require(index < committeeSize, "Index out of bounds");
        validatorPublicKeys[index] = pubKey;
    }

    /**
     * @notice Submit a foreign chain block header certified by a PQC committee attestation.
     */
    function submitHeaderWithAttestation(
        BlockHeader calldata header,
        CommitteeAttestation calldata attestation
    ) external returns (bool) {
        require(header.blockNumber == latestBlockNumber + 1, "Non-sequential block");
        require(attestation.signatures.length >= threshold, "Threshold not met");
        require(attestation.blockHash == header.blockHash, "Hash mismatch");

        bytes32 attestationDigest = keccak256(
            abi.encodePacked(header.blockNumber, header.blockHash, header.stateRoot)
        );

        // Verify each committee member's PQC signature
        for (uint256 i = 0; i < attestation.signatures.length; i++) {
            uint256 valIdx = attestation.validatorIndices[i];
            bytes storage pubKey = validatorPublicKeys[valIdx];
            require(pubKey.length > 0, "Validator key missing");

            bool valid = pqcVerifier.verifyPrehashed(
                attestationDigest,
                attestation.signatures[i],
                pubKey
            );
            require(valid, "Invalid committee signature");
        }

        headers[header.blockNumber] = header;
        latestBlockNumber = header.blockNumber;
        latestBlockHash = header.blockHash;

        emit HeaderSubmitted(header.blockNumber, header.blockHash, header.stateRoot);
        return true;
    }

    /**
     * @notice Verify inclusion of a cross-chain transaction in a committed block.
     */
    function verifyTransactionInclusion(
        uint256 blockNumber,
        bytes32 txHash,
        bytes32[] calldata merkleProof
    ) external view returns (bool) {
        BlockHeader storage header = headers[blockNumber];
        require(header.blockNumber != 0, "Block not committed");

        bytes32 current = txHash;
        for (uint256 i = 0; i < merkleProof.length; i++) {
            current = keccak256(abi.encodePacked(current, merkleProof[i]));
        }

        return current == header.transactionsRoot;
    }
}
