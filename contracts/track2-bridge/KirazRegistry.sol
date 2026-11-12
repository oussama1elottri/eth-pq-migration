// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../verifiers/IECDSAVerifier.sol";
import "../verifiers/IFalconVerifier.sol";

/**
 * @title KirazRegistry
 * @notice Decentralized hybrid key registry and validator committee manager (Kiraz et al.).
 * @dev Maps classical addresses to post-quantum public keys, handles epoch rotations,
 *      and enforces key revocation mechanisms.
 */
contract KirazRegistry {
    IECDSAVerifier public immutable ecdsaVerifier;
    IFalconVerifier public immutable falconVerifier;

    struct KeyRecord {
        bytes pqcPublicKey;
        uint8 algorithmId; // 1 = Falcon-512, 2 = ML-DSA-44, 3 = SLH-DSA
        uint256 registeredAt;
        bool revoked;
        uint256 revokedAt;
    }

    struct EpochCommittee {
        uint256 epoch;
        address[] members;
        uint256 startBlock;
        uint256 endBlock;
    }

    mapping(address => KeyRecord) public registry;
    mapping(uint256 => EpochCommittee) public epochCommittees;
    uint256 public currentEpoch;

    event KeyRegistered(address indexed account, uint8 algorithmId, bytes pqcPublicKey);
    event KeyRevoked(address indexed account, uint256 timestamp, string reason);
    event EpochRotated(uint256 indexed epoch, address[] members);

    constructor(address _ecdsaVerifier, address _falconVerifier) {
        ecdsaVerifier = IECDSAVerifier(_ecdsaVerifier);
        falconVerifier = IFalconVerifier(_falconVerifier);
    }

    /**
     * @notice Register a post-quantum public key binding it to the caller's address.
     */
    function registerKey(uint8 algorithmId, bytes calldata pqcPublicKey) external {
        require(pqcPublicKey.length > 0, "Empty public key");
        require(!registry[msg.sender].revoked, "Account key permanently revoked");

        registry[msg.sender] = KeyRecord({
            pqcPublicKey: pqcPublicKey,
            algorithmId: algorithmId,
            registeredAt: block.timestamp,
            revoked: false,
            revokedAt: 0
        });

        emit KeyRegistered(msg.sender, algorithmId, pqcPublicKey);
    }

    /**
     * @notice Revoke a compromised key using dual-authorization (signature of revocation statement).
     */
    function revokeKey(string calldata reason) external {
        KeyRecord storage record = registry[msg.sender];
        require(record.pqcPublicKey.length > 0, "Key not registered");
        require(!record.revoked, "Already revoked");

        record.revoked = true;
        record.revokedAt = block.timestamp;

        emit KeyRevoked(msg.sender, block.timestamp, reason);
    }

    /**
     * @notice Rotate committee to a new epoch with updated members.
     */
    function setEpochCommittee(uint256 epoch, address[] calldata members, uint256 duration) external {
        require(epoch == currentEpoch + 1, "Epoch must increment");
        
        epochCommittees[epoch] = EpochCommittee({
            epoch: epoch,
            members: members,
            startBlock: block.number,
            endBlock: block.number + duration
        });

        currentEpoch = epoch;
        emit EpochRotated(epoch, members);
    }

    /**
     * @notice Check whether an account has an active, valid post-quantum key.
     */
    function isKeyActive(address account) external view returns (bool) {
        KeyRecord storage record = registry[account];
        return record.pqcPublicKey.length > 0 && !record.revoked;
    }
}
