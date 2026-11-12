// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title HTLCAtomicSwap
 * @notice Cross-chain Hashed Time-Lock Contract (HTLC) for atomic swaps.
 * @dev Used in Track 2 dual-chain benchmarks (ECDSA chain <-> PQC chain).
 */
contract HTLCAtomicSwap {
    enum SwapState {
        EMPTY,
        OPEN,
        COMPLETED,
        REFUNDED
    }

    struct SwapOrder {
        address initiator;
        address participant;
        uint256 amount;
        bytes32 hashLock;
        uint256 timelock;
        SwapState state;
        bytes preimage;
    }

    mapping(bytes32 => SwapOrder) public swaps;

    event SwapInitiated(
        bytes32 indexed swapId,
        address indexed initiator,
        address indexed participant,
        uint256 amount,
        bytes32 hashLock,
        uint256 timelock
    );

    event SwapClaimed(bytes32 indexed swapId, bytes preimage);
    event SwapRefunded(bytes32 indexed swapId);

    /**
     * @notice Open an atomic swap order.
     */
    function initiate(
        bytes32 swapId,
        address participant,
        bytes32 hashLock,
        uint256 timelock
    ) external payable {
        require(msg.value > 0, "Amount must be > 0");
        require(swaps[swapId].state == SwapState.EMPTY, "Swap already exists");
        require(timelock > block.timestamp, "Timelock must be in future");
        require(participant != address(0), "Invalid participant");

        swaps[swapId] = SwapOrder({
            initiator: msg.sender,
            participant: participant,
            amount: msg.value,
            hashLock: hashLock,
            timelock: timelock,
            state: SwapState.OPEN,
            preimage: ""
        });

        emit SwapInitiated(swapId, msg.sender, participant, msg.value, hashLock, timelock);
    }

    /**
     * @notice Claim funds by revealing the preimage of hashLock.
     */
    function claim(bytes32 swapId, bytes calldata preimage) external {
        SwapOrder storage order = swaps[swapId];
        require(order.state == SwapState.OPEN, "Swap not open");
        require(sha256(preimage) == order.hashLock, "Invalid preimage");

        order.state = SwapState.COMPLETED;
        order.preimage = preimage;

        (bool sent, ) = order.participant.call{value: order.amount}("");
        require(sent, "Ether transfer failed");

        emit SwapClaimed(swapId, preimage);
    }

    /**
     * @notice Refund funds to initiator if timelock has elapsed.
     */
    function refund(bytes32 swapId) external {
        SwapOrder storage order = swaps[swapId];
        require(order.state == SwapState.OPEN, "Swap not open");
        require(block.timestamp >= order.timelock, "Timelock not expired");

        order.state = SwapState.REFUNDED;

        (bool sent, ) = order.initiator.call{value: order.amount}("");
        require(sent, "Refund transfer failed");

        emit SwapRefunded(swapId);
    }
}
