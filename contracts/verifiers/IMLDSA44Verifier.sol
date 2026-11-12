// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMLDSA44Verifier {
    function verify(
        bytes calldata message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external view returns (bool);

    function verifyPrehashed(
        bytes32 messageHash,
        bytes calldata signature,
        bytes calldata publicKey
    ) external view returns (bool);
}
