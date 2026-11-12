// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IECDSAVerifier.sol";

/**
 * @title ECDSAVerifier
 * @notice Validates secp256k1 ECDSA signatures with EIP-2 malleable signature protection.
 */
contract ECDSAVerifier is IECDSAVerifier {
    // Maximum allowable s value under EIP-2 to prevent malleability
    bytes32 private constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D57617F0297594DCE6AF48A03BBFD25;

    function verify(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        uint8 v,
        address expectedSigner
    ) external pure override returns (bool) {
        if (expectedSigner == address(0)) {
            return false;
        }
        address recovered = recoverSigner(messageHash, r, s, v);
        return recovered == expectedSigner;
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public pure override returns (address) {
        if (uint256(s) > uint256(SECP256K1_HALF_N)) {
            return address(0);
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        return ecrecover(messageHash, v, r, s);
    }
}
