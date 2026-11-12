// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IECDSAVerifier {
    function verify(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        uint8 v,
        address expectedSigner
    ) external pure returns (bool);

    function recoverSigner(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        uint8 v
    ) external pure returns (address);
}
