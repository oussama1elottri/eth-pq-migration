// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../contracts/verifiers/ECDSAVerifier.sol";
import "../../contracts/verifiers/Falcon512Verifier.sol";
import "../../contracts/verifiers/MLDSA44Verifier.sol";
import "../../contracts/track1-composite/ConcatCombinerVerifier.sol";
import "../../contracts/track1-composite/WeakNestedCombinerVerifier.sol";
import "../../contracts/track1-composite/StrongNestedCombinerVerifier.sol";
import "../../contracts/track1-composite/DualNestingVerifier.sol";
import "../../contracts/track1-composite/SegWitCombinerVerifier.sol";
import "../../contracts/track1-composite/CompositeTypes.sol";

/**
 * @title Track1Benchmark
 * @notice Reproduces Fig. 9 benchmarks: Gas, Calldata, State vs SegWit Stripping tests.
 */
contract Track1Benchmark {
    ECDSAVerifier internal ecdsaVerifier;
    Falcon512Verifier internal falconVerifier;
    MLDSA44Verifier internal mldsaVerifier;

    ConcatCombinerVerifier internal concatVerifier;
    WeakNestedCombinerVerifier internal weakVerifier;
    StrongNestedCombinerVerifier internal strongVerifier;
    DualNestingVerifier internal dualVerifier;
    SegWitCombinerVerifier internal segwitVerifier;

    // Benchmark sample test data
    bytes32 internal messageHash;
    address internal classicalSigner;
    CompositeTypes.ECDSASignature internal classicalSig;
    bytes internal sampleFalconPubKey;
    bytes internal sampleFalconSig;
    bytes internal sampleMLDSAPubKey;
    bytes internal sampleMLDSASig;

    event BenchmarkGasResult(string indexed testName, uint256 gasUsed, uint256 calldataBytes);

    function setUp() public {
        ecdsaVerifier = new ECDSAVerifier();
        falconVerifier = new Falcon512Verifier();
        mldsaVerifier = new MLDSA44Verifier();

        concatVerifier = new ConcatCombinerVerifier(
            address(ecdsaVerifier),
            address(falconVerifier),
            address(mldsaVerifier)
        );

        weakVerifier = new WeakNestedCombinerVerifier(
            address(ecdsaVerifier),
            address(falconVerifier)
        );

        strongVerifier = new StrongNestedCombinerVerifier(
            address(ecdsaVerifier),
            address(falconVerifier)
        );

        dualVerifier = new DualNestingVerifier(
            address(ecdsaVerifier),
            address(falconVerifier)
        );

        segwitVerifier = new SegWitCombinerVerifier(
            address(ecdsaVerifier),
            address(falconVerifier)
        );

        messageHash = keccak256("Track1_Fig9_Benchmark_Payload");
        classicalSigner = address(0x1111111111111111111111111111111111111111);
        classicalSig = CompositeTypes.ECDSASignature({
            r: bytes32(uint256(0x1234)),
            s: bytes32(uint256(0x5678)),
            v: 27
        });

        // Initialize realistic dummy byte buffers for benchmarks
        sampleFalconPubKey = new bytes(897);
        sampleFalconSig = new bytes(666);
        sampleMLDSAPubKey = new bytes(1312);
        sampleMLDSASig = new bytes(2420);
    }

    function test_Benchmark_Baseline_ECDSA() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        ecdsaVerifier.verify(
            messageHash,
            classicalSig.r,
            classicalSig.s,
            classicalSig.v,
            classicalSigner
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Baseline_ECDSA", gasUsed, 65);
    }

    function test_Benchmark_Baseline_Falcon512() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        falconVerifier.verifyPrehashed(messageHash, sampleFalconSig, sampleFalconPubKey);
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Baseline_Falcon512", gasUsed, 897 + 666);
    }

    function test_Benchmark_Baseline_MLDSA44() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        mldsaVerifier.verifyPrehashed(messageHash, sampleMLDSASig, sampleMLDSAPubKey);
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Baseline_MLDSA44", gasUsed, 1312 + 2420);
    }

    function test_Benchmark_Combiner_Concat() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        concatVerifier.verifyConcatFalcon(
            messageHash,
            classicalSigner,
            classicalSig,
            sampleFalconPubKey,
            sampleFalconSig
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Combiner_Concat", gasUsed, 65 + 897 + 666);
    }

    function test_Benchmark_Combiner_WeakNested() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        weakVerifier.verifyInnerECDSAOuterFalcon(
            messageHash,
            classicalSigner,
            classicalSig,
            sampleFalconPubKey,
            sampleFalconSig
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Combiner_WeakNested", gasUsed, 65 + 897 + 666);
    }

    function test_Benchmark_Combiner_StrongNested() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        strongVerifier.verifyStrongNested(
            messageHash,
            classicalSigner,
            classicalSig,
            sampleFalconPubKey,
            sampleFalconSig
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Combiner_StrongNested", gasUsed, 65 + 897 + 666);
    }

    function test_Benchmark_Combiner_DualNesting() public returns (uint256 gasUsed) {
        uint256 gStart = gasleft();
        dualVerifier.verifyDualNesting(
            messageHash,
            classicalSigner,
            classicalSig,
            sampleFalconPubKey,
            sampleFalconSig
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("Combiner_DualNesting", gasUsed, 65 + 897 + 666);
    }

    function test_Benchmark_Calldata_Stripping_SegWit() public returns (uint256 gasUsed) {
        bytes32 witnessCommitment = keccak256(abi.encodePacked(sampleFalconSig, sampleFalconPubKey));
        bytes32[] memory proof = new bytes32[](4);
        proof[0] = bytes32(uint256(1));
        proof[1] = bytes32(uint256(2));
        proof[2] = bytes32(uint256(3));
        proof[3] = bytes32(uint256(4));

        uint256 gStart = gasleft();
        segwitVerifier.verifySegWit(
            messageHash,
            classicalSigner,
            classicalSig,
            witnessCommitment,
            proof
        );
        gasUsed = gStart - gasleft();
        emit BenchmarkGasResult("SegWit_Stripped_Witness", gasUsed, 65 + 32 + (4 * 32));
    }
}
