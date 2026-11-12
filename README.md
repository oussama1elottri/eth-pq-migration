# EVM Post-Quantum Cryptography Benchmark Suite (`evm-pqc-bench`)

[![Foundry](https://img.shields.io/badge/Foundry-Solidity%200.8.24-blue)](https://getfoundry.sh/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docker.com)
[![PQC](https://img.shields.io/badge/PQC-NIST%20FIPS%20204%20%2F%20205%20%2F%20Falcon-purple)](https://csrc.nist.gov/projects/post-quantum-cryptography)

A unified experimental benchmarking framework for **Post-Quantum Cryptography (PQC)** and **Hybrid/Composite Signature Schemes** on the Ethereum Virtual Machine (EVM).

---

## 🗺️ Mapping the Research Tracks

```
                                  +---------------------------------------+
                                  |            evm-pqc-bench              |
                                  +---------------------------------------+
                                                      |
                  +-----------------------------------+-----------------------------------+
                  |                                   |                                   |
                  v                                   v                                   v
        +-------------------+               +-------------------+               +-------------------+
        |      TRACK 1      |               |      TRACK 2      |               |      TRACK 3      |
        | Composite Schemes |               |    Dual-Chain     |               |  Decision Model   |
        |  (Table XV/Fig. 9)|               |  (Relay / Fig. 8) |               | (Table XVI/Fig. 10|
        +-------------------+               +-------------------+               +-------------------+
                  |                                   |                                   |
        * Bindel Combiners                  * Multi-node Anvil/Reth             * Analytical Cost Model
          (Concat, Weak, Strong, Dual)        (Chain A <-> Chain B)             * STARK / Virgo ZK Provers
        * Base ZKNox (Falcon-512)           * Khodaiemehr SPV Relay             * Amortization Threshold K*
        * Fireblocks (ML-DSA-44)            * Kiraz Key Registry                * Gas / Regime Calibration
        * SegWit / Stripping Tests          * HTLC Atomic Swaps                 * Transition Frontier
```

### Track 1: Composite / Hybrid Signatures & On-Chain Verification
- **Paper References**: Table XV & Fig. 9
- **Focus**: Evaluates on-chain gas costs, execution overhead, calldata constraints, and state footprints across classical (ECDSA secp256k1) and post-quantum algorithms (Falcon-512, ML-DSA-44, SLH-DSA).
- **Core Contributions**:
  - Implements the four canonical **Bindel et al.** combiners:
    1. **Concatenation ($C_{concat}$)**: $\sigma = (\sigma_{classical}, \sigma_{pqc})$ verified independently on $m$.
    2. **Weak Nested ($C_{weak}$)**: Outer signature certifies inner signature: $\sigma_2 = Sign_2(\sigma_1)$.
    3. **Strong Nested ($C_{strong}$)**: Outer signature binds message, inner signature, and inner public key: $\sigma_2 = Sign_2(H(m \parallel \sigma_1 \parallel pk_1))$.
    4. **Dual Nesting ($C_{dual}$)**: Mutual cross-binding between classical and post-quantum keys and signatures.
  - **Calldata Stripping / SegWit**: Demonstrates gas savings (>90%) by verifying cryptographic commitments on-chain while keeping full post-quantum witness signatures off execution calldata.

### Track 2: Dual-Chain Non-Composite Cross-Chain & Bridging
- **Paper References**: Fig. 8
- **Focus**: Evaluates cross-chain interoperability between a classical EVM chain and a PQC-secured chain without requiring composite transactions on the legacy chain.
- **Core Contributions**:
  - **Khodaiemehr Relay**: Block header and state verification relay supporting threshold post-quantum committee attestations.
  - **Kiraz Registry**: Decentralized on-chain registry managing hybrid public keys, epoch-based validator committees, and revocation certificates.
  - **HTLC Atomic Swaps**: Hash-locked and time-locked cross-chain asset swaps between ECDSA and PQC domains.
  - **Committee Latency Benchmark**: Evaluates committee scaling ($N \in [4, 128]$) and end-to-end confirmation latency.

### Track 3: Decision Framework & Zero-Knowledge Aggregation
- **Paper References**: Table XVI & Fig. 10
- **Focus**: Econometric and architectural decision framework guiding the transition from classical to post-quantum signatures.
- **Core Contributions**:
  - **STARK / Virgo Cost Model**: Models proof generation latency, verification gas, and proof transmission sizes.
  - **Crossover Amortization Threshold ($K^*$)**: Identifies the exact batch size where recursive ZK-STARK signature aggregation becomes cheaper than native EVM on-chain verification across various gas regimes (10–100 Gwei).
  - **Transition Frontier**: Decision guidance mapping transaction frequency, latency tolerance, and security requirements to the optimal cryptographic architecture.

---

## 📂 Project Directory Structure

```
evm-pqc-bench/
├── README.md                     # Overview mapping Tracks 1, 2, and 3
├── foundry.toml                  # Foundry EVM configuration (Solc 0.8.24, Cancun, via_ir)
├── docker-compose.yml            # Multi-node Anvil/Reth setup for Track 2
│
├── core-crypto/                  # [SHARED] Off-chain liboqs signing & KAT generator
│   ├── requirements.txt          # Python dependencies (cryptography, oqs, eth-keys)
│   ├── kat_generator.py          # Deterministic Known Answer Test generator
│   ├── schemes/                  # ECDSA, ML-DSA-44, Falcon-512, SLH-DSA wrappers
│   └── combiners/                # Bindel et al. (Concat, Weak, Strong, Dual Nesting)
│
├── contracts/                    # [SHARED + TRACKS] Solidity Smart Contracts
│   ├── verifiers/                # Base ZKNox (Falcon) & Fireblocks (ML-DSA) verifiers
│   ├── track1-composite/         # Table XV Combiner verifiers & SegWit/Inline structures
│   └── track2-bridge/            # HTLC Atomic Swaps, Khodaiemehr Relay & Kiraz Registry
│
├── tracks/                       # Paper-specific experiment runners & telemetry
│   ├── track1_composite/         # Fig. 9 benchmarks (gas, calldata, state, stripping tests)
│   ├── track2_dual_chain/        # Fig. 8 cross-chain relayer & committee latency tests
│   └── track3_decision_model/    # Fig. 10 & Table XVI calibration + STARK/Virgo cost model
│
└── results/                      # Deterministic CSV/JSON outputs & paper plots
    ├── paper1_composite/         # Fig. 9 gas breakdown, calldata overhead, stripping stats
    ├── paper2_non_composite/     # Fig. 8 committee latency & relayer telemetry
    └── paper3_decision_framework/# Fig. 10 cost model & Table XVI calibration matrix
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- [Foundry](https://getfoundry.sh/) (`forge`, `anvil`)
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose

### 2. Generate Known Answer Tests (KAT)
```bash
cd evm-pqc-bench
python3 core-crypto/kat_generator.py
```
This produces `core-crypto/kat_vectors.json` with deterministic signatures for all schemes and combiners.

### 3. Run Track 1 Benchmarks (Fig. 9)
```bash
python3 tracks/track1_composite/run_benchmarks.py
```
Outputs generated in `results/paper1_composite/`:
- `fig9_gas_breakdown.csv`: Calldata vs execution gas breakdown.
- `fig9_stripping_efficiency.csv`: Inline vs SegWit stripped witness comparison.
- `fig9_summary.json`: High-level benchmark summary.

### 4. Run Track 2 Latency Tests & Multi-Node Setup (Fig. 8)
#### Standalone Simulation:
```bash
python3 tracks/track2_dual_chain/run_latency_tests.py
```
Outputs generated in `results/paper2_non_composite/`:
- `fig8_committee_latency.csv`: Latency and gas scaling for committee sizes $N \in [4, 128]$.
- `fig8_relayer_telemetry.json`: End-to-end relayer round-trip logs.

#### Multi-Node Docker Network:
```bash
docker compose up -d
```
Spins up:
- `chain-a-anvil`: Primary source EVM chain on port `8545`.
- `chain-b-anvil`: Secondary target PQC chain on port `8546`.
- `track2-relayer`: Cross-chain relayer container bridging state and attestations.

### 5. Run Track 3 Decision Calibration (Fig. 10 & Table XVI)
```bash
python3 tracks/track3_decision_model/calibrate.py
```
Outputs generated in `results/paper3_decision_framework/`:
- `fig10_cost_model.csv`: Per-transaction cost vs batch size ($K \in [1, 1024]$).
- `table_xvi_calibration.json`: Crossover threshold ($K^*$) across 10, 30, 60, and 100 Gwei regimes.
- `transition_frontier.json`: Architectural recommendations matrix.

---

## 🔬 Scientific Methodology & Benchmark Parameters

| Scheme / Combiner | Public Key Size | Signature Size | Verification Gas (EVM) | Security Class |
| :--- | :--- | :--- | :--- | :--- |
| **ECDSA (secp256k1)** | 64 B (uncompressed) | 65 B | ~3,000 | Classical (128-bit) |
| **Falcon-512 (ZKNox)** | 897 B | 666 B | ~84,520 | Post-Quantum (NIST Level 1) |
| **ML-DSA-44 (Fireblocks)** | 1,312 B | 2,420 B | ~168,400 | Post-Quantum (NIST Level 2) |
| **SLH-DSA (SPHINCS+)** | 32 B | 7,856 B | High (>800k) | Post-Quantum (Stateless Hash) |
| **Bindel Concat** | 961 B | 731 B | ~89,920 | Dual (Classical + PQ) |
| **Bindel Strong Nested** | 961 B | 731 B | ~92,470 | Dual (Re-binding Protected) |
| **Bindel Dual Nesting** | 961 B | 731 B | ~93,720 | Dual (Mutually Authenticated) |
| **SegWit Stripped** | 96 B | 225 B | ~7,800 | Dual with DA Commitment |
