#!/usr/bin/env python3
"""
Calibration script for Track 3: Fig. 10 & Table XVI Decision Framework.
Generates empirical calibration curves across gas regimes and batch sizes,
determining the transition frontier between Hybrid, Direct PQC, and STARK/Virgo.
"""

import os
import json
import csv
from cost_model import ArchitectureProfile, DecisionCostModel

def run_calibration():
    print("=" * 70)
    print(" TRACK 3 CALIBRATION RUNNER: Fig. 10 & Table XVI Decision Model")
    print("=" * 70)

    # 1. Architecture Profiles
    p_ecdsa = ArchitectureProfile(
        name="Classical-ECDSA",
        sig_bytes=65,
        pubkey_bytes=64,
        evm_verify_gas=3000,
        prover_time_per_sig_sec=0.0,
        prover_memory_mb=0,
        is_zk_aggregated=False
    )

    p_falcon = ArchitectureProfile(
        name="Direct-Falcon-512",
        sig_bytes=666,
        pubkey_bytes=897,
        evm_verify_gas=84520,
        prover_time_per_sig_sec=0.0,
        prover_memory_mb=0,
        is_zk_aggregated=False
    )

    p_mldsa = ArchitectureProfile(
        name="Direct-ML-DSA-44",
        sig_bytes=2420,
        pubkey_bytes=1312,
        evm_verify_gas=168400,
        prover_time_per_sig_sec=0.0,
        prover_memory_mb=0,
        is_zk_aggregated=False
    )

    p_hybrid = ArchitectureProfile(
        name="Hybrid-Concat-Falcon",
        sig_bytes=65 + 666,
        pubkey_bytes=64 + 897,
        evm_verify_gas=84520 + 3000 + 2400,
        prover_time_per_sig_sec=0.0,
        prover_memory_mb=0,
        is_zk_aggregated=False
    )

    p_stark = ArchitectureProfile(
        name="STARK-Aggregated",
        sig_bytes=0,
        pubkey_bytes=0,
        evm_verify_gas=0,
        prover_time_per_sig_sec=0.18, # 180ms proof generation per sig in AIR
        prover_memory_mb=2048,
        is_zk_aggregated=True,
        proof_bytes=46000, # ~45 KB STARK proof
        batch_verify_gas=280000 # EVM FRI verification
    )

    p_virgo = ArchitectureProfile(
        name="Virgo-Aggregated",
        sig_bytes=0,
        pubkey_bytes=0,
        evm_verify_gas=0,
        prover_time_per_sig_sec=0.045, # Very fast GKR/Virgo prover ~45ms
        prover_memory_mb=1024,
        is_zk_aggregated=True,
        proof_bytes=128000, # ~125 KB proof
        batch_verify_gas=350000
    )

    profiles = [p_ecdsa, p_falcon, p_mldsa, p_hybrid, p_stark, p_virgo]
    batch_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
    gas_regimes = [10.0, 30.0, 60.0, 100.0]

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    results_dir = os.path.join(base_dir, "results", "paper3_decision_framework")
    os.makedirs(results_dir, exist_ok=True)

    # 2. Sweep across batch sizes for default 30 Gwei regime (Fig. 10)
    model_30 = DecisionCostModel(gas_price_gwei=30.0, eth_price_usd=3000.0)
    fig10_rows = []

    for b in batch_sizes:
        row = {"batch_size": b}
        for prof in profiles:
            eval_res = model_30.evaluate_cost_per_tx(prof, batch_size=b)
            row[f"{prof.name}_cost_usd"] = eval_res["total_usd"]
            row[f"{prof.name}_gas"] = eval_res["total_gas"]
        fig10_rows.append(row)

    fig10_csv = os.path.join(results_dir, "fig10_cost_model.csv")
    with open(fig10_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fig10_rows[0].keys()))
        writer.writeheader()
        for r in fig10_rows:
            writer.writerow(r)

    # 3. Calculate Table XVI Crossover Thresholds (K*) across gas regimes
    table_xvi = {}
    for gwei in gas_regimes:
        m = DecisionCostModel(gas_price_gwei=gwei, eth_price_usd=3000.0)
        k_star_falcon_stark = m.find_crossover_threshold(p_falcon, p_stark)
        k_star_mldsa_stark = m.find_crossover_threshold(p_mldsa, p_stark)
        k_star_hybrid_stark = m.find_crossover_threshold(p_hybrid, p_stark)
        k_star_falcon_virgo = m.find_crossover_threshold(p_falcon, p_virgo)

        table_xvi[f"{int(gwei)}_gwei"] = {
            "gas_price_gwei": gwei,
            "crossover_K_star": {
                "Falcon512_vs_STARK": k_star_falcon_stark,
                "MLDSA44_vs_STARK": k_star_mldsa_stark,
                "HybridFalcon_vs_STARK": k_star_hybrid_stark,
                "Falcon512_vs_Virgo": k_star_falcon_virgo
            }
        }

    table_xvi_json = os.path.join(results_dir, "table_xvi_calibration.json")
    with open(table_xvi_json, "w") as f:
        json.dump({
            "table": "Table XVI: Econometric Decision Calibration",
            "description": "Amortization crossover batch size K* above which ZK proof aggregation dominates on-chain verification",
            "regimes": table_xvi
        }, f, indent=2)

    # 4. Write transition frontier decision guidance
    frontier_json = os.path.join(results_dir, "transition_frontier.json")
    with open(frontier_json, "w") as f:
        json.dump({
            "decision_frontier": {
                "low_throughput_single_tx": "Bindel Hybrid Concat with SegWit Stripping",
                "medium_throughput_per_block": "Direct Falcon-512 with Calldata Compression",
                "high_throughput_rollup_batch": "STARK/Virgo Recursive Aggregation (K >= 16)",
                "critical_security_conservatism": "Dual Nesting Combiner (ECDSA + ML-DSA-44)"
            }
        }, f, indent=2)

    print(f"[+] Output written to: {fig10_csv}")
    print(f"[+] Output written to: {table_xvi_json}")
    print(f"[+] Output written to: {frontier_json}")
    print(f"[+] Calibrated STARK crossover for Falcon-512 @ 30 Gwei: K* = {table_xvi['30_gwei']['crossover_K_star']['Falcon512_vs_STARK']}")

if __name__ == "__main__":
    run_calibration()
