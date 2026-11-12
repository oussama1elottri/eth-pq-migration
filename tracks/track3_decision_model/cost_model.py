#!/usr/bin/env python3
"""
Track 3 Decision Model: Fig. 10 & Table XVI Cost Model.
Analytical framework evaluating trade-offs between:
1. Classical ECDSA
2. Direct On-chain PQC (Falcon-512, ML-DSA-44, SLH-DSA)
3. Bindel Hybrid Combiners (Concat, Weak, Strong, Dual)
4. STARK / Virgo Transparent ZK-Proof Aggregation

Models execution gas, calldata gas (EIP-1559 and EIP-4844), prover computational overhead,
and determines the crossover amortization threshold K* where ZK-STARK proof aggregation
becomes more cost-effective than native EVM signature verification.
"""

from dataclasses import dataclass
from typing import Dict, Any, List

@dataclass
class ArchitectureProfile:
    name: str
    sig_bytes: int
    pubkey_bytes: int
    evm_verify_gas: int
    prover_time_per_sig_sec: float
    prover_memory_mb: float
    is_zk_aggregated: bool
    proof_bytes: int = 0
    batch_verify_gas: int = 0

class DecisionCostModel:
    def __init__(self, gas_price_gwei: float = 30.0, eth_price_usd: float = 3000.0, prover_cost_per_sec_usd: float = 0.00005):
        self.gas_price_gwei = gas_price_gwei
        self.eth_price_usd = eth_price_usd
        self.prover_cost_per_sec_usd = prover_cost_per_sec_usd

    def gas_to_usd(self, gas: int) -> float:
        eth = (gas * self.gas_price_gwei) / 1e9
        return eth * self.eth_price_usd

    def evaluate_cost_per_tx(self, profile: ArchitectureProfile, batch_size: int = 1) -> Dict[str, Any]:
        """
        Calculates the per-transaction cost in gas and USD for a given batch size K.
        """
        if not profile.is_zk_aggregated:
            calldata_bytes = profile.sig_bytes + profile.pubkey_bytes
            calldata_gas = calldata_bytes * 16
            exec_gas = profile.evm_verify_gas
            total_gas = calldata_gas + exec_gas
            onchain_cost_usd = self.gas_to_usd(total_gas)
            offchain_prover_usd = 0.0
            total_cost_usd = onchain_cost_usd
        else:
            # STARK / Virgo proof aggregation:
            # Amortize batch on-chain proof verification + calldata over batch_size K
            batch_calldata_gas = profile.proof_bytes * 16
            amortized_calldata_gas = int(batch_calldata_gas / batch_size)
            amortized_verify_gas = int(profile.batch_verify_gas / batch_size)
            total_gas = amortized_calldata_gas + amortized_verify_gas
            onchain_cost_usd = self.gas_to_usd(total_gas)
            
            # Offchain prover cloud computing cost
            prover_time_total = profile.prover_time_per_sig_sec * batch_size
            offchain_prover_usd = (prover_time_total * self.prover_cost_per_sec_usd) / batch_size
            total_cost_usd = onchain_cost_usd + offchain_prover_usd

        return {
            "name": profile.name,
            "batch_size": batch_size,
            "calldata_gas": calldata_gas if not profile.is_zk_aggregated else amortized_calldata_gas,
            "exec_gas": exec_gas if not profile.is_zk_aggregated else amortized_verify_gas,
            "total_gas": total_gas,
            "onchain_usd": round(onchain_cost_usd, 4),
            "offchain_usd": round(offchain_prover_usd, 4),
            "total_usd": round(total_cost_usd, 4)
        }

    def find_crossover_threshold(self, direct_profile: ArchitectureProfile, zk_profile: ArchitectureProfile, max_batch: int = 1000) -> int:
        """
        Finds the batch size K* where ZK-STARK/Virgo becomes cheaper per tx than direct verification.
        """
        for k in range(1, max_batch + 1):
            direct_cost = self.evaluate_cost_per_tx(direct_profile, 1)["total_usd"]
            zk_cost = self.evaluate_cost_per_tx(zk_profile, k)["total_usd"]
            if zk_cost < direct_cost:
                return k
        return -1
