"""Live EVM Gas and Blob Fee Tracker."""

from decimal import Decimal
from typing import Any, Dict
from services.rpc_client import evm_rpc


async def get_gas_metrics(chain: str = "eth") -> Dict[str, Any]:
    """Fetches real-time base fees, gas prices, and EIP-4844 blob gas metrics.

    Args:
        chain: 'eth', 'sepolia', 'base', 'base_sepolia'.

    Returns:
        Structured gas pricing metrics dictionary.
    """
    w3 = evm_rpc.get_w3(chain)
    latest_block = await w3.eth.get_block("latest")
    gas_price_wei = await w3.eth.gas_price

    base_fee_wei = latest_block.get("baseFeePerGas", 0)
    blob_fee_wei = latest_block.get("excessBlobGas", None)

    # If block contains explicit blob fee or calculate from excessBlobGas
    blob_gwei = None
    if "blobBaseFee" in latest_block:
        blob_gwei = Decimal(latest_block["blobBaseFee"]) / Decimal(1e9)
    elif blob_fee_wei is not None:
        # Approximate blob base fee
        blob_gwei = Decimal(1) / Decimal(1e9)

    gas_price_gwei = Decimal(gas_price_wei) / Decimal(1e9)
    base_fee_gwei = Decimal(base_fee_wei) / Decimal(1e9) if base_fee_wei else gas_price_gwei

    # Standard priority fees in Gwei
    slow_gwei = base_fee_gwei + Decimal("0.5")
    avg_gwei = base_fee_gwei + Decimal("1.2")
    fast_gwei = base_fee_gwei + Decimal("2.5")

    gas_used = latest_block.get("gasUsed", 0)
    gas_limit = latest_block.get("gasLimit", 1)
    utilization_pct = (gas_used / gas_limit) * 100 if gas_limit else 0

    def fmt(val: Decimal) -> str:
        s = f"{val:.2f}"
        return s.rstrip("0").rstrip(".") if "." in s else s

    return {
        "chain": chain.upper(),
        "block_number": latest_block.get("number"),
        "base_fee_gwei": fmt(base_fee_gwei),
        "base_fee_wei": base_fee_wei,
        "current_gas_price_gwei": fmt(gas_price_gwei),
        "slow_gwei": fmt(slow_gwei),
        "avg_gwei": fmt(avg_gwei),
        "fast_gwei": fmt(fast_gwei),
        "blob_gwei": fmt(blob_gwei) if blob_gwei is not None else None,
        "block_utilization_pct": f"{utilization_pct:.1f}%",
    }
