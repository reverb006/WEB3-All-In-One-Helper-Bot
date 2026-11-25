"""ERC-20 token inspection and circulating metrics service."""

from decimal import Decimal
from typing import Any, Dict
from eth_abi import decode as abi_decode
from eth_utils import is_address, to_checksum_address
from services.evm_crypto import clean_hex
from services.rpc_client import evm_rpc

# Standard ERC-20 Selectors
SEL_NAME = "0x06fdde03"         # name()
SEL_SYMBOL = "0x95d89b41"       # symbol()
SEL_DECIMALS = "0x313ce567"     # decimals()
SEL_TOTAL_SUPPLY = "0x18160ddd" # totalSupply()


def decode_string_or_bytes32(raw_bytes: bytes) -> str:
    """Decodes standard ABI string, or falls back to bytes32 (e.g. MakerDAO MKR)."""
    if not raw_bytes:
        return ""
    # 1. Try ABI decode string
    try:
        (s,) = abi_decode(["string"], raw_bytes)
        return str(s).strip()
    except Exception:
        pass

    # 2. Try raw bytes32 strip nulls
    try:
        decoded = raw_bytes.decode("utf-8", errors="ignore").replace("\x00", "").strip()
        if decoded:
            return decoded
    except Exception:
        pass

    return raw_bytes.hex()[:16]


async def inspect_token(token_address: str, chain: str = "eth") -> Dict[str, Any]:
    """Inspects an ERC-20 token contract to retrieve name, symbol, decimals, and total supply.

    Args:
        token_address: ERC-20 token contract address.
        chain: 'eth', 'sepolia', 'base', 'base_sepolia'.

    Returns:
        Dictionary with token details and human-readable supply.
    """
    if not is_address(token_address):
        raise ValueError(f"Invalid token address: {token_address}")

    t_addr = to_checksum_address(token_address)

    # 1. Fetch Symbol
    sym_res = await evm_rpc.simulate_call(t_addr, SEL_SYMBOL, chain=chain)
    sym_raw = bytes.fromhex(clean_hex(sym_res.get("return_data", ""))) if sym_res.get("success") else b""
    symbol = decode_string_or_bytes32(sym_raw) or "UNKNOWN"

    # 2. Fetch Name
    name_res = await evm_rpc.simulate_call(t_addr, SEL_NAME, chain=chain)
    name_raw = bytes.fromhex(clean_hex(name_res.get("return_data", ""))) if name_res.get("success") else b""
    name = decode_string_or_bytes32(name_raw) or "Unknown Token"

    # 3. Fetch Decimals
    decimals = 18
    dec_res = await evm_rpc.simulate_call(t_addr, SEL_DECIMALS, chain=chain)
    if dec_res.get("success") and dec_res.get("return_data"):
        try:
            raw_dec = bytes.fromhex(clean_hex(dec_res["return_data"])).rjust(32, b"\x00")
            (dec_val,) = abi_decode(["uint8"], raw_dec)
            decimals = int(dec_val)
        except Exception:
            try:
                (dec_val,) = abi_decode(["uint256"], raw_dec)
                decimals = int(dec_val)
            except Exception:
                pass

    # 4. Fetch Total Supply
    total_supply_raw = 0
    supply_res = await evm_rpc.simulate_call(t_addr, SEL_TOTAL_SUPPLY, chain=chain)
    if supply_res.get("success") and supply_res.get("return_data"):
        try:
            raw_sup = bytes.fromhex(clean_hex(supply_res["return_data"])).rjust(32, b"\x00")
            (sup_val,) = abi_decode(["uint256"], raw_sup)
            total_supply_raw = int(sup_val)
        except Exception:
            pass

    # Format human circulating supply
    scale = Decimal(10) ** Decimal(decimals)
    circulating_amount = Decimal(total_supply_raw) / scale if scale > 0 else Decimal(total_supply_raw)

    def fmt_number(d: Decimal) -> str:
        s = f"{d:,.4f}"
        if "." in s:
            s = s.rstrip("0").rstrip(".")
        return s

    return {
        "success": True,
        "address": t_addr,
        "chain": chain.upper(),
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "total_supply_raw": str(total_supply_raw),
        "total_supply_formatted": fmt_number(circulating_amount),
    }
