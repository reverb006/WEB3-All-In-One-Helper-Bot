"""Etherscan API V2 contract verification and ABI fetcher service."""

from typing import Any, Dict, Optional
import aiohttp
from eth_utils import is_address, to_checksum_address
from config import settings

ETHERSCAN_V2_ENDPOINT = "https://api.etherscan.io/v2/api"

CHAIN_IDS: Dict[str, int] = {
    "eth": 1,
    "mainnet": 1,
    "sepolia": 11155111,
    "eth_sepolia": 11155111,
    "base": 8453,
    "base_mainnet": 8453,
    "base_sepolia": 84532,
    "basesepolia": 84532,
}


async def fetch_contract_source(
    contract_address: str,
    chain: str = "eth",
    session: Optional[aiohttp.ClientSession] = None
) -> Dict[str, Any]:
    """Fetches verified contract source metadata, ABI, and compiler details via Etherscan API V2.

    Args:
        contract_address: Target smart contract address.
        chain: 'eth', 'sepolia', 'base', 'base_sepolia'.
        session: Optional shared aiohttp ClientSession.

    Returns:
        Structured dictionary with verification status and metadata.
    """
    if not is_address(contract_address):
        raise ValueError(f"Invalid contract address: {contract_address}")

    c_addr = to_checksum_address(contract_address)
    chain_key = chain.lower().replace("-", "_")
    chain_id = CHAIN_IDS.get(chain_key, 1)
    api_key = settings.ETHERSCAN_API_KEY or ""

    owns_session = session is None
    client = session or aiohttp.ClientSession()

    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": c_addr,
        "apikey": api_key,
    }
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        async with client.get(
            ETHERSCAN_V2_ENDPOINT,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=8)
        ) as resp:
            if resp.status != 200:
                return {
                    "success": False,
                    "error": f"Explorer API returned HTTP {resp.status}",
                    "address": c_addr,
                }

            data = await resp.json()
            if data.get("status") != "1" or not data.get("result"):
                return {
                    "success": False,
                    "error": data.get("result") or data.get("message", "Contract not verified or not found"),
                    "address": c_addr,
                }

            info = data["result"][0]
            contract_name = info.get("ContractName", "")
            abi_str = info.get("ABI", "")

            is_verified = (
                bool(contract_name)
                and "not verified" not in abi_str.lower()
                and abi_str != "0x"
            )

            is_proxy = info.get("Proxy") == "1"
            impl_addr = info.get("Implementation") or None

            return {
                "success": True,
                "is_verified": is_verified,
                "address": c_addr,
                "chain": chain_key.upper(),
                "chain_id": chain_id,
                "contract_name": contract_name or "Unverified Contract",
                "compiler_version": info.get("CompilerVersion", "Unknown"),
                "optimization_used": "Yes" if info.get("OptimizationUsed") == "1" else "No",
                "runs": info.get("Runs", "0"),
                "license_type": info.get("LicenseType", "Unknown"),
                "evm_version": info.get("EVMVersion", "Default"),
                "constructor_arguments": info.get("ConstructorArguments", ""),
                "is_proxy": is_proxy,
                "implementation": impl_addr,
                "has_abi": is_verified and bool(abi_str),
                "raw_abi_snippet": abi_str[:200] if is_verified else None,
            }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to connect to explorer API: {exc}",
            "address": c_addr,
        }
    finally:
        if owns_session:
            await client.close()
