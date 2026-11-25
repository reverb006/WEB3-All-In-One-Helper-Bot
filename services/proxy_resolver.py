"""Proxy implementation and admin resolver for upgradeable smart contracts.

Supports:
- EIP-1967: Implementation, Admin, and Beacon slots
- EIP-1822: Universal Upgradeable Proxy Standard (UUPS) proxiable slot
- EIP-897: DelegateProxy (implementation() function call)
- OpenZeppelin Legacy Proxy implementation slot
"""

from typing import Any, Dict, Optional
from eth_utils import is_address, to_checksum_address
from web3 import AsyncWeb3
from services.evm_crypto import clean_hex
from services.rpc_client import evm_rpc

# Standard Proxy Storage Slots (EIP-1967 & EIP-1822)
SLOT_EIP1967_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_EIP1822_PROXIABLE = "0xc5f1683641f2d5170d0f05c6113773114d824b0c087271b86a85ffc7430f83da"
SLOT_OZ_LEGACY = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
SLOT_OZ_LEGACY_ADMIN = "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b"

# Selectors
SELECTOR_IMPLEMENTATION = "0x5c60da1b"  # implementation()
SELECTOR_UPGRADE_TO = "0x3659cfe6"      # upgradeTo(address)
SELECTOR_ADMIN = "0xf851a440"           # admin()


def extract_address_from_slot(slot_bytes: bytes) -> Optional[str]:
    """Extracts a 20-byte address from a 32-byte storage word if non-zero."""
    if not slot_bytes or len(slot_bytes) != 32:
        return None
    lower_20 = slot_bytes[12:]
    if lower_20 == b"\x00" * 20:
        return None
    return to_checksum_address(lower_20)


async def resolve_proxy(contract_address: str, chain: str = "eth") -> Dict[str, Any]:
    """Inspects a contract to detect upgradeable proxy patterns and resolve logic contracts.

    Args:
        contract_address: Proxy contract address.
        chain: EVM chain ('eth', 'sepolia', 'base', 'base_sepolia').

    Returns:
        Dictionary with proxy type, implementation address, admin, and beacon details.
    """
    if not is_address(contract_address):
        raise ValueError(f"Invalid contract address: {contract_address}")

    target = to_checksum_address(contract_address)
    w3 = evm_rpc.get_w3(chain)

    # 1. Check EIP-1967 Implementation Slot
    impl_bytes = await evm_rpc.get_storage_at(target, SLOT_EIP1967_IMPLEMENTATION, chain=chain)
    impl_addr = extract_address_from_slot(impl_bytes)

    admin_bytes = await evm_rpc.get_storage_at(target, SLOT_EIP1967_ADMIN, chain=chain)
    admin_addr = extract_address_from_slot(admin_bytes)

    # If no EIP-1967 admin, check OpenZeppelin legacy admin slot
    if not admin_addr:
        oz_admin_bytes = await evm_rpc.get_storage_at(target, SLOT_OZ_LEGACY_ADMIN, chain=chain)
        admin_addr = extract_address_from_slot(oz_admin_bytes)

    # If still no admin, try admin() view call
    if not admin_addr:
        try:
            res_admin = await evm_rpc.simulate_call(target, SELECTOR_ADMIN, chain=chain)
            if res_admin.get("success") and res_admin.get("return_data"):
                raw_ret = bytes.fromhex(clean_hex(res_admin["return_data"]))
                admin_addr = extract_address_from_slot(raw_ret.rjust(32, b"\x00"))
        except Exception:
            pass

    beacon_bytes = await evm_rpc.get_storage_at(target, SLOT_EIP1967_BEACON, chain=chain)
    beacon_addr = extract_address_from_slot(beacon_bytes)

    if impl_addr:
        return {
            "is_proxy": True,
            "proxy_type": "EIP-1967 Transparent / UUPS Proxy",
            "contract_address": target,
            "implementation": impl_addr,
            "admin": admin_addr,
            "beacon": beacon_addr,
            "slot_used": SLOT_EIP1967_IMPLEMENTATION,
        }

    # 2. Check EIP-1967 Beacon Proxy
    if beacon_addr:
        # Try calling implementation() on the beacon contract
        beacon_impl = None
        try:
            res = await evm_rpc.simulate_call(beacon_addr, SELECTOR_IMPLEMENTATION, chain=chain)
            if res.get("success") and res.get("return_data"):
                raw_ret = bytes.fromhex(clean_hex(res["return_data"]))
                beacon_impl = extract_address_from_slot(raw_ret.rjust(32, b"\x00"))
        except Exception:
            pass

        return {
            "is_proxy": True,
            "proxy_type": "EIP-1967 Beacon Proxy",
            "contract_address": target,
            "implementation": beacon_impl,
            "beacon": beacon_addr,
            "admin": admin_addr,
            "slot_used": SLOT_EIP1967_BEACON,
        }

    # 3. Check EIP-1822 (UUPS) Proxiable Slot
    uups_bytes = await evm_rpc.get_storage_at(target, SLOT_EIP1822_PROXIABLE, chain=chain)
    uups_addr = extract_address_from_slot(uups_bytes)
    if uups_addr:
        return {
            "is_proxy": True,
            "proxy_type": "EIP-1822 UUPS Proxy",
            "contract_address": target,
            "implementation": uups_addr,
            "admin": admin_addr,
            "beacon": None,
            "slot_used": SLOT_EIP1822_PROXIABLE,
        }

    # 4. Check OpenZeppelin Legacy Storage Slot
    legacy_bytes = await evm_rpc.get_storage_at(target, SLOT_OZ_LEGACY, chain=chain)
    legacy_addr = extract_address_from_slot(legacy_bytes)
    if legacy_addr:
        return {
            "is_proxy": True,
            "proxy_type": "OpenZeppelin Legacy Proxy",
            "contract_address": target,
            "implementation": legacy_addr,
            "admin": admin_addr,
            "beacon": None,
            "slot_used": SLOT_OZ_LEGACY,
        }

    # 5. Check EIP-897 / Generic implementation() call
    try:
        call_res = await evm_rpc.simulate_call(target, SELECTOR_IMPLEMENTATION, chain=chain)
        if call_res.get("success") and call_res.get("return_data"):
            raw_ret = bytes.fromhex(clean_hex(call_res["return_data"]))
            fn_impl = extract_address_from_slot(raw_ret.rjust(32, b"\x00"))
            if fn_impl:
                return {
                    "is_proxy": True,
                    "proxy_type": "EIP-897 DelegateProxy",
                    "contract_address": target,
                    "implementation": fn_impl,
                    "admin": admin_addr,
                    "beacon": None,
                    "slot_used": "implementation() call",
                }
    except Exception:
        pass

    return {
        "is_proxy": False,
        "proxy_type": "Direct Contract / Non-Standard Proxy",
        "contract_address": target,
        "implementation": None,
        "admin": admin_addr,
        "beacon": None,
        "slot_used": None,
    }
