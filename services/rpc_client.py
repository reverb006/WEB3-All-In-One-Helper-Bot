"""Async Web3 RPC operations and EVM state querying.

Features:
- AsyncWeb3 client connection to EVM chains (Ethereum Mainnet, Base)
- State inspection: eth_getStorageAt and comprehensive 32-byte word decoding
- Read-only transaction simulation via eth_call
- Transaction failure diagnostics & revert reason extraction
"""

import string
from typing import Any, Dict, Optional, Union
from eth_utils import is_address, to_checksum_address
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import ContractLogicError, Web3RPCError
from config import settings
from services.decoder import decode_calldata, decode_revert_data
from services.evm_crypto import clean_hex, hex_to_int256


class EvmRpcClient:
    """Async EVM RPC client for querying state and simulating transactions."""

    def __init__(self):
        self._w3_instances: Dict[str, AsyncWeb3] = {}

    def get_rpc_url(self, chain: str) -> str:
        """Resolves the RPC URL for a given chain name or alias."""
        chain_key = chain.lower().replace("-", "_")
        if chain_key in ("sepolia", "eth_sepolia"):
            return settings.RPC_URL_ETH_SEPOLIA
        elif chain_key in ("base", "base_mainnet"):
            return settings.RPC_URL_BASE
        elif chain_key in ("base_sepolia", "basesepolia"):
            return settings.RPC_URL_BASE_SEPOLIA
        return settings.RPC_URL_ETH

    def get_w3(self, chain: str = "eth") -> AsyncWeb3:
        """Returns the AsyncWeb3 instance for the specified chain ('eth', 'sepolia', 'base', 'base_sepolia')."""
        chain_key = chain.lower().replace("-", "_")
        if chain_key not in self._w3_instances:
            rpc_url = self.get_rpc_url(chain_key)
            self._w3_instances[chain_key] = AsyncWeb3(AsyncHTTPProvider(rpc_url))
        return self._w3_instances[chain_key]

    async def get_storage_at(
        self,
        contract_address: str,
        slot: Union[int, str],
        chain: str = "eth",
        block_identifier: str = "latest"
    ) -> bytes:
        """Fetches the 32-byte storage slot word using eth_getStorageAt."""
        if not is_address(contract_address):
            raise ValueError(f"Invalid contract address: {contract_address}")

        w3 = self.get_w3(chain)
        c_addr = to_checksum_address(contract_address)

        # Parse slot to int or hex
        if isinstance(slot, str):
            clean_s = clean_hex(slot)
            slot_param = int(clean_s, 16)
        else:
            slot_param = int(slot)

        raw_storage = await w3.eth.get_storage_at(c_addr, slot_param, block_identifier=block_identifier)
        # Ensure 32 bytes
        return bytes(raw_storage).rjust(32, b"\x00")

    def decode_storage_word(self, word_bytes: bytes) -> Dict[str, Any]:
        """Decodes a 32-byte EVM storage word into standard interpretations."""
        raw_hex = "0x" + word_bytes.hex()
        uint_val = int.from_bytes(word_bytes, byteorder="big")
        int_val = hex_to_int256(raw_hex)

        # Potential address (if upper 12 bytes are 0x00 and not all zero)
        upper_12 = word_bytes[:12]
        lower_20 = word_bytes[12:]
        is_clean_addr = upper_12 == b"\x00" * 12 and lower_20 != b"\x00" * 20
        addr_val = to_checksum_address(lower_20)

        # Boolean (only if upper 31 bytes are 0 and last byte is 0 or 1)
        bool_val: Optional[bool] = None
        if word_bytes[:31] == b"\x00" * 31:
            if word_bytes[31] == 1:
                bool_val = True
            elif word_bytes[31] == 0:
                bool_val = False

        # Short Solidity string detection (lowest bit of last byte is 0 -> length = byte // 2)
        last_byte = word_bytes[-1]
        short_string: Optional[str] = None
        if last_byte % 2 == 0 and last_byte > 0:
            str_len = last_byte // 2
            if str_len <= 31:
                try:
                    candidate = word_bytes[:str_len].decode("utf-8")
                    if all(c in string.printable for c in candidate):
                        short_string = candidate
                except Exception:
                    pass

        # Raw printable ASCII representation (useful for auditors inspecting packed data)
        ascii_chars = "".join(chr(b) if chr(b) in string.printable and b not in (10, 13) else "." for b in word_bytes)

        return {
            "raw_hex": raw_hex,
            "uint256": uint_val,
            "int256": int_val,
            "address": addr_val,
            "is_clean_address": is_clean_addr,
            "bool": bool_val,
            "short_string": short_string,
            "ascii_preview": ascii_chars,
        }

    async def simulate_call(
        self,
        to_address: str,
        calldata: str,
        from_address: Optional[str] = None,
        value: int = 0,
        chain: str = "eth",
        block_identifier: str = "latest"
    ) -> Dict[str, Any]:
        """Simulates a read-only transaction execution via eth_call."""
        if not is_address(to_address):
            raise ValueError(f"Invalid destination address: {to_address}")

        w3 = self.get_w3(chain)
        clean_call = clean_hex(calldata)
        data_bytes = bytes.fromhex(clean_call)

        call_params = {
            "to": to_checksum_address(to_address),
            "data": data_bytes,
            "from": to_checksum_address(from_address) if from_address and is_address(from_address) else "0x0000000000000000000000000000000000000000",
            "value": value,
        }

        try:
            result_bytes = await w3.eth.call(call_params, block_identifier=block_identifier)
            return {
                "success": True,
                "return_data": "0x" + result_bytes.hex(),
                "return_bytes_len": len(result_bytes),
                "revert_info": None,
            }
        except (ContractLogicError, Web3RPCError, Exception) as exc:
            # Extract revert data from exception if available
            revert_hex = ""
            if hasattr(exc, "data") and exc.data:
                revert_hex = str(exc.data)
            elif hasattr(exc, "message") and "0x" in str(exc.message):
                # Search for hex in error message
                msg = str(exc.message)
                idx = msg.find("0x")
                revert_hex = msg[idx:].split()[0].rstrip(",.")

            revert_info = await decode_revert_data(revert_hex) if revert_hex else {"message": str(exc)}
            return {
                "success": False,
                "return_data": revert_hex,
                "revert_info": revert_info,
                "raw_error": str(exc),
            }

    async def diagnose_revert(self, tx_hash: str, chain: str = "eth") -> Dict[str, Any]:
        """Investigates a failed transaction, re-simulates it, and decodes the revert reason."""
        w3 = self.get_w3(chain)
        clean_hash = clean_hex(tx_hash)
        if len(clean_hash) != 64:
            raise ValueError(f"Invalid transaction hash: {tx_hash}")

        hash_with_0x = "0x" + clean_hash

        # 1. Fetch transaction receipt
        try:
            receipt = await w3.eth.get_transaction_receipt(hash_with_0x)
        except Exception as exc:
            return {
                "success": False,
                "error": f"Failed to fetch transaction receipt: {exc}",
                "tx_hash": hash_with_0x,
            }

        if receipt is None:
            return {
                "success": False,
                "error": "Transaction not found or pending",
                "tx_hash": hash_with_0x,
            }

        # Check status
        status = receipt.get("status")
        if status == 1:
            return {
                "status": "success",
                "tx_hash": hash_with_0x,
                "block_number": receipt.get("blockNumber"),
                "gas_used": receipt.get("gasUsed"),
                "message": "Transaction succeeded! It did not revert.",
            }

        # 2. Fetch original transaction data
        tx = await w3.eth.get_transaction(hash_with_0x)
        block_number = tx.get("blockNumber")
        to_addr = tx.get("to")
        from_addr = tx.get("from")
        input_data = tx.get("input")
        value = tx.get("value", 0)

        # 3. Re-simulate with eth_call at blockNumber - 1 to extract revert payload
        revert_hex = ""
        call_params = {
            "to": to_addr,
            "from": from_addr,
            "data": input_data,
            "value": value,
        }

        # Attempt simulation prior to tx block
        target_block = max(0, block_number - 1) if block_number else "latest"
        try:
            await w3.eth.call(call_params, block_identifier=target_block)
        except (ContractLogicError, Web3RPCError, Exception) as exc:
            if hasattr(exc, "data") and exc.data:
                revert_hex = str(exc.data)
            elif "0x" in str(exc):
                s = str(exc)
                idx = s.find("0x")
                revert_hex = s[idx:].split()[0].rstrip(",.'\"")

        # Fallback to simulation on target block itself if previous block was silent
        if not revert_hex and block_number:
            try:
                await w3.eth.call(call_params, block_identifier=block_number)
            except Exception as exc:
                if hasattr(exc, "data") and exc.data:
                    revert_hex = str(exc.data)

        # Decode revert data
        revert_diagnosis = await decode_revert_data(revert_hex) if revert_hex else {
            "type": "unextracted",
            "message": "Revert reason could not be extracted via eth_call simulation (likely out-of-gas or state-dependent revert).",
        }

        # Attempt to decode original calldata
        calldata_diag = None
        if input_data and len(clean_hex(input_data)) >= 8:
            calldata_diag = await decode_calldata(clean_hex(input_data))

        return {
            "status": "reverted",
            "tx_hash": hash_with_0x,
            "block_number": block_number,
            "gas_used": receipt.get("gasUsed"),
            "gas_limit": tx.get("gas"),
            "from": from_addr,
            "to": to_addr,
            "revert_data_hex": revert_hex or None,
            "revert_diagnosis": revert_diagnosis,
            "calldata_diagnosis": calldata_diag,
        }


# Global singleton instance
evm_rpc = EvmRpcClient()
