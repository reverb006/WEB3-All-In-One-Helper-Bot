"""Calldata parsing, 4-byte selector resolution, and custom error decoding."""

from typing import Any, Dict, List, Optional, Tuple
import aiohttp
from eth_abi import decode as abi_decode
from config import settings
from services.evm_crypto import clean_hex


# Standard EVM Panic code human explanations
PANIC_CODES: Dict[int, str] = {
    0x00: "Generic compiler panic",
    0x01: "Assertion failure (assert(false))",
    0x11: "Arithmetic overflow or underflow",
    0x12: "Division or modulo by zero",
    0x21: "Invalid enum conversion (value out of bounds)",
    0x22: "Storage byte array incorrectly encoded",
    0x31: "Empty array pop (.pop() called on empty array)",
    0x32: "Array index out of bounds",
    0x41: "Memory allocation overflow (too large memory allocation)",
    0x51: "Call to uninitialized internal function pointer",
}

# Standard error selectors
SELECTOR_STRING_ERROR = "0x08c379a0"  # Error(string)
SELECTOR_PANIC_ERROR = "0x4e487b71"   # Panic(uint256)


def parse_function_signature(signature: str) -> Tuple[str, List[str]]:
    """Splits a canonical function signature into its name and top-level parameter types.

    Correctly handles nested tuples such as '(address,uint256)[]' or 'swap((address,uint24))'.

    Args:
        signature: e.g. 'transfer(address,uint256)' or 'commit((uint256,bytes),address)'

    Returns:
        Tuple of (function_name, list_of_types)
    """
    clean_sig = "".join(signature.split())
    paren_idx = clean_sig.find("(")
    if paren_idx == -1 or not clean_sig.endswith(")"):
        return clean_sig, []

    fn_name = clean_sig[:paren_idx]
    params_str = clean_sig[paren_idx + 1 : -1]
    if not params_str:
        return fn_name, []

    # Split by comma respecting parenthesis depth
    types = []
    current = []
    depth = 0
    for char in params_str:
        if char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            types.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if current:
        types.append("".join(current).strip())

    return fn_name, types


async def fetch_signatures(
    selector: str,
    session: Optional[aiohttp.ClientSession] = None
) -> List[str]:
    """Queries OpenChain and 4byte Directory for function signatures matching a 4-byte selector.

    Args:
        selector: 4-byte selector in hex (with or without 0x prefix).
        session: Optional shared aiohttp ClientSession.

    Returns:
        List of matching human-readable function signatures.
    """
    clean_sel = clean_hex(selector).lower()
    if len(clean_sel) < 8:
        return []
    sel_8 = clean_sel[:8]
    sel_with_0x = "0x" + sel_8

    signatures: List[str] = []
    owns_session = session is None
    client = session or aiohttp.ClientSession()

    try:
        # 1. Query OpenChain API
        openchain_url = f"{settings.OPENCHAIN_API_URL}?function={sel_with_0x}&filter=true"
        try:
            async with client.get(openchain_url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("ok") and data.get("result", {}).get("function"):
                        matches = data["result"]["function"].get(sel_with_0x, [])
                        for m in matches:
                            name = m.get("name")
                            if name and name not in signatures:
                                signatures.append(name)
        except Exception:
            pass

        # 2. Query 4byte Directory if no signatures found yet
        if not signatures:
            fourbyte_url = f"{settings.FOURBYTE_API_URL}?hex_signature={sel_with_0x}"
            try:
                async with client.get(fourbyte_url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = data.get("results", [])
                        for r in results:
                            sig = r.get("text_signature")
                            if sig and sig not in signatures:
                                signatures.append(sig)
            except Exception:
                pass

    finally:
        if owns_session:
            await client.close()

    return signatures


async def fetch_error_signatures(
    selector: str,
    session: Optional[aiohttp.ClientSession] = None
) -> List[str]:
    """Queries OpenChain for custom error signatures matching an error selector."""
    clean_sel = clean_hex(selector).lower()
    if len(clean_sel) < 8:
        return []
    sel_8 = clean_sel[:8]
    sel_with_0x = "0x" + sel_8

    if sel_with_0x == SELECTOR_STRING_ERROR:
        return ["Error(string)"]
    if sel_with_0x == SELECTOR_PANIC_ERROR:
        return ["Panic(uint256)"]

    signatures: List[str] = []
    owns_session = session is None
    client = session or aiohttp.ClientSession()

    try:
        # OpenChain error lookup
        openchain_url = f"https://api.openchain.xyz/signature-database/v1/lookup?error={sel_with_0x}&filter=true"
        try:
            async with client.get(openchain_url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("ok") and data.get("result", {}).get("error"):
                        matches = data["result"]["error"].get(sel_with_0x, [])
                        for m in matches:
                            name = m.get("name")
                            if name and name not in signatures:
                                signatures.append(name)
        except Exception:
            pass

        # Fallback to function query in case registered as function
        if not signatures:
            sigs = await fetch_signatures(sel_with_0x, session=client)
            signatures.extend(sigs)

    finally:
        if owns_session:
            await client.close()

    return signatures


async def decode_calldata(
    calldata: str,
    session: Optional[aiohttp.ClientSession] = None
) -> Dict[str, Any]:
    """Decodes raw EVM calldata into selector, matched signatures, and decoded arguments.

    Args:
        calldata: Hex-encoded calldata.
        session: Optional aiohttp ClientSession.

    Returns:
        Structured dictionary with decoded results.
    """
    raw_hex = clean_hex(calldata)
    if len(raw_hex) < 8:
        return {
            "success": False,
            "error": "Calldata is too short (< 4 bytes for selector)",
            "raw_hex": "0x" + raw_hex,
        }

    selector = "0x" + raw_hex[:8].lower()
    args_hex = raw_hex[8:]
    args_bytes = bytes.fromhex(args_hex) if args_hex else b""

    # Query 4-byte database
    signatures = await fetch_signatures(selector, session=session)

    decoded_matches = []
    raw_words = [
        "0x" + args_hex[i : i + 64]
        for i in range(0, len(args_hex), 64)
    ]

    for sig in signatures:
        fn_name, param_types = parse_function_signature(sig)
        try:
            if not param_types and not args_bytes:
                decoded_matches.append({
                    "signature": sig,
                    "function_name": fn_name,
                    "params": [],
                    "success": True,
                })
            elif param_types and args_bytes:
                decoded_vals = abi_decode(param_types, args_bytes)
                params_list = []
                for p_type, val in zip(param_types, decoded_vals):
                    # Format value safely
                    if isinstance(val, bytes):
                        val_str = "0x" + val.hex()
                    else:
                        val_str = str(val)
                    params_list.append({
                        "type": p_type,
                        "value": val_str,
                    })
                decoded_matches.append({
                    "signature": sig,
                    "function_name": fn_name,
                    "params": params_list,
                    "success": True,
                })
        except Exception:
            # ABI decode mismatch with this candidate signature
            decoded_matches.append({
                "signature": sig,
                "function_name": fn_name,
                "params": None,
                "success": False,
            })

    return {
        "success": True,
        "selector": selector,
        "signatures": signatures,
        "decoded_matches": decoded_matches,
        "args_bytes_len": len(args_bytes),
        "raw_words": raw_words,
    }


async def decode_revert_data(
    revert_data: str,
    session: Optional[aiohttp.ClientSession] = None
) -> Dict[str, Any]:
    """Decodes EVM revert output hex (Error(string), Panic(uint256), or Custom Error).

    Args:
        revert_data: Hex string returned by reverted execution.
        session: Optional aiohttp ClientSession.

    Returns:
        Structured diagnosis dictionary.
    """
    raw_hex = clean_hex(revert_data)
    if not raw_hex:
        return {
            "type": "empty",
            "message": "Reverted without reason data (or gas limit reached / invalid opcode)",
            "selector": None,
        }

    if len(raw_hex) < 8:
        return {
            "type": "raw",
            "message": f"Raw revert data too short ({len(raw_hex)} hex characters)",
            "raw_hex": "0x" + raw_hex,
            "selector": None,
        }

    selector = "0x" + raw_hex[:8].lower()
    payload = bytes.fromhex(raw_hex[8:])

    # 1. Standard Error(string)
    if selector == SELECTOR_STRING_ERROR:
        try:
            (reason,) = abi_decode(["string"], payload)
            return {
                "type": "Error(string)",
                "selector": selector,
                "reason": reason,
                "message": f"Reverted with reason: '{reason}'",
            }
        except Exception as exc:
            return {
                "type": "Error(string)",
                "selector": selector,
                "reason": None,
                "error": f"Failed to decode string reason: {exc}",
            }

    # 2. Standard Panic(uint256)
    if selector == SELECTOR_PANIC_ERROR:
        try:
            (code,) = abi_decode(["uint256"], payload)
            explanation = PANIC_CODES.get(code, "Unknown Panic code")
            return {
                "type": "Panic(uint256)",
                "selector": selector,
                "code": code,
                "code_hex": hex(code),
                "explanation": explanation,
                "message": f"Reverted with Panic: {hex(code)} ({explanation})",
            }
        except Exception as exc:
            return {
                "type": "Panic(uint256)",
                "selector": selector,
                "error": f"Failed to decode panic code: {exc}",
            }

    # 3. Custom Error
    error_sigs = await fetch_error_signatures(selector, session=session)
    decoded_params = None
    matched_sig = None

    for sig in error_sigs:
        err_name, param_types = parse_function_signature(sig)
        try:
            if not param_types and not payload:
                matched_sig = sig
                decoded_params = []
                break
            elif param_types and payload:
                vals = abi_decode(param_types, payload)
                params_list = []
                for p_type, val in zip(param_types, vals):
                    val_str = "0x" + val.hex() if isinstance(val, bytes) else str(val)
                    params_list.append({"type": p_type, "value": val_str})
                matched_sig = sig
                decoded_params = params_list
                break
        except Exception:
            continue

    return {
        "type": "CustomError",
        "selector": selector,
        "matched_signature": matched_sig,
        "candidate_signatures": error_sigs,
        "decoded_params": decoded_params,
        "raw_payload": "0x" + raw_hex[8:] if raw_hex[8:] else None,
        "message": f"Custom Error: {matched_sig or selector}",
    }
