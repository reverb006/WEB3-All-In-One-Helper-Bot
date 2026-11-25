"""Pure cryptographic and EVM math functions.

Covers:
- Keccak-256 hashing and 4-byte selector derivation
- Counterfactual address derivation (CREATE, CREATE2)
- Dynamic storage mapping slot calculations
- Signed int256 / uint256 conversions
- Ethereum unit conversions (Wei, Gwei, Ether, etc.)
"""

from decimal import Decimal
from typing import Any, Dict, Optional, Tuple, Union
import rlp
from eth_utils import is_address, keccak, to_checksum_address


def clean_hex(val: Union[str, bytes]) -> str:
    """Removes 0x/0X prefix and strips whitespace."""
    if isinstance(val, bytes):
        return val.hex()
    s = val.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return s[2:]
    return s


def keccak256_hex(data: Union[str, bytes], is_hex: bool = False) -> str:
    """Calculates Keccak-256 hash and returns '0x' + 64 hex characters.

    Args:
        data: Input string or bytes.
        is_hex: If True and data is str, parses data as hex bytes instead of utf-8.

    Returns:
        0x-prefixed 64-character hex string.
    """
    if isinstance(data, bytes):
        raw_bytes = data
    elif is_hex:
        raw_bytes = bytes.fromhex(clean_hex(data))
    else:
        raw_bytes = data.encode("utf-8")
    return "0x" + keccak(raw_bytes).hex()


def compute_selector(signature: str) -> str:
    """Calculates the 4-byte EVM function selector from a human-readable signature.

    Example:
        'transfer(address,uint256)' -> '0xa9059cbb'

    Args:
        signature: Function signature string (whitespace inside will be stripped).

    Returns:
        0x-prefixed 8-character hex selector (4 bytes).
    """
    # Clean signature of any intra-argument whitespace e.g. "transfer(address, uint256)"
    cleaned = "".join(signature.split())
    hash_bytes = keccak(cleaned.encode("utf-8"))
    return "0x" + hash_bytes[:4].hex()


def compute_error_selector(signature: str) -> str:
    """Calculates the 4-byte selector for a custom Solidity error.

    Example:
        'Unauthorized()' -> '0x82b42900'

    Args:
        signature: Custom error signature.

    Returns:
        0x-prefixed 8-character hex selector.
    """
    return compute_selector(signature)


def compute_create_address(deployer: str, nonce: int) -> str:
    """Computes the deterministic deployment address using standard EVM CREATE.

    Formula: keccak256(rlp.encode([deployer_address, nonce]))[12:]

    Args:
        deployer: The address of the deploying account or factory.
        nonce: The account nonce of the deployer at creation time.

    Returns:
        Checksummed EVM address.

    Raises:
        ValueError: If deployer is not a valid address or nonce is negative.
    """
    if not is_address(deployer):
        raise ValueError(f"Invalid deployer address: '{deployer}'")
    if nonce < 0:
        raise ValueError(f"Nonce must be non-negative: {nonce}")

    deployer_bytes = bytes.fromhex(clean_hex(deployer))
    # RLP encode: in standard EVM, nonce 0 encodes as b'' (rlp.encode does this for 0)
    encoded = rlp.encode([deployer_bytes, nonce])
    addr_bytes = keccak(encoded)[12:]
    return to_checksum_address(addr_bytes)


def compute_create2_address(
    deployer: str,
    salt: Union[str, bytes, int],
    init_code_or_hash: Union[str, bytes]
) -> str:
    """Computes the counterfactual deployment address using EVM CREATE2.

    Formula: keccak256(0xff ++ deployer ++ salt ++ init_code_hash)[12:]

    Args:
        deployer: Factory contract address.
        salt: 32-byte salt as hex string, integer, or raw bytes.
        init_code_or_hash: 32-byte init code hash or raw init code bytecode.

    Returns:
        Checksummed EVM address.
    """
    if not is_address(deployer):
        raise ValueError(f"Invalid deployer address: '{deployer}'")

    deployer_bytes = bytes.fromhex(clean_hex(deployer))

    # Parse salt to 32 bytes
    if isinstance(salt, int):
        salt_bytes = salt.to_bytes(32, byteorder="big")
    elif isinstance(salt, bytes):
        salt_bytes = salt.rjust(32, b"\x00") if len(salt) < 32 else salt[:32]
    else:
        cleaned_salt = clean_hex(salt)
        if len(cleaned_salt) % 2 != 0:
            cleaned_salt = "0" + cleaned_salt
        salt_bytes = bytes.fromhex(cleaned_salt).rjust(32, b"\x00")

    # Parse init code or hash
    if isinstance(init_code_or_hash, bytes):
        init_bytes = init_code_or_hash
    else:
        init_bytes = bytes.fromhex(clean_hex(init_code_or_hash))

    if len(init_bytes) == 32:
        code_hash = init_bytes
    else:
        # If full init code was provided, compute keccak256
        code_hash = keccak(init_bytes)

    preimage = b"\xff" + deployer_bytes + salt_bytes + code_hash
    addr_bytes = keccak(preimage)[12:]
    return to_checksum_address(addr_bytes)


def compute_mapping_slot(
    key: Union[str, int],
    slot: int,
    key_type: str = "auto"
) -> Dict[str, Any]:
    """Computes the storage slot for a Solidity dynamic mapping: keccak256(h(key) . slot)

    Args:
        key: The key in the mapping (address, uint256, bytes32, string, etc.).
        slot: The base slot index where the mapping is declared.
        key_type: 'auto', 'address', 'uint256', 'bytes32', 'bool', 'string'.

    Returns:
        Dict with slot_hex, slot_int, key_formatted, detected_type.
    """
    slot_bytes = slot.to_bytes(32, byteorder="big")

    key_str = str(key).strip()
    detected_type = key_type.lower()

    if detected_type == "auto":
        if key_str.lower() in ("true", "false"):
            detected_type = "bool"
        elif is_address(key_str):
            detected_type = "address"
        elif (key_str.startswith("0x") or key_str.startswith("0X")) and len(clean_hex(key_str)) == 64:
            detected_type = "bytes32"
        elif key_str.isdigit() or (key_str.startswith("-") and key_str[1:].isdigit()):
            detected_type = "uint256"
        else:
            detected_type = "string"

    if detected_type == "address":
        if not is_address(key_str):
            raise ValueError(f"Invalid address key: {key_str}")
        key_raw = bytes.fromhex(clean_hex(key_str))
        key_bytes = key_raw.rjust(32, b"\x00")
        key_display = to_checksum_address(key_raw)
    elif detected_type in ("uint", "uint256"):
        val = int(key_str, 0 if key_str.startswith("0x") else 10)
        key_bytes = val.to_bytes(32, byteorder="big")
        key_display = str(val)
    elif detected_type == "bytes32":
        cleaned = clean_hex(key_str)
        key_bytes = bytes.fromhex(cleaned).rjust(32, b"\x00")
        key_display = "0x" + key_bytes.hex()
    elif detected_type == "bool":
        b_val = 1 if key_str.lower() in ("true", "1") else 0
        key_bytes = b_val.to_bytes(32, byteorder="big")
        key_display = "true" if b_val == 1 else "false"
    elif detected_type in ("string", "bytes"):
        # For strings/bytes, Solidity uses keccak256(raw_bytes) . slot
        raw_key = key_str.encode("utf-8")
        key_bytes = keccak(raw_key)
        key_display = f'"{key_str}"'
    else:
        raise ValueError(f"Unsupported mapping key type: {key_type}")

    preimage = key_bytes + slot_bytes
    final_slot = keccak(preimage)
    slot_hex = "0x" + final_slot.hex()
    slot_int = int.from_bytes(final_slot, byteorder="big")

    return {
        "slot_hex": slot_hex,
        "slot_int": slot_int,
        "key_display": key_display,
        "key_type": detected_type,
        "base_slot": slot,
        "preimage_hex": "0x" + preimage.hex()
    }


def hex_to_int256(hex_str: str) -> int:
    """Converts a 256-bit hex word to a signed integer using two's complement."""
    val = int(clean_hex(hex_str), 16)
    if val >= (1 << 255):
        val -= (1 << 256)
    return val


def hex_to_uint256(hex_str: str) -> int:
    """Converts a hex word to an unsigned uint256 integer."""
    return int(clean_hex(hex_str), 16)


def int_to_hex256(val: int) -> str:
    """Converts an integer (positive or negative) to a 64-char two's complement hex word."""
    if val < 0:
        val = (1 << 256) + val
    if val >= (1 << 256) or val < 0:
        raise ValueError("Value out of 256-bit bounds")
    return f"0x{val:064x}"


# Ethereum unit multiples in Wei
UNIT_FACTORS: Dict[str, Decimal] = {
    "wei": Decimal("1"),
    "kwei": Decimal("1e3"),
    "babbage": Decimal("1e3"),
    "mwei": Decimal("1e6"),
    "lovelace": Decimal("1e6"),
    "gwei": Decimal("1e9"),
    "shannon": Decimal("1e9"),
    "szabo": Decimal("1e12"),
    "finney": Decimal("1e15"),
    "ether": Decimal("1e18"),
    "eth": Decimal("1e18"),
}


def convert_units(amount: Union[str, int, float, Decimal], from_unit: str = "eth") -> Dict[str, str]:
    """Converts a cryptocurrency amount between EVM units (Wei, Gwei, Ether).

    Args:
        amount: Number to convert.
        from_unit: Source unit ('wei', 'gwei', 'ether', 'eth', etc.).

    Returns:
        Dictionary with conversions formatted cleanly.
    """
    clean_unit = from_unit.strip().lower()
    if clean_unit not in UNIT_FACTORS:
        raise ValueError(f"Unknown unit: '{from_unit}'. Supported: {', '.join(sorted(UNIT_FACTORS.keys()))}")

    # Parse amount as Decimal
    try:
        amt_dec = Decimal(str(amount).strip())
    except Exception as exc:
        raise ValueError(f"Invalid numeric amount: '{amount}'") from exc

    # Convert to Wei base
    wei_val = amt_dec * UNIT_FACTORS[clean_unit]
    if wei_val < 0:
        raise ValueError("Amount cannot be negative")

    # Round wei to integer if very close
    wei_int = int(wei_val)

    gwei_val = wei_val / UNIT_FACTORS["gwei"]
    eth_val = wei_val / UNIT_FACTORS["ether"]

    # Format numbers nicely
    def fmt_dec(d: Decimal) -> str:
        # Normalize and remove trailing zeroes
        norm = d.normalize()
        # Prevent scientific notation
        s = f"{norm:f}"
        if "." in s:
            s = s.rstrip("0").rstrip(".")
        return s or "0"

    return {
        "wei": f"{wei_int:,}".replace(",", " "),
        "wei_raw": str(wei_int),
        "gwei": fmt_dec(gwei_val),
        "ether": fmt_dec(eth_val),
        "input_amount": str(amount),
        "input_unit": clean_unit.upper(),
    }
