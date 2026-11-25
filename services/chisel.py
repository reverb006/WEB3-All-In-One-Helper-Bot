"""Foundry Chisel-style Solidity REPL and evaluation service.

Compiles Solidity snippets, expressions, functions, and contracts on the fly
using solc v0.8.26 and executes them via EVM state simulation (eth_call) on
configured RPC endpoints (Ethereum Mainnet, Base, Sepolia).
"""

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
import solcx
from web3 import Web3
from web3.exceptions import ContractLogicError, ContractPanicError, Web3RPCError
from config import settings
from services.rpc_client import evm_rpc
from utils.formatters import blockquote, bold, code_block, escape_html, inline_code

SOLC_DEFAULT_VERSION = "0.8.26"
_solc_ready = False


def ensure_solc_installed(version: str = SOLC_DEFAULT_VERSION) -> str:
    """Ensures the specified solc compiler is installed and activated."""
    global _solc_ready
    if _solc_ready:
        return version

    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if version not in installed:
        solcx.install_solc(version)
    solcx.set_solc_version(version)
    _solc_ready = True
    return version


def prepare_solidity_source(code: str) -> Tuple[str, bool]:
    """Parses arbitrary user Solidity snippets into a compilable contract.

    Returns:
        (solidity_source, has_return_expression)
    """
    clean_code = code.strip()

    # Strip markdown code blocks if present
    if clean_code.startswith("```"):
        lines = clean_code.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        clean_code = "\n".join(lines).strip()

    # Detect if user passed a full contract/interface/library
    if re.search(r"\b(contract|library|interface)\s+\w+", clean_code):
        if "pragma solidity" not in clean_code:
            clean_code = (
                f"// SPDX-License-Identifier: MIT\npragma solidity ^{SOLC_DEFAULT_VERSION};\n"
                + clean_code
            )
        return clean_code, False

    lines = clean_code.splitlines()
    contract_items: List[str] = []
    body_items: List[str] = []

    in_contract_block = False
    brace_depth = 0
    current_block: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if not in_contract_block:
            # Check for contract-level declarations
            if re.match(r"^(function|struct|event|error|modifier|enum|using)\b", stripped):
                in_contract_block = True
                brace_depth = line.count("{") - line.count("}")
                current_block = [line]
                # Single line declaration like: error Unauthorized();
                if brace_depth == 0 and ";" in line:
                    contract_items.append("\n".join(current_block))
                    current_block = []
                    in_contract_block = False
                continue
            else:
                body_items.append(line)
        else:
            current_block.append(line)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                contract_items.append("\n".join(current_block))
                current_block = []
                in_contract_block = False

    if current_block:
        contract_items.append("\n".join(current_block))

    if not body_items:
        src = f"""// SPDX-License-Identifier: MIT
pragma solidity ^{SOLC_DEFAULT_VERSION};

contract Chisel {{
    {chr(10).join(contract_items)}
    constructor() {{}}
}}"""
        return src, False

    # Check if the last line is an expression
    last_stmt = body_items[-1].strip()
    is_expr = not (last_stmt.endswith(";") or last_stmt.endswith("}"))

    # Also detect if there's only 1 statement and it is an expression ending with semicolon
    if not is_expr and len(body_items) == 1:
        if not re.match(r"^(uint|int|address|bool|bytes|string|mapping|\w+\s+\w+\s*=)", last_stmt):
            is_expr = True
            body_items[-1] = last_stmt.rstrip(";").strip()

    if is_expr:
        prev_statements = "\n        ".join(body_items[:-1])
        expr = body_items[-1].rstrip(";").strip()
        # Strip outer parentheses for tuple if needed
        if expr.startswith("(") and expr.endswith(")") and "," in expr:
            expr = expr[1:-1].strip()

        src = f"""// SPDX-License-Identifier: MIT
pragma solidity ^{SOLC_DEFAULT_VERSION};

contract Chisel {{
    {chr(10).join(contract_items)}

    constructor() {{
        {prev_statements}
        bytes memory __chisel_ret = abi.encode({expr});
        assembly {{
            return(add(__chisel_ret, 0x20), mload(__chisel_ret))
        }}
    }}
}}"""
        return src, True
    else:
        full_body = "\n        ".join(body_items)
        src = f"""// SPDX-License-Identifier: MIT
pragma solidity ^{SOLC_DEFAULT_VERSION};

contract Chisel {{
    {chr(10).join(contract_items)}

    constructor() {{
        {full_body}
    }}
}}"""
        return src, False


def find_encode_call(node: Any) -> Optional[List[str]]:
    """Traverses the solc AST to find argument types passed into abi.encode."""
    if isinstance(node, dict):
        if node.get("nodeType") == "FunctionCall":
            fn = node.get("expression", {})
            if fn.get("memberName") == "encode":
                return [
                    arg.get("typeDescriptions", {}).get("typeString")
                    for arg in node.get("arguments", [])
                ]
        for v in node.values():
            res = find_encode_call(v)
            if res is not None:
                return res
    elif isinstance(node, list):
        for item in node:
            res = find_encode_call(item)
            if res is not None:
                return res
    return None


def type_to_abi(t: Optional[str]) -> str:
    """Normalizes solc AST type string to a canonical ABI type for eth_abi.decode."""
    if not t:
        return "bytes"
    if t.startswith("int_const"):
        try:
            val = int(t.split()[1])
            return "int256" if val < 0 else "uint256"
        except (IndexError, ValueError):
            return "uint256"
    if t.startswith("literal_string") or "string" in t:
        return "string"
    if t.startswith("contract ") or t == "address payable":
        return "address"
    if "bytes memory" in t or "bytes storage" in t:
        return "bytes"
    return t


def _clean_compiler_error(stderr_text: str) -> str:
    """Cleans compiler output by removing boilerplate SPDX and pragma warnings."""
    clean_lines = []
    skip = False
    for line in stderr_text.splitlines():
        if "Warning: SPDX license identifier not provided" in line:
            skip = True
            continue
        if "Warning: Source file does not specify required compiler version" in line:
            skip = True
            continue
        if skip:
            if line.strip().startswith("-->") or not line.strip():
                continue
            skip = False
        clean_lines.append(line)
    return "\n".join(clean_lines).strip()


def _sync_compile_and_execute(code: str, rpc_url: str) -> Dict[str, Any]:
    """Synchronous compilation and EVM simulation runner."""
    ensure_solc_installed(SOLC_DEFAULT_VERSION)
    src, has_expr = prepare_solidity_source(code)

    try:
        compiled = solcx.compile_source(src, output_values=["ast", "bin"])
    except solcx.exceptions.SolcError as e:
        clean_err = _clean_compiler_error(e.stderr_data or e.message)
        return {
            "success": False,
            "error_type": "compilation",
            "error": clean_err,
            "source": src,
        }

    # Find the compiled contract
    contract_key = list(compiled.keys())[-1]
    bytecode_hex = compiled[contract_key]["bin"]
    if not bytecode_hex:
        return {
            "success": False,
            "error_type": "compilation",
            "error": "Compiler generated empty bytecode.",
            "source": src,
        }

    bytecode = "0x" + bytecode_hex
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    # Estimate Gas
    gas_estimate = None
    try:
        gas_estimate = w3.eth.estimate_gas({"data": bytecode})
    except Exception:
        pass

    # Execute via eth_call
    try:
        ret_bytes = w3.eth.call({"data": bytecode})
    except ContractPanicError as e:
        return {
            "success": False,
            "error_type": "panic",
            "error": str(e),
            "gas": gas_estimate,
        }
    except ContractLogicError as e:
        return {
            "success": False,
            "error_type": "revert",
            "error": str(e),
            "gas": gas_estimate,
        }
    except Web3RPCError as e:
        return {
            "success": False,
            "error_type": "rpc_error",
            "error": str(e),
            "gas": gas_estimate,
        }
    except Exception as e:
        return {
            "success": False,
            "error_type": "runtime",
            "error": str(e),
            "gas": gas_estimate,
        }

    # If it was an expression, decode output
    outputs = []
    if has_expr and ret_bytes:
        ast = compiled[contract_key].get("ast", {})
        raw_types = find_encode_call(ast) or []
        abi_types = [type_to_abi(t) for t in raw_types]
        try:
            decoded = abi_decode(abi_types, ret_bytes)
            for t, val in zip(abi_types, decoded):
                outputs.append({"type": t, "value": val})
        except Exception:
            # Fallback raw hex if decode fails
            outputs.append({"type": "bytes", "value": ret_bytes})

    return {
        "success": True,
        "outputs": outputs,
        "gas": gas_estimate,
        "raw_return": ret_bytes.hex() if ret_bytes else "",
        "has_expr": has_expr,
    }


async def run_chisel(code: str, chain: str = "eth") -> Dict[str, Any]:
    """Asynchronously compiles and evaluates Solidity snippets in a sandbox."""
    rpc_url = evm_rpc.get_rpc_url(chain)
    return await asyncio.to_thread(_sync_compile_and_execute, code, rpc_url)


def format_chisel_response(result: Dict[str, Any], query_snippet: str) -> str:
    """Formats the evaluation result into a Foundry Chisel-style Telegram HTML card."""
    div = "───────────────────────────"
    lines = [
        f"⚡ <b>Foundry Chisel REPL</b> (Solidity v{SOLC_DEFAULT_VERSION})",
        div,
    ]

    short_code = query_snippet.strip()
    if len(short_code) > 200:
        short_code = short_code[:197] + "..."
    lines.append(f"<b>Code:</b>\n{code_block(short_code, 'solidity')}")

    if not result.get("success"):
        err_type = result.get("error_type", "error")
        err_msg = result.get("error", "Unknown error")
        if err_type == "compilation":
            lines.append("❌ <b>Compilation Error:</b>")
            lines.append(code_block(err_msg))
        elif err_type in ("panic", "revert"):
            lines.append(f"⚠️ <b>EVM Execution Reverted:</b>")
            lines.append(blockquote(escape_html(err_msg)))
            if result.get("gas"):
                lines.append(f"⛽ <b>Gas Used Before Revert:</b> ~{result['gas']:,}")
        else:
            lines.append("❌ <b>Execution Error:</b>")
            lines.append(blockquote(escape_html(err_msg)))
        return "\n".join(lines)

    outputs = result.get("outputs", [])
    gas = result.get("gas")

    if not outputs:
        lines.append("✅ <b>Execution Succeeded</b> (0 return data)")
        if gas:
            lines.append(f"⛽ <b>Gas:</b> ~{gas:,}")
        return "\n".join(lines)

    lines.append("<b>Evaluation Output:</b>")
    for i, item in enumerate(outputs):
        t = item["type"]
        val = item["value"]

        # Tree formatting like Chisel
        lines.append(f"<b>Type:</b> {inline_code(t)}")

        if isinstance(val, bool):
            lines.append(f"└ <b>Value:</b> {inline_code(str(val).lower())}")
        elif isinstance(val, int):
            lines.append(f"├ <b>Decimal:</b> {inline_code(f'{val:,}')}")
            lines.append(f"├ <b>Hex:</b> {inline_code(hex(val))}")
            if val >= 10**9:
                # Add human readable ETH / Gwei representation if applicable
                if val >= 10**18 and val % (10**15) == 0:
                    lines.append(f"├ <b>ETH:</b> {inline_code(f'{val / 10**18:g} ether')}")
                elif val >= 10**9 and val % (10**6) == 0:
                    lines.append(f"├ <b>Gwei:</b> {inline_code(f'{val / 10**9:g} gwei')}")
            lines.append(f"└ <b>Gas:</b> ~{gas:,}" if gas else "")
        elif isinstance(val, bytes):
            hex_val = "0x" + val.hex()
            lines.append(f"├ <b>Hex:</b> {inline_code(hex_val)}")
            lines.append(f"├ <b>Length:</b> {len(val)} bytes")
            lines.append(f"└ <b>Gas:</b> ~{gas:,}" if gas else "")
        elif isinstance(val, str) and (val.startswith("0x") and len(val) == 42):
            checksum = to_checksum_address(val)
            lines.append(f"├ <b>Address:</b> {inline_code(checksum)}")
            lines.append(f"└ <b>Gas:</b> ~{gas:,}" if gas else "")
        elif isinstance(val, str):
            lines.append(f"├ <b>String:</b> {inline_code(repr(val))}")
            lines.append(f"└ <b>Gas:</b> ~{gas:,}" if gas else "")
        else:
            lines.append(f"├ <b>Value:</b> {inline_code(str(val))}")
            lines.append(f"└ <b>Gas:</b> ~{gas:,}" if gas else "")

        if i < len(outputs) - 1:
            lines.append("")

    return "\n".join(lines).strip()
