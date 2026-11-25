"""Slash command handlers and interactive menu for EVM Swiss Army Knife Telegram bot."""

import logging
from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from eth_utils import is_address
from services.contract_source import fetch_contract_source
from services.decoder import decode_calldata, decode_revert_data
from services.disassembler import disassemble, format_disassembly
from services.evm_crypto import (
    compute_create2_address,
    compute_create_address,
    compute_error_selector,
    compute_mapping_slot,
    compute_selector,
    convert_units,
    hex_to_int256,
    hex_to_uint256,
    int_to_hex256,
    keccak256_hex,
)
from services.gas_tracker import get_gas_metrics
from services.ai_auditor import ask_gemini
from services.proxy_resolver import resolve_proxy
from services.chisel import format_chisel_response, run_chisel
from services.rpc_client import evm_rpc


from services.solidity_docs import (
    get_all_categories,
    search_solidity,
    SOLIDITY_REFERENCE,
)
from services.token_inspector import inspect_token

from utils.formatters import (
    blockquote,
    bold,
    chunk_message,
    code_block,
    escape_html,
    inline_code,
)

logger = logging.getLogger("evm_swiss_knife")
router = Router(name="commands")

DIVIDER = "───────────────────────────"


# =========================================================================
# Interactive Help Menu & Keyboards
# =========================================================================

def get_help_keyboard(current: str = "main") -> InlineKeyboardMarkup:
    """Builds an interactive navigation keyboard for the help menu."""
    buttons = [
        [
            InlineKeyboardButton(text="• 🔍 Calldata & Sigs •" if current == "calldata" else "🔍 Calldata & Sigs", callback_data="help_calldata"),
            InlineKeyboardButton(text="• 🔢 EVM Math •" if current == "math" else "🔢 EVM Math", callback_data="help_math"),
        ],
        [
            InlineKeyboardButton(text="• 📦 Storage & State •" if current == "storage" else "📦 Storage & State", callback_data="help_storage"),
            InlineKeyboardButton(text="• 🏗️ Deployments •" if current == "deploy" else "🏗️ Deployments", callback_data="help_deploy"),
        ],
        [
            InlineKeyboardButton(text="• 🛡️ Proxy Resolver •" if current == "proxy" else "🛡️ Proxy Resolver", callback_data="help_proxy"),
            InlineKeyboardButton(text="• 📜 Contract Source •" if current == "source" else "📜 Contract Source", callback_data="help_source"),
        ],
        [
            InlineKeyboardButton(text="• 🪙 Token Inspector •" if current == "token" else "🪙 Token Inspector", callback_data="help_token"),
            InlineKeyboardButton(text="• ⛽ Gas Tracker •" if current == "gas" else "⛽ Gas Tracker", callback_data="help_gas"),
        ],
        [
            InlineKeyboardButton(text="• 📖 Solidity Docs •" if current == "solidity" else "📖 Solidity Docs", callback_data="help_solidity"),
            InlineKeyboardButton(text="• ⚡ Chisel REPL •" if current == "chisel" else "⚡ Chisel REPL", callback_data="help_chisel"),
        ],
        [
            InlineKeyboardButton(text="• 🤖 AI Auditor •" if current == "ai" else "🤖 AI Auditor", callback_data="help_ai"),
            InlineKeyboardButton(text="• ⚡ Simulation •" if current == "sim" else "⚡ Simulation", callback_data="help_sim"),
        ],
        [
            InlineKeyboardButton(text="• ⚙️ Disassembler •" if current == "disasm" else "⚙️ Disassembler", callback_data="help_disasm"),
            InlineKeyboardButton(text="• 💡 Inline Mode •" if current == "inline" else "💡 Inline Mode", callback_data="help_inline"),
        ],
        [
            InlineKeyboardButton(text="• 🏠 Main Menu •" if current == "main" else "🏠 Main Menu", callback_data="help_main"),
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_help_text(section: str = "main", bot_username: str = "YourBotName") -> str:
    """Returns clean, spacious, and human-readable HTML help text."""
    bot_handle = f"@{escape_html(bot_username.lstrip('@'))}"
    if section == "calldata":
        return (
            "<blockquote><b>🔍 CALLDATA & SIGNATURES</b>\n"
            "Decode arbitrary transaction calldata, compute selectors, and inspect custom errors.</blockquote>\n\n"
            "🔹 <b>/decode &lt;calldata&gt;</b>\n"
            "<i>Resolves 4-byte selector and decodes ABI parameters via OpenChain.</i>\n\n"
            "<b>Example:</b>\n"
            "<code>/decode 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000de0b6b3a7640000</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/hash &lt;signature&gt;</b>\n"
            "<i>Computes the 4-byte selector and full Keccak-256 hash.</i>\n\n"
            "<b>Example:</b>\n"
            "<code>/hash transfer(address,uint256)</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/error &lt;signature&gt;</b>\n"
            "<i>Generates the 4-byte selector for custom Solidity errors.</i>\n\n"
            "<b>Examples:</b>\n"
            "<code>/error Unauthorized()</code>\n"
            "<code>/error InsufficientBalance(uint256,uint256)</code>\n"
        )
    elif section == "math":
        return (
            "<blockquote><b>🔢 EVM MATH & UNIT CONVERSIONS</b>\n"
            "Real-time cryptocurrency unit conversions and 256-bit integer arithmetic.</blockquote>\n\n"
            "🔹 <b>/convert &lt;amount&gt; &lt;unit&gt;</b>\n"
            "<i>Convert seamlessly across Wei, Gwei, Ether, Finney, and Szabo.</i>\n\n"
            "<b>Examples:</b>\n"
            "<code>/convert 1.5 eth</code>\n"
            "<code>/convert 50 gwei</code>\n"
            "<code>/convert 1000000000 wei</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/hex &lt;integer&gt;</b>\n"
            "<i>Converts positive or negative integers into a 256-bit (32-byte) hex word.</i>\n\n"
            "<b>Examples:</b>\n"
            "<code>/hex 12345</code>\n"
            "<code>/hex -1</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/dec &lt;hex_string&gt;</b>\n"
            "<i>Decodes hex into both unsigned uint256 and signed int256.</i>\n\n"
            "<b>Examples:</b>\n"
            "<code>/dec 0x3039</code>\n"
            "<code>/dec 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff</code>\n"
        )
    elif section == "storage":
        return (
            "<blockquote><b>📦 STORAGE & CONTRACT STATE</b>\n"
            "Compute dynamic mapping storage locations and inspect live contract storage.</blockquote>\n\n"
            "🔹 <b>/slot &lt;key&gt; &lt;slot_number&gt; [type]</b>\n"
            "<i>Locates dynamic mapping slot via: keccak256(h(key) . slot)</i>\n"
            "• Supports <code>address</code>, <code>uint256</code>, and <code>bytes32</code> keys.\n\n"
            "<b>Examples:</b>\n"
            "<code>/slot 0xd8da6bf26964af9d7eed9e03e53415d37aa96045 0</code>\n"
            "<code>/slot 1 2 uint256</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/storage &lt;contract&gt; &lt;slot&gt; [chain]</b>\n"
            "<i>Queries eth_getStorageAt and decodes into uint, int, address, bool, string, ASCII.</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Examples:</b>\n"
            "<code>/storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0 eth</code>\n"
            "<code>/storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0 sepolia</code>\n"
        )
    elif section == "deploy":
        return (
            "<blockquote><b>🏗️ COUNTERFACTUAL DEPLOYMENTS</b>\n"
            "Pre-calculate deterministic contract addresses before broadcasting transactions.</blockquote>\n\n"
            "🔹 <b>/create &lt;deployer&gt; &lt;nonce&gt;</b>\n"
            "<i>Standard CREATE: keccak256(rlp([deployer, nonce]))[12:]</i>\n\n"
            "<b>Examples:</b>\n"
            "<code>/create 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 0</code>\n"
            "<code>/create 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 1</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/create2 &lt;deployer&gt; &lt;salt&gt; &lt;init_code_hash&gt;</b>\n"
            "<i>Factory CREATE2: keccak256(0xff ++ deployer ++ salt ++ init_hash)[12:]</i>\n\n"
            "<b>Example (Uniswap V2 DAI/WETH Pair):</b>\n"
            "<code>/create2 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f 0x0 0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f</code>\n"
        )
    elif section == "proxy":
        return (
            "<blockquote><b>🛡️ PROXY IMPLEMENTATION RESOLVER</b>\n"
            "Inspect upgradeable contracts to find the actual logic contract and admin address.</blockquote>\n\n"
            "🔹 <b>/proxy &lt;contract_address&gt; [chain]</b>\n"
            "<i>Checks EIP-1967, EIP-1822 UUPS, Beacon Proxy, and Legacy OpenZeppelin slots.</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example (USDC Proxy on Mainnet):</b>\n"
            "<code>/proxy 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 eth</code>\n\n"
            "<b>Example on Sepolia:</b>\n"
            "<code>/proxy 0xYourProxyContract sepolia</code>\n"
        )
    elif section == "source":
        return (
            "<blockquote><b>📜 ETHERSCAN VERIFIED SOURCE & ABI</b>\n"
            "Fetch contract name, verification status, compiler version, and ABI via Etherscan V2.</blockquote>\n\n"
            "🔹 <b>/source &lt;contract_address&gt; [chain]</b>\n"
            "<i>Retrieves compiler settings, optimization runs, and ABI preview.</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example (WETH on Mainnet):</b>\n"
            "<code>/source 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 eth</code>\n\n"
            "<b>Example on Base:</b>\n"
            "<code>/source 0x4200000000000000000000000000000000000006 base</code>\n"
        )
    elif section == "token":
        return (
            "<blockquote><b>🪙 ERC-20 TOKEN INSPECTOR</b>\n"
            "Inspect token name, symbol, decimals, and circulating total supply in one command.</blockquote>\n\n"
            "🔹 <b>/token &lt;token_address&gt; [chain]</b>\n"
            "<i>Queries name(), symbol(), decimals(), and totalSupply() via dry-run simulation.</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example (DAI Stablecoin on Mainnet):</b>\n"
            "<code>/token 0x6B175474E89094C44Da98b954EedeAC495271d0F eth</code>\n\n"
            "<b>Example on Base:</b>\n"
            "<code>/token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 base</code>\n"
        )
    elif section == "gas":
        return (
            "<blockquote><b>⛽ LIVE GAS & BLOB FEE TRACKER</b>\n"
            "Check real-time base fees, recommended priority fees, and EIP-4844 blob gas.</blockquote>\n\n"
            "🔹 <b>/gas [chain]</b>\n"
            "<i>Displays block utilization, base fee in Gwei, and Slow/Avg/Fast tiers.</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Examples:</b>\n"
            "<code>/gas eth</code>\n"
            "<code>/gas base</code>\n"
            "<code>/gas sepolia</code>\n"
        )
    elif section == "sim":
        return (
            "<blockquote><b>⚡ SIMULATION & REVERTS</b>\n"
            "Diagnose failed transactions, decode revert reasons, and dry-run calls without spending gas.</blockquote>\n\n"
            "🔹 <b>/revert &lt;tx_hash&gt; [chain]</b>\n"
            "<i>Re-simulates failed tx to extract revert reason (Panic, Error, or Custom Error).</i>\n"
            "• Supported Chains: <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/revert 0xYourFailedTxHash sepolia</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>/call &lt;to&gt; &lt;calldata&gt; [chain]</b>\n"
            "<i>Executes a read-only simulation via eth_call (no gas spent).</i>\n\n"
            "<b>Example (calling WETH name()):</b>\n"
            "<code>/call 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0x06fdde03 eth</code>\n"
        )
    elif section == "solidity":
        return (
            "<blockquote><b>📖 SOLIDITY & FOUNDRY AUDITOR REFERENCE</b>\n"
            "Instant documentation, syntax, security gotchas, and copyable code examples for Solidity globals and Foundry cheatcodes.</blockquote>\n\n"
            "🔹 <b>/sol &lt;function_or_keyword&gt;</b>\n"
            "<i>Searches Solidity globals, special functions, and Foundry cheatcodes.</i>\n\n"
            "<b>Popular Reference Topics:</b>\n"
            "• <code>/sol gasleft</code> (or <code>/sol gas.left</code>) — Remaining EVM gas\n"
            "• <code>/sol receive</code> — Plain Ether receiver\n"
            "• <code>/sol fallback</code> — Proxy fallback function pattern\n"
            "• <code>/sol msg.sender</code> — Caller vs tx.origin security\n"
            "• <code>/sol encodePacked</code> — Hash collision vulnerability\n"
            "• <code>/sol delegatecall</code> — Context execution & proxy risks\n"
            "• <code>/sol ecrecover</code> — Signature recovery & malleability\n"
            "• <code>/sol vm.prank</code> — Spoof msg.sender in Foundry tests\n"
            "• <code>/sol vm.warp</code> — Time travel / timestamp manipulation\n"
            "• <code>/sol vm.expectRevert</code> — Assert custom errors or reverts\n"
            "• <code>/sol tstore</code> — Cancun EIP-1153 transient storage\n\n"
            f"{DIVIDER}\n\n"
            "💡 <b>Inline Search Anywhere:</b>\n"
            f"<code>{bot_handle} sol gasleft</code>\n"
            f"<code>{bot_handle} sol vm.prank</code>"
        )
    elif section == "chisel":
        return (
            "<blockquote><b>⚡ FOUNDRY CHISEL SOLIDITY REPL</b>\n"
            "Fast, local Solidity REPL powered by solc v0.8.26 and real-time EVM state simulation (eth_call). Test any Solidity expression, math, hash, or logic instantly.</blockquote>\n\n"
            "🔹 <b>/chisel &lt;expression_or_code&gt;</b> (Aliases: /eval, /solc)\n"
            "<i>Evaluates Solidity expressions, functions, contracts, or assembly blocks.</i>\n\n"
            "<b>Quick Examples:</b>\n"
            "• <code>/chisel 1 ether / 1 gwei</code> — Unit math\n"
            "• <code>/chisel type(uint256).max</code> — Max integer value\n"
            "• <code>/chisel keccak256(bytes(\"hello\"))</code> — Keccak hash\n"
            "• <code>/chisel uint256 a = 10; uint256 b = 20; a * b</code> — Multi-line script\n"
            "• <code>/chisel abi.encodeWithSignature(\"transfer(address,uint256)\", 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 100)</code> — ABI encoding\n"
            "• <code>/chisel function double(uint x) internal pure returns (uint) { return x * 2; } double(21)</code> — Custom functions\n"
            "• <code>/chisel 1 + 1 == 2</code> — Boolean expressions\n\n"
            f"{DIVIDER}\n\n"
            "💡 <b>Inline Evaluation Anywhere:</b>\n"
            f"<code>{bot_handle} chisel 1 ether / 1 gwei</code>\n"
            f"<code>{bot_handle} chisel type(uint256).max</code>"
        )
    elif section == "ai":
        return (
            "<blockquote><b>🤖 WEB3 & SMART CONTRACT AI AUDITOR</b>\n"
            "Powered by Google Gemini 3.8 Flash. Instant smart contract security auditing, vulnerability triage, EVM internal analysis, and exploit explanations.</blockquote>\n\n"
            "🔹 <b>/ask &lt;question_or_code&gt;</b> (Aliases: <code>/ai</code>, <code>/audit</code>)\n"
            "<i>Ask any question or provide a Solidity contract snippet for an instant audit.</i>\n\n"
            "<b>Quick Examples:</b>\n"
            "• <code>/ask what is reentrancy and how to prevent it?</code>\n"
            "• <code>/ask difference between call, delegatecall, and staticcall</code>\n"
            "• <code>/ask how does ERC-4626 vault inflation attack work?</code>\n"
            "• <code>/ask explain Cancun EIP-1153 transient storage tstore/tload</code>\n\n"
            f"{DIVIDER}\n\n"
            "💬 <b>Reply to Any Message:</b>\n"
            "<i>You can reply to any failed transaction, /revert output, or code snippet with <code>/ask why did this happen?</code> for instant contextual diagnosis!</i>\n\n"
            f"{DIVIDER}\n\n"
            "💡 <b>Inline AI Query Anywhere:</b>\n"
            f"<code>{bot_handle} ask what is an oracle manipulation attack?</code>"
        )
    elif section == "disasm":
        return (
            "<blockquote><b>⚙️ EVM BYTECODE DISASSEMBLER</b>\n"
            "Convert raw runtime or creation bytecode into clean, sequential EVM opcodes.</blockquote>\n\n"
            "🔹 <b>/disasm &lt;hex_bytecode&gt;</b>\n"
            "<i>Parses opcodes with PC offsets, immediate operands (PUSH1..PUSH32), Cancun opcodes (PUSH0, MCOPY, TLOAD, TSTORE), and JUMPDEST count.</i>\n\n"
            "<b>Example (standard contract preamble):</b>\n"
            "<code>/disasm 6080604052348015600f57600080fd5b50</code>\n"
        )
    elif section == "inline":
        return (
            "<blockquote><b>💡 TELEGRAM INLINE QUERIES</b>\n"
            "Use your bot inside ANY chat, group, or DM without inviting it! Just type:\n"
            f"<code>{bot_handle} &lt;query&gt;</code></blockquote>\n\n"
            "🔹 <b>AI Web3 Auditor</b>\n"
            f"<code>{bot_handle} ask what is flash loan price manipulation?</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Foundry Chisel Live Evaluator</b>\n"
            f"<code>{bot_handle} chisel 1 ether / 1 gwei</code>\n"
            f"<code>{bot_handle} chisel type(uint256).max</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Solidity Reference Lookup</b>\n"
            f"<code>{bot_handle} sol receive</code>\n"
            f"<code>{bot_handle} sol delegatecall</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>4-Byte Selector Lookup</b>\n"
            f"<code>{bot_handle} 0xa9059cbb</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Function Keccak & Selector</b>\n"
            f"<code>{bot_handle} transfer(address,uint256)</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Unit Conversions</b>\n"
            f"<code>{bot_handle} 2.5 eth</code>\n"
            f"<code>{bot_handle} 50 gwei</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Hex & Decimal Numbers</b>\n"
            f"<code>{bot_handle} 0xff</code>\n"
            f"<code>{bot_handle} 1000</code>\n\n"
            f"{DIVIDER}\n\n"
            "🔹 <b>Mapping Slot Math</b>\n"
            f"<code>{bot_handle} slot 0xd8da6b... 0</code>\n"
        )
    else:
        # Main Overview Menu
        return (
            "<blockquote><b>🛡️ EVM SWISS ARMY KNIFE</b>\n"
            "Smart Contract Security, Auditing & State Diagnostics\n"
            "Networks: <b>Ethereum</b> • <b>Sepolia</b> • <b>Base</b> • <b>Base Sepolia</b></blockquote>\n\n"
            "Tap any command or click a category button below:\n\n"
            "🤖 <b>AI Smart Contract Auditor</b>\n"
            "• /ask — Ask Web3 security, Solidity & EVM questions (Gemini)\n\n"
            "🔍 <b>Signatures & Calldata</b>\n"
            "• /decode — Resolve 4-byte selector & parameters\n"
            "• /hash — Compute Keccak-256 & 4-byte selector\n"
            "• /error — Calculate custom error 4-byte selector\n\n"
            "🔢 <b>EVM Math & Units</b>\n"
            "• /convert — Convert across Wei, Gwei, and Ether\n"
            "• /hex — Integer to 256-bit hex word\n"
            "• /dec — Hex to uint256 & signed int256\n\n"
            "📦 <b>State & Storage</b>\n"
            "• /slot — Dynamic mapping slot locator\n"
            "• /storage — Read & decode live 32-byte slot\n\n"
            "🛡️ <b>Auditor & Developer Essentials</b>\n"
            "• /chisel — Foundry Solidity REPL & expression evaluator\n"
            "• /sol — Search Solidity special functions & docs\n"
            "• /proxy — Resolve proxy logic contract & admin\n"
            "• /source — Fetch Etherscan verification & ABI\n"
            "• /token — Inspect ERC-20 symbol, decimals & supply\n"
            "• /gas — Live gas fees & priority tiers\n\n"
            "🏗️ <b>Deployments</b>\n"
            "• /create — Deterministic CREATE address\n"
            "• /create2 — Counterfactual CREATE2 address\n\n"
            "⚡ <b>Simulation & Diagnostics</b>\n"
            "• /revert — Diagnose failed tx & extract error\n"
            "• /call — Dry-run read-only <code>eth_call</code>\n\n"
            "⚙️ <b>Bytecode Analysis</b>\n"
            "• /disasm — Disassemble bytecode to opcodes\n\n"
            f"{DIVIDER}\n\n"
            "👇 <i>Select a category below to view copyable examples:</i>"
        )



@router.message(CommandStart())
@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    """Displays the comprehensive interactive help menu."""
    bot_username = getattr(message.bot, "_cached_username", None) or "YourBotName"
    text = get_help_text("main", bot_username=bot_username)
    keyboard = get_help_keyboard("main")
    await message.answer(text, parse_mode="HTML", reply_markup=keyboard, disable_web_page_preview=True)


@router.callback_query(F.data.startswith("help_"))
async def cb_help_navigation(callback: CallbackQuery) -> None:
    """Handles category navigation clicks inside the interactive help menu."""
    section = callback.data.replace("help_", "")
    bot_username = getattr(callback.bot, "_cached_username", None) or "YourBotName"
    text = get_help_text(section, bot_username=bot_username)
    keyboard = get_help_keyboard(section)
    try:
        await callback.message.edit_text(text, parse_mode="HTML", reply_markup=keyboard, disable_web_page_preview=True)
    except Exception as exc:
        if "message is not modified" not in str(exc).lower():
            logger.error("Failed to edit help menu: %s", exc)
    await callback.answer()


# =========================================================================
# 1. Signatures & Calldata Decoding
# =========================================================================

@router.message(Command("decode"))
async def cmd_decode(message: Message) -> None:
    """Decodes calldata and attempts 4-byte selector resolution."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        example = "/decode 0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa960450000000000000000000000000000000000000000000000000de0b6b3a7640000"
        await message.answer(
            "<blockquote><b>⚠️ Usage: /decode &lt;calldata&gt;</b>\n"
            "Extracts 4-byte selector & decodes ABI parameters via OpenChain.</blockquote>\n\n"
            "💡 <b>Example:</b>\n"
            f"<code>{example}</code>",
            parse_mode="HTML",
        )
        return

    calldata = parts[1].strip()
    status_msg = await message.answer("🔄 <i>Querying OpenChain & 4byte databases...</i>", parse_mode="HTML")

    try:
        res = await decode_calldata(calldata)
        if not res["success"]:
            await status_msg.edit_text(f"❌ <b>Error:</b> {escape_html(res.get('error', 'Failed to decode'))}", parse_mode="HTML")
            return

        selector = res["selector"]
        signatures = res["signatures"]
        decoded_matches = res["decoded_matches"]

        lines = [
            "<blockquote><b>💎 CALLDATA DECODER REPORT</b></blockquote>",
            f"🎯 <b>Selector:</b> <code>{selector}</code>",
            f"📏 <b>Payload Size:</b> <code>{res['args_bytes_len']}</code> bytes\n",
        ]

        if signatures:
            lines.append("📋 <b>Verified Function Signatures:</b>")
            for sig in signatures[:5]:
                lines.append(f"• <code>{escape_html(sig)}</code>")
            lines.append("")
        else:
            lines.append("⚠️ <i>No verified signature found in OpenChain / 4byte.</i>\n")

        success_matches = [m for m in decoded_matches if m.get("success")]
        if success_matches:
            best = success_matches[0]
            lines.append(f"✅ <b>Decoded Function:</b> <b>{escape_html(best['function_name'])}</b>")
            if best["params"]:
                lines.append("\n<b>Parameters:</b>")
                for p in best["params"]:
                    lines.append(f"• <code>{escape_html(p['type'])}</code>: <code>{escape_html(p['value'])}</code>")
            else:
                lines.append("<i>(Function takes zero arguments)</i>")
        elif res["raw_words"]:
            lines.append("\n📦 <b>Raw 32-Byte Stack Words:</b>")
            lines.append(code_block("\n".join(res["raw_words"][:8])))

        final_text = "\n".join(lines)
        chunks = chunk_message(final_text)
        await status_msg.edit_text(chunks[0], parse_mode="HTML")
        for extra in chunks[1:]:
            await message.answer(extra, parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Decoding error:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("hash"))
async def cmd_hash(message: Message) -> None:
    """Calculates Keccak-256 and returns the 4-byte selector."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /hash &lt;signature&gt;</b>\n"
            "Calculates the 4-byte selector and full Keccak-256 hash.</blockquote>\n\n"
            "💡 <b>Example:</b>\n"
            "<code>/hash transfer(address,uint256)</code>",
            parse_mode="HTML",
        )
        return

    sig = parts[1].strip()
    selector = compute_selector(sig)
    full_hash = keccak256_hex(sig.encode("utf-8"))

    text = (
        "<blockquote><b>🔐 KECCAK-256 & 4-BYTE SELECTOR</b></blockquote>\n"
        f"• <b>Input Signature:</b> <code>{escape_html(sig)}</code>\n"
        f"• <b>4-Byte Selector:</b> <code>{selector}</code>\n\n"
        f"💎 <b>Full Keccak-256 Hash:</b>\n{code_block(full_hash)}"
    )
    await message.answer(text, parse_mode="HTML")


@router.message(Command("error"))
async def cmd_error(message: Message) -> None:
    """Calculates 4-byte selector for custom Solidity error."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /error &lt;error_signature&gt;</b>\n"
            "Calculates the 4-byte selector for custom Solidity errors.</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/error Unauthorized()</code>\n"
            "<code>/error InsufficientBalance(uint256,uint256)</code>",
            parse_mode="HTML",
        )
        return

    err_sig = parts[1].strip()
    selector = compute_error_selector(err_sig)
    full_hash = keccak256_hex(err_sig.encode("utf-8"))

    text = (
        "<blockquote><b>🚨 SOLIDITY CUSTOM ERROR SELECTOR</b></blockquote>\n"
        f"• <b>Error Signature:</b> <code>{escape_html(err_sig)}</code>\n"
        f"• <b>4-Byte Selector:</b> <code>{selector}</code>\n\n"
        f"💎 <b>Full Hash:</b>\n{code_block(full_hash)}"
    )
    await message.answer(text, parse_mode="HTML")


# =========================================================================
# 2. EVM Math & Unit Conversions
# =========================================================================

@router.message(Command("convert"))
async def cmd_convert(message: Message) -> None:
    """Converts across EVM units: Wei, Gwei, Ether."""
    parts = (message.text or "").strip().split()
    if len(parts) < 3:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /convert &lt;amount&gt; &lt;unit&gt;</b>\n"
            "Converts across Wei, Gwei, Ether, Finney, and Szabo.</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/convert 1.5 eth</code>\n"
            "<code>/convert 50 gwei</code>\n"
            "<code>/convert 1000000000 wei</code>",
            parse_mode="HTML",
        )
        return

    amount, unit = parts[1], parts[2]
    try:
        conv = convert_units(amount, unit)
        text = (
            "<blockquote><b>🔄 EVM UNIT CONVERSION</b></blockquote>\n"
            f"Input: <code>{conv['input_amount']}</code> <b>{escape_html(conv['input_unit'])}</b>\n\n"
            f"🔹 <b>Wei:</b>  <code>{conv['wei']}</code>\n"
            f"    <i>(raw: <code>{conv['wei_raw']}</code>)</i>\n\n"
            f"🔹 <b>Gwei:</b> <code>{conv['gwei']}</code>\n\n"
            f"🔹 <b>Ether:</b> <code>{conv['ether']}</code>"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>Conversion failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("hex"))
async def cmd_hex(message: Message) -> None:
    """Converts integer into 256-bit hex word."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /hex &lt;integer&gt;</b>\n"
            "Converts positive or negative integers into a 256-bit hex word.</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/hex 12345</code>\n"
            "<code>/hex -1</code>",
            parse_mode="HTML",
        )
        return

    try:
        val = int(parts[1].strip(), 10)
        hex_word = int_to_hex256(val)
        hex_compact = hex(val) if val >= 0 else hex_word
        text = (
            "<blockquote><b>🔢 DECIMAL TO 256-BIT HEX</b></blockquote>\n"
            f"• <b>Decimal:</b> <code>{val}</code>\n"
            f"• <b>Compact Hex:</b> <code>{hex_compact}</code>\n\n"
            f"📦 <b>256-bit Padded Word:</b>\n{code_block(hex_word)}"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>Invalid integer:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("dec"))
async def cmd_dec(message: Message) -> None:
    """Converts hex word into unsigned uint256 and signed int256."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /dec &lt;hex_string&gt;</b>\n"
            "Decodes hex into both unsigned uint256 and signed int256.</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/dec 0x3039</code>\n"
            "<code>/dec 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff</code>",
            parse_mode="HTML",
        )
        return

    hex_str = parts[1].strip()
    try:
        uint_val = hex_to_uint256(hex_str)
        int_val = hex_to_int256(hex_str)
        text = (
            "<blockquote><b>🔢 HEX TO DECIMAL RESOLVER</b></blockquote>\n"
            f"• <b>Hex Input:</b> <code>{escape_html(hex_str)}</code>\n\n"
            f"🔹 <b>uint256 (unsigned):</b>\n{code_block(str(uint_val))}\n"
            f"🔹 <b>int256 (signed 2's complement):</b>\n{code_block(str(int_val))}"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>Conversion failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 3. Storage & Mapping Resolvers
# =========================================================================

@router.message(Command("slot"))
async def cmd_slot(message: Message) -> None:
    """Computes dynamic mapping storage slot location."""
    parts = (message.text or "").strip().split()
    if len(parts) < 3:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /slot &lt;key&gt; &lt;slot_number&gt; [type]</b>\n"
            "Locates dynamic mapping slot via: keccak256(h(key) . slot)</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/slot 0xd8da6bf26964af9d7eed9e03e53415d37aa96045 0</code>\n"
            "<code>/slot 1 2 uint256</code>",
            parse_mode="HTML",
        )
        return

    key = parts[1]
    try:
        slot = int(parts[2], 0)
    except ValueError:
        await message.answer("❌ Slot number must be a valid integer or hex", parse_mode="HTML")
        return

    key_type = parts[3] if len(parts) > 3 else "auto"

    try:
        info = compute_mapping_slot(key, slot, key_type=key_type)
        text = (
            "<blockquote><b>📦 MAPPING STORAGE SLOT LOCATOR</b>\n"
            "Formula: <code>keccak256(h(key) . slot)</code></blockquote>\n"
            f"• <b>Key:</b> <code>{escape_html(info['key_display'])}</code> (type: <code>{info['key_type']}</code>)\n"
            f"• <b>Declaration Slot:</b> <code>{info['base_slot']}</code>\n\n"
            f"📍 <b>Calculated Storage Slot (Hex):</b>\n{code_block(info['slot_hex'])}\n"
            f"📍 <b>Slot Offset (Decimal):</b>\n<code>{info['slot_int']}</code>\n\n"
            f"🔍 <b>Preimage (Key . Slot):</b>\n{code_block(info['preimage_hex'])}"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>Calculation failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("storage"))
async def cmd_storage(message: Message) -> None:
    """Queries contract storage slot via eth_getStorageAt and decodes it."""
    parts = (message.text or "").strip().split()
    if len(parts) < 3:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /storage &lt;contract&gt; &lt;slot&gt; [chain]</b>\n"
            "Queries eth_getStorageAt and decodes the 32-byte word into all types.</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Examples:</b>\n"
            "<code>/storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0 eth</code>\n"
            "<code>/storage 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0 sepolia</code>",
            parse_mode="HTML",
        )
        return

    addr, slot_input = parts[1], parts[2]
    chain = parts[3] if len(parts) > 3 else "eth"

    if not is_address(addr):
        await message.answer("❌ Invalid contract address", parse_mode="HTML")
        return

    status_msg = await message.answer(f"🔄 <i>Reading storage slot from {escape_html(chain.upper())} RPC...</i>", parse_mode="HTML")

    try:
        slot_bytes = await evm_rpc.get_storage_at(addr, slot_input, chain=chain)
        decoded = evm_rpc.decode_storage_word(slot_bytes)

        lines = [
            f"<blockquote><b>📦 STORAGE INSPECTOR ({escape_html(chain.upper())})</b></blockquote>",
            f"• <b>Contract:</b> <code>{escape_html(addr)}</code>",
            f"• <b>Slot Index:</b> <code>{escape_html(slot_input)}</code>\n",
            "📦 <b>Raw 32-Byte Storage Word:</b>",
            code_block(decoded["raw_hex"]),
            f"🔹 <b>uint256:</b> <code>{decoded['uint256']}</code>",
            f"🔹 <b>int256:</b>  <code>{decoded['int256']}</code>",
        ]

        if decoded["is_clean_address"]:
            lines.append(f"🏷️ <b>Checksum Address:</b> <code>{decoded['address']}</code>")

        if decoded["bool"] is not None:
            bool_badge = "🟢 True (0x01)" if decoded["bool"] else "🔴 False (0x00)"
            lines.append(f"🔘 <b>Boolean Flag:</b> {bool_badge}")

        if decoded["short_string"]:
            lines.append(f"📜 <b>Solidity Short String:</b> <code>{escape_html(decoded['short_string'])}</code>")

        lines.append(f"🔎 <b>ASCII Preview:</b> <code>{escape_html(decoded['ascii_preview'])}</code>")

        await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Failed to query storage:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 4. Auditor Essentials: Proxy, Source, Gas, Token (New!)
# =========================================================================

@router.message(Command("proxy"))
async def cmd_proxy(message: Message) -> None:
    """Inspects a contract to detect upgradeable proxies and resolve logic contracts."""
    parts = (message.text or "").strip().split()
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /proxy &lt;contract_address&gt; [chain]</b>\n"
            "Checks EIP-1967, EIP-1822 UUPS, Beacon, and Legacy OpenZeppelin proxy slots.</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example (USDC Proxy on Mainnet):</b>\n"
            "<code>/proxy 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 eth</code>",
            parse_mode="HTML",
        )
        return

    contract_addr = parts[1]
    chain = parts[2] if len(parts) > 2 else "eth"

    if not is_address(contract_addr):
        await message.answer("❌ <b>Error:</b> Invalid contract address. Please provide a valid 20-byte hex address (0x...).", parse_mode="HTML")
        return

    status_msg = await message.answer(f"🔍 <i>Inspecting proxy slots on {escape_html(chain.upper())}...</i>", parse_mode="HTML")

    try:
        info = await resolve_proxy(contract_addr, chain=chain)
        lines = [
            f"<blockquote><b>🛡️ PROXY IMPLEMENTATION RESOLVER ({escape_html(chain.upper())})</b>\n"
            f"Status: <b>{escape_html(info['proxy_type'])}</b></blockquote>\n",
            f"• <b>Contract:</b> <code>{escape_html(info['contract_address'])}</code>",
        ]

        if info["is_proxy"]:
            if info.get("implementation"):
                lines.append(f"\n📍 <b>Logic Implementation:</b>\n{code_block(info['implementation'])}")
            if info.get("admin"):
                lines.append(f"👑 <b>Proxy Admin:</b> <code>{info['admin']}</code>")
            if info.get("beacon"):
                lines.append(f"📡 <b>Beacon Contract:</b> <code>{info['beacon']}</code>")
            if info.get("slot_used"):
                lines.append(f"\n🔍 <i>Slot matched: <code>{info['slot_used']}</code></i>")
        else:
            lines.append(f"\n{DIVIDER}\nℹ️ <i>No standard EIP-1967, EIP-1822, Beacon, or OpenZeppelin proxy slots detected. Contract is likely a direct implementation.</i>")

        await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Proxy resolution failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("source"))
async def cmd_source(message: Message) -> None:
    """Fetches contract verification status, compiler version, and ABI via Etherscan V2."""
    parts = (message.text or "").strip().split()
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /source &lt;contract_address&gt; [chain]</b>\n"
            "Retrieves verified source metadata, compiler settings, and ABI preview via Etherscan V2.</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/source 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 eth</code>",
            parse_mode="HTML",
        )
        return

    contract_addr = parts[1]
    chain = parts[2] if len(parts) > 2 else "eth"

    if not is_address(contract_addr):
        await message.answer("❌ <b>Error:</b> Invalid contract address. Please provide a valid 20-byte hex address (0x...).", parse_mode="HTML")
        return

    status_msg = await message.answer(f"🔍 <i>Querying Etherscan V2 for {escape_html(chain.upper())}...</i>", parse_mode="HTML")

    try:
        info = await fetch_contract_source(contract_addr, chain=chain)
        if not info.get("success"):
            await status_msg.edit_text(f"❌ <b>Failed:</b> {escape_html(str(info.get('error')))}", parse_mode="HTML")
            return

        verified_badge = "✅ Verified" if info["is_verified"] else "❌ Unverified"
        lines = [
            f"<blockquote><b>📜 CONTRACT VERIFICATION ({escape_html(info['chain'])})</b>\n"
            f"<b>{escape_html(info['contract_name'])}</b> • {verified_badge}</blockquote>\n",
            f"• <b>Address:</b> <code>{escape_html(info['address'])}</code>",
        ]

        if info["is_verified"]:
            lines.extend([
                f"• <b>Compiler:</b> <code>{escape_html(info['compiler_version'])}</code>",
                f"• <b>Optimization:</b> {info['optimization_used']} (Runs: {info['runs']})",
                f"• <b>EVM Version:</b> <code>{escape_html(info['evm_version'])}</code>",
            ])
            if info.get("license_type"):
                lines.append(f"• <b>License:</b> <code>{escape_html(info['license_type'])}</code>")
            if info.get("is_proxy") and info.get("implementation"):
                lines.append(f"• <b>Proxy Implementation:</b> <code>{info['implementation']}</code>")
            if info.get("raw_abi_snippet"):
                lines.append(f"\n{DIVIDER}\n📄 <b>ABI Preview:</b>")
                lines.append(code_block(info["raw_abi_snippet"] + "..."))
        else:
            lines.append(f"\n{DIVIDER}\n⚠️ <i>Source code is not verified on the block explorer for {escape_html(info['chain'])}.</i>")

        await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Explorer query error:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("token"))
async def cmd_token(message: Message) -> None:
    """Inspects an ERC-20 token contract to retrieve name, symbol, decimals, and supply."""
    parts = (message.text or "").strip().split()
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /token &lt;token_address&gt; [chain]</b>\n"
            "Retrieves ERC-20 token name, symbol, decimals, and circulating supply.</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example (DAI Stablecoin on Mainnet):</b>\n"
            "<code>/token 0x6B175474E89094C44Da98b954EedeAC495271d0F eth</code>",
            parse_mode="HTML",
        )
        return

    token_addr = parts[1]
    chain = parts[2] if len(parts) > 2 else "eth"

    if not is_address(token_addr):
        await message.answer("❌ <b>Error:</b> Invalid token address. Please provide a valid 20-byte hex address (0x...).", parse_mode="HTML")
        return

    status_msg = await message.answer(f"🔍 <i>Inspecting ERC-20 token on {escape_html(chain.upper())}...</i>", parse_mode="HTML")

    try:
        info = await inspect_token(token_addr, chain=chain)
        lines = [
            f"<blockquote><b>🪙 ERC-20 TOKEN METRICS ({escape_html(info['chain'])})</b>\n"
            f"<b>{escape_html(info['name'])} ({escape_html(info['symbol'])})</b></blockquote>\n",
            f"• <b>Contract:</b> <code>{escape_html(info['address'])}</code>",
            f"• <b>Decimals:</b> <code>{info['decimals']}</code>\n",
            f"{DIVIDER}\n",
            f"🔹 <b>Circulating Supply:</b>\n"
            f"<code>{info['total_supply_formatted']} {escape_html(info['symbol'])}</code>\n",
            f"<i>Raw Base Units: <code>{info['total_supply_raw']}</code></i>",
        ]
        await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Token inspection error:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("gas"))
async def cmd_gas(message: Message) -> None:
    """Checks live gas prices, base fees, and priority tiers."""
    parts = (message.text or "").strip().split()
    chain = parts[1] if len(parts) > 1 else "eth"

    status_msg = await message.answer(f"🔄 <i>Fetching live gas metrics for {escape_html(chain.upper())}...</i>", parse_mode="HTML")

    try:
        metrics = await get_gas_metrics(chain=chain)
        lines = [
            f"<blockquote><b>⛽ LIVE GAS TRACKER ({escape_html(metrics['chain'])})</b>\n"
            f"Block #{metrics['block_number']} • Utilization: {metrics['block_utilization_pct']}</blockquote>\n",
            f"🔹 <b>Base Fee:</b> <code>{metrics['base_fee_gwei']} Gwei</code>",
            f"🔹 <b>Current Gas Price:</b> <code>{metrics['current_gas_price_gwei']} Gwei</code>\n",
            f"{DIVIDER}\n",
            "<b>Recommended Priority Tiers:</b>\n",
            f"• 🐢 <b>Slow:</b>     <code>{metrics['slow_gwei']} Gwei</code>",
            f"• 🚗 <b>Standard:</b> <code>{metrics['avg_gwei']} Gwei</code>",
            f"• 🚀 <b>Fast:</b>     <code>{metrics['fast_gwei']} Gwei</code>",
        ]

        if metrics.get("blob_gwei") is not None:
            lines.append(f"\n\n🔹 <b>Blob Gas Price:</b> <code>{metrics['blob_gwei']} Gwei</code>")

        await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Failed to fetch gas metrics:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("sol", "solidity", "fn"))
async def cmd_solidity(message: Message) -> None:
    """Searches Solidity special functions, globals, and built-ins."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        # Show cheatsheet overview with categories
        cats = get_all_categories()
        cat_lines = []
        for cat_name, items in cats.items():
            sample_names = ", ".join([f"<code>{escape_html(item['name'])}</code>" for item in items[:3]])
            cat_lines.append(f"• <b>{escape_html(cat_name)}:</b>\n  └ {sample_names}")

        await message.answer(
            "<blockquote><b>📖 SOLIDITY & FOUNDRY AUDITOR REFERENCE</b>\n"
            "Search special functions, globals, variables & Foundry cheatcodes.</blockquote>\n\n"
            "🔹 <b>Usage:</b> <code>/sol &lt;function_or_keyword&gt;</code>\n\n"
            "💡 <b>Popular Searches:</b>\n"
            "• <code>/sol gasleft</code> (or <code>/sol gas.left</code>) — Remaining EVM gas\n"
            "• <code>/sol vm.prank</code> — Spoof msg.sender in Foundry\n"
            "• <code>/sol vm.warp</code> — Manipulate block.timestamp\n"
            "• <code>/sol vm.deal</code> — Fund test accounts with Ether\n"
            "• <code>/sol vm.expectRevert</code> — Assert reverts & custom errors\n"
            "• <code>/sol receive</code> — Plain Ether receiver\n"
            "• <code>/sol fallback</code> — Proxy fallback patterns\n"
            "• <code>/sol msg.sender</code> — Caller vs tx.origin security\n"
            "• <code>/sol encodePacked</code> — Hash collision vulnerability\n"
            "• <code>/sol delegatecall</code> — Context execution & proxy risks\n"
            "• <code>/sol ecrecover</code> — Signature recovery & malleability\n"
            "• <code>/sol tstore</code> — Cancun EIP-1153 transient storage\n\n"
            f"{DIVIDER}\n\n"
            "📚 <b>Reference Categories:</b>\n" + "\n\n".join(cat_lines),
            parse_mode="HTML",
        )
        return

    query = parts[1].strip()
    result = search_solidity(query)

    if result["found"] and result["item"]:
        item = result["item"]
        lines = [
            f"<blockquote><b>📖 SOLIDITY REFERENCE • {escape_html(item['category'])}</b>\n"
            f"<b>{escape_html(item['name'])}</b></blockquote>\n",
            "🔹 <b>Syntax:</b>",
            code_block(item["syntax"], language="solidity"),
            "\n🔹 <b>Description:</b>",
            f"<i>{escape_html(item['description'])}</i>\n",
            f"{DIVIDER}\n",
            "⚠️ <b>Auditor Notes & Gotchas:</b>",
            escape_html(item["auditor_notes"]),
            f"\n\n{DIVIDER}\n",
            "💡 <b>Solidity Example:</b>",
            code_block(item["example"], language="solidity"),
            f"\n{DIVIDER}\n",
            f"🔍 <i>Search another: <code>/sol &lt;keyword&gt;</code></i>",
        ]
        await message.answer("\n".join(lines), parse_mode="HTML")
        return

    # No exact match: show suggestions
    suggestions = result.get("suggestions", [])
    if suggestions:
        sugg_list = "\n".join([f"• <code>/sol {escape_html(s)}</code>" for s in suggestions])
        await message.answer(
            f"<blockquote><b>🔍 SOLIDITY SEARCH: {escape_html(query)}</b>\n"
            f"No exact match found. Did you mean one of these?</blockquote>\n\n"
            f"{sugg_list}\n\n"
            f"💡 <i>Tip: Send <code>/sol</code> without parameters to browse all categories.</i>",
            parse_mode="HTML",
        )
    else:
        await message.answer(
            f"<blockquote><b>❌ No Results Found</b>\n"
            f"Could not find any Solidity built-ins matching '<code>{escape_html(query)}</code>'.</blockquote>\n\n"
            f"💡 <i>Send <code>/sol</code> to view all available categories and popular functions.</i>",
            parse_mode="HTML",
        )


# =========================================================================
# 5. Counterfactual Address Derivation
# =========================================================================

@router.message(Command("create"))
async def cmd_create(message: Message) -> None:
    """Computes deterministic address via CREATE."""
    parts = (message.text or "").strip().split()
    if len(parts) < 3:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /create &lt;deployer&gt; &lt;nonce&gt;</b>\n"
            "Calculates deterministic address: keccak256(rlp([deployer, nonce]))[12:]</blockquote>\n\n"
            "💡 <b>Examples:</b>\n"
            "<code>/create 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 0</code>\n"
            "<code>/create 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 1</code>",
            parse_mode="HTML",
        )
        return

    deployer, nonce_str = parts[1], parts[2]
    try:
        nonce = int(nonce_str, 0)
        derived = compute_create_address(deployer, nonce)
        text = (
            "<blockquote><b>🏗️ CREATE DETERMINISTIC ADDRESS</b>\n"
            "Formula: <code>keccak256(rlp([deployer, nonce]))[12:]</code></blockquote>\n"
            f"• <b>Deployer:</b> <code>{escape_html(deployer)}</code>\n"
            f"• <b>Nonce:</b> <code>{nonce}</code>\n\n"
            f"📍 <b>Deployed Address:</b>\n{code_block(derived)}"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>Derivation failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("create2"))
async def cmd_create2(message: Message) -> None:
    """Computes counterfactual address via CREATE2."""
    parts = (message.text or "").strip().split()
    if len(parts) < 4:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /create2 &lt;deployer&gt; &lt;salt&gt; &lt;init_code_hash&gt;</b>\n"
            "Formula: keccak256(0xff ++ deployer ++ salt ++ init_hash)[12:]</blockquote>\n\n"
            "💡 <b>Example (Uniswap V2 DAI/WETH Pair):</b>\n"
            "<code>/create2 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f 0x0 0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f</code>",
            parse_mode="HTML",
        )
        return

    deployer, salt, init_code = parts[1], parts[2], parts[3]
    try:
        derived = compute_create2_address(deployer, salt, init_code)
        text = (
            "<blockquote><b>🏗️ CREATE2 COUNTERFACTUAL ADDRESS</b>\n"
            "Formula: <code>keccak256(0xff ++ deployer ++ salt ++ init_hash)[12:]</code></blockquote>\n"
            f"• <b>Factory Deployer:</b> <code>{escape_html(deployer)}</code>\n"
            f"• <b>Salt:</b> <code>{escape_html(salt)}</code>\n"
            f"• <b>Init Code Hash:</b> <code>{escape_html(init_code[:16])}...</code>\n\n"
            f"📍 <b>Counterfactual Address:</b>\n{code_block(derived)}"
        )
        await message.answer(text, parse_mode="HTML")
    except Exception as exc:
        await message.answer(f"❌ <b>CREATE2 derivation failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 6. Simulation & Diagnostics
# =========================================================================

@router.message(Command("revert"))
async def cmd_revert(message: Message) -> None:
    """Diagnoses a reverted transaction, re-simulates it, and decodes the error."""
    parts = (message.text or "").strip().split()
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /revert &lt;tx_hash&gt; [chain]</b>\n"
            "Re-simulates failed tx to extract revert reason (Panic, Error, or Custom Error).</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/revert 0xYourFailedTxHash sepolia</code>",
            parse_mode="HTML",
        )
        return

    tx_hash = parts[1]
    chain = parts[2] if len(parts) > 2 else "eth"

    status_msg = await message.answer(f"🔍 <i>Investigating failed tx on {escape_html(chain.upper())} RPC...</i>", parse_mode="HTML")

    try:
        diag = await evm_rpc.diagnose_revert(tx_hash, chain=chain)
        if not diag.get("status"):
            await status_msg.edit_text(f"❌ {escape_html(diag.get('error', 'Investigation failed'))}", parse_mode="HTML")
            return

        if diag["status"] == "success":
            await status_msg.edit_text(
                "<blockquote><b>✅ TRANSACTION SUCCEEDED</b></blockquote>\n"
                f"• <b>Tx Hash:</b> <code>{escape_html(diag['tx_hash'])}</code>\n"
                f"• <b>Block:</b> <code>{diag.get('block_number')}</code>\n"
                f"• <b>Gas Used:</b> <code>{diag.get('gas_used')}</code>\n\n"
                "ℹ️ <i>This transaction completed successfully and did not revert.</i>",
                parse_mode="HTML",
            )
            return

        revert_info = diag["revert_diagnosis"]
        lines = [
            "<blockquote><b>🚨 TRANSACTION REVERT INCIDENT REPORT</b></blockquote>",
            f"• <b>Tx Hash:</b> <code>{escape_html(diag['tx_hash'])}</code>",
            f"• <b>Block:</b> <code>{diag.get('block_number')}</code>",
            f"• <b>From:</b> <code>{escape_html(str(diag.get('from')))}</code>",
            f"• <b>To:</b> <code>{escape_html(str(diag.get('to')))}</code>",
            f"• <b>Gas:</b> <code>{diag.get('gas_used')}</code> / <code>{diag.get('gas_limit')}</code>\n",
            "💥 <b>Decoded Revert Reason:</b>",
        ]

        err_type = revert_info.get("type", "unknown")
        if err_type == "Error(string)":
            lines.append(f"• <b>Reason:</b> <code>{escape_html(revert_info.get('reason', 'None'))}</code>")
        elif err_type == "Panic(uint256)":
            lines.append(f"• <b>Panic Code:</b> <code>{escape_html(revert_info.get('code_hex', ''))}</code>")
            lines.append(f"• <b>Explanation:</b> <i>{escape_html(revert_info.get('explanation', ''))}</i>")
        elif err_type == "CustomError":
            lines.append(f"• <b>Custom Error:</b> <code>{escape_html(revert_info.get('matched_signature') or revert_info.get('selector', ''))}</code>")
            if revert_info.get("decoded_params"):
                lines.append("\n<b>Decoded Arguments:</b>")
                for p in revert_info["decoded_params"]:
                    lines.append(f"  └ <code>{escape_html(p['type'])}</code>: <code>{escape_html(p['value'])}</code>")
        else:
            lines.append(f"• <i>{escape_html(revert_info.get('message', 'No details available'))}</i>")

        if diag.get("revert_data_hex"):
            lines.append("\n📦 <b>Raw Revert Hex:</b>")
            lines.append(code_block(diag["revert_data_hex"][:200]))

        final_text = "\n".join(lines)
        chunks = chunk_message(final_text)
        await status_msg.edit_text(chunks[0], parse_mode="HTML")
        for c in chunks[1:]:
            await message.answer(c, parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Diagnostics error:</b> {escape_html(str(exc))}", parse_mode="HTML")


@router.message(Command("call"))
async def cmd_call(message: Message) -> None:
    """Simulates a read-only transaction using eth_call."""
    parts = (message.text or "").strip().split()
    if len(parts) < 3:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /call &lt;to&gt; &lt;calldata&gt; [chain]</b>\n"
            "Executes a read-only simulation via eth_call (no gas spent).</blockquote>\n\n"
            "💡 <b>Chains:</b> <code>eth</code>, <code>sepolia</code>, <code>base</code>, <code>base_sepolia</code>\n\n"
            "<b>Example:</b>\n"
            "<code>/call 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 0x06fdde03 eth</code>",
            parse_mode="HTML",
        )
        return

    to_addr, calldata = parts[1], parts[2]
    chain = parts[3] if len(parts) > 3 else "eth"

    status_msg = await message.answer(f"🔄 <i>Simulating call on {escape_html(chain.upper())} RPC...</i>", parse_mode="HTML")

    try:
        sim = await evm_rpc.simulate_call(to_addr, calldata, chain=chain)
        if sim["success"]:
            ret_hex = sim["return_data"]
            lines = [
                "<blockquote><b>✅ CALL SIMULATION SUCCEEDED</b></blockquote>",
                f"• <b>Destination:</b> <code>{escape_html(to_addr)}</code>",
                f"• <b>Return Bytes:</b> <code>{sim['return_bytes_len']}</code> bytes\n",
                "📦 <b>Return Data Hex:</b>",
                code_block(ret_hex[:400]),
            ]
            await status_msg.edit_text("\n".join(lines), parse_mode="HTML")
        else:
            revert_info = sim.get("revert_info", {})
            lines = [
                "<blockquote><b>❌ CALL SIMULATION REVERTED</b></blockquote>",
                f"• <b>Destination:</b> <code>{escape_html(to_addr)}</code>",
                f"• <b>Revert Details:</b> {escape_html(revert_info.get('message', str(sim.get('raw_error'))))}",
            ]
            if sim.get("return_data"):
                lines.append("\n" + code_block(str(sim["return_data"])[:200]))
            await status_msg.edit_text("\n".join(lines), parse_mode="HTML")

    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Simulation failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 7. Bytecode Disassembly
# =========================================================================

@router.message(Command("disasm"))
async def cmd_disasm(message: Message) -> None:
    """Disassembles hex bytecode into EVM opcodes."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚠️ Usage: /disasm &lt;hex_bytecode&gt;</b>\n"
            "Converts raw bytecode into sequential EVM opcodes.</blockquote>\n\n"
            "💡 <b>Example:</b>\n"
            "<code>/disasm 6080604052348015600f57600080fd5b50</code>",
            parse_mode="HTML",
        )
        return

    bytecode_str = parts[1].strip()
    try:
        instructions, stats = disassemble(bytecode_str)
        formatted = format_disassembly(instructions, stats, max_lines=75)

        header = (
            "<blockquote><b>⚙️ EVM BYTECODE DISASSEMBLY</b></blockquote>\n"
            f"Size: <code>{stats['bytecode_size']}</code> bytes | "
            f"Instructions: <code>{stats['instruction_count']}</code> | "
            f"JUMPDESTs: <code>{stats['jumpdest_count']}</code>\n\n"
        )
        body = code_block(formatted, language="evm")
        full_text = header + body

        chunks = chunk_message(full_text)
        for c in chunks:
            await message.answer(c, parse_mode="HTML")

    except Exception as exc:
        await message.answer(f"❌ <b>Disassembly failed:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 8. Foundry Chisel Solidity REPL & Evaluator
# =========================================================================

@router.message(Command("chisel", "eval", "solc", "ch"))
async def cmd_chisel(message: Message) -> None:
    """Evaluates arbitrary Solidity expressions, functions, or contracts in an EVM sandbox."""
    parts = (message.text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "<blockquote><b>⚡ FOUNDRY CHISEL SOLIDITY REPL</b>\n"
            "Evaluate any Solidity expression, math, types, or custom functions instantly in a live EVM sandbox!</blockquote>\n\n"
            "🔹 <b>Usage:</b> <code>/chisel &lt;code_or_expression&gt;</code> (Aliases: <code>/eval</code>, <code>/solc</code>)\n\n"
            "💡 <b>Try these examples:</b>\n"
            "• <code>/chisel 1 ether / 1 gwei</code>\n"
            "• <code>/chisel type(uint256).max</code>\n"
            "• <code>/chisel keccak256(bytes(\"hello\"))</code>\n"
            "• <code>/chisel uint256 a = 10; uint256 b = 20; a * b</code>\n"
            "• <code>/chisel abi.encodeWithSignature(\"transfer(address,uint256)\", 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 100)</code>\n"
            "• <code>/chisel 1 + 1 == 2</code>\n\n"
            "<i>Supports functions, Yul assembly, full contracts, and returns exact types, gas, and hex data!</i>",
            parse_mode="HTML",
        )
        return

    code = parts[1].strip()
    status_msg = await message.answer("⚡ <i>Compiling with solc v0.8.26 & simulating in EVM...</i>", parse_mode="HTML")

    try:
        res = await run_chisel(code)
        text = format_chisel_response(res, code)
        chunks = chunk_message(text)
        await status_msg.edit_text(chunks[0], parse_mode="HTML")
        for c in chunks[1:]:
            await message.answer(c, parse_mode="HTML")
    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>Chisel error:</b> {escape_html(str(exc))}", parse_mode="HTML")


# =========================================================================
# 10. AI Web3 & Smart Contract Auditor (/ask, /ai, /audit)
# =========================================================================

@router.message(Command("ask", "ai", "audit"))
async def cmd_ask(message: Message) -> None:
    """Answers Web3 security, Solidity auditing, and EVM architecture questions using Gemini."""
    parts = (message.text or "").strip().split(maxsplit=1)

    # Check if this message replies to a previous message or code snippet
    context_text = None
    if message.reply_to_message and (message.reply_to_message.text or message.reply_to_message.caption):
        context_text = message.reply_to_message.text or message.reply_to_message.caption

    query = parts[1].strip() if len(parts) > 1 else ""

    if not query and not context_text:
        await message.answer(
            "<blockquote><b>🤖 WEB3 & SOLIDITY AI AUDITOR</b>\n"
            "Powered by Google Gemini 3.8 Flash for real-time security auditing and EVM analysis.</blockquote>\n\n"
            "🔹 <b>Usage:</b> <code>/ask &lt;your question or code snippet&gt;</code>\n"
            "🔹 <b>Aliases:</b> <code>/ai</code>, <code>/audit</code>\n\n"
            "💡 <b>Try asking:</b>\n"
            "• <code>/ask what is reentrancy and how to prevent it?</code>\n"
            "• <code>/ask audit this code: <paste Solidity></code>\n"
            "• <code>/ask difference between call and delegatecall</code>\n"
            "• <code>/ask how does flash loan price manipulation work?</code>\n\n"
            "💬 <b>Context-Aware Replying:</b>\n"
            "<i>You can reply to any failed transaction, /revert output, or code snippet with <code>/ask why did this happen?</code> for instant contextual diagnosis!</i>",
            parse_mode="HTML",
        )
        return

    # If user replied with just /ask and no additional question
    if not query and context_text:
        query = "Explain this message, analyze any smart contract errors or code, and suggest fixes if applicable."

    await message.bot.send_chat_action(chat_id=message.chat.id, action="typing")
    status_msg = await message.answer("🤖 <i>Analyzing with Gemini AI Auditor...</i>", parse_mode="HTML")

    try:
        response_text = await ask_gemini(query, context=context_text)
        header = "<blockquote><b>🤖 WEB3 AI AUDITOR</b></blockquote>\n\n"
        full_message = header + response_text

        chunks = chunk_message(full_message)
        try:
            await status_msg.edit_text(chunks[0], parse_mode="HTML")
        except Exception:
            await status_msg.edit_text(chunks[0])

        for c in chunks[1:]:
            try:
                await message.answer(c, parse_mode="HTML")
            except Exception:
                await message.answer(c)
    except Exception as exc:
        await status_msg.edit_text(f"❌ <b>AI Auditor error:</b> {escape_html(str(exc))}", parse_mode="HTML")



