"""Inline query handler for instant @BotName searches and calculations."""

import hashlib
from typing import List
from aiogram import Router
from aiogram.types import (
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
)
from services.decoder import fetch_signatures
from services.evm_crypto import (
    clean_hex,
    compute_mapping_slot,
    compute_selector,
    convert_units,
    hex_to_int256,
    hex_to_uint256,
    int_to_hex256,
    keccak256_hex,
)
from services.ai_auditor import ask_gemini
from services.chisel import format_chisel_response, run_chisel
from services.solidity_docs import search_solidity, SOLIDITY_REFERENCE
from utils.formatters import code_block, escape_html, inline_code

router = Router(name="inline")


def make_id(val: str) -> str:
    """Generates unique deterministic ID for inline query results."""
    return hashlib.md5(val.encode("utf-8")).hexdigest()[:16]


@router.inline_query()
async def inline_handler(inline_query: InlineQuery) -> None:
    """Handles real-time inline queries from any Telegram chat."""
    query = inline_query.query.strip()
    results: List[InlineQueryResultArticle] = []

    # 1. Empty query: Show helpful suggestion cards
    if not query:
        results.append(
            InlineQueryResultArticle(
                id=make_id("help_ask"),
                title="🤖 AI Web3 Auditor (Gemini)",
                description="Type ask what is reentrancy? for instant AI security analysis",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Ask AI any smart contract security question with <code>@bot ask what is reentrancy?</code>!",
                    parse_mode="HTML",
                ),
            )
        )
        results.append(
            InlineQueryResultArticle(
                id=make_id("help_chisel"),
                title="⚡ Chisel: Live Solidity Evaluator",
                description="Type chisel 1 ether / 1 gwei to evaluate Solidity expressions",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Evaluate Solidity expressions anywhere with <code>@bot chisel 1 ether / 1 gwei</code> or <code>@bot chisel type(uint256).max</code>!",
                    parse_mode="HTML",
                ),
            )
        )

        results.append(
            InlineQueryResultArticle(
                id=make_id("help_solidity"),
                title="📖 Solidity Special Functions & Reference",
                description="Type sol receive or sol delegatecall for instant documentation",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Search Solidity built-in functions like <code>@bot sol receive</code> or <code>@bot sol delegatecall</code> anywhere!",
                    parse_mode="HTML",
                ),
            )
        )

        results.append(
            InlineQueryResultArticle(
                id=make_id("help_selector"),
                title="🔍 4-Byte Selector Resolution",
                description="Type 0xa9059cbb to lookup function signatures",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Search any 4-byte selector like <code>@bot 0xa9059cbb</code> to resolve its function signature!",
                    parse_mode="HTML",
                ),
            )
        )
        results.append(
            InlineQueryResultArticle(
                id=make_id("help_hash"),
                title="🔐 Keccak256 & Selector Calculator",
                description="Type transfer(address,uint256) to compute 4-byte selector",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Type any signature like <code>@bot transfer(address,uint256)</code> to calculate its selector!",
                    parse_mode="HTML",
                ),
            )
        )
        results.append(
            InlineQueryResultArticle(
                id=make_id("help_convert"),
                title="🔄 Unit Conversion",
                description="Type 1.5 eth or 50 gwei for instant unit conversion",
                input_message_content=InputTextMessageContent(
                    message_text="💡 <b>Tip:</b> Type amounts like <code>@bot 1.5 eth</code> or <code>@bot 50 gwei</code> to convert EVM units!",
                    parse_mode="HTML",
                ),
            )
        )
        await inline_query.answer(results, cache_time=10, is_personal=True)
        return

    # 2. Check for Function Signature: Contains '(' and ')'
    if "(" in query and ")" in query:
        try:
            selector = compute_selector(query)
            full_hash = keccak256_hex(query.encode("utf-8"))
            msg = (
                "<blockquote><b>🔐 KECCAK-256 SELECTOR CALCULATION</b></blockquote>\n"
                f"• <b>Signature:</b> <code>{escape_html(query)}</code>\n"
                f"• <b>4-Byte Selector:</b> <code>{selector}</code>\n\n"
                f"💎 <b>Full Keccak Hash:</b>\n{code_block(full_hash)}"
            )
            results.append(
                InlineQueryResultArticle(
                    id=make_id(f"sig_{query}"),
                    title=f"Selector: {selector}",
                    description=f"Keccak-256 for '{query}'",
                    input_message_content=InputTextMessageContent(
                        message_text=msg,
                        parse_mode="HTML",
                    ),
                )
            )
        except Exception:
            pass

    # 3. Check for 4-Byte Selector: 8 or 10 hex characters
    raw_query = clean_hex(query)
    if len(raw_query) == 8:
        selector = "0x" + raw_query.lower()
        try:
            sigs = await fetch_signatures(selector)
            if sigs:
                for sig in sigs[:5]:
                    msg = (
                        "<blockquote><b>🎯 RESOLVED 4-BYTE SELECTOR</b></blockquote>\n"
                        f"• <b>Selector:</b> <code>{selector}</code>\n"
                        f"• <b>Signature:</b> <code>{escape_html(sig)}</code>"
                    )
                    results.append(
                        InlineQueryResultArticle(
                            id=make_id(f"sel_{selector}_{sig}"),
                            title=f"Function: {sig}",
                            description=f"Selector: {selector}",
                            input_message_content=InputTextMessageContent(
                                message_text=msg,
                                parse_mode="HTML",
                            ),
                        )
                    )
            else:
                msg = f"⚠️ <i>No verified signatures found for selector</i> <code>{selector}</code>"
                results.append(
                    InlineQueryResultArticle(
                        id=make_id(f"sel_none_{selector}"),
                        title=f"Selector: {selector}",
                        description="No matching signatures in 4byte / OpenChain",
                        input_message_content=InputTextMessageContent(
                            message_text=msg,
                            parse_mode="HTML",
                        ),
                    )
                )
        except Exception:
            pass

    # 4. Check for Unit Conversion: "<number> <unit>"
    parts = query.split()
    if len(parts) == 2:
        num_str, unit_str = parts[0], parts[1].lower()
        try:
            conv = convert_units(num_str, unit_str)
            msg = (
                "<blockquote><b>🔄 EVM UNIT CONVERSION</b></blockquote>\n"
                f"Input: <code>{conv['input_amount']}</code> <b>{escape_html(conv['input_unit'])}</b>\n\n"
                f"• <b>Wei:</b> <code>{conv['wei']}</code> (<code>{conv['wei_raw']}</code>)\n"
                f"• <b>Gwei:</b> <code>{conv['gwei']}</code>\n"
                f"• <b>Ether:</b> <code>{conv['ether']}</code>"
            )
            results.append(
                InlineQueryResultArticle(
                    id=make_id(f"conv_{query}"),
                    title=f"{conv['input_amount']} {conv['input_unit']} Conversion",
                    description=f"{conv['ether']} ETH | {conv['gwei']} Gwei | {conv['wei_raw']} Wei",
                    input_message_content=InputTextMessageContent(
                        message_text=msg,
                        parse_mode="HTML",
                    ),
                )
            )
        except Exception:
            pass

    # 5. Check for Hex or Decimal Number
    if query.startswith("0x") or query.startswith("0X"):
        try:
            uint_val = hex_to_uint256(query)
            int_val = hex_to_int256(query)
            msg = (
                "<blockquote><b>🔢 HEX TO DECIMAL CONVERSION</b></blockquote>\n"
                f"• <b>Hex:</b> <code>{escape_html(query)}</code>\n"
                f"• <b>uint256:</b> <code>{uint_val}</code>\n"
                f"• <b>int256:</b> <code>{int_val}</code>"
            )
            results.append(
                InlineQueryResultArticle(
                    id=make_id(f"hex_{query}"),
                    title=f"Dec: {uint_val}",
                    description=f"int256: {int_val} | Hex: {query}",
                    input_message_content=InputTextMessageContent(
                        message_text=msg,
                        parse_mode="HTML",
                    ),
                )
            )
        except Exception:
            pass
    elif query.isdigit() or (query.startswith("-") and query[1:].isdigit()):
        try:
            val = int(query, 10)
            hex_word = int_to_hex256(val)
            msg = (
                "<blockquote><b>🔢 INTEGER TO HEX WORD</b></blockquote>\n"
                f"• <b>Decimal:</b> <code>{val}</code>\n\n"
                f"📦 <b>256-bit Hex Word:</b>\n{code_block(hex_word)}"
            )
            results.append(
                InlineQueryResultArticle(
                    id=make_id(f"dec_{query}"),
                    title=f"Hex: {hex(val)}",
                    description=f"256-bit word: {hex_word[:18]}...",
                    input_message_content=InputTextMessageContent(
                        message_text=msg,
                        parse_mode="HTML",
                    ),
                )
            )
        except Exception:
            pass

    # 6. Check for Mapping Slot Query: e.g. "slot <key> <slot_num>"
    if query.lower().startswith("slot "):
        subparts = query.split()
        if len(subparts) >= 3:
            key, slot_s = subparts[1], subparts[2]
            try:
                slot_n = int(slot_s, 0)
                info = compute_mapping_slot(key, slot_n)
                msg = (
                    "<blockquote><b>📦 MAPPING STORAGE SLOT</b></blockquote>\n"
                    f"• <b>Key:</b> <code>{escape_html(info['key_display'])}</code>\n"
                    f"• <b>Slot:</b> <code>{slot_n}</code>\n\n"
                    f"📍 <b>Calculated Slot:</b>\n{code_block(info['slot_hex'])}"
                )
                results.append(
                    InlineQueryResultArticle(
                        id=make_id(f"slot_{query}"),
                        title=f"Slot: {info['slot_hex'][:14]}...",
                        description=f"Mapping slot for {key} at slot {slot_n}",
                        input_message_content=InputTextMessageContent(
                            message_text=msg,
                            parse_mode="HTML",
                        ),
                    )
                )
            except Exception:
                pass

    # 7. Check for Solidity Reference query: "sol <query>" or direct keyword match
    sol_q = None
    if query.lower().startswith("sol ") or query.lower().startswith("solidity "):
        sol_q = query.split(maxsplit=1)[1].strip()
    elif query.lower() in [i["id"].lower() for i in SOLIDITY_REFERENCE] or any(
        query.lower() == a.lower().replace("()", "") for i in SOLIDITY_REFERENCE for a in i.get("aliases", [])
    ):
        sol_q = query

    if sol_q:
        sol_res = search_solidity(sol_q)
        if sol_res["found"] and sol_res["item"]:
            item = sol_res["item"]
            msg = (
                f"<blockquote><b>📖 SOLIDITY REFERENCE • {escape_html(item['category'])}</b>\n"
                f"<b>{escape_html(item['name'])}</b></blockquote>\n\n"
                f"🔹 <b>Description:</b>\n<i>{escape_html(item['description'])}</i>\n\n"
                f"⚠️ <b>Auditor Notes & Gotchas:</b>\n{escape_html(item['auditor_notes'])}\n\n"
                f"💡 <b>Solidity Example:</b>\n{code_block(item['example'], language='solidity')}"
            )
            results.append(
                InlineQueryResultArticle(
                    id=make_id(f"sol_{item['id']}"),
                    title=f"Solidity: {item['name']}",
                    description=f"{item['category']} — {item['description'][:60]}...",
                    input_message_content=InputTextMessageContent(
                        message_text=msg,
                        parse_mode="HTML",
                    ),
                )
            )
        elif sol_res.get("suggestions"):
            for s_name in sol_res["suggestions"][:4]:
                s_item = next((i for i in SOLIDITY_REFERENCE if i["name"] == s_name), None)
                if s_item:
                    msg = (
                        f"<blockquote><b>📖 SOLIDITY REFERENCE • {escape_html(s_item['category'])}</b>\n"
                        f"<b>{escape_html(s_item['name'])}</b></blockquote>\n\n"
                        f"🔹 <b>Description:</b>\n<i>{escape_html(s_item['description'])}</i>\n\n"
                        f"⚠️ <b>Auditor Notes & Gotchas:</b>\n{escape_html(s_item['auditor_notes'])}\n\n"
                        f"💡 <b>Solidity Example:</b>\n{code_block(s_item['example'], language='solidity')}"
                    )
                    results.append(
                        InlineQueryResultArticle(
                            id=make_id(f"sol_sugg_{s_item['id']}"),
                            title=f"Solidity: {s_item['name']}",
                            description=f"{s_item['category']} — {s_item['description'][:60]}...",
                            input_message_content=InputTextMessageContent(
                                message_text=msg,
                                parse_mode="HTML",
                            ),
                        )
                    )

    # 8. Check for Chisel Evaluation: "chisel <expr>" or "eval <expr>"
    if query.lower().startswith("chisel ") or query.lower().startswith("eval "):
        chisel_code = query.split(maxsplit=1)[1].strip()
        if chisel_code:
            try:
                res = await run_chisel(chisel_code)
                card_text = format_chisel_response(res, chisel_code)
                desc = "Execution failed"
                if res.get("success") and res.get("outputs"):
                    first_val = res["outputs"][0]["value"]
                    desc = f"Result: {first_val}"
                elif res.get("success"):
                    desc = "Success (0 return data)"
                else:
                    desc = res.get("error", "Error")[:60]

                results.append(
                    InlineQueryResultArticle(
                        id=make_id(f"chisel_{chisel_code}"),
                        title=f"⚡ Chisel: {chisel_code[:40]}",
                        description=desc,
                        input_message_content=InputTextMessageContent(
                            message_text=card_text,
                            parse_mode="HTML",
                        ),
                    )
                )
            except Exception:
                pass

    # 9. Check for AI Ask query: "ask <question>" or "ai <question>"
    if query.lower().startswith("ask ") or query.lower().startswith("ai "):
        ai_q = query.split(maxsplit=1)[1].strip()
        if ai_q:
            try:
                answer = await ask_gemini(ai_q)
                full_msg = f"<blockquote><b>🤖 WEB3 AI AUDITOR</b>\n<b>Q:</b> {escape_html(ai_q)}</blockquote>\n\n" + answer
                results.append(
                    InlineQueryResultArticle(
                        id=make_id(f"ask_{ai_q}"),
                        title=f"🤖 AI Answer: {ai_q[:40]}",
                        description="Instant smart contract security analysis via Gemini 3.8 Flash",
                        input_message_content=InputTextMessageContent(
                            message_text=full_msg,
                            parse_mode="HTML",
                        ),
                    )
                )
            except Exception:
                pass

    await inline_query.answer(results, cache_time=15, is_personal=True)


