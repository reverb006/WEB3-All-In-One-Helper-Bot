"""Web3 & Smart Contract Security AI Auditor Service.

Powered by Google Gemini via the official google-genai SDK.
Provides real-time, expert-level auditing, vulnerability analysis, transaction
debugging, and Solidity/EVM explanations.
"""

import asyncio
import logging
import re
from typing import Optional
from google import genai
from google.genai import types
from config import settings

logger = logging.getLogger("evm_swiss_knife")

SYSTEM_INSTRUCTION = """You are an elite Smart Contract Security Researcher and EVM Auditor embedded inside the EVM Swiss Army Knife Telegram bot.

MISSION & TONE:
- Be ultra-CONCISE, PUNCHY, and DIRECT.
- NEVER write giant essays, long academic intros, or verbose filler. Keep explanations bite-sized and skimmable in 15-20 seconds (under 250-350 words total).
- Answer the user's core question immediately in the first 1-2 sentences.

SPACING & READABILITY (CRITICAL FOR TELEGRAM):
- NEVER cram text together. Telegram messages need generous breathing room.
- ALWAYS leave an empty line between sections, headers, code snippets, and bullet points.
- ALWAYS wrap all Solidity function signatures, variables, events, and opcodes in backticks (`function()`, `uint256`, `Transfer`).
- NEVER use LaTeX math notation (e.g. no $\\ge$, no $x$). Use clean Unicode or standard symbols: >=, <=, !=, *, ->.
- Use clean Markdown headers (### Section Title) and bullet points (* Point).

STRUCTURE FOR CONCEPTS / STANDARDS (e.g. ERC-20, ERC-721, proxy patterns):
1. ⚡ Quick TL;DR (1-2 punchy sentences explaining what it is).
2. 🔹 Core Mechanics / Functions (concise list of essential signatures with a 1-line note, separated by blank lines).
3. 🛡️ Auditor Gotchas (2-3 quick bullet points on real-world vulnerabilities, attack vectors, or integration traps).

STRUCTURE FOR VULNERABILITIES / AUDIT QUESTIONS:
1. ⚡ Root Cause (1-2 sentences).
2. 🎯 Exploit Scenario (1-2 sentences explaining attacker profit or impact).
3. 🛡️ Mitigation (minimal, clean Solidity fix or 1-2 practical bullet points).
"""

FALLBACK_MODELS = [
    "gemini-3.8-flash",
    "gemini-flash-lite-latest",
    "gemini-3.5-flash-lite",
]


def clean_latex(text: str) -> str:
    """Replaces common LaTeX math notation with readable Unicode equivalents."""
    replacements = [
        (r"\$\\ge\$|\\ge\b|\\geq\b", "≥"),
        (r"\$\\le\$|\\le\b|\\leq\b", "≤"),
        (r"\$\\ne\$|\\ne\b|\\neq\b", "≠"),
        (r"\$\\times\$|\\times\b", "×"),
        (r"\$\\pm\$|\\pm\b", "±"),
        (r"\$\\approx\$|\\approx\b", "≈"),
        (r"\$\\to\$|\\to\b|\\rightarrow\b", "→"),
        (r"\$\\leftarrow\b", "←"),
    ]
    for pattern, rep in replacements:
        text = re.sub(pattern, rep, text)
    # Replace remaining $formula$ with <code>formula</code>
    text = re.sub(r"\$([^\$]+)\$", r"<code>\1</code>", text)
    return text


def escape_telegram_html(text: str) -> str:
    """Escapes only &, <, > so quotes and apostrophes remain natural for Telegram."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def markdown_to_telegram_html(text: str) -> str:
    """Converts standard Markdown formatting into clean, crash-proof Telegram HTML with generous spacing."""
    if not text:
        return ""

    # 1. Clean LaTeX math first
    text = clean_latex(text)

    # 2. Protect fenced code blocks (```lang ... ```)
    code_blocks = []

    def _save_block(m):
        lang = m.group(1) or ""
        code = m.group(2)
        code_blocks.append((lang, code))
        return f"\n\n@@@CODE_BLOCK_{len(code_blocks)-1}@@@\n\n"

    text = re.sub(r"```(\w+)?\n?(.*?)```", _save_block, text, flags=re.DOTALL)

    # 3. Protect inline code (`code`)
    inline_codes = []

    def _save_inline(m):
        inline_codes.append(m.group(1))
        return f"@@@INLINE_CODE_{len(inline_codes)-1}@@@"

    text = re.sub(r"`([^`]+)`", _save_inline, text)

    # 4. Escape HTML special characters (&, <, > only)
    text = escape_telegram_html(text)

    # 5. Convert Markdown Headings (# Heading, ## Heading, ### Heading) with breathing room
    def _heading_repl(m):
        level = len(m.group(1))
        title = m.group(2).strip()
        if level == 1:
            return f"\n\n<b><u>{title.upper()}</u></b>\n\n"
        elif level == 2:
            return f"\n\n<b>📌 {title}</b>\n\n"
        else:
            return f"\n\n<b>🔹 {title}</b>\n\n"

    text = re.sub(r"^(#{1,4})\s+(.+)$", _heading_repl, text, flags=re.MULTILINE)

    # 6. Convert Horizontal Rules (---, ***, ___) with generous padding
    text = re.sub(
        r"^(---|___|\*\*\*)\s*$",
        "\n\n───────────────────────────\n\n",
        text,
        flags=re.MULTILINE,
    )

    # 7. Convert Bold (**text** or __text__)
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.*?)__", r"<b>\1</b>", text)

    # 8. Convert Italic (*text* or _text_) - avoid matching lone ' * ' multiplication
    text = re.sub(r"(?:^|(?<=[\s(]))_([^_]+)_(?=[\s),.:;!?]|$)", r"<i>\1</i>", text)
    text = re.sub(r"(?:^|(?<=[\s(]))\*([^*\s][^*]*[^*\s]|\S)\*(?=[\s),.:;!?]|$)", r"<i>\1</i>", text)

    # 9. Convert bullet lists (* item, - item, + item) with empty line spacing for breathing room
    text = re.sub(r"(?:\n|^)\s*[*+-]\s+", "\n\n• ", text)

    # 10. Auto-format bare function/event/error signatures on their own line
    def _auto_signature(m):
        leading_space = m.group(1)
        sig = m.group(2).strip()
        return f"\n\n{leading_space}<code>{sig}</code>\n"

    # Matches lines like: totalSupply() external view returns (uint256)
    text = re.sub(
        r"^(\s*)([a-zA-Z_]\w*\s*\(.*?\)\s*(?:external|public|internal|private|view|pure|returns|payable|\{).*)$",
        _auto_signature,
        text,
        flags=re.MULTILINE,
    )
    # Matches lines starting with event/error/function
    text = re.sub(
        r"^(\s*)((?:function|event|error|modifier)\s+.*)$",
        _auto_signature,
        text,
        flags=re.MULTILINE,
    )

    # 11. Restore inline codes
    for i, code in enumerate(inline_codes):
        text = text.replace(
            f"@@@INLINE_CODE_{i}@@@", f"<code>{escape_telegram_html(code)}</code>"
        )

    # 12. Restore code blocks with clean padding
    for i, (lang, code) in enumerate(code_blocks):
        escaped_code = escape_telegram_html(code.rstrip())
        if lang:
            rep = f'<pre><code class="language-{lang}">{escaped_code}</code></pre>'
        else:
            rep = f"<pre><code>{escaped_code}</code></pre>"
        text = text.replace(f"@@@CODE_BLOCK_{i}@@@", rep)

    # 13. Clean up excessive newlines: normalize 3+ newlines to exactly 2 (\n\n = 1 empty line)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


async def ask_gemini(query: str, context: Optional[str] = None) -> str:
    """Queries Gemini with the auditor system prompt and optional message context."""
    api_key = settings.GEMINI_API_KEY
    if not api_key:
        return (
            "<blockquote><b>⚠️ Gemini API Key Missing</b></blockquote>\n\n"
            "Please configure <code>GEMINI_API_KEY</code> in your <code>.env</code> file to enable AI Auditor answers.\n\n"
            "💡 Get a free API key at: https://aistudio.google.com"
        )

    client = genai.Client(api_key=api_key)

    # Build prompt
    prompt_parts = []
    if context:
        prompt_parts.append(f"Context from previous message / code:\n{context}\n")
    prompt_parts.append(f"User Query:\n{query}")
    full_prompt = "\n".join(prompt_parts)

    candidate_models = [settings.GEMINI_MODEL] + [
        m for m in FALLBACK_MODELS if m != settings.GEMINI_MODEL
    ]

    last_error = None
    for model_name in candidate_models:
        try:
            logger.info("Querying Gemini model: %s", model_name)
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=model_name,
                    contents=full_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=SYSTEM_INSTRUCTION,
                        temperature=0.2,
                        max_output_tokens=4096,
                    ),
                ),
                timeout=25.0,
            )
            raw_text = response.text or ""
            if raw_text:
                return markdown_to_telegram_html(raw_text)
        except Exception as exc:
            logger.warning("Gemini error with model %s: %s", model_name, exc)
            last_error = exc

    # If all models failed
    error_msg = escape_telegram_html(str(last_error)) if last_error else "Unknown error"
    return (
        "<blockquote><b>❌ Gemini Generation Failed</b></blockquote>\n\n"
        f"<b>Error details:</b>\n<code>{error_msg}</code>"
    )
