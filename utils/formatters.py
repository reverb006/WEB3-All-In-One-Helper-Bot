"""Telegram message formatters and helpers supporting rich HTML formatting."""

import html
import re
from typing import List


def escape_html(text: str) -> str:
    """Escapes HTML special characters (&, <, >) for safe Telegram HTML formatting."""
    if not text:
        return ""
    return html.escape(str(text), quote=False)


# Backward compatibility alias
escape_md = escape_html


def bold(text: str) -> str:
    """Wraps text in bold HTML tags."""
    return f"<b>{escape_html(text)}</b>"


def italic(text: str) -> str:
    """Wraps text in italic HTML tags."""
    return f"<i>{escape_html(text)}</i>"


def inline_code(code: str) -> str:
    """Wraps code in inline <code> tags."""
    return f"<code>{escape_html(code)}</code>"


def code_block(code: str, language: str = "") -> str:
    """Wraps code in <pre><code> tags with optional syntax language."""
    safe = escape_html(code)
    if language:
        return f'<pre><code class="language-{escape_html(language)}">{safe}</code></pre>'
    return f"<pre><code>{safe}</code></pre>"


def blockquote(text: str, expandable: bool = False) -> str:
    """Wraps text in a Telegram blockquote."""
    attr = " expandable" if expandable else ""
    return f"<blockquote{attr}>{text}</blockquote>"


def format_hex(data: str) -> str:
    """Normalizes hex data string to have a lowercase 0x prefix."""
    s = data.strip()
    if not s.startswith("0x") and not s.startswith("0X"):
        s = "0x" + s
    return s.lower()


def chunk_message(text: str, max_chars: int = 4000) -> List[str]:
    """Splits a long text message into safe chunks <= max_chars.

    Attempts to split cleanly across newlines.
    """
    if len(text) <= max_chars:
        return [text]

    lines = text.split("\n")
    chunks = []
    current_chunk = []
    current_len = 0

    for line in lines:
        line_len = len(line) + 1
        if current_len + line_len > max_chars:
            if current_chunk:
                chunks.append("\n".join(current_chunk))
                current_chunk = [line]
                current_len = line_len
            else:
                for i in range(0, len(line), max_chars):
                    chunks.append(line[i : i + max_chars])
                current_chunk = []
                current_len = 0
        else:
            current_chunk.append(line)
            current_len += line_len

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks
