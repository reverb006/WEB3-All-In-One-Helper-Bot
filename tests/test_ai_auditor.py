"""Unit and integration tests for Web3 AI Auditor service."""

import pytest
from services.ai_auditor import ask_gemini, markdown_to_telegram_html


def test_markdown_to_telegram_html_formatting():
    markdown = """**Title in Bold** and _italic text_.
Here is some `inline_code()` with <brackets> & ampersands.
```solidity
// SPDX-License-Identifier: MIT
function transfer(address to, uint256 amount) external {
    require(amount > 0, "Zero amount");
}
```
Done!"""

    html_out = markdown_to_telegram_html(markdown)

    assert "<b>Title in Bold</b>" in html_out
    assert "<i>italic text</i>" in html_out
    assert "<code>inline_code()</code>" in html_out
    assert "&lt;brackets&gt;" in html_out
    assert "&amp; ampersands" in html_out
    assert '<pre><code class="language-solidity">' in html_out
    assert "&gt; 0" in html_out


def test_markdown_to_telegram_html_advanced():
    markdown = """### 1. Mandatory Functions
---
totalSupply() external view returns (uint256)
* Emitted on approval.
The allowance must be $\\ge$ amount.
"""
    html_out = markdown_to_telegram_html(markdown)
    assert "<b>🔹 1. Mandatory Functions</b>" in html_out
    assert "───────────────────────────" in html_out
    assert "<code>totalSupply() external view returns (uint256)</code>" in html_out
    assert "• Emitted on approval." in html_out
    assert "≥" in html_out



@pytest.mark.asyncio
async def test_ask_gemini_missing_key(monkeypatch):
    import services.ai_auditor as ai_mod

    monkeypatch.setattr(ai_mod.settings, "GEMINI_API_KEY", None)
    answer = await ask_gemini("What is reentrancy?")
    assert "Gemini API Key Missing" in answer


@pytest.mark.asyncio
async def test_ask_gemini_mocked(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock, patch
    import services.ai_auditor as ai_mod

    monkeypatch.setattr(ai_mod.settings, "GEMINI_API_KEY", "test-gemini-key")

    mock_response = MagicMock()
    mock_response.text = "**Root Cause:** External call before state update in `withdraw()`."

    with patch("services.ai_auditor.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_instance

        answer = await ask_gemini("What is reentrancy in Solidity?")
        assert "<b>Root Cause:</b>" in answer
        assert "<code>withdraw()</code>" in answer
