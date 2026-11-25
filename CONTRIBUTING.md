# Contributing to EVM Swiss Army Knife

Contributions from smart-contract auditors, security researchers, and EVM developers are welcome!

## Development Setup

```bash
git clone https://github.com/reverb006/WEB3-All-In-One-Helper-Bot.git
cd WEB3-All-In-One-Helper-Bot
python -m venv .venv
# Activate venv, then:
pip install -r requirements.txt
cp .env.example .env
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Adding Commands or Solidity Reference Topics

- **New Solidity / Foundry reference entries**: Add items to `SOLIDITY_REFERENCE` in `services/solidity_docs.py` with `id`, `name`, `category`, `syntax`, `description`, `auditor_notes`, `example`, and `aliases`, then verify with `tests/test_solidity_docs.py`.
- **New RPC / EVM tools**: Keep pure/network logic inside `services/`, register slash commands in `handlers/commands.py`, add inline support in `handlers/inline.py` if applicable, and register menu commands in `bot.py`.
- Keep `.env`, logs, and private API keys out of commits.
