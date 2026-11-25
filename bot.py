"""EVM Swiss Army Knife - Telegram Bot Entrypoint.

Initializes the aiogram Dispatcher, registers command and inline routers,
sets up bot command menu, and starts polling.
"""

import asyncio
import logging
import socket
import sys
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand
from config import settings
from handlers import commands_router, inline_router

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    # Prefer IPv4 on Windows to prevent IPv6 TCP timeouts to googleapis.com / Telegram API
    _orig_getaddrinfo = socket.getaddrinfo

    def _ipv4_preferred_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        try:
            results = _orig_getaddrinfo(host, port, family, type, proto, flags)
            v4 = [r for r in results if r[0] == socket.AF_INET]
            return v4 if v4 else results
        except Exception:
            return _orig_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = _ipv4_preferred_getaddrinfo

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("evm_swiss_knife")


async def setup_bot_commands(bot: Bot) -> None:
    """Configures the native Telegram menu commands list."""
    commands = [
        BotCommand(command="help", description="Show all Swiss Army Knife commands"),
        BotCommand(command="ask", description="AI Web3 & smart contract auditor (Gemini)"),
        BotCommand(command="decode", description="Decode calldata & 4-byte selector"),

        BotCommand(command="hash", description="Compute Keccak256 & selector"),
        BotCommand(command="error", description="Compute custom error selector"),
        BotCommand(command="convert", description="Convert Wei, Gwei, Ether"),
        BotCommand(command="hex", description="Convert integer to 256-bit hex"),
        BotCommand(command="dec", description="Convert hex to decimal (uint/int256)"),
        BotCommand(command="slot", description="Dynamic mapping storage slot math"),
        BotCommand(command="storage", description="Read & decode contract storage slot"),
        BotCommand(command="proxy", description="Resolve proxy logic implementation & admin"),
        BotCommand(command="source", description="Fetch verified contract source & ABI"),
        BotCommand(command="token", description="Inspect ERC-20 symbol, decimals & supply"),
        BotCommand(command="gas", description="Live gas fees & priority tiers"),
        BotCommand(command="chisel", description="Foundry Solidity REPL & evaluator"),
        BotCommand(command="sol", description="Solidity special functions & reference"),

        BotCommand(command="create", description="Compute CREATE deployment address"),
        BotCommand(command="create2", description="Compute CREATE2 address"),
        BotCommand(command="revert", description="Diagnose failed transaction revert"),
        BotCommand(command="call", description="Dry-run simulate eth_call"),
        BotCommand(command="disasm", description="Disassemble bytecode to EVM opcodes"),
    ]
    try:
        me = await bot.get_me()
        if me and me.username:
            bot._cached_username = me.username  # type: ignore[attr-defined]
        await bot.set_my_commands(commands)
        logger.info("Bot commands menu registered successfully")
    except Exception as exc:
        logger.warning("Failed to register bot commands menu: %s", exc)


async def main() -> None:
    """Main application loop."""
    if not settings.BOT_TOKEN or settings.BOT_TOKEN.startswith("TEST_") or "example" in settings.BOT_TOKEN:
        logger.error(
            "ERROR: Valid BOT_TOKEN is missing! Please configure BOT_TOKEN in .env or environment variables."
        )
        print("\n=======================================================")
        print("[!] ACTION REQUIRED: Set your BOT_TOKEN in .env file")
        print("Obtain a token from https://t.me/BotFather on Telegram")
        print("=======================================================\n")
        # Exit gracefully if running directly with --check
        if len(sys.argv) > 1 and sys.argv[1] == "--check":
            return
        sys.exit(1)

    bot = Bot(
        token=settings.BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher()

    # Register handlers
    dp.include_router(commands_router)
    dp.include_router(inline_router)

    # Bot lifecycle hooks
    dp.startup.register(setup_bot_commands)

    logger.info("Starting EVM Swiss Army Knife Bot...")
    try:
        # Drop pending updates and start polling
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await bot.session.close()
        logger.info("Bot stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Process terminated.")
