"""Handlers package for Telegram bot commands and inline queries."""
from handlers.commands import router as commands_router
from handlers.inline import router as inline_router

__all__ = ["commands_router", "inline_router"]
