"""Configuration management for the EVM Swiss Army Knife Telegram bot."""

import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Application settings and environment variable configuration."""

    # Telegram Bot
    BOT_TOKEN: str = Field(
        default="",
        description="Telegram Bot API Token obtained from @BotFather"
    )

    # RPC Endpoints
    RPC_URL_ETH: str = Field(
        default="https://ethereum-rpc.publicnode.com",
        description="Ethereum Mainnet RPC URL"
    )
    RPC_URL_ETH_SEPOLIA: str = Field(
        default="https://ethereum-sepolia-rpc.publicnode.com",
        description="Ethereum Sepolia Testnet RPC URL"
    )
    RPC_URL_BASE: str = Field(
        default="https://base-rpc.publicnode.com",
        description="Base Mainnet RPC URL"
    )
    RPC_URL_BASE_SEPOLIA: str = Field(
        default="https://base-sepolia-rpc.publicnode.com",
        description="Base Sepolia Testnet RPC URL"
    )

    # Optional Etherscan API Key
    ETHERSCAN_API_KEY: Optional[str] = Field(
        default=None,
        description="Etherscan API key for contract verification / ABI lookups"
    )

    # Signature API Lookups
    OPENCHAIN_API_URL: str = Field(
        default="https://api.openchain.xyz/signature-database/v1/lookup",
        description="OpenChain signature database endpoint"
    )
    FOURBYTE_API_URL: str = Field(
        default="https://www.4byte.directory/api/v1/signatures/",
        description="4byte Directory API endpoint"
    )

    # Disassembly & Display Limits
    MAX_DISASM_LINES: int = Field(
        default=80,
        description="Maximum lines of disassembled opcodes to return in a single view"
    )

    # Google Gemini AI Assistant
    GEMINI_API_KEY: Optional[str] = Field(
        default=None,
        description="Google Gemini API key for Web3 / Solidity AI auditing"
    )
    GEMINI_MODEL: str = Field(
        default="gemini-3.8-flash",
        description="Gemini model to use for /ask queries"
    )

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Global settings singleton
settings = Settings()
