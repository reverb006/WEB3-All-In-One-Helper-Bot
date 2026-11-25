"""Unit and integration tests for new auditor services:
- proxy_resolver
- token_inspector
- gas_tracker
- contract_source
"""

import pytest
from services.contract_source import fetch_contract_source
from services.gas_tracker import get_gas_metrics
from services.proxy_resolver import extract_address_from_slot, resolve_proxy
from services.token_inspector import decode_string_or_bytes32, inspect_token
from eth_abi import encode as abi_encode


def test_extract_address_from_slot():
    """Validates 20-byte address extraction from 32-byte EVM storage word."""
    zero_slot = b"\x00" * 32
    assert extract_address_from_slot(zero_slot) is None

    test_addr_bytes = bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045")
    padded_slot = b"\x00" * 12 + test_addr_bytes
    extracted = extract_address_from_slot(padded_slot)
    assert extracted.lower() == "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"

    assert extract_address_from_slot(b"too_short") is None


def test_decode_string_or_bytes32():
    """Validates both ABI string decoding and bytes32 string fallbacks."""
    # 1. Standard ABI string
    encoded_abi = abi_encode(["string"], ["Wrapped Ether"])
    assert decode_string_or_bytes32(encoded_abi) == "Wrapped Ether"

    # 2. Raw bytes32 string (e.g. MakerDAO MKR symbol)
    raw_bytes32 = b"MKR" + b"\x00" * 29
    assert decode_string_or_bytes32(raw_bytes32) == "MKR"

    # 3. Empty bytes
    assert decode_string_or_bytes32(b"") == ""


@pytest.mark.asyncio
async def test_inspect_token_weth():
    """Tests live ERC-20 token inspection on Mainnet WETH contract."""
    weth_addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    try:
        res = await inspect_token(weth_addr, chain="eth")
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")

    assert res["success"] is True
    assert res["symbol"] == "WETH"
    assert "Wrapped" in res["name"]
    assert res["decimals"] == 18
    assert int(res["total_supply_raw"]) > 0
    assert float(res["total_supply_formatted"].replace(",", "")) > 0


@pytest.mark.asyncio
async def test_get_gas_metrics():
    """Tests real-time gas tracking metrics on Ethereum Mainnet RPC."""
    try:
        metrics = await get_gas_metrics(chain="eth")
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")

    assert metrics["chain"] == "ETH"
    assert metrics["block_number"] > 0
    assert float(metrics["base_fee_gwei"]) >= 0
    assert float(metrics["slow_gwei"]) > 0
    assert float(metrics["avg_gwei"]) >= float(metrics["slow_gwei"])
    assert float(metrics["fast_gwei"]) >= float(metrics["avg_gwei"])
    assert "%" in metrics["block_utilization_pct"]


@pytest.mark.asyncio
async def test_resolve_proxy_direct_contract():
    """Tests proxy resolver on WETH (which is a direct non-proxy contract)."""
    weth_addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    try:
        res = await resolve_proxy(weth_addr, chain="eth")
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")

    assert res["contract_address"] == weth_addr
    assert res["is_proxy"] is False
    assert "Direct Contract" in res["proxy_type"]


@pytest.mark.asyncio
async def test_resolve_proxy_usdc():
    """Tests proxy resolver on USDC (EIP-1967 Transparent proxy on Ethereum Mainnet)."""
    usdc_proxy = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    try:
        res = await resolve_proxy(usdc_proxy, chain="eth")
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")

    assert res["contract_address"] == usdc_proxy
    assert res["is_proxy"] is True
    assert "Proxy" in res["proxy_type"]
    assert res["implementation"] is not None
    assert res["implementation"].startswith("0x")
    assert res["admin"] is not None
    assert res["admin"].startswith("0x")


@pytest.mark.asyncio
async def test_fetch_contract_source_mocked():
    """Deterministically validates Etherscan V2 response parsing offline."""
    from unittest.mock import AsyncMock, MagicMock

    payload = {
        "status": "1",
        "result": [{
            "ContractName": "WETH9",
            "ABI": '[{"constant":true,"inputs":[],"name":"name","type":"function"}]',
            "CompilerVersion": "v0.4.19+commit.c4cffa57",
            "OptimizationUsed": "0",
            "Runs": "0",
            "LicenseType": "None",
            "EVMVersion": "Default",
            "ConstructorArguments": "",
            "Proxy": "0",
            "Implementation": "",
        }],
    }
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=payload)
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_cm)

    res = await fetch_contract_source("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", chain="eth", session=mock_session)
    assert res["success"] is True
    assert res["is_verified"] is True
    assert res["contract_name"] == "WETH9"
    assert res["has_abi"] is True


@pytest.mark.asyncio
async def test_fetch_contract_source_weth():
    """Tests fetching verified contract source info from Etherscan V2 when API key is configured."""
    from config import settings
    if not settings.ETHERSCAN_API_KEY:
        pytest.skip("ETHERSCAN_API_KEY not configured")

    weth_addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    res = await fetch_contract_source(weth_addr, chain="eth")
    if not res.get("success"):
        pytest.skip(f"Explorer API unavailable or rate-limited: {res.get('error')}")

    assert res["is_verified"] is True
    assert "WETH" in res["contract_name"]
    assert res["has_abi"] is True
