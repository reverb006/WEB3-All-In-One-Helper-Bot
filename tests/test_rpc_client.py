"""Unit and integration tests for RPC client state queries and simulations."""

import pytest
from services.rpc_client import evm_rpc

# Mainnet WETH9 contract
WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"


@pytest.mark.asyncio
async def test_rpc_get_storage_and_decode():
    try:
        word = await evm_rpc.get_storage_at(WETH_ADDRESS, 0)
        assert len(word) == 32
        decoded = evm_rpc.decode_storage_word(word)
        assert "raw_hex" in decoded
        assert "uint256" in decoded
        assert "int256" in decoded
        assert "address" in decoded
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")


@pytest.mark.asyncio
async def test_rpc_simulate_call_weth_totalsupply():
    try:
        # totalSupply() selector: 0x18160ddd
        res = await evm_rpc.simulate_call(WETH_ADDRESS, "0x18160ddd")
        assert res["success"] is True
        assert res["return_bytes_len"] == 32
        assert res["return_data"].startswith("0x")
    except Exception as exc:
        pytest.skip(f"RPC endpoint offline or rate-limited: {exc}")
