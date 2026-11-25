"""Unit tests for calldata decoding, error decoding, and signature parsing."""

import pytest
from eth_abi import encode
from services.decoder import (
    decode_calldata,
    decode_revert_data,
    fetch_signatures,
    parse_function_signature,
)


def test_signature_parsing():
    # Simple signature
    name, types = parse_function_signature("transfer(address,uint256)")
    assert name == "transfer"
    assert types == ["address", "uint256"]

    # Zero args
    name, types = parse_function_signature("totalSupply()")
    assert name == "totalSupply"
    assert types == []

    # Nested tuple
    name, types = parse_function_signature("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))")
    assert name == "exactInputSingle"
    assert types == ["(address,address,uint24,address,uint256,uint256,uint160)"]

    # Array of tuples
    name, types = parse_function_signature("multicall(bytes[],address)")
    assert name == "multicall"
    assert types == ["bytes[]", "address"]


@pytest.mark.asyncio
async def test_revert_string_decoding():
    # Standard Error(string): selector 0x08c379a0 + abi.encode("Unauthorized access")
    selector = bytes.fromhex("08c379a0")
    encoded_str = encode(["string"], ["Unauthorized access"])
    revert_data = (selector + encoded_str).hex()

    decoded = await decode_revert_data(revert_data)
    assert decoded["type"] == "Error(string)"
    assert decoded["reason"] == "Unauthorized access"


@pytest.mark.asyncio
async def test_panic_code_decoding():
    # Standard Panic(uint256): selector 0x4e487b71 + abi.encode(0x11) -> Arithmetic overflow/underflow
    selector = bytes.fromhex("4e487b71")
    encoded_panic = encode(["uint256"], [0x11])
    revert_data = (selector + encoded_panic).hex()

    decoded = await decode_revert_data(revert_data)
    assert decoded["type"] == "Panic(uint256)"
    assert decoded["code"] == 0x11
    assert "overflow" in decoded["explanation"].lower()


@pytest.mark.asyncio
async def test_empty_revert_data():
    decoded = await decode_revert_data("")
    assert decoded["type"] == "empty"


@pytest.mark.asyncio
async def test_decode_calldata_erc20_transfer_mocked(monkeypatch):
    from unittest.mock import AsyncMock
    import services.decoder as dec_mod

    monkeypatch.setattr(dec_mod, "fetch_signatures", AsyncMock(return_value=["transfer(address,uint256)"]))
    vitalik = "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
    one_eth = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
    calldata = "0xa9059cbb" + vitalik + one_eth

    res = await decode_calldata(calldata)
    assert res["success"] is True
    assert res["selector"] == "0xa9059cbb"
    decoded_matches = [m for m in res["decoded_matches"] if m.get("success")]
    assert len(decoded_matches) == 1
    assert decoded_matches[0]["function_name"] == "transfer"
    assert "d8da6bf26964af9d7eed9e03e53415d37aa96045" in decoded_matches[0]["params"][0]["value"].lower()
    assert decoded_matches[0]["params"][1]["value"] == "1000000000000000000"


@pytest.mark.asyncio
async def test_fetch_signatures_openchain():
    # 0xa9059cbb is transfer(address,uint256)
    sigs = await fetch_signatures("0xa9059cbb")
    if not sigs:
        pytest.skip("OpenChain / 4byte APIs unreachable or rate-limited")
    assert any("transfer(address,uint256)" in s for s in sigs)


@pytest.mark.asyncio
async def test_decode_calldata_erc20_transfer():
    # transfer(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045, 1000000000000000000)
    vitalik = "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
    one_eth = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
    calldata = "0xa9059cbb" + vitalik + one_eth

    res = await decode_calldata(calldata)
    if not res.get("signatures"):
        pytest.skip("OpenChain / 4byte APIs unreachable or rate-limited")
    assert res["success"] is True
    assert res["selector"] == "0xa9059cbb"

    decoded_matches = [m for m in res["decoded_matches"] if m.get("success")]
    assert len(decoded_matches) > 0
    match = decoded_matches[0]
    assert match["function_name"] == "transfer"
    assert len(match["params"]) == 2
    assert match["params"][0]["type"] == "address"
    assert "d8da6bf26964af9d7eed9e03e53415d37aa96045" in match["params"][0]["value"].lower()
    assert match["params"][1]["type"] == "uint256"
    assert match["params"][1]["value"] == "1000000000000000000"
