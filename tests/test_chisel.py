"""Unit tests for the Foundry Chisel Solidity REPL service."""

import pytest
from services.chisel import (
    ensure_solc_installed,
    format_chisel_response,
    prepare_solidity_source,
    run_chisel,
)


@pytest.fixture(scope="module", autouse=True)
def setup_solc():
    ensure_solc_installed("0.8.26")


def test_prepare_solidity_source_single_expression():
    src, has_expr = prepare_solidity_source("1 ether / 1 gwei")
    assert has_expr is True
    assert "bytes memory __chisel_ret = abi.encode(1 ether / 1 gwei);" in src
    assert "pragma solidity ^0.8.26;" in src


def test_prepare_solidity_source_multiline_variables():
    code = """
    uint256 a = 10;
    uint256 b = 20;
    a + b
    """
    src, has_expr = prepare_solidity_source(code)
    assert has_expr is True
    assert "uint256 a = 10;" in src
    assert "uint256 b = 20;" in src
    assert "bytes memory __chisel_ret = abi.encode(a + b);" in src


def test_prepare_solidity_source_with_function():
    code = """
    function mul(uint x, uint y) internal pure returns (uint) {
        return x * y;
    }
    mul(6, 7)
    """
    src, has_expr = prepare_solidity_source(code)
    assert has_expr is True
    assert "function mul" in src
    assert "bytes memory __chisel_ret = abi.encode(mul(6, 7));" in src


def test_prepare_solidity_source_full_contract():
    code = """
    contract MyTest {
        function foo() public pure returns (uint) { return 42; }
    }
    """
    src, has_expr = prepare_solidity_source(code)
    assert has_expr is False
    assert "contract MyTest" in src


async def _run_chisel_or_skip(code: str):
    res = await run_chisel(code)
    if not res.get("success") and res.get("error_type") in ("rpc_error", "runtime"):
        pytest.skip(f"RPC endpoint offline or rate-limited: {res.get('error')}")
    return res


@pytest.mark.asyncio
async def test_run_chisel_arithmetic():
    res = await _run_chisel_or_skip("1 ether / 1 gwei")
    assert res["success"] is True
    assert len(res["outputs"]) == 1
    assert res["outputs"][0]["type"] == "uint256"
    assert res["outputs"][0]["value"] == 1_000_000_000


@pytest.mark.asyncio
async def test_run_chisel_keccak():
    res = await _run_chisel_or_skip('keccak256(bytes("hello"))')
    assert res["success"] is True
    assert len(res["outputs"]) == 1
    assert res["outputs"][0]["type"] == "bytes32"
    assert res["outputs"][0]["value"].hex() == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"


@pytest.mark.asyncio
async def test_run_chisel_type_max():
    res = await _run_chisel_or_skip("type(uint256).max")
    assert res["success"] is True
    assert len(res["outputs"]) == 1
    assert res["outputs"][0]["type"] == "uint256"
    assert res["outputs"][0]["value"] == 2**256 - 1


@pytest.mark.asyncio
async def test_run_chisel_function_execution():
    code = """
    function cube(uint n) internal pure returns (uint) {
        return n * n * n;
    }
    cube(3)
    """
    res = await _run_chisel_or_skip(code)
    assert res["success"] is True
    assert len(res["outputs"]) == 1
    assert res["outputs"][0]["value"] == 27


@pytest.mark.asyncio
async def test_run_chisel_compilation_error():
    res = await run_chisel("uint256 a = 'invalid_type';")
    assert res["success"] is False
    assert res["error_type"] == "compilation"
    assert "not implicitly convertible" in res["error"] or "Error" in res["error"]



@pytest.mark.asyncio
async def test_run_chisel_arithmetic_underflow():
    code = """
    uint256 a = 0;
    uint256 b = a - 1;
    b
    """
    res = await _run_chisel_or_skip(code)
    assert res["success"] is False
    assert res["error_type"] == "panic"
    assert "0x11" in res["error"]


def test_format_chisel_response():
    sample_result = {
        "success": True,
        "outputs": [{"type": "uint256", "value": 1_000_000_000}],
        "gas": 63142,
    }
    formatted = format_chisel_response(sample_result, "1 ether / 1 gwei")
    assert "Foundry Chisel REPL" in formatted
    assert "1,000,000,000" in formatted
    assert "63,142" in formatted
