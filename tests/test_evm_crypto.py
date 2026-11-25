"""Unit tests for pure EVM cryptography, address derivation, and unit conversions."""

import pytest
from eth_utils import keccak
from services.evm_crypto import (
    compute_create2_address,
    compute_create_address,
    compute_error_selector,
    compute_mapping_slot,
    compute_selector,
    convert_units,
    hex_to_int256,
    hex_to_uint256,
    int_to_hex256,
    keccak256_hex,
)


def test_keccak_and_selectors():
    # ERC20 transfer(address,uint256)
    sig = "transfer(address,uint256)"
    selector = compute_selector(sig)
    assert selector == "0xa9059cbb"

    # Handles intra-whitespace
    assert compute_selector("transfer(address, uint256)") == "0xa9059cbb"

    # ERC20 balanceOf(address)
    assert compute_selector("balanceOf(address)") == "0x70a08231"

    # Custom Error: Unauthorized() -> 0x82b42900
    assert compute_error_selector("Unauthorized()") == "0x82b42900"

    # Custom Error: InsufficientBalance(uint256,uint256)
    assert compute_error_selector("InsufficientBalance(uint256,uint256)") == "0xcf479181"

    # Raw keccak256 string
    h = keccak256_hex("Hello World")
    assert h.startswith("0x")
    assert len(h) == 66


def test_create_address_derivation():
    # Known Ethereum CREATE test vectors:
    # Deployer: 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0
    deployer = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
    addr_0 = compute_create_address(deployer, 0)
    assert addr_0 == "0xcd234A471b72ba2F1Ccf0A70FCABA648a5eeCD8d"

    addr_1 = compute_create_address(deployer, 1)
    assert addr_1 == "0x343c43A37D37dfF08AE8C4A11544c718AbB4fCF8"

    with pytest.raises(ValueError):
        compute_create_address("0xinvalid", 0)

    with pytest.raises(ValueError):
        compute_create_address(deployer, -1)


def test_create2_address_derivation():
    # 1. EIP-1014 Specification Test Vector:
    # Deployer: 0x0000000000000000000000000000000000000000
    # Salt: 0x0000000000000000000000000000000000000000000000000000000000000000
    # Init code: 0x00 -> keccak256(0x00)
    # Expected address: 0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38
    deployer = "0x0000000000000000000000000000000000000000"
    salt = "0x0"
    init_code = "0x00"
    addr = compute_create2_address(deployer, salt, init_code)
    assert addr == "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38"

    # 2. Canonical Uniswap V2 DAI/WETH Pair Test Vector:
    factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
    dai = bytes.fromhex("6B175474E89094C44Da98b954EedeAC495271d0F")
    weth = bytes.fromhex("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
    t0, t1 = sorted([dai, weth])
    pair_salt = keccak(t0 + t1)
    init_code_hash = "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f"
    pair_addr = compute_create2_address(factory, pair_salt, init_code_hash)
    assert pair_addr == "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"


def test_mapping_slot_calculation():
    # Address key at slot 0
    vitalik = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    info = compute_mapping_slot(vitalik, 0)
    assert info["slot_hex"].startswith("0x")
    assert len(info["slot_hex"]) == 66
    assert info["key_type"] == "address"
    assert info["base_slot"] == 0

    # Uint key at slot 2
    info_uint = compute_mapping_slot("1", 2)
    assert info_uint["key_type"] == "uint256"
    assert info_uint["slot_int"] > 0


def test_hex_int256_conversions():
    # 0 -> 0x00...00
    zero_hex = int_to_hex256(0)
    assert zero_hex == "0x" + "0" * 64
    assert hex_to_uint256(zero_hex) == 0
    assert hex_to_int256(zero_hex) == 0

    # 1 -> 0x00...01
    one_hex = int_to_hex256(1)
    assert one_hex == "0x" + "0" * 63 + "1"
    assert hex_to_uint256(one_hex) == 1
    assert hex_to_int256(one_hex) == 1

    # -1 -> 0xff...ff
    neg_one_hex = int_to_hex256(-1)
    assert neg_one_hex == "0x" + "f" * 64
    assert hex_to_int256(neg_one_hex) == -1
    assert hex_to_uint256(neg_one_hex) == 2**256 - 1

    # -100
    neg_100_hex = int_to_hex256(-100)
    assert hex_to_int256(neg_100_hex) == -100


def test_unit_conversions():
    # 1.5 ETH
    conv = convert_units("1.5", "eth")
    assert conv["wei_raw"] == "1500000000000000000"
    assert conv["gwei"] == "1500000000"
    assert conv["ether"] == "1.5"

    # 50 Gwei
    conv_gwei = convert_units("50", "gwei")
    assert conv_gwei["wei_raw"] == "50000000000"
    assert conv_gwei["ether"] == "0.00000005"

    # 1000 Wei
    conv_wei = convert_units("1000", "wei")
    assert conv_wei["wei_raw"] == "1000"

    with pytest.raises(ValueError):
        convert_units("invalid", "eth")

    with pytest.raises(ValueError):
        convert_units("1.0", "unknown_unit")
