"""Unit tests for the Solidity & Foundry Special Functions and Reference service."""

import pytest
from services.solidity_docs import (
    SOLIDITY_REFERENCE,
    get_all_categories,
    search_solidity,
)


def test_reference_database_structure():
    """Validates that all entries in the reference database have complete metadata."""
    assert len(SOLIDITY_REFERENCE) >= 30

    required_fields = ["id", "name", "category", "syntax", "description", "auditor_notes", "example", "aliases"]
    for item in SOLIDITY_REFERENCE:
        for field in required_fields:
            assert field in item, f"Missing field '{field}' in item '{item.get('name')}'"
            assert item[field], f"Field '{field}' cannot be empty in item '{item.get('name')}'"
        assert isinstance(item["aliases"], list)


def test_search_special_contract_functions():
    """Tests search for receive, fallback, and constructor."""
    for fn in ["receive", "receive()", "fallback", "fallback()", "constructor"]:
        res = search_solidity(fn)
        assert res["found"] is True
        assert res["item"] is not None
        assert "Special Contract Functions" in res["item"]["category"]


def test_search_global_variables_and_gasleft():
    """Tests search for msg.sender, tx.origin, block.timestamp, gasleft, gas.left, blobbasefee."""
    queries = [
        ("gasleft", "gasleft"),
        ("gas.left", "gasleft"),
        ("gas_left", "gasleft"),
        ("msg.sender", "msg_sender"),
        ("sender", "msg_sender"),
        ("tx.origin", "tx_origin"),
        ("origin", "tx_origin"),
        ("block.timestamp", "block_timestamp"),
        ("timestamp", "block_timestamp"),
        ("prevrandao", "block_prevrandao"),
        ("block.chainid", "block_chainid"),
        ("blobbasefee", "block_blobbasefee"),
        ("blobhash", "blobhash"),
    ]
    for q, expected_id in queries:
        res = search_solidity(q)
        assert res["found"] is True, f"Failed to find {q}"
        assert res["item"]["id"] == expected_id, f"Expected {expected_id} for {q}, got {res['item']['id']}"
        assert res["item"]["category"] == "Global Variables"


def test_search_address_and_contract_members():
    """Tests search for address(this), .balance, .code, .codehash."""
    queries = ["address(this)", "this", "balance", "address.balance", "code", "codehash"]
    for q in queries:
        res = search_solidity(q)
        assert res["found"] is True, f"Failed to find {q}"
        assert res["item"]["category"] == "Address & Contract Members"


def test_search_abi_encoding():
    """Tests search for abi.encode, abi.encodePacked, abi.encodeCall, abi.decode."""
    for q in ["abi.encode", "encodePacked", "abi.encodePacked", "abi.encodeCall", "abi.decode"]:
        res = search_solidity(q)
        assert res["found"] is True, f"Failed to find {q}"
        assert res["item"]["category"] == "ABI Encoding"
        if "encodePacked" in q:
            assert "collision" in res["item"]["auditor_notes"].lower()


def test_search_cryptography():
    """Tests search for keccak256 and ecrecover."""
    res_keccak = search_solidity("keccak256")
    assert res_keccak["found"] is True
    assert res_keccak["item"]["category"] == "Cryptography"

    res_ecrecover = search_solidity("ecrecover")
    assert res_ecrecover["found"] is True
    assert "malleability" in res_ecrecover["item"]["auditor_notes"].lower()
    assert "address(0)" in res_ecrecover["item"]["auditor_notes"].lower()


def test_search_low_level_calls():
    """Tests search for call, delegatecall, staticcall, selfdestruct."""
    for q in ["call", ".call", "delegatecall", "staticcall", "selfdestruct"]:
        res = search_solidity(q)
        assert res["found"] is True, f"Failed to find {q}"
        assert res["item"]["category"] == "Low-Level Calls"


def test_search_transient_storage_and_yul():
    """Tests search for tstore, tload, sstore, sload, mstore."""
    res_tstore = search_solidity("tstore")
    assert res_tstore["found"] is True
    assert "EIP-1153" in res_tstore["item"]["description"]

    res_sstore = search_solidity("sstore")
    assert res_sstore["found"] is True


def test_search_foundry_cheatcodes():
    """Tests search for Foundry cheatcodes like vm.prank, vm.warp, vm.deal, vm.expectRevert."""
    cheatcodes = [
        ("vm.prank", "vm_prank"),
        ("prank", "vm_prank"),
        ("startprank", "vm_prank"),
        ("vm.deal", "vm_deal"),
        ("deal", "vm_deal"),
        ("vm.warp", "vm_warp"),
        ("warp", "vm_warp"),
        ("vm.roll", "vm_roll"),
        ("roll", "vm_roll"),
        ("vm.expectRevert", "vm_expectRevert"),
        ("expectrevert", "vm_expectRevert"),
        ("expectRevert", "vm_expectRevert"),
        ("vm.expectEmit", "vm_expectEmit"),
        ("expectemit", "vm_expectEmit"),
        ("vm.mockCall", "vm_mockCall"),
        ("mockcall", "vm_mockCall"),
        ("vm.load", "vm_load_store"),
        ("vm.store", "vm_load_store"),
        ("vm.sign", "vm_sign"),
        ("vm.addr", "vm_sign"),
        ("vm.assume", "vm_assume"),
        ("assume", "vm_assume"),
        ("console.log", "console_log"),
        ("console", "console_log"),
    ]
    for q, expected_id in cheatcodes:
        res = search_solidity(q)
        assert res["found"] is True, f"Failed to find Foundry cheatcode for '{q}'"
        assert res["item"]["id"] == expected_id, f"Expected {expected_id} for '{q}', got {res['item']['id']}"
        assert res["item"]["category"] == "Foundry Cheatcodes"


def test_fuzzy_and_suggestions():
    """Tests typo suggestions and non-matching queries."""
    # Typo: 'receve'
    res_typo = search_solidity("receve")
    assert res_typo["found"] is False
    assert any("receive" in s.lower() for s in res_typo["suggestions"])

    # Empty query
    res_empty = search_solidity("")
    assert res_empty["found"] is False
    assert len(res_empty["suggestions"]) > 0


def test_get_all_categories():
    """Tests category grouping helper."""
    cats = get_all_categories()
    assert len(cats) >= 6
    assert "Special Contract Functions" in cats
    assert "Global Variables" in cats
    assert "Address & Contract Members" in cats
    assert "ABI Encoding" in cats
    assert "Cryptography" in cats
    assert "Low-Level Calls" in cats
    assert "Foundry Cheatcodes" in cats
