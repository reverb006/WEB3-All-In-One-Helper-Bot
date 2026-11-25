"""Unit tests for the EVM bytecode disassembler."""

from services.disassembler import disassemble, format_disassembly


def test_disassembler_standard_preamble():
    # Standard Solidity preamble:
    # 6080 (PUSH1 0x80)
    # 6040 (PUSH1 0x40)
    # 52   (MSTORE)
    # 34   (CALLVALUE)
    # 80   (DUP1)
    # 15   (ISZERO)
    # 600f (PUSH1 0x0f)
    # 57   (JUMPI)
    # 6000 (PUSH1 0x00)
    # 80   (DUP1)
    # fd   (REVERT)
    # 5b   (JUMPDEST)
    # 50   (POP)
    bytecode = "6080604052348015600f57600080fd5b50"
    instructions, stats = disassemble(bytecode)

    assert stats["bytecode_size"] == 17
    assert stats["instruction_count"] == 13
    assert stats["jumpdest_count"] == 1
    assert stats["push_count"] == 4

    mnemonics = [inst.mnemonic for inst in instructions]
    assert mnemonics == [
        "PUSH1",
        "PUSH1",
        "MSTORE",
        "CALLVALUE",
        "DUP1",
        "ISZERO",
        "PUSH1",
        "JUMPI",
        "PUSH1",
        "DUP1",
        "REVERT",
        "JUMPDEST",
        "POP",
    ]

    assert instructions[0].operand_hex == "0x80"
    assert instructions[1].operand_hex == "0x40"
    assert instructions[6].operand_hex == "0x0f"
    assert instructions[8].operand_hex == "0x00"

    formatted = format_disassembly(instructions, stats)
    assert "PUSH1" in formatted
    assert "MSTORE" in formatted
    assert "JUMPDEST" in formatted


def test_push0_and_cancun_opcodes():
    # 5f (PUSH0), 5e (MCOPY), 5c (TLOAD), 5d (TSTORE)
    bytecode = "5f5e5c5d00"
    instructions, stats = disassemble(bytecode)
    mnemonics = [inst.mnemonic for inst in instructions]
    assert mnemonics == ["PUSH0", "MCOPY", "TLOAD", "TSTORE", "STOP"]
    assert stats["instruction_count"] == 5
    assert stats["push_count"] == 1
