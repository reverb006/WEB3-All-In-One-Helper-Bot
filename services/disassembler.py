"""EVM Bytecode Disassembler.

Parses raw EVM bytecode into human-readable mnemonic instructions with PC offsets,
immediate operands, JUMPDEST tracking, and Cancun/Dencun opcode support.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from services.evm_crypto import clean_hex

OPCODES: Dict[int, str] = {
    # 0x00: Stop and Arithmetic Operations
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    # 0x10: Comparison & Bitwise Logic Operations
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    # 0x20: Cryptographic Operations
    0x20: "KECCAK256",
    # 0x30: Environmental Information
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    # 0x40: Block Information
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    # 0x50: Stack, Memory, Storage and Flow Operations
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    # 0x80..0x8F: Duplication Operations
    **{0x80 + i: f"DUP{i+1}" for i in range(16)},
    # 0x90..0x9F: Exchange Operations
    **{0x90 + i: f"SWAP{i+1}" for i in range(16)},
    # 0xA0..0xA4: Logging Operations
    **{0xA0 + i: f"LOG{i}" for i in range(5)},
    # 0xE0..0xEF: EOF Preview Opcodes
    0xE0: "RJUMP",
    0xE1: "RJUMPI",
    0xE2: "RJUMPV",
    0xE3: "CALLF",
    0xE4: "RETF",
    0xE5: "JUMPF",
    0xD0: "DATALOAD",
    0xD1: "DATALOADN",
    0xD2: "DATASIZE",
    0xD3: "DATACOPY",
    # 0xF0: System Operations
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

# Add PUSH1 to PUSH32
for i in range(1, 33):
    OPCODES[0x5F + i] = f"PUSH{i}"


@dataclass
class Instruction:
    """Represents a disassembled EVM instruction."""
    pc: int
    opcode: int
    mnemonic: str
    operand: Optional[bytes] = None

    @property
    def operand_hex(self) -> str:
        """Returns 0x-prefixed hex string of operand if present."""
        if self.operand is not None:
            return "0x" + self.operand.hex()
        return ""

    def __str__(self) -> str:
        pc_str = f"[{self.pc:04x}]"
        if self.operand is not None:
            return f"{pc_str} {self.mnemonic:<8} {self.operand_hex}"
        return f"{pc_str} {self.mnemonic}"


def disassemble(bytecode: str | bytes) -> Tuple[List[Instruction], Dict[str, int]]:
    """Disassembles hex string or raw bytes into EVM Instructions.

    Args:
        bytecode: Raw bytecode as hex or bytes.

    Returns:
        Tuple of (list_of_instructions, statistics_dict)
    """
    if isinstance(bytecode, str):
        raw_hex = clean_hex(bytecode)
        if len(raw_hex) % 2 != 0:
            raw_hex = "0" + raw_hex
        data = bytes.fromhex(raw_hex)
    else:
        data = bytecode

    instructions: List[Instruction] = []
    jumpdest_count = 0
    push_count = 0
    pc = 0
    length = len(data)

    while pc < length:
        op = data[pc]
        mnemonic = OPCODES.get(op, f"UNKNOWN(0x{op:02x})")

        if 0x60 <= op <= 0x7F:
            # PUSH1 .. PUSH32
            push_len = op - 0x5F
            operand = data[pc + 1 : pc + 1 + push_len]
            # If remaining bytes are less than push_len, slice returns available bytes
            instructions.append(Instruction(pc=pc, opcode=op, mnemonic=mnemonic, operand=operand))
            push_count += 1
            pc += 1 + len(operand)
        elif op == 0x5F:
            # PUSH0 (no immediate bytes)
            instructions.append(Instruction(pc=pc, opcode=op, mnemonic=mnemonic))
            push_count += 1
            pc += 1
        elif op in (0xE0, 0xE1):
            # RJUMP / RJUMPI: 2 immediate bytes
            operand = data[pc + 1 : pc + 3]
            instructions.append(Instruction(pc=pc, opcode=op, mnemonic=mnemonic, operand=operand))
            pc += 1 + len(operand)
        else:
            if op == 0x5B:
                jumpdest_count += 1
            instructions.append(Instruction(pc=pc, opcode=op, mnemonic=mnemonic))
            pc += 1

    stats = {
        "bytecode_size": length,
        "instruction_count": len(instructions),
        "jumpdest_count": jumpdest_count,
        "push_count": push_count,
    }

    return instructions, stats


def format_disassembly(
    instructions: List[Instruction],
    stats: Dict[str, int],
    max_lines: int = 70
) -> str:
    """Formats disassembly output into a clean string suitable for Telegram display.

    Args:
        instructions: List of parsed instructions.
        stats: Statistics dictionary.
        max_lines: Cap on displayed instruction lines.

    Returns:
        Formatted disassembly string.
    """
    lines = []
    lines.append(
        f"// Size: {stats['bytecode_size']} bytes | Total: {stats['instruction_count']} instructions | JUMPDESTs: {stats['jumpdest_count']}"
    )
    lines.append("// " + "-" * 45)

    displayed_instructions = instructions[:max_lines]
    for inst in displayed_instructions:
        lines.append(str(inst))

    if len(instructions) > max_lines:
        remaining = len(instructions) - max_lines
        lines.append(f"... [{remaining} more instructions truncated]")

    return "\n".join(lines)
