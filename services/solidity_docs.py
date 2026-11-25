"""Solidity & Foundry Reference Service.

Authoritative, auditor-curated reference database for:
1. Special Contract Functions (receive, fallback, constructor)
2. Global Variables & Execution Context (msg.*, tx.*, block.*, gasleft, blobhash)
3. Address & Contract Members (address(this), .balance, .code, .codehash)
4. ABI Encoding & Decoding (abi.encode, abi.encodePacked, abi.encodeCall, etc.)
5. Cryptographic Primitives (keccak256, ecrecover, sha256, ripemd160)
6. Error Handling & Invariants (require, assert, revert, custom errors)
7. Low-Level Calls & Transfers (.call, .delegatecall, .staticcall, .transfer, .send, selfdestruct)
8. Mathematical Functions (addmod, mulmod)
9. Type Introspection & Units (type(T), ether units, time units)
10. Inline Assembly / Yul (mstore, mload, sstore, sload, tstore, tload, calldatacopy)
11. Foundry Cheatcodes (vm.prank, vm.warp, vm.roll, vm.deal, vm.expectRevert, vm.expectEmit,
    vm.mockCall, vm.load, vm.store, vm.sign, vm.addr, vm.assume, console.log)
"""

from typing import Any, Dict, List, Optional
import difflib

SOLIDITY_REFERENCE: List[Dict[str, Any]] = [
    # =========================================================================
    # 1. Special Contract Functions
    # =========================================================================
    {
        "id": "receive",
        "name": "receive()",
        "category": "Special Contract Functions",
        "syntax": "receive() external payable { ... }",
        "description": (
            "Executed on plain Ether transfers when calldata (msg.data) is completely empty. "
            "A contract can have at most one receive function. It cannot take parameters, cannot "
            "return anything, and must have external visibility and payable state mutability."
        ),
        "auditor_notes": (
            "• Falls back to fallback() if receive() does not exist.\n"
            "• If Ether is sent via .transfer() or .send(), receive() only receives a 2300 gas stipend. "
            "Keep logic minimal (such as emitting an event) to avoid out-of-gas reverts.\n"
            "• To reject plain Ether transfers, omit receive() and make fallback() non-payable."
        ),
        "example": (
            "// Emits an event upon receiving plain Ether\n"
            "receive() external payable {\n"
            "    emit FundsReceived(msg.sender, msg.value);\n"
            "}"
        ),
        "aliases": ["receive", "receive()", "receive ether", "plain ether"],
    },
    {
        "id": "fallback",
        "name": "fallback()",
        "category": "Special Contract Functions",
        "syntax": "fallback() external [payable] { ... }\n// Or with calldata/returndata:\nfallback(bytes calldata input) external [payable] returns (bytes memory output)",
        "description": (
            "Executed when a call does not match any function selector in the contract, or if msg.data "
            "is empty and no receive() function is defined. It is the backbone of upgradeable proxy contracts."
        ),
        "auditor_notes": (
            "• If payable, it can accept Ether alongside arbitrary calldata.\n"
            "• In proxy contracts, fallback() uses assembly delegatecall to forward execution to logic contracts.\n"
            "• Unintended payable fallback functions can trap user funds or allow unexpected reentrancy."
        ),
        "example": (
            "// Standard upgradeable proxy fallback pattern\n"
            "fallback() external payable {\n"
            "    address logic = implementation;\n"
            "    assembly {\n"
            "        calldatacopy(0, 0, calldatasize())\n"
            "        let result := delegatecall(gas(), logic, 0, calldatasize(), 0, 0)\n"
            "        returndatacopy(0, 0, returndatasize())\n"
            "        switch result\n"
            "        case 0 { revert(0, returndatasize()) }\n"
            "        default { return(0, returndatasize()) }\n"
            "    }\n"
            "}"
        ),
        "aliases": ["fallback", "fallback()", "proxy fallback"],
    },
    {
        "id": "constructor",
        "name": "constructor()",
        "category": "Special Contract Functions",
        "syntax": "constructor(<parameters>) [payable] { ... }",
        "description": (
            "Optional contract initialization routine executed exactly once during contract creation. "
            "The constructor code is included in creation bytecode (init code) but is NOT included in "
            "the deployed runtime bytecode."
        ),
        "auditor_notes": (
            "• Upgradeable proxies DO NOT execute the implementation's constructor. Instead, use initialize() "
            "functions protected by OpenZeppelin's Initializable modifier.\n"
            "• Uninitialized implementation contracts can be hijacked (e.g. Parity wallet hack). Always call "
            "_disableInitializers() in the constructor of implementation contracts."
        ),
        "example": (
            "contract Token {\n"
            "    address public immutable owner;\n"
            "    \n"
            "    constructor(address initialOwner) {\n"
            "        require(initialOwner != address(0), \"Zero address\");\n"
            "        owner = initialOwner;\n"
            "    }\n"
            "}"
        ),
        "aliases": ["constructor", "constructor()", "init code", "initialization"],
    },

    # =========================================================================
    # 2. Global Variables & Execution Context
    # =========================================================================
    {
        "id": "gasleft",
        "name": "gasleft()",
        "category": "Global Variables",
        "syntax": "uint256 remaining = gasleft();",
        "description": (
            "Returns the remaining gas available in the current EVM execution frame. "
            "Corresponds directly to the EVM GAS opcode (0x5A)."
        ),
        "auditor_notes": (
            "⚠️ RELAYER & REENTRANCY ATTACK VECTOR:\n"
            "• 63/64th Rule (EIP-150): When calling another contract, at most 63/64 of the remaining gas is forwarded.\n"
            "• Gas Griefing: Do not rely strictly on gasleft() checks in relayers (e.g. requiring remaining gas > X) "
            "because an attacker can craft a transaction with just enough gas to make your sub-call fail while outer tx succeeds."
        ),
        "example": (
            "uint256 startGas = gasleft();\n"
            "// ... execute operation\n"
            "uint256 gasSpent = startGas - gasleft();"
        ),
        "aliases": ["gasleft", "gasleft()", "gas.left", "gas_left", "gas left", "remaining gas"],
    },
    {
        "id": "msg_sender",
        "name": "msg.sender",
        "category": "Global Variables",
        "syntax": "address sender = msg.sender;",
        "description": (
            "Returns the immediate caller (address) of the current execution frame. If an external user "
            "calls Contract A which calls Contract B, inside Contract B msg.sender is Contract A."
        ),
        "auditor_notes": (
            "• Crucial difference from tx.origin: msg.sender changes with each external contract call.\n"
            "• In meta-transactions (ERC-2771 / account abstraction), msg.sender is the trusted forwarder, "
            "so use _msgSender() to extract the real signer from calldata."
        ),
        "example": (
            "modifier onlyOwner() {\n"
            "    require(msg.sender == owner, \"Unauthorized\");\n"
            "    _;\n"
            "}"
        ),
        "aliases": ["msg.sender", "msgsender", "msg_sender", "sender", "caller"],
    },
    {
        "id": "msg_value",
        "name": "msg.value",
        "category": "Global Variables",
        "syntax": "uint256 amount = msg.value;",
        "description": (
            "Returns the number of Wei sent with the current transaction or message call. "
            "Can only be accessed in functions marked with the 'payable' modifier."
        ),
        "auditor_notes": (
            "• Dangerous in loops / multi-calls: msg.value is persistent across an entire transaction. "
            "If a multi-call executes multiple operations that each check msg.value, the same deposit "
            "can be double-credited (e.g., Sushiswap / BentoBox vulnerability)."
        ),
        "example": (
            "function deposit() external payable {\n"
            "    require(msg.value > 0, \"Zero deposit\");\n"
            "    balances[msg.sender] += msg.value;\n"
            "}"
        ),
        "aliases": ["msg.value", "msgvalue", "msg_value", "value", "wei sent"],
    },
    {
        "id": "msg_data",
        "name": "msg.data",
        "category": "Global Variables",
        "syntax": "bytes calldata data = msg.data;",
        "description": (
            "Returns the complete transaction calldata payload as a read-only 'bytes calldata' slice. "
            "Contains the 4-byte selector followed by ABI-encoded arguments."
        ),
        "auditor_notes": (
            "• Reading msg.data is gas-efficient because it references read-only calldata memory.\n"
            "• In ERC-2771 meta-transactions, the last 20 bytes of msg.data encode the real user's address."
        ),
        "example": (
            "// Forward entire calldata payload to logic contract\n"
            "(bool ok, bytes memory res) = target.call(msg.data);"
        ),
        "aliases": ["msg.data", "msgdata", "msg_data", "calldata", "raw calldata"],
    },
    {
        "id": "msg_sig",
        "name": "msg.sig",
        "category": "Global Variables",
        "syntax": "bytes4 selector = msg.sig;",
        "description": (
            "Returns the first four bytes of the calldata (i.e. the function selector identifying "
            "which function was invoked)."
        ),
        "auditor_notes": (
            "• Equivalent to 'bytes4(msg.data[:4])'.\n"
            "• Often used in permission managers or proxy contracts to enforce function-level ACLs."
        ),
        "example": (
            "function checkPermission() internal view {\n"
            "    require(isAllowed[msg.sig][msg.sender], \"Forbidden function\");\n"
            "}"
        ),
        "aliases": ["msg.sig", "msgsig", "msg_sig", "selector", "function selector"],
    },
    {
        "id": "tx_origin",
        "name": "tx.origin",
        "category": "Global Variables",
        "syntax": "address origin = tx.origin;",
        "description": (
            "Returns the original Externally Owned Account (EOA) that signed and initiated the transaction. "
            "Unlike msg.sender, tx.origin never changes throughout a sequence of nested contract calls."
        ),
        "auditor_notes": (
            "🚨 CRITICAL SECURITY VULNERABILITY: NEVER use tx.origin for authorization!\n"
            "• If Alice is tricked into calling a malicious contract, that malicious contract can call "
            "your contract, and tx.origin will still be Alice! This enables phishing attacks.\n"
            "• It also breaks account abstraction (ERC-4337 smart contract wallets, where tx.origin is a bundler)."
        ),
        "example": (
            "// ❌ INSECURE:\n"
            "// require(tx.origin == owner); // Phishing vulnerable!\n\n"
            "// ✅ SECURE:\n"
            "require(msg.sender == owner, \"Not authorized\");"
        ),
        "aliases": ["tx.origin", "txorigin", "tx_origin", "origin", "tx origin", "eoa sender"],
    },
    {
        "id": "tx_gasprice",
        "name": "tx.gasprice",
        "category": "Global Variables",
        "syntax": "uint256 price = tx.gasprice;",
        "description": (
            "Returns the gas price of the transaction in Wei. Under EIP-1559, this represents the effective "
            "gas price paid by the sender (basefee + priority fee)."
        ),
        "auditor_notes": (
            "• Can be manipulated by users/searchers via priority fee bids.\n"
            "• Used by relayers to compute gas refunds: tx.gasprice * gasUsed."
        ),
        "example": (
            "uint256 refund = gasSpent * tx.gasprice;\n"
            "payable(msg.sender).transfer(refund);"
        ),
        "aliases": ["tx.gasprice", "txgasprice", "tx_gasprice", "gasprice", "gas price"],
    },
    {
        "id": "block_timestamp",
        "name": "block.timestamp",
        "category": "Global Variables",
        "syntax": "uint256 currentTime = block.timestamp;",
        "description": (
            "Current block timestamp in seconds since Unix epoch (1970-01-01). Equivalent to 'now' "
            "(which was deprecated in Solidity 0.7.0)."
        ),
        "auditor_notes": (
            "• Validators have slight discretion over block timestamps (typically +-15 seconds).\n"
            "• NEVER use block.timestamp as a source of pseudo-randomness for lotteries or games.\n"
            "• Safe for lockups, vesting schedules, or auctions spanning hours or days."
        ),
        "example": (
            "function withdraw() external {\n"
            "    require(block.timestamp >= lockExpiry[msg.sender], \"Locked\");\n"
            "    // ... process withdrawal\n"
            "}"
        ),
        "aliases": ["block.timestamp", "blocktimestamp", "block_timestamp", "timestamp", "now", "time"],
    },
    {
        "id": "block_number",
        "name": "block.number",
        "category": "Global Variables",
        "syntax": "uint256 currentBlock = block.number;",
        "description": (
            "Returns the current Ethereum block number. Increments sequentially with each block."
        ),
        "auditor_notes": (
            "• On L2 networks (Arbitrum, Optimism, Base), block.number may return the L1 block number "
            "or L2 sequencer block number depending on network configuration.\n"
            "• Don't assume 12-second block intervals across different EVM chains."
        ),
        "example": (
            "require(block.number > votingEndBlock, \"Voting still active\");"
        ),
        "aliases": ["block.number", "blocknumber", "block_number", "block height", "block num"],
    },
    {
        "id": "block_prevrandao",
        "name": "block.prevrandao",
        "category": "Global Variables",
        "syntax": "uint256 randomSeed = block.prevrandao;",
        "description": (
            "Randomness output provided by the beacon chain consensus layer (EIP-4399). "
            "Replaced 'block.difficulty' after Ethereum's Merge (PoS transition)."
        ),
        "auditor_notes": (
            "• Still NOT completely secure for high-stakes randomness (e.g. multimillion dollar casinos). "
            "Block proposers can choose whether to propose a block or withhold it to influence the next seed.\n"
            "• For tamper-proof randomness, use Chainlink VRF or commit-reveal schemes."
        ),
        "example": (
            "// Post-merge randomness beacon seed\n"
            "uint256 seed = block.prevrandao;\n"
            "uint256 winner = uint256(keccak256(abi.encodePacked(seed, block.timestamp))) % totalParticipants;"
        ),
        "aliases": ["block.prevrandao", "blockprevrandao", "prevrandao", "block.difficulty", "difficulty", "randomness"],
    },
    {
        "id": "block_chainid",
        "name": "block.chainid",
        "category": "Global Variables",
        "syntax": "uint256 currentChain = block.chainid;",
        "description": (
            "Returns the current EVM chain ID (e.g. 1 for Ethereum Mainnet, 11155111 for Sepolia, "
            "8453 for Base). Added in Solidity 0.8.0."
        ),
        "auditor_notes": (
            "• Critical for EIP-712 typed structured signatures to prevent cross-chain signature replay attacks.\n"
            "• Always dynamically read block.chainid in EIP-712 DOMAIN_SEPARATOR if chain forks can occur."
        ),
        "example": (
            "function getDomainSeparator() public view returns (bytes32) {\n"
            "    return keccak256(\n"
            "        abi.encode(TYPE_HASH, NAME_HASH, VERSION_HASH, block.chainid, address(this))\n"
            "    );\n"
            "}"
        ),
        "aliases": ["block.chainid", "blockchainid", "block_chainid", "chainid", "chain id"],
    },
    {
        "id": "block_basefee",
        "name": "block.basefee",
        "category": "Global Variables",
        "syntax": "uint256 baseFee = block.basefee;",
        "description": (
            "Returns the EIP-1559 base fee of the current block in Wei. Available in Solidity 0.8.7+."
        ),
        "auditor_notes": (
            "• Useful for gas-metering, relayer refunds, or MEV-aware contract logic.\n"
            "• Allows contracts to calculate exact priority fees paid: tx.gasprice - block.basefee."
        ),
        "example": (
            "uint256 priorityFee = tx.gasprice - block.basefee;"
        ),
        "aliases": ["block.basefee", "blockbasefee", "block_basefee", "basefee", "base fee"],
    },
    {
        "id": "block_blobbasefee",
        "name": "block.blobbasefee",
        "category": "Global Variables",
        "syntax": "uint256 blobFee = block.blobbasefee;",
        "description": (
            "Returns the base fee per blob gas in the current block under Cancun EIP-4844 / EIP-7516. "
            "Available in Solidity 0.8.24+."
        ),
        "auditor_notes": (
            "• Used by Layer 2 rollup sequencers and blob data market contracts to check blob gas pricing.\n"
            "• Corresponds to EVM opcode BLOBBASEFEE (0x4A)."
        ),
        "example": (
            "// Query blob gas base fee in Solidity 0.8.24+\n"
            "uint256 currentBlobFee = block.blobbasefee;"
        ),
        "aliases": ["block.blobbasefee", "blockblobbasefee", "blobbasefee", "blob base fee", "eip-4844 fee"],
    },
    {
        "id": "block_coinbase",
        "name": "block.coinbase",
        "category": "Global Variables",
        "syntax": "address payable feeRecipient = block.coinbase;",
        "description": (
            "Address of the current block miner / validator fee recipient who produced the block."
        ),
        "auditor_notes": (
            "• Used in MEV searcher contracts to send direct priority fee bribes: block.coinbase.transfer(bribe).\n"
            "• Do not use for access control or randomness."
        ),
        "example": (
            "// MEV miner bribe payment\n"
            "block.coinbase.transfer(tipAmount);"
        ),
        "aliases": ["block.coinbase", "blockcoinbase", "coinbase", "miner", "fee recipient"],
    },
    {
        "id": "block_gaslimit",
        "name": "block.gaslimit",
        "category": "Global Variables",
        "syntax": "uint256 limit = block.gaslimit;",
        "description": (
            "Returns the maximum gas limit of the current block (e.g. 30,000,000 gas on Ethereum Mainnet)."
        ),
        "auditor_notes": (
            "• Loops that iterate through unbounded arrays can exceed block.gaslimit, causing permanent Denial of Service (DoS)."
        ),
        "example": (
            "require(estimatedGas < block.gaslimit, \"Gas limit exceeded\");"
        ),
        "aliases": ["block.gaslimit", "blockgaslimit", "gaslimit", "block gas limit"],
    },
    {
        "id": "blockhash",
        "name": "blockhash()",
        "category": "Global Variables",
        "syntax": "bytes32 hash = blockhash(uint256 blockNumber);",
        "description": (
            "Returns the Keccak-256 hash of the given block. Only works for the 256 most recent blocks "
            "excluding the current block. Returns 0 for older blocks or future blocks."
        ),
        "auditor_notes": (
            "• If queried for a block older than 256 blocks, blockhash() silently returns bytes32(0)!\n"
            "• Lotteries that rely on blockhash(betBlock) will always produce 0 if resolved after 256 blocks, "
            "which attackers can exploit to predict outcomes."
        ),
        "example": (
            "bytes32 prevHash = blockhash(block.number - 1);"
        ),
        "aliases": ["blockhash", "blockhash()", "block hash"],
    },
    {
        "id": "blobhash",
        "name": "blobhash()",
        "category": "Global Variables",
        "syntax": "bytes32 hash = blobhash(uint256 index);",
        "description": (
            "Cancun EIP-4844 opcode (BLOBHASH 0x49). Returns the versioned hash of the index-th blob "
            "attached to the current transaction. Returns 0 if index is out of bounds."
        ),
        "auditor_notes": (
            "• Used by L2 settlement contracts (Optimism, Arbitrum, Base) to verify blob data availability.\n"
            "• Available in Solidity 0.8.24+."
        ),
        "example": (
            "// Query first blob versioned hash\n"
            "bytes32 vHash = blobhash(0);\n"
            "require(vHash != bytes32(0), \"No blob attached\");"
        ),
        "aliases": ["blobhash", "blobhash()", "blob hash", "eip-4844", "blob"],
    },

    # =========================================================================
    # 3. Address & Contract Members
    # =========================================================================
    {
        "id": "address_this",
        "name": "address(this)",
        "category": "Address & Contract Members",
        "syntax": "address self = address(this);\nuint256 balance = address(this).balance;",
        "description": (
            "Returns the address of the currently executing contract instance. Used to inspect self balance, "
            "compute storage keys, or pass contract address as recipient."
        ),
        "auditor_notes": (
            "⚠️ BALANCE INVARIANT GOTCHA:\n"
            "• Never assume address(this).balance can only increase through receive() or fallback()!\n"
            "• Ether can be forcefully sent to any contract via selfdestruct, block mining rewards (coinbase), "
            "or pre-calculated deployment addresses. Strict equality checks 'assert(address(this).balance == totalDeposits)' "
            "can be bricked by sending 1 Wei!"
        ),
        "example": (
            "uint256 contractBal = address(this).balance;\n"
            "token.transferFrom(msg.sender, address(this), amount);"
        ),
        "aliases": ["address(this)", "this", "address this", "self address"],
    },
    {
        "id": "address_balance",
        "name": "<address>.balance",
        "category": "Address & Contract Members",
        "syntax": "uint256 bal = account.balance;",
        "description": (
            "Returns the balance of the given Ethereum address in Wei (native currency). "
            "Corresponds to the EVM BALANCE opcode (0x31)."
        ),
        "auditor_notes": (
            "• Cold account balance access costs 2600 gas (EIP-2929).\n"
            "• For contracts, balance checks can be manipulated via flash loans or forced Ether injection."
        ),
        "example": (
            "uint256 userBal = msg.sender.balance;"
        ),
        "aliases": ["balance", "address.balance", "<address>.balance", "account balance", "eth balance"],
    },
    {
        "id": "address_code",
        "name": "<address>.code / .codehash",
        "category": "Address & Contract Members",
        "syntax": "bytes memory code = target.code;\nbytes32 cHash = target.codehash;",
        "description": (
            "• <address>.code: returns the deployed runtime bytecode as 'bytes memory' (EXTCODECOPY).\n"
            "• <address>.codehash: returns the Keccak-256 hash of the runtime code (EXTCODEHASH)."
        ),
        "auditor_notes": (
            "⚠️ ISCONTRACT() VULNERABILITY:\n"
            "• Checking 'target.code.length > 0' returns FALSE during a contract's constructor execution "
            "(because bytecode is not yet written to state). Malicious contracts can bypass 'require(!isContract(msg.sender))' "
            "by executing the attack from their constructor!"
        ),
        "example": (
            "bytes32 hash = target.codehash;\n"
            "bool isEmpty = (hash == bytes32(0) || hash == 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);"
        ),
        "aliases": ["code", "codehash", "address.code", "address.codehash", "iscontract", "extcodehash"],
    },

    # =========================================================================
    # 4. ABI Encoding & Decoding
    # =========================================================================
    {
        "id": "abi_encode",
        "name": "abi.encode()",
        "category": "ABI Encoding",
        "syntax": "bytes memory encoded = abi.encode(...);",
        "description": (
            "Standard ABI encoding of the given arguments according to the Ethereum ABI specification. "
            "Every type is padded to 32-byte (256-bit) words. Safe against hash collisions."
        ),
        "auditor_notes": (
            "• Use abi.encode() when hashing multiple dynamic arguments (strings, bytes, arrays) with keccak256 "
            "to prevent hash collisions.\n"
            "• Standard encoding can be decoded cleanly using abi.decode()."
        ),
        "example": (
            "bytes memory data = abi.encode(msg.sender, amount, \"USD\");\n"
            "(address user, uint256 amt, string memory currency) = abi.decode(data, (address, uint256, string));"
        ),
        "aliases": ["abi.encode", "abi.encode()", "abiencode", "encode"],
    },
    {
        "id": "abi_encodePacked",
        "name": "abi.encodePacked()",
        "category": "ABI Encoding",
        "syntax": "bytes memory packed = abi.encodePacked(...);",
        "description": (
            "Non-standard packed encoding of arguments. Omits 32-byte padding for elements shorter than 32 bytes "
            "and directly concatenates bytes and string data."
        ),
        "auditor_notes": (
            "🚨 CRITICAL HASH COLLISION VULNERABILITY:\n"
            "• When multiple variable-length arguments (e.g. two strings or bytes) are passed to abi.encodePacked(), "
            "hash collisions occur: keccak256(abi.encodePacked('a', 'bc')) == keccak256(abi.encodePacked('ab', 'c'))!\n"
            "• In Solidity 0.8.x+, the compiler warns about this collision risk.\n"
            "• Recommendation: Use abi.encode() instead of abi.encodePacked() when hashing dynamic types."
        ),
        "example": (
            "// ⚠️ Dangerous hash collision:\n"
            "// keccak256(abi.encodePacked(str1, str2));\n\n"
            "// ✅ Safe with abi.encode():\n"
            "bytes32 hash = keccak256(abi.encode(str1, str2));"
        ),
        "aliases": ["abi.encodePacked", "abi.encodePacked()", "abiencodepacked", "encodePacked", "packed encoding"],
    },
    {
        "id": "abi_encodeWithSelector",
        "name": "abi.encodeWithSelector()",
        "category": "ABI Encoding",
        "syntax": "bytes memory payload = abi.encodeWithSelector(bytes4 selector, ...);",
        "description": (
            "Prepend a 4-byte function selector to standard ABI-encoded arguments. "
            "Commonly used to build calldata for low-level .call() or .delegatecall()."
        ),
        "auditor_notes": (
            "• Prefer abi.encodeCall() in modern Solidity (0.8.11+) because encodeWithSelector lacks compile-time "
            "type safety checks (typos in argument types won't be caught at compile-time)."
        ),
        "example": (
            "bytes4 selector = bytes4(keccak256(\"transfer(address,uint256)\"));\n"
            "bytes memory payload = abi.encodeWithSelector(selector, recipient, amount);\n"
            "(bool ok, ) = token.call(payload);"
        ),
        "aliases": ["abi.encodeWithSelector", "abi.encodeWithSelector()", "abiencodewithselector", "encodeWithSelector"],
    },
    {
        "id": "abi_encodeWithSignature",
        "name": "abi.encodeWithSignature()",
        "category": "ABI Encoding",
        "syntax": "bytes memory payload = abi.encodeWithSignature(string memory signature, ...);",
        "description": (
            "Computes bytes4(keccak256(bytes(signature))) and encodes it with the remaining arguments. "
            "Convenient shortcut, but signature typos will not be caught at compile-time."
        ),
        "auditor_notes": (
            "• Typo vulnerability: A typo like 'transfer(address, uint256)' with a space creates a completely "
            "wrong selector!\n"
            "• Always prefer type-safe abi.encodeCall() or explicit selectors."
        ),
        "example": (
            "bytes memory data = abi.encodeWithSignature(\"transfer(address,uint256)\", to, amount);"
        ),
        "aliases": ["abi.encodeWithSignature", "abi.encodeWithSignature()", "abiencodewithsignature", "encodeWithSignature"],
    },
    {
        "id": "abi_encodeCall",
        "name": "abi.encodeCall()",
        "category": "ABI Encoding",
        "syntax": "bytes memory payload = abi.encodeCall(IERC20.transfer, (recipient, amount));",
        "description": (
            "Introduced in Solidity 0.8.11. Provides compile-time type-checked calldata encoding. "
            "Validates the target function existence, argument counts, and argument types at compile time."
        ),
        "auditor_notes": (
            "• Best practice: Strongly recommended over abi.encodeWithSelector or abi.encodeWithSignature.\n"
            "• If the interface changes or parameters don't match, compilation fails immediately."
        ),
        "example": (
            "// Type-safe calldata generation\n"
            "bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, amount));\n"
            "(bool success, bytes memory returnData) = address(token).call(data);"
        ),
        "aliases": ["abi.encodeCall", "abi.encodeCall()", "abiencodecall", "encodeCall"],
    },
    {
        "id": "abi_decode",
        "name": "abi.decode()",
        "category": "ABI Encoding",
        "syntax": "(Type1 a, Type2 b) = abi.decode(bytes memory data, (Type1, Type2));",
        "description": (
            "Decodes standard ABI-encoded binary data into concrete Solidity types. Reverts if data length "
            "is insufficient or types are invalid."
        ),
        "auditor_notes": (
            "• In low-level .call(), always verify success boolean before calling abi.decode() on returnData.\n"
            "• If the returnData length is 0 (e.g. non-compliant ERC-20 tokens like USDT), abi.decode will revert! "
            "Use OpenZeppelin's SafeERC20 to handle non-compliant returns."
        ),
        "example": (
            "(bool ok, bytes memory returnData) = token.staticcall(abi.encodeCall(IERC20.balanceOf, (user)));\n"
            "require(ok && returnData.length >= 32, \"Call failed\");\n"
            "uint256 balance = abi.decode(returnData, (uint256));"
        ),
        "aliases": ["abi.decode", "abi.decode()", "abidecode", "decode"],
    },

    # =========================================================================
    # 5. Cryptographic Primitives
    # =========================================================================
    {
        "id": "keccak256",
        "name": "keccak256()",
        "category": "Cryptography",
        "syntax": "bytes32 hash = keccak256(bytes memory data);",
        "description": (
            "Computes the Ethereum Keccak-256 cryptographic hash (NIST SHA-3 candidate prior to final FIPS 202). "
            "The native hashing primitive used across Ethereum for addresses, storage slots, and signatures."
        ),
        "auditor_notes": (
            "• Input must be bytes memory. To hash strings or numbers, wrap in abi.encode() or abi.encodePacked().\n"
            "• Beware of hash collisions with abi.encodePacked() when hashing multiple variable-length parameters."
        ),
        "example": (
            "bytes32 leaf = keccak256(abi.encode(account, amount));"
        ),
        "aliases": ["keccak256", "keccak", "keccak256()", "sha3"],
    },
    {
        "id": "ecrecover",
        "name": "ecrecover()",
        "category": "Cryptography",
        "syntax": "address signer = ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s);",
        "description": (
            "Recovers the Ethereum address associated with the public key that created the ECDSA signature "
            "(v, r, s) over the given 32-byte digest."
        ),
        "auditor_notes": (
            "🚨 CRITICAL SIGNATURE VULNERABILITIES:\n"
            "1. Zero Address Return: If the signature is invalid or malformed, ecrecover returns address(0) "
            "WITHOUT reverting! If you check 'signer == authorized', an uninitialized variable can match address(0)!\n"
            "2. Signature Malleability: Any valid (v, r, s) has a valid complementary signature (v', r, -s mod n). "
            "Always enforce s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D57617F8140F15C57779977DE7F7E19 (EIP-2).\n"
            "3. Replay Attacks: Enforce nonces, deadline, and block.chainid (EIP-712).\n"
            "Recommendation: Use OpenZeppelin's ECDSA.recover() library instead of raw ecrecover()."
        ),
        "example": (
            "address signer = ecrecover(ethSignedMessageHash, v, r, s);\n"
            "require(signer != address(0), \"Invalid signature\");\n"
            "require(signer == authorizedSigner, \"Unauthorized\");"
        ),
        "aliases": ["ecrecover", "ecrecover()", "ecdsa", "signature recovery", "recover signature"],
    },

    # =========================================================================
    # 6. Error Handling & Invariants
    # =========================================================================
    {
        "id": "require",
        "name": "require()",
        "category": "Error Handling",
        "syntax": "require(bool condition, string memory message);",
        "description": (
            "Validates user inputs, preconditions, and return values. If condition evaluates to false, "
            "it reverts state changes, refunds remaining gas, and encodes Error(string) with the message."
        ),
        "auditor_notes": (
            "• Long revert strings increase contract deployment bytecode size and gas costs.\n"
            "• In Solidity 0.8.4+, Custom Errors with 'if (!condition) revert MyError();' are much cheaper."
        ),
        "example": (
            "require(recipient != address(0), \"Invalid recipient\");\n"
            "require(balance >= amount, \"Insufficient balance\");"
        ),
        "aliases": ["require", "require()"],
    },
    {
        "id": "assert",
        "name": "assert()",
        "category": "Error Handling",
        "syntax": "assert(bool condition);",
        "description": (
            "Used to check internal contract invariants and test for conditions that should mathematically NEVER "
            "be false. Failing assert() reverts with Panic(0x01) (Assertion failure)."
        ),
        "auditor_notes": (
            "• In Solidity < 0.8.0, assert consumed ALL remaining gas (invalid opcode 0xFE). In 0.8.0+, it refunds "
            "gas and reverts with Panic(uint256).\n"
            "• Formal verification tools (Certora, Slither, Foundry invariant tests) specifically target assert() statements."
        ),
        "example": (
            "// After withdrawal, balance must strictly decrease\n"
            "uint256 balanceBefore = totalDeposits;\n"
            "totalDeposits -= amount;\n"
            "assert(totalDeposits < balanceBefore);"
        ),
        "aliases": ["assert", "assert()", "panic", "invariant"],
    },
    {
        "id": "revert",
        "name": "revert()",
        "category": "Error Handling",
        "syntax": "// Traditional string revert:\nrevert(\"Reason string\");\n\n// Custom Error (Solidity 0.8.4+):\nerror Unauthorized(address caller);\nrevert Unauthorized(msg.sender);",
        "description": (
            "Unconditionally aborts execution, rolls back all state changes, refunds unused gas, "
            "and provides revert data to the caller."
        ),
        "auditor_notes": (
            "• Custom errors (Solidity 0.8.4+) are defined via 'error Name(args)' and only cost 4 bytes selector + args, "
            "saving massive amounts of deployment and runtime gas compared to string reverts.\n"
            "• Custom errors can be caught via try/catch or analyzed with our /revert tool!"
        ),
        "example": (
            "error InsufficientBalance(uint256 available, uint256 required);\n\n"
            "function withdraw(uint256 amount) external {\n"
            "    if (amount > balances[msg.sender]) {\n"
            "        revert InsufficientBalance(balances[msg.sender], amount);\n"
            "    }\n"
            "    balances[msg.sender] -= amount;\n"
            "}"
        ),
        "aliases": ["revert", "revert()", "custom error", "error"],
    },

    # =========================================================================
    # 7. Low-Level Calls & Transfers
    # =========================================================================
    {
        "id": "call",
        "name": "<address>.call()",
        "category": "Low-Level Calls",
        "syntax": "(bool success, bytes memory returnData) = target.call{value: val, gas: g}(payload);",
        "description": (
            "Low-level message call forwarding arbitrary calldata payload and optional Ether value. "
            "Executes code in the TARGET contract's context (target's storage and target's msg.sender)."
        ),
        "auditor_notes": (
            "🚨 CRITICAL REENTRANCY RISK:\n"
            "• .call forwards all available gas by default. If sending Ether to an untrusted address, "
            "the recipient's fallback/receive function can re-enter your contract!\n"
            "• Always follow the Checks-Effects-Interactions (CEI) pattern or use OpenZeppelin ReentrancyGuard.\n"
            "• Always check the returned boolean 'success' flag!"
        ),
        "example": (
            "// Recommended pattern for sending Ether (CEI + .call)\n"
            "balances[msg.sender] = 0; // State updated before external call\n"
            "(bool sent, ) = msg.sender.call{value: amount}(\"\");\n"
            "require(sent, \"Ether transfer failed\");"
        ),
        "aliases": ["call", ".call", "address.call", "<address>.call"],
    },
    {
        "id": "delegatecall",
        "name": "<address>.delegatecall()",
        "category": "Low-Level Calls",
        "syntax": "(bool success, bytes memory returnData) = logicAddress.delegatecall(payload);",
        "description": (
            "Executes target contract's code in the context of the CALLING contract. "
            "Storage, msg.sender, and msg.value remain exactly the same as the caller's context. "
            "The foundational primitive for all proxy patterns (EIP-1967, UUPS, Diamond)."
        ),
        "auditor_notes": (
            "🚨 HIGHEST SECURITY RISK IN SMART CONTRACTS:\n"
            "1. Storage Collision: Both proxy and logic contract MUST have identical storage layouts!\n"
            "2. Arbitrary Delegatecall: Never allow arbitrary user-supplied target addresses. An attacker "
            "can delegatecall to a contract that executes selfdestruct or overwrites the proxy admin slot."
        ),
        "example": (
            "(bool success, bytes memory result) = implementation.delegatecall(msg.data);\n"
            "require(success, \"Execution failed\");"
        ),
        "aliases": ["delegatecall", ".delegatecall", "address.delegatecall", "<address>.delegatecall", "proxy delegatecall"],
    },
    {
        "id": "staticcall",
        "name": "<address>.staticcall()",
        "category": "Low-Level Calls",
        "syntax": "(bool success, bytes memory returnData) = target.staticcall(payload);",
        "description": (
            "Read-only external call (opcodes STATICCALL). Reverts if the target contract attempts to modify "
            "EVM state (sstore, create, transfer, log/emit events)."
        ),
        "auditor_notes": (
            "• Ideal for querying price oracles, viewing balances, or checking simulation outcomes safely.\n"
            "• Guaranteed to cause no state mutations."
        ),
        "example": (
            "(bool ok, bytes memory data) = oracle.staticcall(abi.encodeCall(IOracle.getPrice, (token)));\n"
            "require(ok, \"Oracle query failed\");\n"
            "uint256 price = abi.decode(data, (uint256));"
        ),
        "aliases": ["staticcall", ".staticcall", "address.staticcall", "<address>.staticcall"],
    },
    {
        "id": "transfer",
        "name": "<address payable>.transfer()",
        "category": "Low-Level Calls",
        "syntax": "payable(recipient).transfer(amount);",
        "description": (
            "Transfers amount in Wei to a payable address with a fixed stipend of 2300 gas. "
            "Reverts automatically if the transfer fails or recipient runs out of gas."
        ),
        "auditor_notes": (
            "⚠️ DEPRECATED BEST PRACTICE:\n"
            "• The 2300 gas stipend was designed to prevent reentrancy, but gas costs of SLOAD/SSTORE have "
            "changed with EIPs (e.g. EIP-1884), and smart contract wallets (Gnosis Safe, Account Abstraction) "
            "often require > 2300 gas to receive Ether.\n"
            "• Modern recommendation: Use call{value: amount}('') with Checks-Effects-Interactions instead."
        ),
        "example": (
            "// Legacy transfer (may fail for smart contract wallets):\n"
            "payable(msg.sender).transfer(amount);"
        ),
        "aliases": ["transfer", "address.transfer", "payable.transfer", "eth transfer"],
    },
    {
        "id": "selfdestruct",
        "name": "selfdestruct()",
        "category": "Low-Level Calls",
        "syntax": "selfdestruct(payable(recipient));",
        "description": (
            "Historically deleted the contract bytecode from Ethereum state and sent all contract Ether balance "
            "to the recipient address."
        ),
        "auditor_notes": (
            "⚠️ DEPRECATED IN DENCUN (EIP-6780):\n"
            "• Since the Cancun-Dencun hard fork, selfdestruct NO LONGER deletes contract code or storage "
            "unless the contract was created in the SAME transaction!\n"
            "• Forced Ether injection: selfdestruct can still force-feed Ether into a contract without calling "
            "receive() or fallback(), which breaks invariants relying on 'address(this).balance == totalDeposits'."
        ),
        "example": (
            "// Only destroys code if created in same tx (Dencun EIP-6780)\n"
            "selfdestruct(payable(owner));"
        ),
        "aliases": ["selfdestruct", "selfdestruct()", "suicide", "destroy contract"],
    },

    # =========================================================================
    # 8. Mathematical & Utility Functions
    # =========================================================================
    {
        "id": "addmod",
        "name": "addmod()",
        "category": "Mathematical Functions",
        "syntax": "uint256 result = addmod(uint256 x, uint256 y, uint256 k);",
        "description": (
            "Computes (x + y) % k with arbitrary precision arithmetic. The addition does not wrap around "
            "or overflow at 2^256. Reverts if k == 0."
        ),
        "auditor_notes": (
            "• Essential for cryptographic routines (modular arithmetic, elliptic curves, RSA, zero-knowledge proofs).\n"
            "• Highly optimized native EVM opcode (ADDMOD)."
        ),
        "example": (
            "// Safe modular addition without 256-bit overflow\n"
            "uint256 sum = addmod(type(uint256).max, 10, 1000);"
        ),
        "aliases": ["addmod", "addmod()", "modular addition"],
    },
    {
        "id": "mulmod",
        "name": "mulmod()",
        "category": "Mathematical Functions",
        "syntax": "uint256 result = mulmod(uint256 x, uint256 y, uint256 k);",
        "description": (
            "Computes (x * y) % k with arbitrary precision arithmetic. The multiplication does not wrap around "
            "or overflow at 2^256. Reverts if k == 0."
        ),
        "auditor_notes": (
            "• Essential for DeFi AMM constant-product formulas and cryptography where x * y exceeds 256 bits.\n"
            "• Highly optimized native EVM opcode (MULMOD)."
        ),
        "example": (
            "uint256 product = mulmod(amountA, amountB, denominator);"
        ),
        "aliases": ["mulmod", "mulmod()", "modular multiplication"],
    },

    # =========================================================================
    # 9. Type Introspection & Units
    # =========================================================================
    {
        "id": "type_info",
        "name": "type(T)",
        "category": "Type Introspection",
        "syntax": "type(Contract).creationCode\ntype(Contract).runtimeCode\ntype(IInterface).interfaceId\ntype(uint256).max\ntype(int256).min",
        "description": (
            "Provides compile-time introspection about contract types and primitive types.\n"
            "• type(C).creationCode: init bytecode used for CREATE/CREATE2.\n"
            "• type(C).runtimeCode: deployed runtime bytecode.\n"
            "• type(I).interfaceId: EIP-165 4-byte interface identifier (XOR of function selectors).\n"
            "• type(T).min / type(T).max: minimum and maximum values of integer type T."
        ),
        "auditor_notes": (
            "• type(C).creationCode cannot be accessed from within C or any contract inheriting from C.\n"
            "• Frequently used to compute CREATE2 salt / init code hashes."
        ),
        "example": (
            "// CREATE2 init code hash computation\n"
            "bytes32 initHash = keccak256(abi.encodePacked(type(Pair).creationCode, abi.encode(tokenA, tokenB)));\n"
            "uint256 maxApproval = type(uint256).max;"
        ),
        "aliases": ["type", "type()", "type(c)", "creationcode", "interfaceid", "max uint"],
    },

    # =========================================================================
    # 10. Inline Assembly & Transient Storage (Yul)
    # =========================================================================
    {
        "id": "tstore_tload",
        "name": "tstore() / tload()",
        "category": "Yul & Transient Storage",
        "syntax": "assembly {\n    tstore(slot, value)\n    let val := tload(slot)\n}",
        "description": (
            "EIP-1153 Transient Storage introduced in the Cancun hard fork (Solidity 0.8.24+). "
            "Stores 32-byte values in transient storage that behaves like storage but is completely CLEARED "
            "at the end of the transaction. Costs only 100 gas per access."
        ),
        "auditor_notes": (
            "🔥 MODERN AUDIT FOCUS:\n"
            "• Gas Revolution: Perfect for Reentrancy Guards (costs ~100 gas instead of ~2100-5000 gas for SSTORE).\n"
            "• Security Trap: Because transient storage is NOT cleared between calls in the same transaction, "
            "if a reentrancy guard or temporary approval isn't manually reset, subsequent calls in a multi-call "
            "can read stale transient state!"
        ),
        "example": (
            "// Gas-efficient Transient Reentrancy Guard\n"
            "bytes32 constant GUARD_SLOT = keccak256(\"reentrancy.guard\");\n\n"
            "modifier nonReentrant() {\n"
            "    assembly {\n"
            "        if tload(GUARD_SLOT) { revert(0, 0) }\n"
            "        tstore(GUARD_SLOT, 1)\n"
            "    }\n"
            "    _;\n"
            "    assembly {\n"
            "        tstore(GUARD_SLOT, 0)\n"
            "    }\n"
            "}"
        ),
        "aliases": ["tstore", "tload", "transient storage", "eip-1153", "cancun storage"],
    },
    {
        "id": "sstore_sload",
        "name": "sstore() / sload()",
        "category": "Yul & Assembly",
        "syntax": "assembly {\n    sstore(slot, value)\n    let val := sload(slot)\n}",
        "description": (
            "Low-level EVM storage read and write opcodes in inline assembly. Directly accesses persistent "
            "contract storage slots."
        ),
        "auditor_notes": (
            "• Used in EIP-1967 custom proxy storage slots to prevent storage collision with logic contracts.\n"
            "• Cold vs Warm storage access: Cold SLOAD costs 2100 gas, warm SLOAD costs 100 gas."
        ),
        "example": (
            "bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n"
            "function getImplementation() public view returns (address impl) {\n"
            "    assembly {\n"
            "        impl := sload(IMPL_SLOT)\n"
            "    }\n"
            "}"
        ),
        "aliases": ["sstore", "sload", "assembly storage", "storage slot"],
    },
    {
        "id": "mstore_mload",
        "name": "mstore() / mload()",
        "category": "Yul & Assembly",
        "syntax": "assembly {\n    mstore(offset, value)\n    let val := mload(offset)\n}",
        "description": (
            "Writes (mstore) or reads (mload) a 32-byte word to/from EVM memory. Memory is linear and expands "
            "dynamically, with a quadratic gas cost for large expansions."
        ),
        "auditor_notes": (
            "• Solidity Free Memory Pointer: The slot 0x40 in memory stores the free memory pointer. "
            "If you write to memory without updating 0x40, Solidity may overwrite your data!\n"
            "• Zero slot (0x60) is reserved for empty dynamic memory arrays."
        ),
        "example": (
            "assembly {\n"
            "    let ptr := mload(0x40)       // Load free memory pointer\n"
            "    mstore(ptr, 0x1234)          // Store value\n"
            "    mstore(0x40, add(ptr, 0x20)) // Update free memory pointer\n"
            "}"
        ),
        "aliases": ["mstore", "mload", "assembly memory", "free memory pointer"],
    },

    # =========================================================================
    # 11. Foundry Cheatcodes (forge-std Vm.sol)
    # =========================================================================
    {
        "id": "vm_prank",
        "name": "vm.prank() / vm.startPrank()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.prank(address sender);\nvm.prank(address sender, address origin);\n// Multi-call persistent:\nvm.startPrank(address sender);\nvm.stopPrank();",
        "description": (
            "Sets msg.sender (and optionally tx.origin) for the NEXT call (vm.prank) or for all SUBSEQUENT calls "
            "(vm.startPrank) until vm.stopPrank() is invoked. The most essential Foundry cheatcode for testing permissions."
        ),
        "auditor_notes": (
            "• vm.prank ONLY affects the immediate next external call! Calls inside the test contract itself "
            "before the external call can consume the prank unexpectedly.\n"
            "• Always pair vm.startPrank() with vm.stopPrank() to avoid bleeding state into subsequent tests."
        ),
        "example": (
            "function test_onlyOwnerCanWithdraw() public {\n"
            "    vm.prank(owner);\n"
            "    vault.withdraw(100);\n"
            "    \n"
            "    // Test unauthorized user reverts\n"
            "    vm.prank(attacker);\n"
            "    vm.expectRevert(\"Unauthorized\");\n"
            "    vault.withdraw(100);\n"
            "}"
        ),
        "aliases": ["vm.prank", "vmprank", "vm_prank", "prank", "startprank", "vm.startprank", "stopprank", "spoof sender"],
    },
    {
        "id": "vm_deal",
        "name": "vm.deal()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.deal(address who, uint256 newBalance);",
        "description": (
            "Sets the native currency (Ether) balance of any address to the specified amount in Wei. "
            "Allows funding test accounts or test contracts instantaneously."
        ),
        "auditor_notes": (
            "• Does not emit deposit events or trigger receive()/fallback() functions—directly modifies state storage.\n"
            "• For ERC-20 token balances, use stdCheats `deal(address token, address to, uint256 amount)` instead."
        ),
        "example": (
            "function test_deposit() public {\n"
            "    address alice = makeAddr(\"alice\");\n"
            "    vm.deal(alice, 10 ether);\n"
            "    \n"
            "    vm.prank(alice);\n"
            "    vault.deposit{value: 5 ether}();\n"
            "    assertEq(vault.balanceOf(alice), 5 ether);\n"
            "}"
        ),
        "aliases": ["vm.deal", "vmdeal", "vm_deal", "deal", "fund address", "set balance"],
    },
    {
        "id": "vm_warp",
        "name": "vm.warp()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.warp(uint256 newTimestamp);",
        "description": (
            "Sets block.timestamp to the specified value in seconds. Crucial for testing time-locks, vesting, "
            "auctions, deadlines, and staking reward accumulation."
        ),
        "auditor_notes": (
            "• Moving time backwards is allowed in tests, but may trigger underflow errors in contracts that expect "
            "monotonic time progression (e.g. `uint256 elapsed = block.timestamp - lastUpdated`)."
        ),
        "example": (
            "function test_vestingRelease() public {\n"
            "    // Fast forward 30 days\n"
            "    vm.warp(block.timestamp + 30 days);\n"
            "    tokenVesting.release();\n"
            "}"
        ),
        "aliases": ["vm.warp", "vmwarp", "vm_warp", "warp", "time travel", "set timestamp"],
    },
    {
        "id": "vm_roll",
        "name": "vm.roll()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.roll(uint256 newBlockNumber);",
        "description": (
            "Sets block.number to the specified value. Used to test block-based governance voting periods, "
            "compound-style interest rate updates, or blockhash expirations."
        ),
        "auditor_notes": (
            "• Often combined with vm.warp() (e.g. `vm.warp(block.timestamp + 120); vm.roll(block.number + 10);`) "
            "to simulate realistic block intervals in fork tests."
        ),
        "example": (
            "function test_votingPeriodExpired() public {\n"
            "    // Advance 50,000 blocks\n"
            "    vm.roll(block.number + 50000);\n"
            "    vm.expectRevert(\"Voting closed\");\n"
            "    governor.castVote(proposalId, 1);\n"
            "}"
        ),
        "aliases": ["vm.roll", "vmroll", "vm_roll", "roll", "advance blocks", "set block number"],
    },
    {
        "id": "vm_expectRevert",
        "name": "vm.expectRevert()",
        "category": "Foundry Cheatcodes",
        "syntax": "// Expect any revert:\nvm.expectRevert();\n// Expect specific string message:\nvm.expectRevert(\"Insufficient funds\");\n// Expect custom error selector:\nvm.expectRevert(CustomError.selector);\n// Expect custom error with params:\nvm.expectRevert(abi.encodeWithSelector(CustomError.selector, arg1, arg2));",
        "description": (
            "Instructs the EVM that the NEXT external call MUST revert. If the call does not revert, "
            "or reverts with different revert data, the test immediately fails."
        ),
        "auditor_notes": (
            "• Must be called IMMEDIATELY before the reverting external call!\n"
            "• Only works on external calls (e.g. `contract.method()`), not internal library calls.\n"
            "• Custom errors: Always pass `abi.encodeWithSelector(CustomError.selector, ...)` or `CustomError.selector` "
            "for gas-efficient custom error assertions."
        ),
        "example": (
            "function test_revertUnauthorized() public {\n"
            "    vm.prank(unauthorizedUser);\n"
            "    vm.expectRevert(abi.encodeWithSelector(Vault.Unauthorized.selector, unauthorizedUser));\n"
            "    vault.emergencyWithdraw();\n"
            "}"
        ),
        "aliases": ["vm.expectrevert", "vmexpectrevert", "vm_expectrevert", "expectrevert", "expect revert", "assert revert"],
    },
    {
        "id": "vm_expectEmit",
        "name": "vm.expectEmit()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData);\n// Or check emitter address:\nvm.expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter);",
        "description": (
            "Asserts that a specific event is emitted during the subsequent call. You define the expectation "
            "by calling vm.expectEmit(...), emitting the expected event, and then calling the target function."
        ),
        "auditor_notes": (
            "• Pattern: 1) vm.expectEmit; 2) emit ExpectedEvent(...); 3) execute targetContract.action().\n"
            "• If topics don't match or the event is never emitted, Forge fails the test."
        ),
        "example": (
            "function test_emitTransfer() public {\n"
            "    // Expect topic1 (indexed from), topic2 (indexed to), and unindexed data (amount)\n"
            "    vm.expectEmit(true, true, false, true);\n"
            "    emit Transfer(address(this), recipient, 1000);\n"
            "    \n"
            "    token.transfer(recipient, 1000);\n"
            "}"
        ),
        "aliases": ["vm.expectemit", "vmexpectemit", "vm_expectemit", "expectemit", "expect emit", "assert event"],
    },
    {
        "id": "vm_mockCall",
        "name": "vm.mockCall() / vm.clearMockedCalls()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.mockCall(address where, bytes calldata data, bytes calldata retdata);\n// Match any calldata with exact value:\nvm.mockCall(address where, uint256 msgValue, bytes calldata data, bytes calldata retdata);\nvm.clearMockedCalls();",
        "description": (
            "Intercepts calls to a target address matching the specified calldata (or selector) and forces "
            "it to return the mocked return data. Indispensable for mocking Chainlink oracles or external Uniswap pools."
        ),
        "auditor_notes": (
            "• Mocking is prioritized by specificity: exact calldata match takes precedence over selector-only match.\n"
            "• Clear mocked calls with vm.clearMockedCalls() if subsequent tests need real logic."
        ),
        "example": (
            "function test_oraclePrice() public {\n"
            "    // Mock Chainlink latestRoundData to return $2,000\n"
            "    bytes memory retData = abi.encode(uint80(1), int256(2000e8), uint256(0), uint256(block.timestamp), uint80(1));\n"
            "    vm.mockCall(chainlinkFeed, abi.encodeWithSignature(\"latestRoundData()\"), retData);\n"
            "    \n"
            "    assertEq(lendingPool.getCollateralPrice(), 2000e8);\n"
            "}"
        ),
        "aliases": ["vm.mockcall", "vmmockcall", "vm_mockcall", "mockcall", "mock call", "mock oracle"],
    },
    {
        "id": "vm_load_store",
        "name": "vm.load() / vm.store()",
        "category": "Foundry Cheatcodes",
        "syntax": "bytes32 val = vm.load(address target, bytes32 slot);\nvm.store(address target, bytes32 slot, bytes32 value);",
        "description": (
            "Directly reads (vm.load) or overrides (vm.store) any persistent contract storage slot. "
            "Allows setting private state variables, reentrancy locks, or upgrading proxy slots in unit tests."
        ),
        "auditor_notes": (
            "• Combines perfectly with /slot to calculate the exact storage slot of mapping elements before loading or storing!\n"
            "• Bypasses internal contract guards and sanity checks."
        ),
        "example": (
            "function test_overridePrivateVariable() public {\n"
            "    // Override slot 0 directly\n"
            "    vm.store(address(vault), bytes32(uint256(0)), bytes32(uint256(1337)));\n"
            "    assertEq(vault.totalValue(), 1337);\n"
            "}"
        ),
        "aliases": ["vm.load", "vm.store", "vmload", "vmstore", "vm_load", "vm_store", "cheat storage"],
    },
    {
        "id": "vm_etch",
        "name": "vm.etch()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.etch(address target, bytes calldata newRuntimeBytecode);",
        "description": (
            "Sets the runtime bytecode at a target address to the provided bytecode. "
            "Allows deploying contracts to specific pre-determined addresses without executing constructors."
        ),
        "auditor_notes": (
            "• Does not execute constructor or initializers—injects pure runtime bytecode.\n"
            "• Ideal for testing upgrades, mocking precompiles, or recreating mainnet addresses."
        ),
        "example": (
            "function test_etchMock() public {\n"
            "    address precompile = address(0x999);\n"
            "    vm.etch(precompile, hex\"600160005260206000f3\"); // returns 1\n"
            "}"
        ),
        "aliases": ["vm.etch", "vmetch", "vm_etch", "etch", "inject bytecode", "set bytecode"],
    },
    {
        "id": "vm_sign",
        "name": "vm.sign() / vm.addr()",
        "category": "Foundry Cheatcodes",
        "syntax": "(uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256 privateKey, bytes32 digest);\naddress signer = vm.addr(uint256 privateKey);",
        "description": (
            "Generates an ECDSA signature (v, r, s) over the 32-byte digest using a private key (vm.sign), "
            "and calculates the corresponding public Ethereum address (vm.addr)."
        ),
        "auditor_notes": (
            "• Standard for testing EIP-2612 permit(), EIP-712 typed signatures, and off-chain orderbooks.\n"
            "• Automatically enforces low-s values (EIP-2 compliant)."
        ),
        "example": (
            "function test_permit() public {\n"
            "    uint256 aliceKey = 0xA11CE;\n"
            "    address alice = vm.addr(aliceKey);\n"
            "    bytes32 digest = token.computeDigest(alice, spender, 1000, deadline);\n"
            "    \n"
            "    (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, digest);\n"
            "    token.permit(alice, spender, 1000, deadline, v, r, s);\n"
            "}"
        ),
        "aliases": ["vm.sign", "vmsign", "vm_sign", "vm.addr", "vmaddr", "sign digest", "private key"],
    },
    {
        "id": "vm_assume",
        "name": "vm.assume()",
        "category": "Foundry Cheatcodes",
        "syntax": "vm.assume(bool condition);",
        "description": (
            "In Foundry fuzz tests, if condition evaluates to false, the fuzzer discards the current inputs "
            "and generates new random inputs. Used to filter out invalid test scenarios."
        ),
        "auditor_notes": (
            "⚠️ FUZZER REJECTION BIAS:\n"
            "• Do not use vm.assume() on narrow conditions (e.g. `vm.assume(x == 42)`), as Forge will hit the max "
            "rejections limit and abort the test!\n"
            "• Use bound(val, min, max) instead of vm.assume() for range constraints."
        ),
        "example": (
            "function testFuzz_deposit(uint256 amount) public {\n"
            "    vm.assume(amount > 0 && amount < 1_000_000 ether);\n"
            "    vault.deposit(amount);\n"
            "}"
        ),
        "aliases": ["vm.assume", "vmassume", "vm_assume", "assume", "fuzz filter", "fuzzing"],
    },
    {
        "id": "console_log",
        "name": "console.log() / console2.log()",
        "category": "Foundry Cheatcodes",
        "syntax": "import \"forge-std/console.sol\";\nconsole.log(\"User:\", msg.sender);\nconsole.log(\"Amount:\", amount);\nconsole2.log(\"State:\", slot);",
        "description": (
            "Hardhat/Foundry console logging utility. Prints formatted debug output directly to the terminal "
            "when running `forge test -vv` or `-vvv`."
        ),
        "auditor_notes": (
            "• Strip all console.log imports before deploying to production mainnet to prevent unnecessary bytecode bloat.\n"
            "• Uses the special Hardhat precompile address `0x000000000000000000636F6E736F6C652E6C6F67`."
        ),
        "example": (
            "import \"forge-std/console2.sol\";\n\n"
            "function test_inspect() public {\n"
            "    console2.log(\"Gas remaining:\", gasleft());\n"
            "    console2.log(\"Sender:\", msg.sender);\n"
            "}"
        ),
        "aliases": ["console.log", "console", "console2", "console2.log", "print", "debug print"],
    },
]


def _normalize(text: str) -> str:
    """Strips parentheses, dots, underscores, dashes, spaces, and lowers case."""
    return (
        text.strip()
        .lower()
        .replace("()", "")
        .replace(".", "")
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
    )


def search_solidity(query: str) -> Dict[str, Any]:
    """Searches the Solidity and Foundry reference database for functions, keywords, or cheatcodes.

    Args:
        query: Search string (e.g. 'gas.left', 'vm.prank', 'ecrecover', 'encodePacked').

    Returns:
        Dictionary containing:
        - 'found': True if exact or unique match found
        - 'item': Dict of matched item (if found)
        - 'suggestions': List of matching items if multiple matches found
        - 'query': Original cleaned query
    """
    raw_clean = query.strip().lower()
    norm_q = _normalize(query)

    if not norm_q:
        return {
            "found": False,
            "item": None,
            "suggestions": [item["name"] for item in SOLIDITY_REFERENCE[:8]],
            "query": query,
        }

    # 1. Exact match on raw string, ID, name, or aliases
    for item in SOLIDITY_REFERENCE:
        # Check raw without ()
        if raw_clean.replace("()", "") == item["id"].lower() or raw_clean.replace("()", "") == item["name"].lower().replace("()", ""):
            return {"found": True, "item": item, "suggestions": [], "query": query}
        for alias in item.get("aliases", []):
            if raw_clean.replace("()", "") == alias.lower().replace("()", ""):
                return {"found": True, "item": item, "suggestions": [], "query": query}

        # Check normalized version (handles gas.left == gasleft, vm.prank == vmprank, etc.)
        if norm_q == _normalize(item["id"]) or norm_q == _normalize(item["name"]):
            return {"found": True, "item": item, "suggestions": [], "query": query}
        for alias in item.get("aliases", []):
            if norm_q == _normalize(alias):
                return {"found": True, "item": item, "suggestions": [], "query": query}

    # 2. Substring / partial match on normalized names and aliases
    matches = []
    for item in SOLIDITY_REFERENCE:
        matched = False
        norm_name = _normalize(item["name"])
        norm_id = _normalize(item["id"])

        if norm_q in norm_name or norm_q in norm_id:
            matched = True
        else:
            for alias in item.get("aliases", []):
                if norm_q in _normalize(alias):
                    matched = True
                    break
        if matched and item not in matches:
            matches.append(item)

    if len(matches) == 1:
        return {"found": True, "item": matches[0], "suggestions": [], "query": query}
    elif len(matches) > 1:
        return {
            "found": False,
            "item": None,
            "suggestions": [m["name"] for m in matches[:10]],
            "query": query,
        }

    # 3. Fuzzy search for typos
    all_names = [item["name"] for item in SOLIDITY_REFERENCE]
    all_aliases = [alias for item in SOLIDITY_REFERENCE for alias in item.get("aliases", [])]
    close = difflib.get_close_matches(raw_clean, all_names + all_aliases, n=5, cutoff=0.5)

    # Map matched alias back to canonical item name
    sugg_names = []
    for c in close:
        for item in SOLIDITY_REFERENCE:
            if c == item["name"] or c in item.get("aliases", []):
                if item["name"] not in sugg_names:
                    sugg_names.append(item["name"])

    return {
        "found": False,
        "item": None,
        "suggestions": sugg_names[:6],
        "query": query,
    }


def get_all_categories() -> Dict[str, List[Dict[str, str]]]:
    """Groups all reference items by category."""
    cats: Dict[str, List[Dict[str, str]]] = {}
    for item in SOLIDITY_REFERENCE:
        cat = item["category"]
        if cat not in cats:
            cats[cat] = []
        cats[cat].append({
            "id": item["id"],
            "name": item["name"],
            "syntax": item["syntax"].split("\n")[0],
        })
    return cats
