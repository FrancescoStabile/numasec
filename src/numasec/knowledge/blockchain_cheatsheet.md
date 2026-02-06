# Blockchain & Smart Contract Exploitation

## Solidity Vulnerability Patterns

### Reentrancy
```solidity
// Vulnerable: external call before state update
function withdraw() public {
    uint bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");
    require(ok);
    balances[msg.sender] = 0;  // ← too late
}

// Attack: attacker's receive() calls withdraw() again before balance zeroed
// Fix: checks-effects-interactions pattern (update state BEFORE call)
// Fix: ReentrancyGuard / nonReentrant modifier
```

### Integer Overflow/Underflow (pre-Solidity 0.8)
```solidity
// Solidity < 0.8: no automatic overflow checks
uint8 x = 255; x += 1;  // → 0 (overflow)
uint8 y = 0;   y -= 1;  // → 255 (underflow)

// Fix: Solidity ≥ 0.8 has built-in checks
// Fix: SafeMath library for older versions
// Attack: bypass token balance checks, mint unlimited tokens
```

### Access Control
```solidity
// Missing access control
function mint(address to, uint amount) public {
    balances[to] += amount;  // anyone can call!
}

// tx.origin vs msg.sender
// tx.origin = original caller (EOA), msg.sender = immediate caller
// Vulnerable: require(tx.origin == owner) → phishing attack via malicious contract
// Fix: always use msg.sender for auth
```

### Delegatecall Vulnerabilities
```solidity
// delegatecall executes code in caller's context (storage)
// If attacker controls the target address → arbitrary storage writes
// Proxy pattern bugs: implementation can selfdestruct, storage collisions
```

### Flash Loan Attacks
```solidity
// 1. Borrow massive amount (no collateral)
// 2. Manipulate price oracle / pool
// 3. Exploit the manipulated state
// 4. Repay loan + fee in same transaction
// Defense: use TWAP (time-weighted average price) oracles
```

### Front-Running / MEV
```
// Mempool monitoring → see pending transactions
// Insert transaction with higher gas price → execute before victim
// Sandwich attack: buy before victim, sell after victim
// Tools: Flashbots, MEV-Boost
```

## Smart Contract Audit Checklist

```
1. Access control — who can call sensitive functions?
2. Reentrancy — external calls before state updates?
3. Integer arithmetic — overflow/underflow (< 0.8)?
4. Oracle manipulation — price feeds manipulable?
5. Flash loan attack surface — can state be exploited atomically?
6. Front-running — are transactions order-dependent?
7. Timestamp dependence — block.timestamp as randomness?
8. Denial of service — can loops be made unbounded?
9. Selfdestruct — can implementation be destroyed?
10. Delegatecall — storage layout collisions?
11. Signature replay — nonce protection?
12. ERC-20 approve race condition — approve(0) first?
```

## Tools

```bash
# Static analysis
slither .                           # Comprehensive Solidity analyzer
mythril analyze contract.sol        # Symbolic execution
solhint contract.sol                # Linter

# Fuzzing
echidna . --contract TestContract   # Property-based fuzzer

# Decompilation (bytecode → readable)
panoramix 0xADDRESS                 # Decompile from chain
heimdall decompile -a 0xADDRESS     # Alternative decompiler

# Interaction
cast call 0xADDRESS "balanceOf(address)" 0xUSER --rpc-url URL  # Foundry
cast send 0xADDRESS "withdraw()" --private-key KEY --rpc-url URL

# Block explorers
# Etherscan, BscScan, PolygonScan → read/write contract, view source
```

## DeFi Attack Patterns

```
# Price Oracle Manipulation
1. Flash loan large amount of token A
2. Swap on DEX to crash token A price
3. Exploit protocol that reads manipulated price
4. Swap back, repay flash loan

# Governance Attack
1. Flash loan governance tokens
2. Create + vote on malicious proposal
3. Execute proposal (drain treasury)
4. Repay tokens

# Bridge Exploitation
1. Fake deposit proof on source chain
2. Claim tokens on destination chain
# Notable: Ronin ($625M), Wormhole ($326M), Nomad ($190M)
```
