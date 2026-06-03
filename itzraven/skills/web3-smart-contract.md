---
name: web3-smart-contract
description: Web3 & smart contract security auditing — DeFi, reentrancy, Flash loans, Solidity static analysis
category: blockchain
---

# Web3 / Smart Contract Audit Methodology

> For authorized smart contract audits and DeFi security assessments.

## PHASE 1 — Reconnaissance
```bash
# Gather contract info from blockchain explorers
# Etherscan: https://etherscan.io/address/CONTRACT_ADDRESS#code
# Check verified source code, ABI, transaction history

# Find similar contracts / forked projects
# Search for contract bytecode similarities
```

## PHASE 2 — Static Analysis
```bash
# Slither — Static analysis framework
slither contract.sol --detect all --json slither_report.json

# Mythril — Security analysis tool
mythril analyze contract.sol --execution-timeout 300

# Aderyn — Rust-based Solidity AST analyzer
aderyn contract.sol

# Semgrep — Custom rules
semgrep --config auto contract.sol
```

### Critical Vulnerability Checklist
- **Reentrancy**: External calls before state updates
- **Flash Loan Attacks**: Price oracle manipulation within single transaction
- **Integer Overflow/Underflow**: Arithmetic without SafeMath (pre-0.8)
- **Access Control**: Missing `onlyOwner`, `onlyRole` modifiers
- **Front-running**: Transaction ordering dependence (TOD)
- **Unchecked External Calls**: Ignored return values from `call{value:}()`
- **Timestamp Dependence**: `block.timestamp` used for randomness
- **Delegatecall Injection**: Untrusted contract addresses in delegatecall
- **Signature Replay**: Missing nonce in EIP-712 signatures
- **Price Oracle Manipulation**: Single-source oracles (Uniswap TWAP)

## PHASE 3 — DeFi Protocol Testing
- Test liquidity pool math
- Check for donation attacks
- Verify fee calculation rounding
- Test flash loan integration points
- Check reward distribution fairness

## PHASE 4 — Common Attack Vectors

### Reentrancy
```solidity
// ❌ Vulnerable:
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

// ✅ Secure:
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool success,) = msg.sender.call{value: amount}("");
}
```

### Oracle Manipulation
- Test large swaps in low-liquidity pools
- Check if spot price is used without TWAP
- Verify minimum/maximum price bounds

### Access Control
- Check `tx.origin` vs `msg.sender` usage
- Verify `_disableInitializers()` in upgradeable proxies
- Test selfdestruct in implementation contracts

## Tools
- **Slither**: `slither contract.sol --detect all`
- **Mythril**: `mythril analyze contract.sol`
- **Foundry**: `forge test`, `forge coverage`
- **Hardhat**: `npx hardhat test` with `hardhat-gas-reporter`
- **Echidna**: Fuzzing — `echidna-test contract.sol`
- **Certora**: Formal verification (paid)
