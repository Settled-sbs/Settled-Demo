# Settled Protocol, Demo Repo

**EVM Spend Enforcement for ERC-7579 Smart Accounts**

Deterministic on-chain guardrails that prevent treasury drainage, even with full key compromise.

--- 


## What This Is

An ERC-7579 Hook Module (Type 4) that enforces spend limits and blocks dangerous transaction patterns at the EVM level. Install on any ERC-7579 smart account in one transaction.

| Feature | Status |
|---------|--------|
| Per-transaction spend limits | ✅ |
| Cumulative spend caps | ✅ |
| Contract whitelisting | ✅ |
| Block `approve()` / `increaseAllowance()` / `permit()` / `setApprovalForAll()` | ✅ |
| Block `transferFrom` drains | ✅ |
| Emergency pause | ✅ |
| Single-call execution enforcement | ✅ |
| Batch execution parsing | 🚧 In Progress |



## What It Doesn't Do

- Doesn't prevent bad trades within limits
- Doesn't prevent protocol exploits (Aave, Compound getting hacked)
- Doesn't prevent owner key compromise
- Doesn't do batch execution (v0.1)
- Doesn't verify token legitimacy (v0.2)
- Doesn't check slippage (owner responsibility)

---

## Architecture

```
User EOA
    │
    ├──► EIP-7702 Delegation (optional)
    │
    └──► ERC-7579 Smart Account (Nexus, Kernel, Safe7579)
            │
            ├──► Session Key (Validator) — Agent signs here
            │
            └──► Settled Hook (Type 4) — Enforcement happens here
                    │
                    ├── preCheck: whitelist + method blocklist + snapshot
                    ├── execute: target contract call
                    └── postCheck: spend limit enforcement
```

**The agent can sign. The hook decides if it executes.**

---

## Biconomy Nexus Integration

### Current Status

Testing on Avalanche Fuji with Biconomy Nexus 1.2.0.

| Test | Status |
|------|--------|
| Hook installation via `installModule` | ✅ Passing |
| Single-call `execute()` parsing | ✅ Passing |
| `preCheck` whitelist enforcement | ✅ Passing |
| `postCheck` spend limit enforcement | ✅ Passing |
| `approve()` blocking | ✅ Passing |
| Batch `execute()` parsing | 🚧 Calldata offset verification needed |

### Known Integration Points

**Nexus `execute()` encoding:**
- Selector: `0x0000189a` (`execute(mode, executionCalldata)`)
- Mode: `bytes32` with callType `0x00` for single call
- Target extracted at offset +100 bytes
- Inner selector extracted at offset +152 bytes

**Open Question for Biconomy Engineers:**
> Does Nexus pass full `executeBatch()` calldata to `preCheck`, or does it iterate and call `preCheck` per inner transaction? This affects how cumulative spend limits are enforced across batch operations.

---

### Contracts

| File | Purpose |
|---|---|
| `HookGuard.vy` | Core hook — whitelist, spend caps, cumulative limits |
| `HookGuard.sol` | Solidity version, for brevity |
| `MockTBill.vy` | Test token (18 decimals) |
| `MockUSDC.vy` | Test stablecoin (6 decimals) |
| `MockDEX.vy` | 1:1 fixed-rate swap for testing |

---

### Deployment (Fuji Testnet)

| Contract | Address | Network |
|----------|---------|---------|
| `HookGuard.vy` | `0xb1143e214d7667C68b0236980579cfa3Dde485E6` | Avalanche Fuji |
| `MockDEX.vy` | `0x18556DA13313f3532c54711497A8FedAC273220E` | Avalanche Fuji |
| USDC (Circle Testnet) | `0x5425890298aed601595a70AB815c96711a31Bc65` | Avalanche Fuji |

---

## Quick Start

### 1. Install the Hook

```vyper
# Via your smart account's installModule()
# Module type: 4 (HOOK)
# Data: abi_encode(owner, trackedToken, maxSpendPerTx, maxSpendTotal, initialWhitelist[4])

hook.onInstall(
    abi_encode(
        msg.sender,                    # owner
        0x5425890298aed601595a70AB815c96711a31Bc65,  # USDC
        100 * 10**6,                  # maxSpendPerTx: 100 USDC
        500 * 10**6,                  # maxSpendTotal: 500 USDC
        [0x18556DA13313f3532c54711497A8FedAC273220E]  # MockDEX whitelisted
    )
)
```

### 2. Execute a Guarded Transaction

```typescript
// Agent attempts swap — HookGuard validates
const tx = await smartAccount.execute({
    target: MOCK_DEX,
    data: encodeFunctionData({
        abi: MOCK_DEX_ABI,
        functionName: "swap",
        args: [parseUnits("50", 6)]  // 50 USDC
    })
});
// ✅ Passes: within limit, whitelisted target

// Agent attempts infinite approve — HookGuard blocks
const maliciousTx = await smartAccount.execute({
    target: USDC,
    data: encodeFunctionData({
        abi: ERC20_ABI,
        functionName: "approve",
        args: [attackerAddress, MaxUint256]
    })
});
// ❌ Reverts: "allowance methods blocked"
```

---

## The Problem We Solve

| Attack Vector | Without Settled | With Settled |
|---------------|-----------------|--------------|
| Compromised session key → infinite approve | 💸 Total drainage | 🚫 Reverted at EVM |
| Compromised session key → transfer to random address | 💸 Total drainage | 🚫 Reverted: non-whitelisted |
| Compromised session key → overspend | 💸 Total drainage | 🚫 Reverted: exceeds limit |
| Compromised session key → transferFrom drain | 💸 Total drainage | 🚫 Reverted: blocked pattern |

---

## Contract: `HookGuard.vy`

### Key Functions

```vyper
@external
def preCheck(msgSender: address, msgValue: uint256, msgData: Bytes[8192]) -> Bytes[2048]:
    """
    @notice Validates target + method before execution
    @dev Blocks: non-whitelisted targets, blocked selectors, paused accounts
    """

@external
def postCheck(hookData: Bytes[2048]):
    """
    @notice Enforces spend limits after execution
    @dev Reverts if balance delta exceeds maxSpendPerTx or total cap
    """

@external
def togglePause(smartAccount: address):
    """@notice Emergency pause. Owner only."""

@external
def updateWhitelist(smartAccount: address, target: address, allowed: bool):
    """@notice Update whitelisted targets. Owner only."""
```

### Blocked Selectors

| Selector | Method | Why Blocked |
|----------|--------|-------------|
| `0x095ea7b3` | `approve(address,uint256)` | Infinite allowance vector |
| `0x39509351` | `increaseAllowance(address,uint256)` | Allowance escalation |
| `0x23b872dd` | `transferFrom(address,address,uint256)` | Drain vector when `from == account` |
| `0xd505accf` | `permit(...)` | Signature-based allowance bypass |
| `0xa22cb465` | `setApprovalForAll(address,bool)` | NFT operator drain |

---


### Tested Scenarios

1. Swap within limits → passes
2. Swap exceeds per-tx cap → reverts at postCheck
3. Swap to non-whitelisted target → reverts at preCheck
4. Cumulative spend exceeds total cap → reverts at postCheck

### Run Simulation

```bash

uv sync 

uv run ape run scripts/simulations.py --network ethereum:local
```

### Architecture

```
Agent signs UserOp → Smart Account → preCheck (whitelist + snapshot)
                                      ↓
                                    execute (swap on DEX)
                                      ↓
                                    postCheck (spend limits)
```


**Test Matrix:**
- ✅ Standard DEX swap within limits
- ✅ Per-transaction limit enforcement
- ✅ Cumulative lifecycle caps
- ✅ Target extraction filters
- ✅ Method blocklist validation
- ✅ Pause/unpause functionality

---

## Roadmap

| Milestone | Status |
|-----------|--------|
| Core hook architecture (Vyper) | ✅ Complete |
| Local simulation rig | ✅ 100% pass rate |
| Fuji testnet deployment | ✅ Live |
| **Biconomy Nexus integration** | 🚧 Testing |
| Batch execution parsing | 🚧 In Progress |
| Mainnet audit | ⏳ Pending |

---
### The Idea. In Summary

> "Your agent can be completely compromised. The server can be owned. The LLM can be tricked. The session key can leak. Capital still can't move past what you allowed."

Everything else is your responsibility.

---
## Contact

- **Founder:** Benjamin Mgbeoji
- **Twitter:** [@secondfrontman](https://x.com/secondfrontman)
- **Email:** xphinix1@gmail.com
- **Demo:** [Video link coming]

---
### License

MIT
