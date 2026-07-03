# Settled Protocol, Demo Repo

## Capital That Can't Be Drained

ERC-7579 hook module. One contract, per-account config. Enforces whitelist + spend caps at the EVM level.

### What It Does

- `preCheck`: Validates target is whitelisted. Snapshots balance.
- `postCheck`: Enforces per-tx and cumulative spend limits. Reverts if exceeded.
- Agent session key can sign anything. Hook decides what executes.

### What It Doesn't Do

- Doesn't prevent bad trades within limits
- Doesn't prevent protocol exploits (Aave, Compound getting hacked)
- Doesn't prevent owner key compromise
- Doesn't do batch execution (v0.1)
- Doesn't verify token legitimacy (v0.2)
- Doesn't check slippage (owner responsibility)

### Contracts

| File | Purpose |
|---|---|
| `HookGuard.vy` | Core hook — whitelist, spend caps, cumulative limits |
| `HookGuard.sol` | Solidity version, for brevity |
| `MockTBill.vy` | Test token (18 decimals) |
| `MockUSDC.vy` | Test stablecoin (6 decimals) |
| `MockDEX.vy` | 1:1 fixed-rate swap for testing |

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

### Current State

- Local simulation works
- No audit yet
- No mainnet deployment
- No real 7579 account integration (uses deployer as proxy)
- No session key flow
- No bundler integration

### Roadmap (Not Promises)

| Version | What | Status |
|---|---|---|
| v0.1 | Single-call, whitelist, spend caps | Works locally |
| v0.2 | Batch execution, token oracle | Not started |
| v0.3 | Multi-asset, cross-chain | Not started |
| v0.4 | Compliance reporting, RWA identity | Not started |

### The Honest Pitch

> "Your agent can be completely compromised. The server can be owned. The LLM can be tricked. The session key can leak. Capital still can't move past what you allowed."

That's it. Everything else is your responsibility.

### License

MIT
