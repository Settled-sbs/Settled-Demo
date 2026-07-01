# Audit Scope Specification: Settled Protocol v0.1

This document outlines the exact boundary of the execution environment submitted for security verification.

## Target Review Architecture

The audit scope is strictly isolated to the core invariant enforcement engine.

### In Scope
* `contracts/HookGuard.vy`: The unified ERC-7579 compliance and guard logic contract.
  * State management for per-account configurations (whitelists, balance snapshots, spend limits).
  * Invariant math integrity during `preCheck` and `postCheck` hooks.
  * Storage isolation boundaries preventing cross-account configuration corruption.
  * Access control vectors on configuration modification entry points.

### Out of Scope
* Native ERC-7579 Smart Account implementations (e.g., Biconomy, Safe, or ZeroDev account kernels).
* Off-chain agent orchestration frameworks or private session-key management modules.

## Known Architecture Assumptions & Risk Profiles

1. **The 1-Wei Balance Drift Vector:** Current balance delta tracking enforces absolute inflows and outflows (`balance_after > balance_before`). It does not validate fair market price execution in v0.1.
2. **Malicious Calldata Shadowing:** High-severity risks involving execution nesting within custom target payloads are acknowledged; validation relies entirely on target whitelisting in this version.
3. **Reentrancy Vectors:** The engine relies on the host account kernel's execution lifecycle security to prevent storage state manipulation between `preCheck` and `postCheck`.