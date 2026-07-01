# @version 0.4.3
"""
@title FirewallHook
@notice Settled Protocol's on-chain firewall. ERC-7579 HOOK module (type 4).

@dev Enforcement model (defense in depth):
    1. WHITELIST — preCheck reverts if call target not approved
    2. PRE/POST BALANCE DELTA — snapshot before, enforce limit after
    3. CUMULATIVE SPEND CAP — lifetime spend bounded at install

    postCheck runs INSIDE the userOp execution. Violation reverts atomically.
    Agent session key can sign ops, but cannot push funds past hook limits.
    Only smart account owner can change whitelist/limits — session key has
    no permission to touch firewall config.
"""


interface IERC20:
    def balanceOf(account: address) -> uint256: view

HOOK_MODULE_TYPE: constant(uint256) = 4

struct AccountConfig:
    initialized: bool
    paused: bool
    owner: address
    trackedToken: address
    maxSpendPerTx: uint256
    maxSpendTotal: uint256
    spentTotal: uint256

configs: public(HashMap[address, AccountConfig])
whitelist: public(HashMap[address, HashMap[address, bool]])

event HookInstalled:
    account: indexed(address)
    owner: address
    maxSpendPerTx: uint256
    maxSpendTotal: uint256

event WhitelistUpdated:
    account: indexed(address)
    target: indexed(address)
    allowed: bool

event SpendRecorded:
    account: indexed(address)
    amount: uint256
    newTotal: uint256

event Violation:
    account: indexed(address)
    reason: String[64]

@external
@view
def isModuleType(typeID: uint256) -> bool:
    return typeID == HOOK_MODULE_TYPE

@external
@view
def isInitialized(smartAccount: address) -> bool:
    return self.configs[smartAccount].initialized

@external
def onInstall(data: Bytes[1024]):
    account: address = msg.sender
    assert not self.configs[account].initialized, "already installed"

    owner: address = empty(address)
    trackedToken: address = empty(address)
    maxSpendPerTx: uint256 = 0
    maxSpendTotal: uint256 = 0
    initialWhitelist: address[4] = empty(address[4])

    owner, trackedToken, maxSpendPerTx, maxSpendTotal, initialWhitelist = abi_decode(
        data, (address, address, uint256, uint256, address[4])
    )

    assert owner != empty(address), "owner required"
    assert maxSpendPerTx > 0 and maxSpendPerTx <= maxSpendTotal, "bad limits"

    self.configs[account] = AccountConfig(
        initialized=True,
        paused=False,
        owner=owner,
        trackedToken=trackedToken,
        maxSpendPerTx=maxSpendPerTx,
        maxSpendTotal=maxSpendTotal,
        spentTotal=0,
    )

    for target: address in initialWhitelist:
        if target != empty(address):
            self.whitelist[account][target] = True
            log WhitelistUpdated(account=account, target=target, allowed=True)

    log HookInstalled(
        account=account,
        owner=owner,
        maxSpendPerTx=maxSpendPerTx,
        maxSpendTotal=maxSpendTotal,
    )

@external
def onUninstall(data: Bytes[1024]):
    account: address = msg.sender
    self.configs[account] = empty(AccountConfig)

@external
def updateWhitelist(target: address, allowed: bool):
    account: address = msg.sender
    cfg: AccountConfig = self.configs[account]
    assert cfg.initialized, "not installed"
    assert msg.sender == cfg.owner, "only owner can update whitelist"
    self.whitelist[account][target] = allowed
    log WhitelistUpdated(account=account, target=target, allowed=allowed)

@external
def updateLimits(maxSpendPerTx: uint256, maxSpendTotal: uint256):
    account: address = msg.sender
    cfg: AccountConfig = self.configs[account]
    assert msg.sender == cfg.owner, "only owner can update limits"
    assert cfg.initialized, "not installed"
    assert maxSpendPerTx > 0 and maxSpendPerTx <= maxSpendTotal, "bad limits"
    assert maxSpendTotal >= cfg.spentTotal, "below already-spent total"

    self.configs[account].maxSpendPerTx = maxSpendPerTx
    self.configs[account].maxSpendTotal = maxSpendTotal

@internal
@view
def _balanceOf(account: address, token: address) -> uint256:
    if token == empty(address):
        return account.balance
    return staticcall IERC20(token).balanceOf(account)

@internal
@pure
def _decodeTarget(msgData: Bytes[8192]) -> address:
    """
    Extract target from ERC-7579 single execution msg.data.
    Layout: selector(4) + mode(32) + offset(32) + length(32) + target(20) + ...
    """
    assert len(msgData) >= 68, "malformed calldata"

    callType: Bytes[1] = slice(msgData, 4, 1)
    assert convert(callType, uint256) == 0, "only single-call execution allowed"

    offsetBytes: Bytes[32] = slice(msgData, 36, 32)
    offset: uint256 = convert(offsetBytes, uint256)
    dataStart: uint256 = 4 + offset

    assert len(msgData) >= dataStart + 52, "malformed execution calldata"

    # target is at dataStart + 32 (after the length word)
    targetBytes: Bytes[20] = slice(msgData, dataStart + 32, 20)
    return convert(targetBytes, address)

@external
def preCheck(msgSender: address, msgValue: uint256, msgData: Bytes[8192]) -> Bytes[2048]:
    """
    @notice Snapshots balance before execution and validates target.
    """
    account: address = msg.sender
    cfg: AccountConfig = self.configs[account]
    
    assert cfg.initialized, "firewall not installed"

    # Extract and validate target
    target: address = self._decodeTarget(msgData)
    assert self.whitelist[account][target], "target not whitelisted"

    # Snapshot balance
    balanceBefore: uint256 = self._balanceOf(account, cfg.trackedToken)

    # Return hook data for postCheck
    return abi_encode(account, balanceBefore)

@external
def postCheck(hookData: Bytes[2048]):
    """
    @notice Enforces spend limits after execution.
    """
    account: address = empty(address)
    balanceBefore: uint256 = 0
    
    account, balanceBefore = abi_decode(hookData, (address, uint256))
    assert account == msg.sender, "hookData/account mismatch"

    cfg: AccountConfig = self.configs[account]
    balanceAfter: uint256 = self._balanceOf(account, cfg.trackedToken)

    # If balance grew or held flat, nothing spent
    if balanceAfter >= balanceBefore:
        return

    # Calculate spend and enforce limits
    spent: uint256 = balanceBefore - balanceAfter
    assert spent <= cfg.maxSpendPerTx, "exceeds per-tx spending limit"
    assert cfg.spentTotal + spent <= cfg.maxSpendTotal, "exceeds total spending limit"

    self.configs[account].spentTotal += spent
    log SpendRecorded(account=account, amount=spent, newTotal=self.configs[account].spentTotal)

@external
@view
def getConfig(account: address) -> AccountConfig:
    return self.configs[account]