# @version 0.4.3
"""
@title AgentFirewall.vy
@notice Settled Protocol's on-chain firewall for agent autonomous operations. ERC-7579 HOOK module (type 4).

@dev Enforcement model (defense in depth):
    1. WHITELIST — preCheck reverts if call target not approved
    2. METHOD BLOCKLIST — blocks approve, increaseAllowance, transferFrom drains
    3. PRE/POST BALANCE DELTA — snapshot before, enforce limit after
    4. CUMULATIVE SPEND CAP — lifetime spend bounded at install
    5. PAUSE — owner can emergency-stop all agent execution

    postCheck runs INSIDE the userOp execution. Violation reverts atomically.
    Agent session key can sign ops, but cannot push funds past hook limits.
    Only smart account owner can change whitelist/limits — session key has
    no permission to touch firewall config.
"""


interface IERC20:
    def balanceOf(account: address) -> uint256: view
    def allowance(owner: address, spender: address) -> uint256: view

HOOK_MODULE_TYPE: constant(uint256) = 4

# ─── ERC-7579 Mode Enums / Values ───
CALLTYPE_SINGLE: constant(bytes1) = 0x00
CALLTYPE_DELEGATE: constant(bytes1) = 0xFF

# ─── Blocked function selectors ───
# These are the 4 byte keccak256 signatures of dangerous methods
APPROVE_SELECTOR: constant(bytes4) = 0x095ea7b3          # approve(address,uint256)
INCREASE_ALLOWANCE_SELECTOR: constant(bytes4) = 0x39509351  # increaseAllowance(address,uint256)
TRANSFER_FROM_SELECTOR: constant(bytes4) = 0x23b872dd    # transferFrom(address,address,uint256)
PERMIT_SELECTOR: constant(bytes4) = 0xd505accf           # permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
SET_APPROVAL_FOR_ALL_SELECTOR: constant(bytes4) = 0xa22cb465  # setApprovalForAll(address,bool)

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

# Track known spenders to optionally reset allowances (future use)
knownSpenders: public(HashMap[address, DynArray[address, 50]])


event ModuleInstalled:
    moduleTypeId: uint256
    account: indexed(address)

event ModuleUninstalled:
    moduleTypeId: uint256
    account: indexed(address)

event FirewallActive:
    account: indexed(address)
    owner: address
    trackedToken: address
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

event Paused:
    account: indexed(address)
    paused: bool

event MethodBlocked:
    account: indexed(address)
    target: indexed(address)
    selector: bytes4


@external
@view
def isModuleType(moduleTypeId: uint256) -> bool:
    return moduleTypeId == HOOK_MODULE_TYPE


@external
@view
def isInitialized(smartAccount: address) -> bool:
    return self.configs[smartAccount].initialized


@external
def onInstall(data: Bytes[1024]):
    """
    @notice Install the hook on a smart account.
    @param data ABI-encoded: (owner, trackedToken, maxSpendPerTx, maxSpendTotal, initialWhitelist[4])
    """
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

    log ModuleInstalled(
        moduleTypeId=HOOK_MODULE_TYPE,
        account=account,
    )
    log FirewallActive(
        account=account,
        owner=owner,
        trackedToken=trackedToken,
        maxSpendPerTx=maxSpendPerTx,
        maxSpendTotal=maxSpendTotal,
    )

@external
def onUninstall(data: Bytes[1024]):
    """
    @notice Uninstall hook called by the Smart Account.
    """
    account: address = msg.sender
    assert self.configs[account].initialized, "not installed"

    # Reset account configuration - (This is a security risk if the agent can just uninstall the firewall, but we assume this is not the case for V1.)
    self.configs[account] = empty(AccountConfig)
    log ModuleUninstalled(moduleTypeId=HOOK_MODULE_TYPE, account=account)


@external
def togglePause(smartAccount: address):
    """
    @notice Emergency pause/unpause for a specific smart account.
    @param smartAccount The address of the Smart Account to pause.
    """
    cfg: AccountConfig = self.configs[smartAccount]
    
    assert cfg.initialized, "firewall not installed"
    
    # Verify that the caller (msg.sender) is the configured owner of THIS smart account
    assert msg.sender == cfg.owner, "only owner can toggle pause"

    newPaused: bool = not cfg.paused
    self.configs[smartAccount].paused = newPaused
    log Paused(account=smartAccount, paused=newPaused)


@external
def updateWhitelist(smartAccount: address, target: address, allowed: bool):
    """
    @notice Add or remove a whitelisted target for a smart account. Owner only.
    """
    cfg: AccountConfig = self.configs[smartAccount]
    
    assert cfg.initialized, "firewall not installed"
    assert msg.sender == cfg.owner, "only owner can update whitelist"
    
    self.whitelist[smartAccount][target] = allowed
    log WhitelistUpdated(account=smartAccount, target=target, allowed=allowed)


@external
def updateLimits(smartAccount: address, maxSpendPerTx: uint256, maxSpendTotal: uint256):
    """
    @notice Update spend limits for a smart account. Owner only.
    """
    cfg: AccountConfig = self.configs[smartAccount]
    
    assert cfg.initialized, "firewall not installed"
    assert msg.sender == cfg.owner, "only owner can update limits"
    assert maxSpendPerTx > 0 and maxSpendPerTx <= maxSpendTotal, "bad limits"
    assert maxSpendTotal >= cfg.spentTotal, "below already-spent total"

    self.configs[smartAccount].maxSpendPerTx = maxSpendPerTx
    self.configs[smartAccount].maxSpendTotal = maxSpendTotal


@internal
@view
def _balanceOf(account: address, token: address) -> uint256:
    """@notice Get token balance. MUST be ERC-20 compliant."""
    return staticcall IERC20(token).balanceOf(account)


@internal
@view
def _getBalance(account: address) -> uint256:
    """@notice Get account native balance"""
    return account.balance
    

@internal
@pure
def _decodeTarget(msgData: Bytes[8192]) -> address:
    """
    @notice Extracts target address from standard ERC-7579 execute() call.
    @dev Layout:
         4 bytes (selector) + 32 bytes (mode) + 32 bytes (offset) + 32 bytes (length)
         Target starts explicitly at byte 100 for 20 bytes.
    """
    assert len(msgData) >= 120, "malformed execution calldata"
    
    # Extract target from packed executionCalldata (starts at byte 100)
    targetBytes: Bytes[20] = slice(msgData, 100, 20)
    return convert(targetBytes, address)


@internal
@pure
def _decodeInnerSelector(msgData: Bytes[8192]) -> bytes4:
    """
    @notice Extracts the inner target function selector from execute() call.
    @dev Inner callData starts immediately after target (20B) + value (32B) at byte 152.
    """
    # 4 (sel) + 32 (mode) + 32 (offset) + 32 (length) + 20 (target) + 32 (value) + 4 (inner selector) = 156 bytes min
    if len(msgData) < 156:
        return empty(bytes4)

    return convert(slice(msgData, 152, 4), bytes4)


@internal
@pure
def _isDangerousTransferFrom(msgData: Bytes[8192], account: address) -> bool:
    """
    @notice Validates if transferFrom is attempting to drain the smart account.
    @dev transferFrom(address from, address to, uint256 value)
         The 'from' parameter starts 4 bytes after the inner selector (152 + 4 = byte 156).
    """
    selector: bytes4 = self._decodeInnerSelector(msgData)
    if selector != TRANSFER_FROM_SELECTOR:
        return False

    if len(msgData) < 188: # 156 + 32 bytes (ABI encoded 'from' address)
        return False

    # Extract 20 byte address from the 32 byte ABI padded slot at byte 156
    fromBytes: Bytes[20] = slice(msgData, 168, 20)
    fromAddr: address = convert(fromBytes, address)

    return fromAddr == account

@internal
@pure
def _isBlockedSelector(selector: bytes4) -> bool:
    """@notice Check if a function selector is in the blocklist."""
    return (
        selector == APPROVE_SELECTOR
        or selector == INCREASE_ALLOWANCE_SELECTOR
        or selector == PERMIT_SELECTOR
        or selector == SET_APPROVAL_FOR_ALL_SELECTOR
    )


@external
@nonreentrant
def preCheck(msgSender: address, msgValue: uint256, msgData: Bytes[8192]) -> Bytes[2048]:
    """
    @notice Snapshots balance before execution and validates target + method.
    @dev Blocks: non-whitelisted targets, blocked selectors, paused accounts.
    """
    account: address = msg.sender
    cfg: AccountConfig = self.configs[account]

    assert cfg.initialized, "firewall not installed"
    assert not cfg.paused, "firewall paused"

    # (From ERC-7579 spec)
    # The execution mode is a bytes32 value that is structured as follows:
    # callType (1 byte): 0x00 for a single call, 0x01 for a batch call, 0xfe for staticcall and 0xff for delegatecall
    # execType (1 byte): 0x00 for executions that revert on failure, 0x01 for executions that do not revert on failure but implement some form of error handling
    # unused (4 bytes): this range is reserved for future standardization
    # modeSelector (4 bytes): an additional mode selector that can be used to create further execution modes
    # modePayload (22 bytes): additional data to be passed

    callType: bytes1 = convert(slice(msgData, 4, 1), bytes1)
    
    # Revert if batching is attempted (forces 1-call-at-a-time security model for V1)
    assert callType == CALLTYPE_SINGLE, "AgentFirewall: only single call allowed"

    # ─── Extract and validate target ───
    target: address = self._decodeTarget(msgData)
    assert self.whitelist[account][target], "target not whitelisted"

    # ─── Block dangerous method selectors ───
    innerSelector: bytes4 = self._decodeInnerSelector(msgData)

    if self._isBlockedSelector(innerSelector):
        log MethodBlocked(account=account, target=target, selector=innerSelector)
        log Violation(account=account, reason="blocked method: allowance")
        raise "allowance methods blocked"

    # ─── Block transferFrom draining FROM account ───
    if self._isDangerousTransferFrom(msgData, account):
        log Violation(account=account, reason="blocked: transferFrom drain")
        raise "transferFrom drain blocked"

    # ─── Snapshot balance ───
    balanceBefore: uint256 = self._balanceOf(account, cfg.trackedToken)

    # Return hook data for postCheck
    return abi_encode(account, balanceBefore)


@external
@nonreentrant
def postCheck(hookData: Bytes[2048]):
    """
    @notice Enforces spend limits after execution.
    @dev If balance grew or held flat, nothing spent.
    """
    account: address = empty(address)
    balanceBefore: uint256 = 0

    account, balanceBefore = abi_decode(hookData, (address, uint256))
    assert account == msg.sender, "hookData/account mismatch"

    cfg: AccountConfig = self.configs[account]
    balanceAfter: uint256 = self._balanceOf(account, cfg.trackedToken)

    # If balance grew or held flat, no spend occurred, so all good here.s
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
def getNativeBalance(account: address) -> uint256:
    """@notice Get native balance of a smart account."""
    return self._getBalance(account)


@external
@view
def getConfig(account: address) -> AccountConfig:
    """@notice Read full config for an account."""
    return self.configs[account]


@external
@view
def isWhitelisted(smartAccount: address, target: address) -> bool:
    """@notice Check if a target is whitelisted for an account."""
    return self.whitelist[smartAccount][target]


@external
@view
def isMethodBlocked(selector: bytes4) -> bool:
    """@notice Check if a selector is globally blocked."""
    return self._isBlockedSelector(selector)