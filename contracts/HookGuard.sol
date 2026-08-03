// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * @title AgentFirewall
 * @notice Settled Protocol's on-chain firewall. ERC-7579 HOOK module (type 4). Writted in Solidity with AI, might contain bugs/vulnerabilities. Use at your own risk.
 * @dev Solidity equivalent of AgentFirewall.vy.
 *      Enforces pre/post check spending limits, selector blocklists, and target whitelists.
 */

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract AgentFirewall {
    // ─── Constants ───
    uint256 public constant HOOK_MODULE_TYPE = 4;

    // ERC-7579 Mode Enums
    bytes1 public constant CALLTYPE_SINGLE = 0x00;
    bytes1 public constant CALLTYPE_DELEGATE = 0xFF;

    // Blocked function selectors
    bytes4 public constant APPROVE_SELECTOR = 0x095ea7b3;               // approve(address,uint256)
    bytes4 public constant INCREASE_ALLOWANCE_SELECTOR = 0x39509351;   // increaseAllowance(address,uint256)
    bytes4 public constant TRANSFER_FROM_SELECTOR = 0x23b872dd;         // transferFrom(address,address,uint256)
    bytes4 public constant PERMIT_SELECTOR = 0xd505accf;                // permit(address,address,uint256,uint8,bytes32,bytes32)
    bytes4 public constant SET_APPROVAL_FOR_ALL_SELECTOR = 0xa22cb465;   // setApprovalForAll(address,bool)

    // ─── Structs & State Variables ───
    struct AccountConfig {
        bool initialized;
        bool paused;
        address owner;
        address trackedToken;
        uint256 maxSpendPerTx;
        uint256 maxSpendTotal;
        uint256 spentTotal;
    }

    mapping(address => AccountConfig) public configs;
    mapping(address => mapping(address => bool)) public whitelist;

    // Reentrancy lock flag
    uint256 private _reentrancyStatus;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    // ─── Events ───
    event ModuleInstalled(uint256 moduleTypeId, address indexed account);
    event ModuleUninstalled(uint256 moduleTypeId, address indexed account);
    event Installed(
        address indexed account,
        address owner,
        address trackedToken,
        uint256 maxSpendPerTx,
        uint256 maxSpendTotal
    );
    event WhitelistUpdated(address indexed account, address indexed target, bool allowed);
    event SpendRecorded(address indexed account, uint256 amount, uint256 newTotal);
    event Violation(address indexed account, string reason);
    event Paused(address indexed account, bool paused);
    event MethodBlocked(address indexed account, address indexed target, bytes4 selector);

    // ─── Modifiers ───
    modifier nonReentrant() {
        require(_reentrancyStatus != _ENTERED, "ReentrancyGuard: reentrant call");
        _reentrancyStatus = _ENTERED;
        _;
        _reentrancyStatus = _NOT_ENTERED;
    }

    constructor() {
        _reentrancyStatus = _NOT_ENTERED;
    }

    // ─── ERC-7579 Interface Functions ───

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == HOOK_MODULE_TYPE;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return configs[smartAccount].initialized;
    }

    /**
     * @notice Install the hook on a smart account.
     * @param data ABI-encoded: (owner, trackedToken, maxSpendPerTx, maxSpendTotal, initialWhitelist[4])
     */
    function onInstall(bytes calldata data) external {
        address account = msg.sender;
        require(!configs[account].initialized, "already installed");

        (
            address owner,
            address trackedToken,
            uint256 maxSpendPerTx,
            uint256 maxSpendTotal,
            address[4] memory initialWhitelist
        ) = abi.decode(data, (address, address, uint256, uint256, address[4]));

        require(owner != address(0), "owner required");
        require(maxSpendPerTx > 0 && maxSpendPerTx <= maxSpendTotal, "bad limits");

        configs[account] = AccountConfig({
            initialized: true,
            paused: false,
            owner: owner,
            trackedToken: trackedToken,
            maxSpendPerTx: maxSpendPerTx,
            maxSpendTotal: maxSpendTotal,
            spentTotal: 0
        });

        for (uint256 i = 0; i < initialWhitelist.length; i++) {
            address target = initialWhitelist[i];
            if (target != address(0)) {
                whitelist[account][target] = true;
                emit WhitelistUpdated(account, target, true);
            }
        }

        emit ModuleInstalled(HOOK_MODULE_TYPE, account);
        emit Installed(account, owner, trackedToken, maxSpendPerTx, maxSpendTotal);
    }

    /**
     * @notice Uninstall hook. Clears account config.
     */
    function onUninstall(bytes calldata) external {
        address account = msg.sender;
        delete configs[account];
        emit ModuleUninstalled(HOOK_MODULE_TYPE, account);
    }

    // ─── Admin Functions ───

    function togglePause(address smartAccount) external {
        AccountConfig storage cfg = configs[smartAccount];
        require(cfg.initialized, "firewall not installed");
        require(msg.sender == cfg.owner, "only owner can toggle pause");

        bool newPaused = !cfg.paused;
        cfg.paused = newPaused;
        emit Paused(smartAccount, newPaused);
    }

    function updateWhitelist(address smartAccount, address target, bool allowed) external {
        AccountConfig storage cfg = configs[smartAccount];
        require(cfg.initialized, "firewall not installed");
        require(msg.sender == cfg.owner, "only owner can update whitelist");

        whitelist[smartAccount][target] = allowed;
        emit WhitelistUpdated(smartAccount, target, allowed);
    }

    function updateLimits(address smartAccount, uint256 maxSpendPerTx, uint256 maxSpendTotal) external {
        AccountConfig storage cfg = configs[smartAccount];
        require(cfg.initialized, "firewall not installed");
        require(msg.sender == cfg.owner, "only owner can update limits");
        require(maxSpendPerTx > 0 && maxSpendPerTx <= maxSpendTotal, "bad limits");
        require(maxSpendTotal >= cfg.spentTotal, "below already-spent total");

        cfg.maxSpendPerTx = maxSpendPerTx;
        cfg.maxSpendTotal = maxSpendTotal;
    }

    // ─── Internal Helpers & Slicing Engine ───

    function _balanceOf(address account, address token) internal view returns (uint256) {
        if (token == address(0)) {
            return account.balance;
        }
        return IERC20(token).balanceOf(account);
    }

    function _decodeTarget(bytes calldata msgData) internal pure returns (address target) {
        require(msgData.length >= 120, "malformed execution calldata");
        // Target is packed at byte index 100 in standard ERC-7579 single calls
        return address(bytes20(msgData[100:120]));
    }

    function _decodeInnerSelector(bytes calldata msgData) internal pure returns (bytes4) {
        if (msgData.length < 156) {
            return bytes4(0);
        }
        // Inner selector starts after target (20B) + value (32B) at byte index 152
        return bytes4(msgData[152:156]);
    }

    function _isDangerousTransferFrom(bytes calldata msgData, address account) internal pure returns (bool) {
        bytes4 selector = _decodeInnerSelector(msgData);
        if (selector != TRANSFER_FROM_SELECTOR) {
            return false;
        }

        if (msgData.length < 188) {
            return false;
        }

        // Extract 20-byte address from the 32-byte ABI slot at byte index 156 (skip 12-byte zero padding -> index 168)
        address fromAddr = address(bytes20(msgData[168:188]));
        return fromAddr == account;
    }

    function _isBlockedSelector(bytes4 selector) internal pure returns (bool) {
        return (
            selector == APPROVE_SELECTOR ||
            selector == INCREASE_ALLOWANCE_SELECTOR ||
            selector == PERMIT_SELECTOR ||
            selector == SET_APPROVAL_FOR_ALL_SELECTOR
        );
    }

    // ─── ERC-7579 Hook Execution Controls ───

    /**
     * @notice Snapshots balance before execution and validates target + method.
     */
    function preCheck(address, uint256, bytes calldata msgData) external nonReentrant returns (bytes memory) {
        address account = msg.sender;
        AccountConfig memory cfg = configs[account];

        require(cfg.initialized, "firewall not installed");
        require(!cfg.paused, "firewall paused");

        // Extract callType (first byte of 32-byte mode parameter at byte index 4)
        bytes1 callType = bytes1(msgData[4:5]);
        require(callType == CALLTYPE_SINGLE, "AgentFirewall: only single call allowed");

        // ─── Extract and validate target ───
        address target = _decodeTarget(msgData);
        require(whitelist[account][target], "target not whitelisted");

        // ─── Block dangerous method selectors ───
        bytes4 innerSelector = _decodeInnerSelector(msgData);

        if (_isBlockedSelector(innerSelector)) {
            emit MethodBlocked(account, target, innerSelector);
            emit Violation(account, "blocked method: allowance");
            revert("allowance methods blocked");
        }

        // ─── Block transferFrom draining FROM account ───
        if (_isDangerousTransferFrom(msgData, account)) {
            emit Violation(account, "blocked: transferFrom drain");
            revert("transferFrom drain blocked");
        }

        // ─── Snapshot balance ───
        uint256 balanceBefore = _balanceOf(account, cfg.trackedToken);

        // Return hook data for postCheck
        return abi.encode(account, balanceBefore);
    }

    /**
     * @notice Enforces spend limits after execution.
     */
    function postCheck(bytes calldata hookData) external nonReentrant {
        (address account, uint256 balanceBefore) = abi.decode(hookData, (address, uint256));
        require(account == msg.sender, "hookData/account mismatch");

        AccountConfig storage cfg = configs[account];
        uint256 balanceAfter = _balanceOf(account, cfg.trackedToken);

        // If balance grew or held flat (e.g., yield strategy profit), exit cleanly
        if (balanceAfter >= balanceBefore) {
            return;
        }

        // Calculate net spend and enforce caps
        uint256 spent = balanceBefore - balanceAfter;
        require(spent <= cfg.maxSpendPerTx, "exceeds per-tx spending limit");
        require(cfg.spentTotal + spent <= cfg.maxSpendTotal, "exceeds total spending limit");

        cfg.spentTotal += spent;
        emit SpendRecorded(account, spent, cfg.spentTotal);
    }

    // ─── View Functions ───

    function getConfig(address account) external view returns (AccountConfig memory) {
        return configs[account];
    }

    function isWhitelisted(address smartAccount, address target) external view returns (bool) {
        return whitelist[smartAccount][target];
    }

    function isMethodBlocked(bytes4 selector) external pure returns (bool) {
        return _isBlockedSelector(selector);
    }
}