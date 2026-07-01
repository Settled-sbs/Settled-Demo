// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

contract FirewallHook {
    
    uint256 public constant HOOK_MODULE_TYPE = 4;

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

    event HookInstalled(
        address indexed account,
        address owner,
        uint256 maxSpendPerTx,
        uint256 maxSpendTotal
    );
    
    event WhitelistUpdated(
        address indexed account,
        address indexed target,
        bool allowed
    );
    
    event SpendRecorded(
        address indexed account,
        uint256 amount,
        uint256 newTotal
    );
    
    event Violation(
        address indexed account,
        string reason
    );

    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == HOOK_MODULE_TYPE;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return configs[smartAccount].initialized;
    }

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

        for (uint256 i = 0; i < 4; i++) {
            address target = initialWhitelist[i];
            if (target != address(0)) {
                whitelist[account][target] = true;
                emit WhitelistUpdated(account, target, true);
            }
        }

        emit HookInstalled(account, owner, maxSpendPerTx, maxSpendTotal);
    }

    function onUninstall(bytes calldata) external {
        address account = msg.sender;
        delete configs[account];
    }

    function updateWhitelist(address target, bool allowed) external {
        address account = msg.sender;
        AccountConfig memory cfg = configs[account];
        require(cfg.initialized, "not installed");
        require(msg.sender == cfg.owner, "only owner can update whitelist");
        
        whitelist[account][target] = allowed;
        emit WhitelistUpdated(account, target, allowed);
    }

    function updateLimits(uint256 maxSpendPerTx, uint256 maxSpendTotal) external {
        address account = msg.sender;
        AccountConfig storage cfg = configs[account];
        require(msg.sender == cfg.owner, "only owner can update limits");
        require(cfg.initialized, "not installed");
        require(maxSpendPerTx > 0 && maxSpendPerTx <= maxSpendTotal, "bad limits");
        require(maxSpendTotal >= cfg.spentTotal, "below already-spent total");

        cfg.maxSpendPerTx = maxSpendPerTx;
        cfg.maxSpendTotal = maxSpendTotal;
    }

    function _balanceOf(address account, address token) internal view returns (uint256) {
        if (token == address(0)) {
            return account.balance;
        }
        return IERC20(token).balanceOf(account);
    }

    function _decodeTarget(bytes calldata msgData) internal pure returns (address target) {
        /*
        Extract target from ERC-7579 single execution msg.data.
        Layout: selector(4) + mode(32) + offset(32) + length(32) + target(20) + ...
        */
        require(msgData.length >= 68, "malformed calldata");

        bytes1 callType = msgData[4];
        require(uint8(callType) == 0, "only single-call execution allowed");

        uint256 offset;
        assembly {
            // Read the 32 bytes starting at index 36 (4 + 32)
            offset := calldataload(36)
        }
        uint256 dataStart = 4 + offset;

        require(msgData.length >= dataStart + 52, "malformed execution calldata");

        assembly {
            // Target is at dataStart + 32 (skipping the 32-byte dynamic bytes length field)
            // Plus an additional 12 bytes padding offset since address is 20 bytes inside a 32-byte word
            target := calldataload(add(dataStart, 52))
        }
    }

    function preCheck(
        address, 
        uint256, 
        bytes calldata msgData
    ) external returns (bytes memory) {
        address account = msg.sender;
        AccountConfig memory cfg = configs[account];
        
        require(cfg.initialized, "firewall not installed");

        // Extract and validate target
        address target = _decodeTarget(msgData);
        require(whitelist[account][target], "target not whitelisted");

        // Snapshot balance
        uint256 balanceBefore = _balanceOf(account, cfg.trackedToken);

        // Return hook data for postCheck
        return abi.encode(account, balanceBefore);
    }

    function postCheck(bytes calldata hookData) external {
        (address account, uint256 balanceBefore) = abi.decode(hookData, (address, uint256));
        require(account == msg.sender, "hookData/account mismatch");

        AccountConfig storage cfg = configs[account];
        uint256 balanceAfter = _balanceOf(account, cfg.trackedToken);

        // If balance grew or held flat, nothing spent
        if (balanceAfter >= balanceBefore) {
            return;
        }

        // Calculate spend and enforce limits
        uint256 spent = balanceBefore - balanceAfter;
        require(spent <= cfg.maxSpendPerTx, "exceeds per-tx spending limit");
        require(cfg.spentTotal + spent <= cfg.maxSpendTotal, "exceeds total spending limit");

        cfg.spentTotal += spent;
        emit SpendRecorded(account, spent, cfg.spentTotal);
    }

    function getConfig(address account) external view returns (AccountConfig memory) {
        return configs[account];
    }
}