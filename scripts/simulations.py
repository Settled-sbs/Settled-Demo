"""
Ape script to deploy mocks and run a deterministic preCheck -> swap -> postCheck
flow locally using Anvil.

Run: ape run deploy_test --network ethereum:local
"""
from ape import accounts, project, networks
from eth_abi.abi import encode
from eth_utils import function_signature_to_4byte_selector

CALLTYPE_SINGLE = 0


def build_execute_msgdata(
    selector: bytes,
    target: str,
    value: int,
    call_data: bytes,
    calltype: int = CALLTYPE_SINGLE,
) -> bytes:
    """Build msg.data for ERC-7579 execute() call."""
    assert len(selector) == 4, "selector must be 4 bytes"

    exec_mode = bytes([calltype]) + (b"\x00" * 31)
    offset = 64
    offset_word = offset.to_bytes(32, "big")

    target_bytes = bytes.fromhex(target[2:]) if target.startswith("0x") else bytes.fromhex(target)
    assert len(target_bytes) == 20, "target must be 20 bytes"
    value_word = value.to_bytes(32, "big")
    payload = target_bytes + value_word + call_data

    length_word = len(payload).to_bytes(32, "big")
    pad_len = (32 - (len(payload) % 32)) % 32
    payload_padded = payload + (b"\x00" * pad_len)

    return selector + exec_mode + offset_word + length_word + payload_padded


def main():
    with networks.parse_network_choice("ethereum:local") as provider:
        print(f"Connected to local Anvil at {provider.uri}")
        
        deployer = accounts.test_accounts[0]
        print(f"Deployer: {deployer.address}")
        
        # Deploy contracts
        print("\n[1/4] Deploying MockTBill...")
        mock_rwa = project.MockTBill.deploy(sender=deployer)
        print(f"  MockTBill: {mock_rwa.address}")
        
        print("\n[2/4] Deploying MockUSDC...")
        mock_usdc = project.MockUSDC.deploy(sender=deployer)
        print(f"  MockUSDC: {mock_usdc.address}")
        
        print("\n[3/4] Deploying MockDEX...")
        mock_dex = project.MockDEX.deploy(mock_rwa.address, mock_usdc.address, sender=deployer)
        print(f"  MockDEX: {mock_dex.address}")
        
        print("\n[4/4] Deploying FirewallHook...")
        firewall = project.HookGuard.deploy(sender=deployer)
        print(f"  FirewallHook: {firewall.address}")
        
        # Configure firewall
        print("\n[5/6] Configuring firewall...")
        owner = deployer.address
        tracked_token = mock_rwa.address
        max_per_tx = 10**20   # 100 RWA
        max_total = 10**22    # 10,000 RWA
        
        initial_whitelist = [
            mock_dex.address,
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000"
        ]
        
        install_data = encode(
            ['address', 'address', 'uint256', 'uint256', 'address[4]'],
            [owner, tracked_token, max_per_tx, max_total, initial_whitelist]
        )
        
        firewall.onInstall(install_data, sender=deployer)
        print(f"  Firewall installed")
        
        print(firewall.getConfig(deployer.address))

        
        # Fund accounts — give DEX enough USDC for ALL tests
        print("\n[6/6] Funding...")
        mint_amount = 10**24  # 1M RWA (plenty for all tests)
        mock_rwa.mint(deployer.address, mint_amount, sender=deployer)
        mock_rwa.approve(mock_dex.address, mint_amount, sender=deployer)
        
        # DEX needs enough USDC to cover the excessive swap too
        # If swap rate is 1 RWA = 10^-6 USDC (10**6 USDC per 10**18 RWA)
        # Then 10^21 RWA = 10^9 USDC. Give DEX 10^15 to be safe.
        usdc_mint = 10**15
        mock_usdc.mint(mock_dex.address, usdc_mint, sender=deployer)
        print(f"  Minted {mint_amount} RWA to deployer")
        print(f"  Minted {usdc_mint} USDC to DEX")
        
        # ============================================
        # SIMULATION 1: Agent swap within limits
        # ============================================
        print("\n" + "="*50)
        print("SIMULATION 1: Agent swap within limits")
        print("="*50)
        
        swap_amount = 10**18  # 1 RWA
        
        swap_selector = function_signature_to_4byte_selector("swap(address,address,uint256)")
        inner_calldata = swap_selector + encode(
            ['address', 'address', 'uint256'],
            [mock_rwa.address, mock_usdc.address, swap_amount]
        )
        
        execute_selector = b"\x00\x00\x00\x00"
        msgdata = build_execute_msgdata(
            execute_selector,
            mock_dex.address,
            0,
            inner_calldata
        )
        
        print(f"\nSwap amount: {swap_amount} RWA (limit: {max_per_tx})")
        print(f"Target: {mock_dex.address}")
        
        rwa_before = mock_rwa.balanceOf(deployer.address)
        usdc_before = mock_usdc.balanceOf(deployer.address)
        print(f"\nBalances before: RWA={rwa_before}, USDC={usdc_before}")
        
        print(f"\n--- preCheck ---")
        try:
            hook_data = firewall.preCheck.call(deployer.address, 0, msgdata, sender=deployer)
            print(f"  ✓ preCheck passed")
            print(f"  Hook data: {hook_data.hex()[:64]}...")
        except Exception as e:
            print(f"  ✗ preCheck FAILED: {e}")
            return
        
        print(f"\n--- Execute swap ---")
        tx = mock_dex.swap(mock_rwa.address, mock_usdc.address, swap_amount, sender=deployer)
        print(f"  ✓ Swap executed (gas: {tx.gas_used})")
        
        print(f"\n--- postCheck ---")
        try:
            tx_post = firewall.postCheck(hook_data, sender=deployer)
            print(f"  ✓ postCheck passed (gas: {tx_post.gas_used})")
        except Exception as e:
            print(f"  ✗ postCheck FAILED: {e}")
            return
        
        rwa_after = mock_rwa.balanceOf(deployer.address)
        usdc_after = mock_usdc.balanceOf(deployer.address)
        print(f"\nBalances after: RWA={rwa_after} (Δ: {rwa_before - rwa_after}), USDC={usdc_after} (Δ: {usdc_after - usdc_before})")
        
        # ============================================
        # SIMULATION 2: Exceed per-tx limit (should REVERT at postCheck)
        # ============================================
        print("\n" + "="*50)
        print("SIMULATION 2: Exceed per-tx limit (should revert)")
        print("="*50)
        
        # Amount above max_per_tx (10^20)
        excessive_amount = 10**21  # 1,000 RWA > 100 RWA limit
        
        inner_calldata_excess = swap_selector + encode(
            ['address', 'address', 'uint256'],
            [mock_rwa.address, mock_usdc.address, excessive_amount]
        )
        msgdata_excess = build_execute_msgdata(
            execute_selector,
            mock_dex.address,
            0,
            inner_calldata_excess
        )
        
        print(f"\nSwap amount: {excessive_amount} RWA (limit: {max_per_tx})")
        
        print(f"\n--- preCheck ---")
        try:
            hook_data_excess = firewall.preCheck.call(deployer.address, 0, msgdata_excess, sender=deployer)
            print(f"  ✓ preCheck passed (whitelist only)")
        except Exception as e:
            print(f"  ✗ preCheck FAILED: {e}")
            return
        
        print(f"\n--- Execute swap ---")
        # This should succeed on DEX (funded enough now)
        tx = mock_dex.swap(mock_rwa.address, mock_usdc.address, excessive_amount, sender=deployer)
        print(f"  ✓ DEX swap executed (gas: {tx.gas_used})")
        
        print(f"\n--- postCheck ---")
        try:
            tx_post = firewall.postCheck(hook_data_excess, sender=deployer)
            print(f"  ✗ postCheck PASSED — BUG! Should have reverted!")
        except Exception as e:
            error_msg = str(e)
            if "exceeds" in error_msg.lower() or "revert" in error_msg.lower():
                print(f"  ✓ postCheck correctly REVERTED: {error_msg[:100]}")
            else:
                print(f"  ? postCheck failed with unexpected error: {error_msg[:100]}")
        
        # ============================================
        # SIMULATION 3: Non-whitelisted target (should REVERT at preCheck)
        # ============================================
        print("\n" + "="*50)
        print("SIMULATION 3: Non-whitelisted target (should revert)")
        print("="*50)
        
        malicious_target = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        
        msgdata_malicious = build_execute_msgdata(
            execute_selector,
            malicious_target,
            0,
            inner_calldata  # doesn't matter, target check happens first
        )
        
        print(f"\nTarget: {malicious_target}")
        
        print(f"\n--- preCheck ---")
        try:
            hook_data_malicious = firewall.preCheck.call(deployer.address, 0, msgdata_malicious, sender=deployer)
            print(f"  ✗ preCheck PASSED — BUG! Should have reverted!")
        except Exception as e:
            error_msg = str(e)
            if "whitelist" in error_msg.lower() or "not allowed" in error_msg.lower():
                print(f"  ✓ preCheck correctly REVERTED: {error_msg[:100]}")
            else:
                print(f"  ? preCheck failed with unexpected error: {error_msg[:100]}")
        
        # ============================================
        # SIMULATION 4: Cumulative spend cap
        # ============================================
        print("\n" + "="*50)
        print("SIMULATION 4: Cumulative spend cap")
        print("="*50)

        # Check current spent total
        config = firewall.getConfig(deployer.address)
        print(f"\nCurrent spent: {config.spentTotal} / {config.maxSpendTotal}")

        # We've spent 1 RWA so far. Do 99 more swaps of 100 RWA each to reach 9,999.
        # Then one more swap of 2 RWA should exceed the 10,000 cap.

        # For demo speed, just do 2 more swaps to show the pattern, then update cap
        swaps_to_do = 2
        swap_size = 10**20  # 100 RWA (at per-tx limit)

        print(f"\nDoing {swaps_to_do} swaps of {swap_size} RWA to accumulate spend...")

        for i in range(swaps_to_do):
            inner = swap_selector + encode(
                ['address', 'address', 'uint256'],
                [mock_rwa.address, mock_usdc.address, swap_size]
            )
            msg = build_execute_msgdata(execute_selector, mock_dex.address, 0, inner)
            
            hook = firewall.preCheck.call(deployer.address, 0, msg, sender=deployer)
            tx = mock_dex.swap(mock_rwa.address, mock_usdc.address, swap_size, sender=deployer)
            firewall.postCheck(hook, sender=deployer)
            print(f"  Swap {i+1}: OK")

        config_after = firewall.getConfig(deployer.address)
        print(f"\nSpent after {swaps_to_do} swaps: {config_after.spentTotal} / {config_after.maxSpendTotal}")

        # Now update total cap to something just above current spent for quick test
        new_total = config_after.spentTotal + 10**18  # current + 1 RWA
        print(f"\nUpdating total cap to {new_total} (current + 1 RWA)...")
        firewall.updateLimits(10**20, new_total, sender=deployer)

        # Try one more 100 RWA swap — should exceed new total cap
        print(f"\nTrying one more 100 RWA swap (should exceed new total cap)...")
        inner_over = swap_selector + encode(
            ['address', 'address', 'uint256'],
            [mock_rwa.address, mock_usdc.address, swap_size]
        )
        msg_over = build_execute_msgdata(execute_selector, mock_dex.address, 0, inner_over)

        hook_over = firewall.preCheck.call(deployer.address, 0, msg_over, sender=deployer)
        tx = mock_dex.swap(mock_rwa.address, mock_usdc.address, swap_size, sender=deployer)

        try:
            firewall.postCheck(hook_over, sender=deployer)
            print(f"  ✗ postCheck PASSED — BUG!")
        except Exception as e:
            error_msg = str(e)
            if "total" in error_msg.lower() or "exceeds" in error_msg.lower():
                print(f"  ✓ postCheck correctly REVERTED for total cap: {error_msg[:100]}")
            else:
                print(f"  ? Unexpected: {error_msg[:100]}")
        else:
            print(f"  Already at cap, skipping")

        # ============================================
        # SIMULATION 5: The Exploitation Bypass Test
        # ============================================
        print("\n" + "="*50)
        print("SIMULATION 5: Enforcing Allowance Bypass Block")
        print("="*50)
        
        approve_selector = function_signature_to_4byte_selector("approve(address,uint256)")
        malicious_approve_calldata = approve_selector + encode(
            ['address', 'uint256'],
            [deployer.address, 2**256 - 1]
        )
        
        # Wrap approval payload inside the standard target execution frame
        malicious_msgdata = build_execute_msgdata(mock_rwa.address, 0, malicious_approve_calldata)
        
        print("--- Running preCheck Against Malicious Approval Attack Vector ---")
        try:
            firewall.preCheck.call(deployer.address, 0, malicious_msgdata, sender=deployer)
            print("  ✗ CRITICAL BUG: Firewall allowed raw approval calldata to proceed.")
        except Exception as e:
            if "allowance inflation forbidden" in str(e).lower():
                print("  ✓ SUCCESS: Firewall intercepted and rejected dynamic ERC20 approval.")
            else:
                print(f"  ? Verification call reverted with alternate code: {e}")
        
        print("\n" + "="*50)
        print("All simulations complete.")
        print("="*50)