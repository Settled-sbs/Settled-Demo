# pragma version ^0.4.0
"""
@title MockDEX
@notice Simple 1:1 swap for testing delta guard
"""

interface IERC20:
    def transferFrom(_from: address, _to: address, _value: uint256) -> bool: nonpayable
    def transfer(_to: address, _value: uint256) -> bool: nonpayable
    def balanceOf(_owner: address) -> uint256: view
    def decimals() -> uint8: view

RWA: public(immutable(address))
USDC: public(immutable(address))

@deploy
def __init__(_rwa: address, _usdc: address):
    RWA = _rwa
    USDC = _usdc

@external
def swap(tokenIn: address, tokenOut: address, amount: uint256):
    """
    @notice 1:1 swap for testing
    @dev Pulls tokenIn from caller, sends tokenOut to caller
    """
    assert (tokenIn == RWA and tokenOut == USDC) or (tokenIn == USDC and tokenOut == RWA), "Invalid pair"
    assert tokenIn != tokenOut, "Same token"
    
    # Pull tokenIn from caller (proxy)
    success: bool = extcall IERC20(tokenIn).transferFrom(msg.sender, self, amount)
    assert success, "Transfer in failed"
    
    # Determine amount out (1:1, adjust for decimals)
    amountOut: uint256 = amount
    if tokenIn == RWA and tokenOut == USDC:
        amountOut = amount * 10**6 // 10**18  # RWA 18dec → USDC 6dec
    elif tokenIn == USDC and tokenOut == RWA:
        amountOut = amount * 10**18 // 10**6  # USDC 6dec → RWA 18dec
    
    # Send tokenOut to caller (proxy)
    success = extcall IERC20(tokenOut).transfer(msg.sender, amountOut)
    assert success, "Transfer out failed"