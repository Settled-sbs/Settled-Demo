# @pragma version ^0.4.0

"""
@title Custom USDC (Testnet)
@notice Simple ERC20 for Fuji Testnet minting 1B tokens to deployer.
"""

from ethereum.ercs import IERC20

implements: IERC20

# ERC20 Metadata
NAME: constant(String[32]) = "USD Coin"
SYMBOL: constant(String[32]) = "USDC"
DECIMALS: constant(uint8) = 18

# State Variables
totalSupply: public(uint256)
balanceOf: public(HashMap[address, uint256])
allowance: public(HashMap[address, HashMap[address, uint256]])

admin: public(address)

# Events
event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    _value: uint256

event Approval:
    owner: indexed(address)
    spender: indexed(address)
    _value: uint256

@deploy
def __init__():
    # 1 Billion * 10^18
    initial_supply: uint256 = 1_000_000_000 * 10**convert(DECIMALS, uint256)
    
    self.totalSupply = initial_supply
    self.balanceOf[msg.sender] = initial_supply
    self.admin = msg.sender
    log Transfer(empty(address), msg.sender, initial_supply)

@external
def mint(receiver: address, amount: uint256):
    assert msg.sender == self.admin, "Only admin can mint"
    self.totalSupply += amount
    self.balanceOf[receiver] += amount
    log Transfer(empty(address), receiver, amount)

@external
def transfer(to: address, _value: uint256) -> bool:
    assert to != empty(address), "Cannot transfer to zero address"
    self.balanceOf[msg.sender] -= _value
    self.balanceOf[to] += _value
    log Transfer(msg.sender, to, _value)
    return True

@external
def transferFrom(sender: address, receiver: address, _value: uint256) -> bool:
    assert receiver != empty(address), "Cannot transfer to zero address"
    self.allowance[sender][msg.sender] -= _value
    self.balanceOf[sender] -= _value
    self.balanceOf[receiver] += _value
    log Transfer(sender, receiver, _value)
    return True

@external
def approve(spender: address, _value: uint256) -> bool:
    self.allowance[msg.sender][spender] = _value
    log Approval(msg.sender, spender, _value)
    return True

@external
@view
def name() -> String[32]:
    return NAME

@external
@view
def symbol() -> String[32]:
    return SYMBOL

@external
@view
def decimals() -> uint8:
    return DECIMALS