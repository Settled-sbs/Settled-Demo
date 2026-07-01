# pragma version ^0.4.0
"""
@title MockRWA
@notice Simple whitelisted ERC-20 to Settled Guard can test against for RWA logic
"""

from ethereum.ercs import IERC20

implements: IERC20

name: public(String[32])
symbol: public(String[32])
decimals: public(uint8)
totalSupply: public(uint256)
balanceOf: public(HashMap[address, uint256])
allowance: public(HashMap[address, HashMap[address, uint256]])

owner: public(address)
whitelist: public(HashMap[address, bool])

event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    value: uint256

@deploy
def __init__():
    self.name = "Mock Treasury Bill"
    self.symbol = "mT-BILL"
    self.decimals = 18
    self.owner = msg.sender
    self.whitelist[msg.sender] = True

@external
def addToWhitelist(addr: address):
    assert msg.sender == self.owner
    self.whitelist[addr] = True

@external
def mint(receiver: address, amount: uint256):
    assert msg.sender == self.owner
    self.totalSupply += amount
    self.balanceOf[receiver] += amount
    log Transfer(empty(address), receiver, amount)

@external
def transfer(to: address, amount: uint256) -> bool:
    # This is the "RWA Check" - only whitelisted addresses can trade
    assert self.whitelist[msg.sender], "NOT_WHITELISTED"
    assert self.balanceOf[msg.sender] >= amount, "INSUFFICIENT_BALANCE"
    
    self.balanceOf[msg.sender] -= amount
    self.balanceOf[to] += amount
    log Transfer(msg.sender, to, amount)
    return True

@external
def approve(spender: address, amount: uint256) -> bool:
    self.allowance[msg.sender][spender] = amount
    return True

@external
def transferFrom(from_: address, to: address, amount: uint256) -> bool:
    # This is the "RWA Check" - only whitelisted addresses can trade
    assert self.whitelist[from_], "NOT_WHITELISTED"
    assert self.balanceOf[from_] >= amount, "INSUFFICIENT_BALANCE"
    assert self.allowance[from_][msg.sender] >= amount, "INSUFFICIENT_ALLOWANCE"
    
    self.balanceOf[from_] -= amount
    self.balanceOf[to] += amount
    self.allowance[from_][msg.sender] -= amount
    log Transfer(from_, to, amount)
    return True
