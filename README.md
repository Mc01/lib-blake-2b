# Lib Blake2b

## Installation
```sh
npm i git+https://github.com/Mc01/lib-blake-2b.git
```

## Usage

Import and use directly in your Diamond Proxy:
```solidity
// ensure input bytecode is padded by 256 bits
bytes memory inputBytes_ = abi.encodePacked(new bytes(256 - input_.length), input_);

// compute blake 2b hash out of padded input bytecode
bytes32 outputHash_ = Blake2bAB.blake2b_256(inputBytes_); 
```
