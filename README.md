# Olympus protocol libraries

This repository contains a group of libraries used by the Olympus protocol.

Some of this libraries are a direct copy of an external repository. 
For compliance with MIT licence we add a link to the original repository.

* `base58`: A direct copy of the [btcsuite](https://github.com/btcsuite) base58 implementation.  [Original Source](https://github.com/btcsuite/btcutil/tree/master/base58)
* `bip32`: A bip32 implementation using bls key pairs.
* `bip39`: An implementation of bip39 on golang.
* `hdwallets`: An hdwallets interface using bip32, bip39 and bls.
* `bls`: A Pure GO bls library implementing the BLS12-381 curve created by the [Phore Project](https://github.com/phoreproject/). [Original Source](https://github.com/phoreproject/bls)
