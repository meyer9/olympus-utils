# Olympus protocol libraries

![Actions](https://github.com/grupokindynos/olympus-utils/workflows/Utils/badge.svg)
[![codecov](https://codecov.io/gh/grupokindynos/olympus-utils/branch/master/graph/badge.svg)](https://codecov.io/gh/grupokindynos/olympus-utils)
[![Go Report](https://goreportcard.com/badge/github.com/grupokindynos/olympus-utils)](https://goreportcard.com/report/github.com/grupokindynos/olympus-utils) 
[![GoDocs](https://godoc.org/github.com/grupokindynos/olympus-utils?status.svg)](http://godoc.org/github.com/grupokindynos/olympus-utils)

This repository contains a group of libraries used by the Olympus protocol.

Some of this libraries are a direct copy of an external repository. 
For compliance with MIT licence we add a link to the original repository.

* `address`: A library to parse and convert bls Public/Secret keys to bech32 Olympus format.
* `amount`: An amount handling interface copied and modified from [btcsuite](https://github.com/btcsuite) amount interface.  [Original Source](https://github.com/btcsuite/btcutil/tree/master/amount.go)
* `base58`: A direct copy of the [btcsuite](https://github.com/btcsuite) base58 implementation.  [Original Source](https://github.com/btcsuite/btcutil/tree/master/base58)
* `bip39`: An implementation of bip39 on golang.
* `bls`: A Pure GO bls library implementing the BLS12-381 curve created by the [Phore Project](https://github.com/phoreproject/). [Original Source](https://github.com/grupokindynos/olympus-utils/bls)
* `chainhash`: Hashing functions utility for Olympus.
* `hdwallets`: A HD wallets implementation using bls key pairs.
