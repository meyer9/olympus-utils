Go BLS HD Wallet tools
------------------
> This library is using the BLS12-381 curve to generate HD Wallets.
> This should not be used for Bitcoin or any other cryptocurrency using the secp256k1 curve.
>
 - BIP32 - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 - BLS Implementation - https://github.com/phoreproject/bls

### Get this library

        go get github.com/grupokindynos/olympus-utils/hdwallets

### Example

        // Generate a random 256 bit seed
        seed, err := hdwallets.GenerateSeed(256)

        // Create a master private key
        masterprv := hdwallet.NewMaster(seed, []byte{0x03, 0xE2, 0x59, 0x45})

        // Convert a private key to public key
        masterpub := masterprv.Neuter([]byte{0x03, 0xE2, 0x5D, 0x7E})

        // Generate new child key based on private or public key
        childprv, err := masterprv.Child(0)
        childpub, err := masterpub.Child(0)