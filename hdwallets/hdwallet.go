package hdwallets

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/grupokindynos/olympus-utils/base58"
	"github.com/grupokindynos/olympus-utils/bls"
	"github.com/grupokindynos/olympus-utils/bls/g2pubs"
	"github.com/grupokindynos/olympus-utils/chainhash"
	"math/big"
)

const (
	MinSeedBytes = 16 // 128 bits
	MaxSeedBytes = 64 // 512 bits
	maxUint8     = 1<<8 - 1
)

var (
	HardenedKeyStart = uint32(0x80000000) // 2^31
	masterKey        = []byte("Olympus seed")

	ErrInvalidSeedLen       = fmt.Errorf("seed length must be between %d and %d bits", MinSeedBytes*8, MaxSeedBytes*8)
	ErrDeriveBeyondMaxDepth = errors.New("cannot derive a key with more than 255 indices in its path")
	ErrUnusableSeed         = errors.New("unusable seed")
	ErrDeriveHardFromPublic = errors.New("cannot derive a hardened key from a public key")
	ErrInvalidChild         = errors.New("the extended key at this index is invalid")
)

type ExtendedKey struct {
	key       []byte // This will be the pubkey for extended pub keys
	pubKey    []byte // This will only be set for extended priv keys
	chainCode []byte
	depth     uint8
	parentFP  []byte
	childNum  uint32
	version   []byte
	isPrivate bool
}

func (k *ExtendedKey) Child(i uint32) (*ExtendedKey, error) {
	// Prevent derivation of children beyond the max allowed depth.
	if k.depth == maxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}

	// There are four scenarios that could happen here:
	// 1) Private extended key -> Hardened child private extended key
	// 2) Private extended key -> Non-hardened child private extended key
	// 3) Public extended key -> Non-hardened child public extended key
	// 4) Public extended key -> Hardened child public extended key (INVALID!)

	// Case #4 is invalid, so error out early.
	// A hardened child extended key may not be created from a public
	// extended key.
	isChildHardened := i >= HardenedKeyStart
	if !k.isPrivate && isChildHardened {
		return nil, ErrDeriveHardFromPublic
	}

	// The data used to derive the child key depends on whether or not the
	// child is hardened per [BIP32].
	//
	// For hardened children:
	//   0x00 || ser256(parentKey) || ser32(i)
	//
	// For normal children:
	//   serP(parentPubKey) || ser32(i)
	keyLen := 33
	data := make([]byte, keyLen+4)
	if isChildHardened {
		// Case #1.
		// When the child is a hardened child, the key is known to be a
		// private key due to the above early return.  Pad it with a
		// leading zero as required by [BIP32] for deriving the child.
		copy(data[1:], k.key)
	} else {
		// Case #2 or #3.
		// This is either a public or private extended key, but in
		// either case, the data which is used to derive the child key
		// starts with the secp256k1 compressed public key bytes.
		copy(data, k.pubKeyBytes())
	}
	binary.BigEndian.PutUint32(data[keyLen:], i)

	// Take the HMAC-SHA512 of the current key's chain code and the derived
	// data:
	//   I = HMAC-SHA512(Key = chainCode, Data = data)
	hmac512 := hmac.New(sha512.New, k.chainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = intermediate key used to derive the child
	//   Ir = child chain code
	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]

	// Both derived public or private keys rely on treating the left 32-byte
	// sequence calculated above (Il) as a 256-bit integer that must be
	// within the valid range for a secp256k1 private key.  There is a small
	// chance (< 1 in 2^127) this condition will not hold, and in that case,
	// a child extended key can't be created for this index and the caller
	// should simply increment to the next index.
	ilNum := new(big.Int).SetBytes(il)
	_, err := bls.FRReprFromBigInt(ilNum)
	if err != nil {
		return nil, ErrInvalidChild
	}
	if ilNum.Sign() == 0 {
		return nil, ErrInvalidChild
	}

	// The algorithm used to derive the child key depends on whether or not
	// a private or public child is being derived.
	//
	// For private children:
	//   childKey = parse256(Il) + parentKey
	//
	// For public children:
	//   childKey = serP(point(parse256(Il)) + parentKey)
	var isPrivate bool
	var childKey []byte
	if k.isPrivate {
		// Case #1 or #2.
		// Add the parent private key to the intermediate private key to
		// derive the final child key.
		//
		// childKey = parse256(Il) + parenKey
		keyNum := new(big.Int).SetBytes(k.key)
		ilNum.Add(ilNum, keyNum)
		ilNum.Mod(ilNum, btcec.S256().N)
		childKey = ilNum.Bytes()
		isPrivate = true
	} else {
		// Case #3.
		// Calculate the corresponding intermediate public key for
		// intermediate private key.
		ilx, ily := btcec.S256().ScalarBaseMult(il)
		if ilx.Sign() == 0 || ily.Sign() == 0 {
			return nil, ErrInvalidChild
		}

		// Convert the serialized compressed parent public key into X
		// and Y coordinates so it can be added to the intermediate
		// public key.
		pubKey, err := btcec.ParsePubKey(k.key, btcec.S256())
		if err != nil {
			return nil, err
		}

		// Add the intermediate public key to the parent public key to
		// derive the final child key.
		//
		// childKey = serP(point(parse256(Il)) + parentKey)
		childX, childY := btcec.S256().Add(ilx, ily, pubKey.X, pubKey.Y)
		pk := btcec.PublicKey{Curve: btcec.S256(), X: childX, Y: childY}
		childKey = pk.SerializeCompressed()
	}

	// The fingerprint of the parent for the derived child is the first 4
	// bytes of the RIPEMD160(SHA256(parentPubKey)).
	parentFP := chainhash.Hash160(k.pubKeyBytes())[:4]
	return NewExtendedKey(k.version, childKey, childChainCode, parentFP,
		k.depth+1, i, isPrivate), nil
}

func (k *ExtendedKey) pubKeyBytes() []byte {
	// Just return the key if it's already an extended public key.
	if !k.isPrivate {
		return k.key
	}
	// This is a private extended key and it is the masterKey. For masterKeys it is not necesary to calculate the pubKey
	// since it is useless and sometimes unsecure.
	if k.ParentFingerprint() == 0 {
		emptyBytes := make([]byte, 96)
		return emptyBytes
	}
	// This is a private extended key and it is not the masterKey, so calculate and memorize the public key if needed.
	if len(k.pubKey) == 0 {
		var rawPrivKey [32]byte
		buf := bytes.NewBuffer(rawPrivKey[:0])
		buf.Write(k.key)
		privKey := g2pubs.DeserializeSecretKey(rawPrivKey)
		pubKey := g2pubs.PrivToPub(privKey).Serialize()
		k.pubKey = pubKey[:]
	}
	return k.pubKey
}

func (k *ExtendedKey) IsPrivate() bool {
	return k.isPrivate
}

func (k *ExtendedKey) Depth() uint8 {
	return k.depth
}

func (k *ExtendedKey) ParentFingerprint() uint32 {
	return binary.BigEndian.Uint32(k.parentFP)
}

func (k *ExtendedKey) Neuter(prefix []byte) (*ExtendedKey, error) {
	if !k.isPrivate {
		return k, nil
	}
	return NewExtendedKey(prefix, k.pubKeyBytes(), k.chainCode, k.parentFP,
		k.depth, k.childNum, false), nil
}

// String returns the extended key as a human-readable base58-encoded string.
func (k *ExtendedKey) String() string {
	if len(k.key) == 0 {
		return "zeroed extended key"
	}
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.childNum)
	// The serialized format is:
	//   version (4) || depth (1) || parent fingerprint (4)) ||
	//   child num (4) || chain code (32) || key data (33) for privkeys or key data(96) for pubkeys || checksum (4)
	var serializedKeyLen int
	if k.isPrivate {
		serializedKeyLen = 4 + 1 + 4 + 4 + 32 + 33 + 4
	} else {
		serializedKeyLen = 4 + 1 + 4 + 4 + 32 + 96 + 4
	}
	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.version...)
	serializedBytes = append(serializedBytes, k.depth)
	serializedBytes = append(serializedBytes, k.parentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.chainCode...)
	if k.isPrivate {
		serializedBytes = append(serializedBytes, 0x00)
		serializedBytes = paddedAppend(32, serializedBytes, k.key)
	} else {
		serializedBytes = append(serializedBytes, k.pubKeyBytes()...)
	}
	checkSum := chainhash.DoubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

func NewMaster(seed []byte, prefix []byte) (*ExtendedKey, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}
	// First take the HMAC-SHA512 of the master key and the seed data:
	//   I = HMAC-SHA512(Key = "Olympus seed", Data = S)
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seed)
	lr := hmac512.Sum(nil)
	// Split "I" into two 32-byte sequences Il and Ir where:
	//   Il = master secret key
	//   Ir = master chain code
	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]
	// Ensure the key is usable.
	secretKeyNum := new(big.Int).SetBytes(secretKey)
	_, err := bls.FRReprFromBigInt(secretKeyNum)
	if err != nil {
		return nil, ErrUnusableSeed
	}
	if secretKeyNum.Sign() == 0 {
		return nil, ErrUnusableSeed
	}
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	return NewExtendedKey(prefix, secretKey, chainCode,
		parentFP, 0, 0, true), nil
}

func NewExtendedKey(version, key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool) *ExtendedKey {
	return &ExtendedKey{
		key:       key,
		chainCode: chainCode,
		depth:     depth,
		parentFP:  parentFP,
		childNum:  childNum,
		version:   version,
		isPrivate: isPrivate,
	}
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
