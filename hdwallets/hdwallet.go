package hdwallets

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/grupokindynos/olympus-utils/bech32"
	"github.com/grupokindynos/olympus-utils/chainhash"
	"github.com/phoreproject/bls"
	"github.com/phoreproject/bls/g1pubs"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

const (
	MinSeedBytes     = 16
	MaxSeedBytes     = 64
	serializedKeyLen = 1 + 4 + 4 + 32 + 48 + 4
	maxUint8         = 1<<8 - 1
)

type Prefixes struct {
	ExtendedPriv string
	ExtendedPub  string
	AddrPubKey   string
	PrivKey      string
}

var (
	BitcoinPrefix = &Prefixes{
		ExtendedPriv: "xprv",
		ExtendedPub:  "xpub",
		AddrPubKey:   "bc",
		PrivKey:      "bp",
	}
	OlympusPrefix = &Prefixes{
		ExtendedPriv: "pprv",
		ExtendedPub:  "ppub",
		AddrPubKey:   "olpub",
		PrivKey:      "olpriv",
	}
)

var (
	HardenedKeyStart        = uint32(0x80000000)
	masterKey               = []byte("Olympus seed")
	ErrInvalidSeedLen       = fmt.Errorf("seed length must be between %d and %d bits", MinSeedBytes*8, MaxSeedBytes*8)
	ErrDeriveBeyondMaxDepth = errors.New("cannot derive a key with more than 255 indices in its path")
	ErrUnusableSeed         = errors.New("unusable seed")
	ErrDeriveHardFromPublic = errors.New("cannot derive a hardened key from a public key")
	ErrInvalidChild         = errors.New("the extended key at this index is invalid")
	ErrNotPrivExtKey        = errors.New("unable to create private keys from a public extended key")
	ErrPrefixNoNet          = errors.New("decoded key doesn't match network prefix")
)

type ExtendedKey struct {
	key       []byte
	pubKey    []byte
	chainCode []byte
	depth     uint8
	parentFP  []byte
	childNum  uint32
	isPrivate bool
	prefix    *Prefixes
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

func (k *ExtendedKey) String() string {
	if len(k.key) == 0 {
		return "zeroed extended key"
	}
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.childNum)
	serializedBytes := make([]byte, 0, serializedKeyLen)
	serializedBytes = append(serializedBytes, k.depth)
	serializedBytes = append(serializedBytes, k.parentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.chainCode...)
	if k.isPrivate {
		serializedBytes = append(serializedBytes, 0x00)
		serializedBytes = paddedAppend(32, serializedBytes, k.key)
		return bech32.Encode(k.prefix.ExtendedPriv, serializedBytes)
	} else {
		serializedBytes = append(serializedBytes, k.pubKeyBytes()...)
		return bech32.Encode(k.prefix.ExtendedPub, serializedBytes)
	}
}

func (k *ExtendedKey) Neuter() (*ExtendedKey, error) {
	if !k.isPrivate {
		return k, nil
	}
	return NewExtendedKey(k.pubKeyBytes(), k.chainCode, k.parentFP,
		k.depth, k.childNum, false, k.prefix), nil
}

func (k *ExtendedKey) pubKeyBytes() []byte {
	if !k.isPrivate {
		return k.key
	}
	if len(k.pubKey) == 0 {
		var rawPrivKey [32]byte
		buf := bytes.NewBuffer(rawPrivKey[:0])
		buf.Write(k.key)
		privKey := g1pubs.DeserializeSecretKey(rawPrivKey)
		pubKey := g1pubs.PrivToPub(privKey).Serialize()
		k.pubKey = pubKey[:]
	}
	return k.pubKey
}

func (k *ExtendedKey) Child(i uint32) (*ExtendedKey, error) {
	if k.depth == maxUint8 {
		return nil, ErrDeriveBeyondMaxDepth
	}
	isChildHardened := i >= HardenedKeyStart
	if !k.isPrivate && isChildHardened {
		return nil, ErrDeriveHardFromPublic
	}
	keyLen := 33
	data := make([]byte, keyLen+4)
	if isChildHardened {
		copy(data[1:], k.key)
	} else {
		copy(data, k.pubKeyBytes())
	}
	binary.BigEndian.PutUint32(data[keyLen:], i)
	hmac512 := hmac.New(sha512.New, k.chainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:len(ilr)/2]
	childChainCode := ilr[len(ilr)/2:]
	ilNum := new(big.Int).SetBytes(il)
	ilNum.Mod(ilNum, bls.RFieldModulus.ToBig())
	fr, err := bls.FRReprFromBigInt(ilNum)
	if err != nil {
		return nil, ErrInvalidChild
	}
	if fr.Cmp(bls.RFieldModulus) > 0 || ilNum.Sign() == 0 {
		return nil, ErrInvalidChild
	}
	var isPrivate bool
	var childKey []byte
	if k.isPrivate {
		keyNum := new(big.Int).SetBytes(k.key)
		ilNum.Add(ilNum, keyNum)
		ilNum.Mod(ilNum, bls.RFieldModulus.ToBig())

		secret := g1pubs.KeyFromFQRepr(fr)
		serializedSecret := secret.Serialize()
		childKey = serializedSecret[:]
		isPrivate = true
	} else {
		var ilslice [32]byte
		buf := bytes.NewBuffer(ilslice[:0])
		buf.Write(il)
		ffqr := bls.FRReprFromBytes(ilslice)
		var rawPubKey [48]byte
		bufPubKey := bytes.NewBuffer(rawPubKey[:0])
		bufPubKey.Write(k.key)
		aff, err := bls.DecompressG1(rawPubKey)
		if err != nil {
			return nil, err
		}
		proj := aff.MulFR(ffqr)
		pubKey := g1pubs.NewPublicKeyFromG1(proj.ToAffine())
		serializedPubKey := pubKey.Serialize()
		childKey = serializedPubKey[:]
	}
	parentFP := chainhash.Hash160(k.pubKeyBytes())[:4]
	return NewExtendedKey(childKey, childChainCode, parentFP,
		k.depth+1, i, isPrivate, k.prefix), nil
}

func (k *ExtendedKey) PubKey() (*g1pubs.PublicKey, error) {
	var rawPubKeyBytes [48]byte
	buf := bytes.NewBuffer(rawPubKeyBytes[:0])
	buf.Write(k.pubKeyBytes())
	return g1pubs.DeserializePublicKey(rawPubKeyBytes)
}

func (k *ExtendedKey) SecretKey() (*g1pubs.SecretKey, error) {
	if !k.isPrivate {
		return nil, ErrNotPrivExtKey
	}
	var rawSecretBytes [32]byte
	buf := bytes.NewBuffer(rawSecretBytes[:0])
	buf.Write(k.key)
	return g1pubs.DeserializeSecretKey(rawSecretBytes), nil
}

func (k *ExtendedKey) Address() (string, error) {
	keyBytes := k.pubKeyBytes()
	pubKeyHash := sha256.Sum256(keyBytes[:])
	ripedmHash := ripemd160.New()
	ripedmHash.Write(pubKeyHash[:])
	checkSumFirst := sha256.Sum256(ripedmHash.Sum(nil))
	checkSumSecond := sha256.Sum256(checkSumFirst[:])
	checkSum := checkSumSecond[0:4]
	pubKeyFullBytes := append(ripedmHash.Sum(nil)[:], checkSum...)
	return bech32.Encode(k.prefix.AddrPubKey, pubKeyFullBytes), nil
}

func (k *ExtendedKey) WIF() (string, error) {
	if !k.isPrivate {
		return "", ErrNotPrivExtKey
	}
	privKeyBytes := k.key
	checkSumFirst := sha256.Sum256(privKeyBytes[:])
	checkSumSecond := sha256.Sum256(checkSumFirst[:])
	checkSum := checkSumSecond[0:4]
	privKeyFullBytes := append(privKeyBytes[:], checkSum...)
	return bech32.Encode(k.prefix.PrivKey, privKeyFullBytes), nil
}

func NewMaster(seed []byte, prefixes *Prefixes) (*ExtendedKey, error) {
	var selectedPrefix *Prefixes
	if prefixes == nil {
		selectedPrefix = BitcoinPrefix
	} else {
		selectedPrefix = prefixes
	}
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}
	hmac512 := hmac.New(sha512.New, masterKey)
	hmac512.Write(seed)
	lr := hmac512.Sum(nil)
	secretKey := lr[:len(lr)/2]
	chainCode := lr[len(lr)/2:]
	secretKeyNum := new(big.Int).SetBytes(secretKey)
	secretKeyNum.Mod(secretKeyNum, bls.RFieldModulus.ToBig())
	if secretKeyNum.Cmp(bls.RFieldModulus.ToBig()) > 0 || secretKeyNum.Sign() == 0 {
		return nil, ErrUnusableSeed
	}
	var rawSecretHash [32]byte
	buf := bytes.NewBuffer(rawSecretHash[:0])
	buf.Write(secretKey)
	secret := g1pubs.DeriveSecretKey(rawSecretHash)
	secretSerialized := secret.Serialize()
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	return NewExtendedKey(secretSerialized[:], chainCode,
		parentFP, 0, 0, true, selectedPrefix), nil
}

func NewExtendedKey(key, chainCode, parentFP []byte, depth uint8,
	childNum uint32, isPrivate bool, prefixes *Prefixes) *ExtendedKey {
	return &ExtendedKey{
		key:       key,
		chainCode: chainCode,
		depth:     depth,
		parentFP:  parentFP,
		childNum:  childNum,
		isPrivate: isPrivate,
		prefix:    prefixes,
	}
}

func NewKeyFromString(key string, prefixes *Prefixes) (*ExtendedKey, error) {
	var selectedPrefix *Prefixes
	if prefixes == nil {
		selectedPrefix = BitcoinPrefix
	} else {
		selectedPrefix = prefixes
	}
	prefix, decoded, err := bech32.Decode(key)
	if err != nil {
		return nil, err
	}
	depth := decoded[:1][0]
	parentFP := decoded[1:5]
	childNum := binary.BigEndian.Uint32(decoded[5:9])
	chainCode := decoded[9:41]
	var keyData []byte
	if len(decoded) == 74 {
		keyData = decoded[41:]
	} else {
		keyData = decoded[41:]
	}
	isPrivate := keyData[0] == 0x00
	if isPrivate {
		if prefix != selectedPrefix.ExtendedPriv {
			return nil, ErrPrefixNoNet
		}
		keyData = keyData[1:]
		keyNum := new(big.Int).SetBytes(keyData)
		keyNum.Mod(keyNum, bls.RFieldModulus.ToBig())
		if keyNum.Cmp(bls.RFieldModulus.ToBig()) > 0 || keyNum.Sign() == 0 {
			return nil, ErrUnusableSeed
		}
	} else {
		if prefix != selectedPrefix.ExtendedPub {
			return nil, ErrPrefixNoNet
		}
		var rawKeyData [48]byte
		buf := bytes.NewBuffer(rawKeyData[:0])
		buf.Write(keyData)
		_, err := g1pubs.DeserializePublicKey(rawKeyData)
		if err != nil {
			return nil, err
		}
	}
	return NewExtendedKey(keyData, chainCode, parentFP, depth,
		childNum, isPrivate, selectedPrefix), nil
}

func GenerateSeed(length uint8) ([]byte, error) {
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
