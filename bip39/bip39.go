package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type MnemonicSize int
type Language string
type Seed struct {
	Bytes []byte
}

const (
	Size12 MnemonicSize = 12
	Size15 MnemonicSize = 15
	Size18 MnemonicSize = 18
	Size21 MnemonicSize = 21
	Size24 MnemonicSize = 24
)

const (
	English            Language = "english"
	French             Language = "french"
	Italian            Language = "italian"
	Japanese           Language = "japanese"
	ChineseSimplified  Language = "chinese_simplified"
	ChineseTraditional Language = "chinese_traditional"
	Czech              Language = "czech"
	Korean             Language = "korean"
)

func CreateNewMnemonic(size MnemonicSize, language Language) (mnemonic []string, err error) {
	mnemonic = make([]string, size)
	checksumSize := int(size*11) / 32
	b := make([]byte, (11*int(size)-checksumSize)/8)
	_, err = rand.Read(b)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(b)
	mnemonicSeed := append(b, checksum[:checksumSize/8+1]...)
	wordIndexes := getInts(mnemonicSeed, size)
	path, err := filepath.Abs("words/" + string(language) + ".txt")
	if err != nil {
		return nil, err
	}
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	wordList := strings.Split(string(dat), "\n")
	for i := 0; i < int(size); i++ {
		mnemonic[i] = wordList[int(wordIndexes[i])]
	}
	return mnemonic, nil
}

func SeedFromMnemonic(mnemonic []string, password string) (seed *Seed, err error) {
	mnemonicSize := len(mnemonic)
	if mnemonicSize != int(Size12) && mnemonicSize != int(Size15) && mnemonicSize != int(Size18) && mnemonicSize != int(Size21) && mnemonicSize != int(Size24) {
		return nil, errors.New("invalid mnemonic size")
	}
	str := strings.Join(mnemonic, " ")
	seed = &Seed{pbkdf2.Key([]byte(str), []byte("mnemonic"+password), 2048, 64, sha512.New)}
	return seed, nil
}

func (s *Seed) toHex() string {
	src := s.Bytes
	seedHex := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(seedHex, s.Bytes)
	return string(seedHex)
}

func (s *Seed) String() string {
	return s.toHex()
}

func getIBit(b []byte, i uint32) uint32 {
	if (b[i/8] & (0x80 >> (i - (i/8)*8))) != 0 {
		return 1
	} else {
		return 0
	}
}

func getInts(b []byte, size MnemonicSize) []uint32 {
	nInts := make([]uint32, size)
	for k := 0; k < int(size)*11; k++ {
		uk := uint32(k)
		span := uk - (uk/11)*11
		bit := getIBit(b, uk)
		if bit != 0 {
			nInts[k/11] = nInts[uk/11] | 0x400>>span
		}
	}
	return nInts
}
