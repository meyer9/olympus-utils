package bip39

import (
	"fmt"
	"testing"
)

var (
	sizes                          = []MnemonicSize{Size12, Size15, Size18, Size21, Size24}
	languages                      = []Language{English, French, Italian, ChineseSimplified, ChineseTraditional, Japanese, Czech, Korean}
	testMnemonicEnglish            = []string{"armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor", "armor"}
	testMnemonicFrench             = []string{"adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat", "adéquat"}
	testMnemonicItalian            = []string{"sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato", "sabotato"}
	testMnemonicChineseSimplified  = []string{"济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济", "济"}
	testMnemonicChineseTraditional = []string{"氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏", "氏"}
	testMnemonicJapanese           = []string{"ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる", "ひたる"}
	testMnemonicCzech              = []string{"tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr", "tygr"}
	testMnemonicKorean             = []string{"옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림", "옷차림"}

	testMnemonics = [][]string{testMnemonicEnglish, testMnemonicFrench, testMnemonicItalian, testMnemonicChineseSimplified, testMnemonicChineseTraditional, testMnemonicJapanese, testMnemonicCzech, testMnemonicKorean}
)

func TestCreateNewMnemonic(t *testing.T) {
	for _, language := range languages {
		for _, size := range sizes {
			mnemonic, err := CreateNewMnemonic(size, language)
			if err != nil {
				t.Errorf("Error creating mnemonic for %v on size %v", language, size)
			}
			if len(mnemonic) != int(size) {
				t.Errorf("Error on mnemonic size for %v on size %v", language, size)
			}
			if int(size) == 24 {
				fmt.Println(mnemonic)
			}
		}
	}
}

func TestSeedFromMnemonic(t *testing.T) {
	for _, mnemonic := range testMnemonics {
		_, err := SeedFromMnemonic(mnemonic, "")
		if err != nil {
			t.Errorf("Unable to create seed from mnemonic %v", err)
		}
		mnemonic = mnemonic[:len(mnemonic)-1]
		seedErr, err := SeedFromMnemonic(mnemonic, "")
		if seedErr != nil {
			t.Errorf("Generate seed for invalid length should return error")
		}
	}
}
