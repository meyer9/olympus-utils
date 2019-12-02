package bech32

import (
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var inverseCharset = [256]int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1}

func Bytes8to5(input []byte) []byte {
	output, _ := ByteSquasher(input, 8, 5)
	return output
}

func Bytes5to8(input []byte) ([]byte, error) {
	return ByteSquasher(input, 5, 8)
}

func ByteSquasher(input []byte, inputWidth, outputWidth uint32) ([]byte, error) {
	var bitstash, accumulator uint32
	var output []byte
	maxOutputValue := uint32((1 << outputWidth) - 1)
	for i, c := range input {
		if c>>inputWidth != 0 {
			return nil, fmt.Errorf("byte %d (%x) high bits set", i, c)
		}
		accumulator = (accumulator << inputWidth) | uint32(c)
		bitstash += inputWidth
		for bitstash >= outputWidth {
			bitstash -= outputWidth
			output = append(output,
				byte((accumulator>>bitstash)&maxOutputValue))
		}
	}
	if inputWidth == 8 && outputWidth == 5 {
		if bitstash != 0 {
			output = append(output,
				byte((accumulator << (outputWidth - bitstash) & maxOutputValue)))
		}
	} else if bitstash >= inputWidth ||
		((accumulator<<(outputWidth-bitstash))&maxOutputValue) != 0 {
		return nil, fmt.Errorf(
			"invalid padding from %d to %d bits", inputWidth, outputWidth)
	}
	return output, nil
}

func SquashedBytesToString(input []byte) (string, error) {
	var s string
	for i, c := range input {
		if c&0xe0 != 0 {
			return "", fmt.Errorf("high bits set at position %d: %x", i, c)
		}
		s += string(charset[c])
	}
	return s, nil
}

func StringToSquashedBytes(input string) ([]byte, error) {
	b := make([]byte, len(input))
	for i, c := range input {
		if inverseCharset[c] == -1 {
			return nil, fmt.Errorf("contains invalid character %s", string(c))
		}
		b[i] = byte(inverseCharset[c])
	}
	return b, nil
}

func PolyMod(values []byte) uint32 {
	gen := []uint32{
		0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
	}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range gen {
			if (top>>uint8(i))&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

func HRPExpand(input string) []byte {
	output := make([]byte, (len(input)*2)+1)
	for i, c := range input {
		output[i] = uint8(c) >> 5
	}
	for i, c := range input {
		output[i+len(input)+1] = uint8(c) & 0x1f
	}
	return output
}

func CreateChecksum(hrp string, data []byte) []byte {
	values := append(HRPExpand(hrp), data...)
	values = append(values, make([]byte, 6)...)
	checksum := PolyMod(values) ^ 1
	for i := 0; i < 6; i++ {
		values[(len(values)-6)+i] = byte(checksum>>(5*(5-uint32(i)))) & 0x1f
	}
	return values[len(values)-6:]
}

func VerifyChecksum(hrp string, data []byte) bool {
	values := append(HRPExpand(hrp), data...)
	checksum := PolyMod(values)
	return checksum == 1
}

func Encode(hrp string, data []byte) string {
	fiveData := Bytes8to5(data)
	return EncodeSquashed(hrp, fiveData)
}

func EncodeSquashed(hrp string, data []byte) string {
	combined := append(data, CreateChecksum(hrp, data)...)
	dataString, err := SquashedBytesToString(combined)
	if err != nil {
		return ""
	}
	return hrp + "1" + dataString
}

func Decode(adr string) (string, []byte, error) {
	hrp, squashedData, err := DecodeSquashed(adr)
	if err != nil {
		return hrp, nil, err
	}
	data, err := Bytes5to8(squashedData)
	if err != nil {
		return hrp, nil, err
	}
	return hrp, data, nil
}

func DecodeSquashed(adr string) (string, []byte, error) {
	lowAdr := strings.ToLower(adr)
	highAdr := strings.ToUpper(adr)
	if adr != lowAdr && adr != highAdr {
		return "", nil, fmt.Errorf("mixed case address")
	}
	adr = lowAdr
	splitLoc := strings.LastIndex(adr, "1")
	if splitLoc == -1 {
		return "", nil, fmt.Errorf("1 separator not present in address")
	}
	hrp := adr[0:splitLoc]
	data, err := StringToSquashedBytes(adr[splitLoc+1:])
	if err != nil {
		return hrp, nil, err
	}
	sumOK := VerifyChecksum(hrp, data)
	if !sumOK {
		return hrp, nil, fmt.Errorf("Checksum invalid")
	}
	data = data[:len(data)-6]
	return hrp, data, nil
}
