package bech32m

import (
	"bytes"
	"fmt"
	"strings"
)

// Enumeration type to list the various supported encodings.
const (
	Bech32  = 1
	Bech32m = 2
	Failed  = -1

	VersionPrefix = 1
	VersionSuffix = 2
)

// var charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32mConst = 0x2bc830a3

var generator = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) int {
	// Internal function that computes the Bech32 checksum.
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			} else {
				chk ^= 0
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	// Expand the HRP into values for checksum computation.
	ret := []byte{}
	for _, c := range hrp {
		ret = append(ret, byte(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, byte(c&31))
	}
	return ret
}

func verifyChecksum(hrp string, data []byte) int {
	// Verify a checksum given HRP and converted data characters.
	c := polymod(append(hrpExpand(hrp), data...))
	if c == 1 {
		return Bech32
	}
	if c == bech32mConst {
		return Bech32m
	}
	return Failed
}

func createChecksum(hrp string, data []byte, spec int) []byte {
	// Compute the checksum values given HRP and data.
	values := append(append(hrpExpand(hrp), data...), []byte{0, 0, 0, 0, 0, 0}...)
	c := 1
	if spec == Bech32m {
		c = bech32mConst
	}
	mod := polymod(values) ^ c
	ret := make([]byte, 6)
	for i := 0; i < len(ret); i++ {
		ret[i] = byte(mod>>uint(5*(5-i))) & 31
	}
	return ret
}

// Encode compute a Bech32 string given HRP and data values.
func Encode(hrp string, data []byte, spec int, charset string) string {
	combined := append(data, createChecksum(hrp, data, spec)...)
	var ret bytes.Buffer
	ret.WriteString(hrp)
	ret.WriteString("1")
	for _, p := range combined {
		ret.WriteByte(charset[p])
	}
	return ret.String()
}

// Decode validate a Bech32/Bech32m string, and determine HRP and data.
func Decode(bechString string, charset string) (string, []byte, int, error) {
	if len(bechString) > 90 {
		return "", nil, Failed, fmt.Errorf("Overall max length exceeded")
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, Failed, fmt.Errorf("Mixed case")
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndex(bechString, "1")
	if pos < 0 {
		return "", nil, Failed, fmt.Errorf("No separator character")
	}
	if pos < 1 {
		return "", nil, Failed, fmt.Errorf("Empty HRP")
	}
	if pos+7 > len(bechString) {
		return "", nil, Failed, fmt.Errorf("Too short checksum")
	}
	hrp := bechString[0:pos]
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, Failed, fmt.Errorf("HRP character out of range")
		}
	}
	data := []byte{}
	for p := pos + 1; p < len(bechString); p++ {
		d := strings.Index(charset, fmt.Sprintf("%c", bechString[p]))
		if d == -1 {
			if p+6 > len(bechString) {
				return "", nil, Failed, fmt.Errorf("Invalid character in checksum")
			}
			return "", nil, Failed, fmt.Errorf("Invalid data character")
		}
		data = append(data, byte(d))
	}
	spec := verifyChecksum(hrp, data)
	if spec == Failed {
		return "", nil, Failed, fmt.Errorf("Invalid checksum")
	}
	return hrp, data[:len(data)-6], spec, nil
}

func Convertbits(data []byte, frombits, tobits uint, pad bool) ([]byte, error) {
	// General power-of-2 base conversion.
	acc := 0
	bits := uint(0)
	ret := []byte{}
	maxv := (1 << tobits) - 1
	maxAcc := (1 << (frombits + tobits - 1)) - 1
	for _, value := range data {
		acc = ((acc << frombits) | int(value)) & maxAcc
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("More than 4 padding bits")
	} else if ((acc << (tobits - bits)) & maxv) != 0 {
		return nil, fmt.Errorf("Non-zero padding in %d-to-%d conversion", tobits, frombits)
	}
	return ret, nil
}

func Bech32mEncode(prefix string, data []byte, charset string) (string, error) {
	conv, err := Convertbits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return Encode(prefix, conv, Bech32m, charset), nil
}

func Bech32mDecode(address, prefix string, charset string) ([]byte, error) {
	prechk, data, spec, err := Decode(address, charset)
	if err != nil || prechk != prefix || spec != Bech32m {
		return nil, err
	}

	hash, err := Convertbits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}

	return hash, nil
}