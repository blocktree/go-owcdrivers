package bech32

import (
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrorInvalidAddress = errors.New("Invalid address!")
	/*
	 This table corresponding to the first 128 chars in ascii table.If the char is not one of
	 "qpzry9x8gf2tvdw0s3jn54khce6mua7l" which is the code table of base32(Only consists
	 of alphanumeric characters excluding "1", "b", "i", and "o"), -1 will be set in
	 the corresponding position.Otherwise, the sequence number of alphanumeric character
	 will be set. For example, '0'is the 48th(from 0 starts) char in ascii table and the 15th
	 (from 0 starts)letter in code table, then 15 will be set in the 48th position.
	*/
	CHARSET_REV = []int8{
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1}
)

func catBytes(data1 []int8, data2 []int8) []int8 {
	return append(data1, data2...)
}

func expandPrefix(prefix string) []int8 {
	ret := make([]int8, len(prefix)*2+1)
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		ret[i] = int8(c >> 5)
		ret[i+len(prefix)+1] = int8(c & 0x1f)
	}
	ret[len(prefix)] = 0
	return ret
}

func polyMod(v []int8) uint32 {
	/*
	   The input is interpreted as a list of coefficients of a polynomial over F = GF(32),
	   with an implicit 1 in front. If the input is [v0,v1,v2,v3,v4], that polynomial is
	   v(x) =1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4.The implicit 1 guarantees that
	   [v0,v1,v2,...] has a distinct checksum from [0,v0,v1,v2,...].The output is a 30-bit
	   integer whose 5-bit groups are the coefficients of the remainder of v(x) mod g(x),
	   where g(x) is the Bech32 generator x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x
	   + {18}.g(x) is chosen in such a way that the resulting code is a BCH code,
	   guaranteeing detection of up to 3 errors within a window of 1023 characters.
	   Among the various possible BCH codes, one was selected to in fact guarantee detection
	   of up to 4 errors within a window of 89 characters.

	   Note that the coefficients are elements of GF(32), here represented as decimal numbers
	   between {}. In this finite field, addition is just XOR of the corresponding numbers. For
	   example, {27} + {13} = {27 ^ 13} = {22}. Multiplication is more complicated, and requires
	   treating the bits of values themselves as coefficients of a polynomial over a smaller field,
	   GF(2), and multiplying those polynomials mod a^5 + a^3 + 1. For example, {5} * {26} =
	   (a^2 + 1) * (a^4 + a^3 + a) = (a^4 + a^3 + a) * a^2 + (a^4 + a^3 + a) = a^6 + a^5 + a^4 + a
	   = a^3 + 1 (mod a^5 + a^3 + 1) = {9}.

	   During the course of the loop below, `c` contains the bitpacked coefficients of the
	   polynomial constructed from just the values of v that were processed so far, mod g(x). In
	   the above example, `c` initially corresponds to 1 mod (x), and after processing 2 inputs of
	   v, it corresponds to x^2 + v0*x + v1 mod g(x). As 1 mod g(x) = 1, that is the starting value
	   for `c`.
	*/
	c := uint32(1)
	for _, v_i := range v {
		/*
		   g(x):=x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + 18
		   We want to update `c` to correspond to a polynomial with one extra term. If the initial
		   value of `c` consists of the coefficients of c(x) = f(x) mod g(x), we modify it to
		   correspond to c'(x) = (f(x) * x + v_i) mod g(x), where v_i is the next input to
		   process. Simplifying:
		   c'(x) = (f(x) * x + v_i) mod g(x)
		         = ((f(x) mod g(x)) * x + v_i) mod g(x)
		         = (c(x) * x + v_i) mod g(x)
		   If c(x) = c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5, we want to compute
		   c'(x) = (c0*x^5 + c1*x^4 + c2*x^3 + c3*x^2 + c4*x + c5) * x + v_i mod g(x)
		         = c0*x^6 + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i mod g(x)
		         = c0*(x^6 mod g(x)) + c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i
		   If we call (x^6 mod g(x)) = k(x), this can be written as
		   c'(x) = (c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i) + c0*k(x)
		*/
		/*First, determine the value of c0:*/
		c0 := uint8(c >> 25)
		/*Then compute c1*x^5 + c2*x^4 + c3*x^3 + c4*x^2 + c5*x + v_i:*/
		c = ((c & 0x1ffffff) << 5) ^ uint32(v_i)
		/*Finally, for each set bit n in c0, conditionally add {2^n}k(x):*/
		if c0&1 != 0 {
			/*
			    k(x)= x^6 mod g(x)
			   	 = x^6 mod (x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + 18)
			        = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
			    Then 29,22,20,21,29,18 form into 32 bit binary 00111011011010100101011110110010.If not enough,
			    fill with 0 in the front.That is 0011(3),1011(b),0110(6),1010(a),0101(5),0111(7),1011(b),0010(2),
			    equal to hex:0x3b6a57b2
			*/
			c ^= 0x3b6a57b2
		}
		/*
		    {2}k(x) = {2}*{29}x^5 + {2}*{22}x^4 + {2}*{20}x^3 + {2}*{21}x^2 +{2}*{29}x + {2}*{18}
		    Due to {2}*{29} = a*(a^4 + a^3 + a^2 + 1) mod(a^5 + a^3 + 1)=(a^5 + a^4 +a^3 + a) mod(a^5 + a^3 + 1)
		   				 = a^4 +a +1
		   				 = {10011}
		   				 = 19
		           {2}*{22} = a*(a^4 + a^2 + a)mod(a^5 + a^3 + 1)
		   				 = (a^5 + a^3 + a^2)mod(a^5 + a^3 + 1)
		   				 = a^2 + 1
		   				 = {101}
		   				 =5
		   		{2}*{20} = a*(a^4 + a^2)mod(a^5 + a^3 +1)
		   				 = (a^5 + a^3)mod(a^5 + a^3 +1)
		   				 =1
		   				 ={1}
		   				 =1
		   		{2}*{21} = a*(a^4 + a^2 + 1)mod(a^5 + a^3 +1)
		   				 = (a^5	+ a^3 + a)mod(a^5 + a^3 +1)
		   				 =a + 1
		   				 ={11}
		   				 =3
		   		{2}*{29} = 19
		   		{2}*{18} = a*(a^4 + a)mod(a^5 + a^3 +1)
		   				 = (a^5 +a^2)mod(a^5 + a^3 +1)
		   				 = a^3 + a^2 +1
		   				 ={1101}
		   				 =13
		    {2}k(x)= {19}x^5 + {5}x^4 + x^3 + {3}x^2 +{19}x + {13}
		    Then 19,5,1,3,19,13 form into 32 bit binary 00100110010100001000111001101101.If not enough,
		    fill with 0 in the front.That is 0010(2),0110(6),0101(5),0000(0),1000(8),1110(e),0110(6),1101(d),
		    equal to hex:0x26508e6d
		*/
		if c0&2 != 0 {
			c ^= 0x26508e6d
		}
		/*
		    {4}k(x)={4}*{29}x^5 + {4}*{22}x^4 + {4}*{20}x^3 + {4}*{21}x^2 +{4}*{29}x + {4}*{18}
		    Due to {4}*{29} = a^2 * (a^4 + a^3 + a^2 + 1) mod(a^5 + a^3 + 1)
		   				 = (a^6 + a^5 +a^4 +a^2) mod (a^5 + a^3 + 1)
		   				 = (a^3 + a^2 + a +1)
		   				 = {1111}
		   				 = 15
		   		{4}*{22} = a^2 * (a^4 + a^2 + a)mod(a^5 + a^3 + 1)
		   				 = (a^6 + a^4 +a^3)mod(a^5 + a^3 + 1)
		   				 = a^3 + a
		   				 = {1010}
		   				 = 10
		   		{4}*{20} = a^2 * (a^4 + a^2)mod(a^5 + a^3 +1)
		   				 = (a^6 + a^4)mod(a^5 + a^3 +1)
		   				 = a
		   				 = {10}
		   				 = 2
		   		{4}*{21} = a^2 * (a^4 + a^2 + 1)mod(a^5 + a^3 +1)
		   				 = (a^6 + a^4 +a^2)mod(a^5 + a^3 + 1)
		   				 = a^2 + a
		   				 = {110}
		   				 = 6
		   		{4}*{29} = 15
		   		{4}*{18} = a^2 * (a^4 + a)mod(a^5 + a^3 + 1)
		   				 = (a^6 + a^3)mod(a^5 + a^3 + 1)
		   				 = a^4 + a^3 + a
		   				 = {11010}
		   				 = 26
		    {4}k(x)= {15}x^5 + {10}x^4 + {2}x^3 + {6}x^2 +{15}x + {26}
		    Then 15,10,2,6,15,26 form into 32 bit binary 00011110101000010001100111111010.If not enough,
		    fill with 0 in the front.That is 0001(1),1110(e),1010(a),0001(1),0001(1),1001(9),1111(f),1010(a)
		    equal to hex:0x1ea119fa
		*/
		if c0&4 != 0 {
			c ^= 0x1ea119fa
		}
		/*
		    {8}k(x)={8}*{29}x^5 + {8}*{22}x^4 + {8}*{20}x^3 + {8}*{21}x^2 +{8}*{29}x + {8}*{18}
		    Due to {8}*{29} = a^3 * (a^4 + a^3 + a^2 + 1) mod(a^5 + a^3 + 1)
		   				 = (a^7 + a^6 +a^5 +a^3) mod (a^5 + a^3 + 1)
		   				 = (a^4 + a^3 + a^2 + a)
		   				 = {11110}
		   				 = 30
		   		{8}*{22} = a^3 * (a^4 + a^2 + a)mod(a^5 + a^3 + 1)
		   				 = (a^7 + a^5 + a^4)mod(a^5 + a^3 + 1)
		   				 = a^4 + a^2
		   				 = {10100}
		   				 = 20
		   		{8}*{20} = a^3 * (a^4 + a^2)mod(a^5 + a^3 +1)
		   				 = (a^7 + a^5)mod(a^5 + a^3 +1)
		   				 = a^2
		   				 = {100}
		   				 = 4
		   		{8}*{21} = a^3 * (a^4 + a^2 + 1)mod(a^5 + a^3 +1)
		   				 = (a^7 + a^5 +a^3)mod(a^5 + a^3 + 1)
		   				 = a^3 + a^2
		   				 = {1100}
		   				 = 12
		   		{8}*{29} = 30
		   		{8}*{18} = a^3 * (a^4 + a)mod(a^5 + a^3 + 1)
		   				 = (a^7 + a^4)mod(a^5 + a^3 + 1)
		   				 = a^4 + a^3 + a^2 + 1
		   				 = {11101}
		   				 = 29
		    {8}k(x)= {30}x^5 + {20}x^4 + {4}x^3 + {12}x^2 +{30}x + {29}
		    Then 30,20,4,12,30,29 form into 32 bit binary 00111101010000100011001111011101.If not enough,
		    fill with 0 in the front.That is 0011(3),1101(d),0100(4),0010(2),0011(3),0011(3),1101(d),1101(d)
		    equal to hex:0x3d4233dd
		*/
		if c0&8 != 0 {
			c ^= 0x3d4233dd
		}
		/*
		    {16}k(x)={16}*{29}x^5 + {16}*{22}x^4 + {16}*{20}x^3 + {16}*{21}x^2 +{16}*{29}x + {16}*{18}
		    Due to {16}*{29} = a^4 * (a^4 + a^3 + a^2 + 1) mod(a^5 + a^3 + 1)
		   				 = (a^8 + a^7 +a^6 +a^4) mod (a^5 + a^3 + 1)
		   				 = (a^4 + a^2 + 1)
		   				 = {10101}
		   				 = 21
		   		{16}*{22}= a^4 * (a^4 + a^2 + a)mod(a^5 + a^3 + 1)
		   				 = (a^8 + a^6 + a^5)mod(a^5 + a^3 + 1)
		   				 = 1
		   				 = {1}
		   				 = 1
		   		{16}*{20}= a^4 * (a^4 + a^2)mod(a^5 + a^3 +1)
		   				 = (a^8 + a^6)mod(a^5 + a^3 +1)
		   				 = a^3
		   				 = {1000}
		   				 = 8
		   		{16}*{21} = a^4 * (a^4 + a^2 + 1)mod(a^5 + a^3 +1)
		   				 = (a^8 + a^6 +a^4)mod(a^5 + a^3 + 1)
		   				 = a^4 + a^3
		   				 = {11000}
		   				 = 24
		   		{16}*{29}= 21
		   		{16}*{18}= a^4 * (a^4 + a)mod(a^5 + a^3 + 1)
		   				 = (a^8 + a^5)mod(a^5 + a^3 + 1)
		   				 = a^4 + a + 1
		   				 = {10011}
		   				 = 19
		    {16}k(x)= {21}x^5 + x^4 + {8}x^3 + {24}x^2 +{21}x + {19}
		    Then 21,1,8,24,21,19 form into 32 bit binary 00101010000101000110001010110011.If not enough,
		    fill with 0 in the front.That is 0010(2),1010(a),0001(1),0100(4),0110(6),0010(2),1011(b),0011(3)
		    equal to hex:0x2a1462b3
		*/
		if c0&16 != 0 {
			c ^= 0x2a1462b3
		}
	}
	return c ^ 1
}

func lowerCase(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return (c - 'A') + 'a'
	}
	return c
}

func verifyChecksum(prefix string, data []int8) bool {
	return polyMod(catBytes(expandPrefix(prefix), data)) == 0
}

func calcChecksum(prefix string, data []int8) []int8 {
	enc := catBytes(expandPrefix(prefix), data)
	ret := [6]int8{}
	tmp := make([]int8, len(enc)+6)

	copy(tmp, enc)

	mod := polyMod(tmp)

	for i := 0; i < 6; i++ {
		ret[i] = int8((mod >> (5 * (5 - uint(i)))) & 0x1f)
	}

	return ret[:]
}

func byteShl1(in *[]int8) {
	tmp := make([]int8, len(*in))
	copy(tmp, *in)
	for i := 0; i < len(tmp)-1; i++ {
		tmp1 := tmp[i] << 1
		tmp2 := tmp[i+1] >> 7
		tmp2 &= 1
		tmp1 |= tmp2
		tmp[i] = tmp1
	}
	tmp[len(tmp)-1] <<= 1
	copy(*in, tmp)
}
func byteShl5(in *[]int8) {
	for i := 0; i < 5; i++ {
		byteShl1(in)
	}
}

func extendPayload(payload []int8) []int8 {
	length := (len(payload)*8 + 4) / 5
	ret := make([]int8, length)
	i := 0
	j := 0
	for i = len(payload) * 8; i >= 5; i -= 5 {
		ret[j] = (payload[0] >> 3) & int8(0x1F)
		byteShl5(&payload)
		j++
	}
	if i > 0 {
		ret[j] = (payload[0] >> 3) & 0x1f
	}
	return ret
}

func unecxtendPayload(extendedPayload []int8) []int8 {
	length := len(extendedPayload) * 5 / 8

	ret := make([]int8, length)

	for i := 0; i < len(extendedPayload)-1; i++ {
		ret[length-1] |= extendedPayload[i]
		byteShl5(&ret)
	}
	ret[length-1] |= extendedPayload[len(extendedPayload)-1]

	return ret
}

func Encode(prefix, alphabet string, payload []byte, payloadPrefix []byte) string {
	int8Payload := make([]int8, len(payload))
	for i := 0; i < len(payload); i++ {
		int8Payload[i] = int8(payload[i])
	}
	extendPayload := extendPayload(int8Payload)
	if payloadPrefix != nil {
		predata := []int8{}
		for _, data := range payloadPrefix {
			predata = append(predata, int8(data))
		}
		extendPayload = append(predata, extendPayload...)
	}

	checksum := calcChecksum(prefix, extendPayload)
	combined := catBytes(extendPayload, checksum)

	ret := prefix + "1"
	for _, b := range combined {
		ret += alphabet[b : b+1]
	}
	return ret
}

func Decode(address, alphabet string) ([]byte, error) {
	lower := false
	upper := false
	hasNumber := false
	prefixSize := 0
	for i := 0; i < len(address); i++ {
		c := address[i]
		if c >= 'a' && c <= 'z' {
			lower = true
			continue
		}
		if c >= 'A' && c <= 'Z' {
			upper = true
			continue
		}
		if c == '0' || (c >= '2' && c <= '9') {
			hasNumber = true
			continue
		}
		if c == '1' {
			if hasNumber || i == 0 || prefixSize != 0 {
				return nil, ErrorInvalidAddress
			}
			prefixSize = i
			continue
		}
		return nil, ErrorInvalidAddress
	}

	if upper && lower {
		return nil, ErrorInvalidAddress
	}

	prefixStr := strings.Split(address, "1")[0]
	prefixSize++
	valueSize := len(address) - prefixSize
	value := make([]int8, valueSize)
	for i := 0; i < valueSize; i++ {
		c := address[i+prefixSize]
		if c > 127 || CHARSET_REV[c] == -1 {
			return nil, ErrorInvalidAddress
		}
		value[i] = CHARSET_REV[c]
	}

	if !verifyChecksum(prefixStr, value) {
		return nil, ErrorInvalidAddress
	}

	tmp := make([]int8, len(value)-6)
	copy(tmp, value)

	ret := unecxtendPayload(tmp)

	bytePayload := make([]byte, len(ret))

	for i := 0; i < len(ret); i++ {
		bytePayload[i] = byte(ret[i])
	}

	if len(bytePayload) == 33 {
		tmp := hex.EncodeToString(bytePayload)[1:65]
		bytePayload, _ = hex.DecodeString(tmp)
	}
	return bytePayload, nil

}
