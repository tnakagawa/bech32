// Copyright (c) 2017 Takatoshi Nakagawa
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
package bech32

import (
	"fmt"
	"strings"
)

var CHARSET string = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var GENERATOR []int = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []int) int {
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= GENERATOR[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []int {
	ret := []int{}
	for _, c := range hrp {
		ret = append(ret, int(string(c)[0]>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(string(c)[0]&31))
	}
	return ret
}

func verifyChecksum(hrp string, data []int) bool {
	return polymod(append(hrpExpand(hrp), data...)) == 1
}

func createChecksum(hrp string, data []int) []int {
	values := append(append(hrpExpand(hrp), data...), []int{0, 0, 0, 0, 0, 0}...)
	mod := polymod(values) ^ 1
	ret := []int{}
	for p := 0; p < 6; p++ {
		ret = append(ret, (mod>>uint(5*(5-p)))&31)
	}
	return ret
}

func Encode(hrp string, data []int) (string, error) {
	combined := append(data, createChecksum(hrp, data)...)
	ret := hrp + "1"
	for idx, p := range combined {
		if p < 0 || p >= len(CHARSET) {
			return "", fmt.Errorf("Invalid data : data[%d]=%d", idx, p)
		}
		ret += fmt.Sprintf("%c", CHARSET[p])
	}
	_, err := Decode(ret)
	if err != nil {
		return "", err
	}
	return ret, nil
}

type Dec struct {
	hrp  string
	data []int
}

func Decode(bechString string) (Dec, error) {
	var ret Dec
	has_lower := false
	has_upper := false
	for idx, c := range bechString {
		if c < 33 || c > 126 {
			return ret, fmt.Errorf("Invalid human-readable part : bechString[%d]=%d", idx, c)
		}
		if c >= 97 && c <= 122 {
			has_lower = true
		}
		if c >= 65 && c <= 90 {
			has_upper = true
		}
	}
	if has_lower && has_upper {
		return ret, fmt.Errorf("Mixed case")
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndex(bechString, "1")
	if pos < 1 || pos+7 > len(bechString) || len(bechString) > 90 {
		return ret, fmt.Errorf("Invalid program length : pos : %d , len : %d", pos, len(bechString))
	}
	hrp := bechString[0:pos]
	data := []int{}
	for p := pos + 1; p < len(bechString); p++ {
		d := strings.Index(CHARSET, fmt.Sprintf("%c", bechString[p]))
		if d == -1 {
			return ret, fmt.Errorf("Invalid data part : bechString[%d]=%d", p, bechString[p])
		}
		data = append(data, d)
	}
	if !verifyChecksum(hrp, data) {
		return ret, fmt.Errorf("Invalid checksum")
	}
	ret.hrp = hrp
	ret.data = data[:len(data)-6]
	return ret, nil
}

func convertbits(data []int, frombits, tobits uint, pad bool) ([]int, error) {
	acc := 0
	bits := uint(0)
	ret := []int{}
	maxv := (1 << tobits) - 1
	for idx, value := range data {
		if value < 0 || (value>>frombits) != 0 {
			return nil, fmt.Errorf("Invalid data range : data[%d]=%d (frombits=%d)", idx, value, frombits)
		}
		acc = (acc << frombits) | value
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(tobits-bits))&maxv)
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("Illegal zero padding")
	} else if ((acc << (tobits - bits)) & maxv) != 0 {
		return nil, fmt.Errorf("Non-zero padding")
	}
	return ret, nil
}

type SegwitAddrDec struct {
	version int
	program []int
}

func SegwitAddrDecode(hrp, addr string) (SegwitAddrDec, error) {
	var ret SegwitAddrDec
	dec, err := Decode(addr)
	if err != nil {
		return ret, err
	}
	if dec.hrp != hrp {
		return ret, fmt.Errorf("Invalid human-readable part : %s != %s", hrp, dec.hrp)
	}
	if len(dec.data) < 1 {
		return ret, fmt.Errorf("Invalid decode data length : %d", len(dec.data))
	}
	if dec.data[0] > 16 {
		return ret, fmt.Errorf("Invalid witness version : %d", dec.data[0])
	}
	res, err := convertbits(dec.data[1:], 5, 8, false)
	if err != nil {
		return ret, err
	}
	if len(res) < 2 || len(res) > 40 {
		return ret, fmt.Errorf("Invalid convertbits length : %d", len(res))
	}
	if dec.data[0] == 0 && len(res) != 20 && len(res) != 32 {
		return ret, fmt.Errorf("Invalid program length for witness version 0 (per BIP141) : %d", len(res))
	}
	ret.version = dec.data[0]
	ret.program = res
	return ret, nil
}

func SegwitAddrEncode(hrp string, version int, program []int) (string, error) {
	data, err := convertbits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	ret, err := Encode(hrp, append([]int{version}, data...))
	if err != nil {
		return "", err
	}
	_, err = SegwitAddrDecode(hrp, ret)
	if err != nil {
		return "", err
	}
	return ret, nil
}
