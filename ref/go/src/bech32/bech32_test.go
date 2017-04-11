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
	"reflect"
	"strings"
	"testing"
)

func segwit_scriptpubkey(version int, program []int) []int {
	if version != 0 {
		return append(append([]int{version + 0x80}, len(program)), program...)
	} else {
		return append(append([]int{version}, len(program)), program...)

	}
}

var VALID_CHECKSUM []string = []string{
	"A12UEL5L",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
}

type item struct {
	address      string
	scriptpubkey []int
}

var VALID_ADDRESS []item = []item{
	item{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
		[]int{
			0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
		},
	},
	item{"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		[]int{
			0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
			0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
			0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
			0x62,
		},
	},
	item{"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
		[]int{
			0x81, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
			0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
			0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
		},
	},
	item{"BC1SW50QA3JX3S",
		[]int{
			0x90, 0x02, 0x75, 0x1e,
		},
	},
	item{"bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
		[]int{
			0x82, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
		},
	},
	item{"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		[]int{
			0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
			0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
			0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
			0x33,
		},
	},
}

var INVALID_ADDRESS []string = []string{
	"tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
	"BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
	"bc1rw5uspcuh",
	"bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
	"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
	"tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
	"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
}

func TestValidChecksum(t *testing.T) {
	for _, test := range VALID_CHECKSUM {
		ret, err := Decode(test)
		if err != nil {
			t.Errorf("Valid checksum for %s : FAIL / error %+v\n", test, err)
		} else {
			fmt.Printf("Valid checksum for %s : ok / ret %+v\n", test, ret)
		}
	}
}

func TestValidAddress(t *testing.T) {
	for _, test := range VALID_ADDRESS {
		hrp := "bc"
		ret, err := SegwitAddrDecode(hrp, test.address)
		if err != nil {
			hrp = "tb"
			ret, err = SegwitAddrDecode(hrp, test.address)
		}
		ok := err == nil
		if ok {
			output := segwit_scriptpubkey(ret.version, ret.program)
			ok = reflect.DeepEqual(output, test.scriptpubkey)
		}
		if ok {
			recreate, err := SegwitAddrEncode(hrp, ret.version, ret.program)
			if err == nil {
				ok = recreate == strings.ToLower(test.address)
			}
		}
		if ok {
			fmt.Printf("Valid address %v : ok\n", test.address)
		} else {
			t.Errorf("Valid address %v : FAIL\n", test.address)
		}
	}
}

func TestInvalidAddress(t *testing.T) {
	for _, test := range INVALID_ADDRESS {
		ok := false
		_, err := SegwitAddrDecode("bc", test)
		if err != nil {
			fmt.Printf("%v : %v\n", test, err)
			_, err = SegwitAddrDecode("tb", test)
			if err != nil {
				fmt.Printf("%v : %v\n", test, err)
				ok = true
			}
		}
		if ok {
			fmt.Printf("Invalid address %v : ok\n", test)
		} else {
			t.Errorf("Invalid address %v : FAIL\n", test)
		}
	}
}

// add coverage tests

func TestCoverage(t *testing.T) {
	var err error
	_, err = SegwitAddrEncode("bc", 0, []int{-1})
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode Invalid data range error case : FAIL")
	} else {
		fmt.Println("Coverage SegwitAddrEncode Invalid data range error case : ok / error :", err)
	}
	_, err = SegwitAddrEncode("bc", 33, []int{})
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode Invalid data error case : FAIL")
	} else {
		fmt.Println("Coverage SegwitAddrEncode Invalid data error case : ok / error :", err)
	}
	_, err = SegwitAddrEncode("bc", 16, []int{0, 1, 2, 3, 4, 5})
	if err != nil {
		t.Errorf("Coverage SegwitAddrEncode witness version normal case : FAIL / error : %+v\n", err)
	} else {
		fmt.Println("Coverage SegwitAddrEncode witness version normal case : ok")
	}
	_, err = SegwitAddrEncode("bc", 17, []int{0, 1, 2, 3, 4, 5})
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode witness version error case : FAIL")
	} else {
		fmt.Println("Coverage SegwitAddrEncode witness version error case : ok / error :", err)
	}
	_, err = SegwitAddrDecode("a", "A12UEL5L")
	if err == nil {
		t.Errorf("Coverage SegwitAddrDecode Invalid decode data length error case : FAIL")
	} else {
		fmt.Println("Coverage SegwitAddrDecode Invalid decode data length error case : ok / error :", err)
	}
	enc, _ := Encode(string(33)+string(126), []int{})
	_, err = Decode(enc)
	if err != nil {
		t.Errorf("Coverage Decode Invalid human-readable part normal case / error : %+v\n", err)
	} else {
		fmt.Println("Coverage Decode Invalid human-readable part normal case : ok")
	}
	enc, _ = Encode(string(32), []int{})
	_, err = Decode(enc)
	if err == nil {
		t.Errorf("Coverage Decode Invalid human-readable part error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid human-readable part error case : ok / error :", err)
	}
	enc, _ = Encode(string(127), []int{})
	_, err = Decode(enc)
	if err == nil {
		t.Errorf("Coverage Decode Invalid human-readable part error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid human-readable part error case : ok / error :", err)
	}
	_, err = Decode("1")
	if err == nil {
		t.Errorf("Coverage Decode Invalid program length error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid program length case : ok / error :", err)
	}
	_, err = Decode("a1qqqqq")
	if err == nil {
		t.Errorf("Coverage Decode Invalid program length error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid program length case : ok / error :", err)
	}
	_, err = Decode("a1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	if err == nil {
		t.Errorf("Coverage Decode Invalid program length error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid program length case : ok / error :", err)
	}
	_, err = Decode("a1qqqqqb")
	if err == nil {
		t.Errorf("Coverage Decode Invalid program length error case : FAIL")
	} else {
		fmt.Println("Coverage Decode Invalid program length case : ok / error :", err)
	}
	_, err = convertbits([]int{33}, 5, 8, false)
	if err == nil {
		t.Errorf("Coverage convertbits Invalid data range error case : FAIL")
	} else {
		fmt.Println("Coverage convertbits Invalid data range error case : ok / error :", err)
	}
}
