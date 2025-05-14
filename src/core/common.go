package core
import(
	"errors"
	"io"
	"io/ioutil"
	"crypto/rand"
	"os"
)

const (
	MAX_KEY_LEN = 1024 // 8192 bits
)

func convertFromHex(a byte) byte{
	if a == 48 {
		return 0
	} else if a == 49 {
		return 1
	} else if a == 50 {
		return 2
	} else if a == 51 {
		return 3
	} else if a == 52 {
		return 4
	} else if a == 53 {
		return 5
	} else if a == 54 {
		return 6
	} else if a == 55 {
		return 7
	} else if a == 56 {
		return 8
	} else if a == 57 {
		return 9
	} else if a == 65 || a == 97 {
		return 10
	} else if a == 66 || a == 98 {
		return 11
	} else if a == 67 || a == 99 {
		return 12
	} else if a == 68 || a == 100 {
		return 13
	} else if a == 69 || a == 101 {
		return 14
	} else if a == 70 || a == 102 {
		return 15
	} 
	return 0
}

func convertToHex(a byte) byte {
	if a == 0 {
		return 48
	} else if a == 1 {
		return 49
	} else if a == 2 {
		return 50
	} else if a == 3 {
		return 51
	} else if a == 4 {
		return 52
	} else if a == 5 {
		return 53
	} else if a == 6 {
		return 54
	} else if a == 7 {
		return 55
	} else if a == 8 {
		return 56
	} else if a == 9 {
		return 57
	} else if a == 10 {
		return 97
	} else if a == 11 {
		return 98
	} else if a == 12 {
		return 99
	} else if a == 13 {
		return 100
	} else if a == 14 {
		return 101
	} else if a == 15 {
		return 102
	}
	return 0
} 

func fromKeyToBytes(key string) ([]byte, []byte, []byte, []byte, error) {
	bkey := []byte(key)
	klen := len(bkey)
	if klen == 0 || klen % 8 != 0 {
		return nil, nil, nil, nil, errors.New("key is invalid.")
	}
	if klen / 2 > MAX_KEY_LEN {
		return nil, nil, nil, nil, errors.New("key is too long")
	}
	w1 := make([]byte, klen / 8)
	w2 := make([]byte, klen / 8)
	w3 := make([]byte, klen / 8)
	w4 := make([]byte, klen / 8)
	for i := 0; i < klen / 8; i++ {
		a := convertFromHex(bkey[2 * i])
		b := convertFromHex(bkey[2 * i + 1])
		w1[i] = (a << 4) | b
	}
	for i := klen / 8; i < (klen / 8) * 2; i++ {
		a := convertFromHex(bkey[2 * i])
		b := convertFromHex(bkey[2 * i + 1])
		w2[i - klen / 8] = (a << 4) | b
	}
	for i := (klen / 8) * 2; i < (klen / 8) * 3; i++ {
		a := convertFromHex(bkey[2 * i])
		b := convertFromHex(bkey[2 * i + 1])
		w3[i - (klen / 8) * 2] = (a << 4) | b
	}
	for i := (klen / 8) * 3; i < (klen / 8) * 4; i++ {
		a := convertFromHex(bkey[2 * i])
		b := convertFromHex(bkey[2 * i + 1])
		w4[i - (klen / 8) * 3] = (a << 4) | b
	}

	num := 0
	for i := 0; i < klen / 8; i++ {
		w := w1[i] ^ w2[i]
		for j := byte(0); j < byte(8); j++ {
			if (w & (byte(1 << (7 - j)))) != byte(0) {
				num++
			}
		} 
	}
	if num % 2 == 0 {
		w2[klen / 8 - 1] = w2[klen / 8 - 1] ^ (0x01) 
	}
	num = 0
	for i := 0; i < klen / 8; i++ {
		w := w3[i] ^ w4[i]
		for j := byte(0); j < byte(8); j++ {
			if (w & (byte(1 << (7 - j)))) != byte(0) {
				num++
			}
		} 
	}
	if num % 2 == 0 {
		w4[klen / 8 - 1] = w4[klen / 8 - 1] ^ (0x01) 
	}
	return w1, w2, w3, w4, nil
}

func fromTextToBytes(text string, fillflag bool, keylen int) ([]byte, int64, error) {
	btext := []byte(text)
	tlen := len(btext)
	if tlen == 0 || tlen % 2 == 1 {
		return nil, int64(0), errors.New("text is invalid.")
	}
	var w []byte
	filllen := 0
	if fillflag {
		if (tlen / 2) % keylen != 0 {
			filllen = keylen - (tlen / 2) % keylen
		} 
		w = make([]byte, tlen / 2 + filllen + keylen)
	} else {
		w = make([]byte, tlen / 2)
	}
	for i := 0; i < tlen / 2; i++ {
		a := convertFromHex(btext[2 * i])
		b := convertFromHex(btext[2 * i + 1])
		w[i] = (a << 4) | b
	}
	if fillflag {
		for j := tlen / 2; j < tlen / 2 + filllen; j++ {
			w[j], _ = genSingle()
		}
		s, _ := genState(keylen)
		for j := tlen / 2 + filllen; j < tlen / 2 + filllen + keylen; j++ {
			w[j] = s[j - tlen / 2 - filllen]
		}
	}
	return w, int64(tlen / 2), nil
}

func fromFileToBytes(file string, fillflag bool, keylen int) ([]byte, int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, int64(0), err
	}
	btext, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, int64(0), err
	}
	tlen := len(btext)
	var w []byte
	if fillflag {
		w = make([]byte, tlen + keylen - (tlen) % keylen + keylen)
	} else {
		w = make([]byte, tlen)
	}
	for i := 0; i < tlen; i++ {
		w[i] = btext[i]
	}
	tlen = tlen * 2


	if fillflag {
		for j := tlen / 2; j < tlen / 2 + keylen - (tlen / 2) % keylen; j++ {
			w[j], _ = genSingle()
		}
		s, _ := genState(keylen)
		for j := tlen / 2 + keylen - (tlen / 2) % keylen; j < tlen / 2 + keylen - (tlen / 2) % keylen + keylen; j++ {
			w[j] = s[j - tlen / 2 - keylen + (tlen / 2) % keylen]
		}
	}
	return w, int64(tlen / 2), nil
}

func inverse(src []byte, l int) ([]byte) {
	dst := make([]byte, l)
	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ 0xFF
	}
	return dst
}

func left(src []byte, l int) ([]byte) {
	dst := make([]byte, l)
	for i := 0; i < l - 1; i++ {
		dst[i] = (src[i] << 1) ^ (src[i + 1] >> 7)
	}
	dst[l - 1] = (src[l - 1] << 1) ^ (src[0] >> 7)
	return dst
}

func xor(x []byte, y []byte, l int) ([]byte) {
	w := make([]byte, l)
	for i := 0; i < l; i++ {
		w[i] = x[i] ^ y[i]
	}
	return w
}

func guess(dst []byte, l int) ([]byte, bool) { // assume the first bit is 0
	src := make([]byte, l)
	cur := byte(0)
	res := true
	for i := 0; i < l; i++ {
		for j := byte(0); j < byte(8); j++ {
			if dst[i] & byte(1 << (7 - j)) == byte(0) {
				if cur == byte(0) {
					cur = byte(0)
				} else {
					cur = byte(1)
				}
			} else {
				if cur == byte(1) {
					cur = byte(0)
				} else {
					cur = byte(1)
				}
			}
			if j < 7 {
				src[i] = src[i] ^ (cur << (7 - j - 1))
			} else if i < l - 1 && j == 7 {
				src[i + 1] = src[i + 1] ^ (cur << 7)
			} else if i == l - 1 && j == 7 {
				if cur == byte(1) {
					res = false
				}
			}
		}
	}
	return src, res
}

func genState(length int) ([]byte, error) {
	gen := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, gen); err != nil {
		return nil, errors.New("get gen err.")
	}
	return gen, nil
}

func genSingle() (byte, error) {
	gen := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, gen); err != nil {
		return 0xAA, errors.New("get single err.")
	}
	return gen[0], nil
}

func ToHex(src []byte) string {
	dst := make([]byte, 2 * len(src))
	for i := 0; i < len(src); i++ {
		dst[2 * i] = convertToHex(src[i] >> 4)
		dst[2 * i + 1] = convertToHex((src[i] << 4) >> 4)
	}
	return string(dst)
}

func eagleEncode(m []byte, w1 []byte, w2 []byte) ([]byte, error) {
	wlen := len(w1)
	st, err := genState(wlen)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(m); i++ {
		for j := byte(0); j < byte(8); j++ {
			if m[i] & (1 << (7 - j)) == byte(0) {
				rs := left(st, wlen)
				rsx := xor(st, rs, wlen)
				st = xor(w1, rsx, wlen)
			} else {
				rs := left(st, wlen)
				rsx := xor(st, rs, wlen)
				st = xor(w2, rsx, wlen)
			}
		}
	}
	return st, nil
}

func eagleDecode(s []byte, w1 []byte, w2 []byte) ([]byte, error) {
	wlen := len(w1)
	st := make([]byte, wlen)
	sm := make([]byte, wlen)
	for i := 0; i < wlen; i++ {
		st[i] = s[i]
	}
	for i := wlen - 1; i >= 0; i-- {
		for j := byte(0); j < byte(8); j++ {
			// try w1
			sr := xor(st, w1, wlen)
			srx, gres := guess(sr, wlen)

			var t byte
			if gres {
				t = byte(0)
			} else {
				sr = xor(st, w2, wlen)
				srx, _ = guess(sr, wlen)
				t = byte(1)
			}

			if (srx[wlen - 1] << j) & (1 << j) == byte(0) {
				st = srx
			} else {
				st = inverse(srx, wlen)
			}
			sm[i] = sm[i] ^ (t << j)
		}
	}
	return sm, nil
}
