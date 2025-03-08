package core

import(
	"fmt"
)

func Decrypt(key, dtype, src string) ([]byte, error) {
	w1, w2, err := fromKeyToBytes(key)
	wlen := len(w1)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}
	var c []byte
	//var cl int64
	if dtype == "text" {
		c, _, err = fromTextToBytes(src, false, 0)
		if err != nil {
			fmt.Printf("err=%v\r\n", err)
			return nil, err
		}
	} else {
		c, _, err = fromFileToBytes(src, false, 0)
		if err != nil {
			fmt.Printf("err=%v\r\n", err)
			return nil, err
		}
	}

	dlen := 0
	dlen += int(c[0]) * 256 * 256 * 256
	dlen += int(c[1]) * 256 * 256
	dlen += int(c[2]) * 256
	dlen += int(c[3])

	dst := make([]byte, dlen)

	// initial final state
	st := make([]byte, wlen)
	for i := 0; i < wlen; i++ {
		st[i] = c[len(c) - wlen + i]
	}

	sm := make([]byte, (len(c) - 4) / 2 - wlen)

	// decrypt the second stage
	for i := len(c) - wlen - 1; i > len(c) - wlen - len(sm) - 1; i-- {
		if (i - 4 + 1) % wlen == 0 {
			st = xor(st, c[i - wlen + 1:], wlen)
		}
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

			if ((srx[wlen - 1] << j) ^ c[i]) & (1 << j) == byte(0) {
				st = srx
			} else {
				st = inverse(srx, wlen)
			}
			sm[i - 4 - len(sm) - wlen] = sm[i - 4 - len(sm) - wlen] ^ (t << j)
		}
	} 

	// decrypt the first stage
	for i := len(c) - len(sm) - wlen - 1; i > 3; i-- {
		if (i - 4 + 1) % wlen == 0 && i - 4 - wlen + 1 < len(sm) {
			st = xor(st, sm[i - 4 - wlen + 1:], wlen)
		}
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

			if ((srx[wlen - 1] << j) ^ c[i]) & (1 << j) == byte(0) {
				st = srx
			} else {
				st = inverse(srx, wlen)
			}

			if i - 4 < dlen {
				dst[i - 4] = dst[i - 4] ^ (t << j)
			}
		}
	}

	return dst, nil
}
