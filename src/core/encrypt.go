package core

import(
	"fmt"
)

func Encrypt(key ,etype, src string) ([]byte, error) {
	w1, w2, err := fromKeyToBytes(key)
	wlen := len(w1)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}

	var m []byte
	var ml int64
	if etype == "text" {
		m, ml, err = fromTextToBytes(src, true, len(w1))
		if err != nil {
			fmt.Printf("err=%v\r\n", err)
			return nil, err
		}
	} else {
		m, ml, err = fromFileToBytes(src, true, len(w1))
		if err != nil {
			fmt.Printf("err=%v\r\n", err)
			return nil, err
		}
	}

	// dlen := 4 + len(m) + len(w1)
	dlen := 4 + len(m) + len(m)
	dst := make([]byte, dlen)
	dst[0] = byte(ml / (256 * 256 * 256))
	dst[1] = byte((ml / (256 * 256)) % 256)
	dst[2] = byte((ml / (256)) % (256 * 256))
	dst[3] = byte(ml % 256)

	// generate initial state
	st, err := genState(wlen)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}

	// generate middle states
	sm, err := genState(len(m) - wlen)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}

	// encrypt the first stage
	for i := 0; i < len(m); i++ {
		if st[wlen - 1] % 2 == 0 {
			dst[4 + i] = dst[4 + i] ^ (0 << 7)
		} else {
			dst[4 + i] = dst[4 + i] ^ (1 << 7)
		}
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

			if j < 7 {
				if st[wlen - 1] % 2 == 0 {
					dst[4 + i] = dst[4 + i] ^ (0 << (7 - j - 1))
				} else {
					dst[4 + i] = dst[4 + i] ^ (1 << (7 - j - 1))
				}
			}
		}
		if (i + 1) % wlen == 0 && i + 1 < len(m) { 
			// st = xor(st, dst[4 + i + 1 - wlen:], wlen)
			st = xor(st, sm[((i + 1) / wlen - 1) * wlen:], wlen)
		}
	}

	// encrypt the second stage
	// st = xor(st, dst[4 + len(m) - wlen:], wlen)
	for i := len(m); i < len(m) + len(sm); i++ {
		if st[wlen - 1] % 2 == 0 {
			dst[4 + i] = dst[4 + i] ^ (0 << 7)
		} else {
			dst[4 + i] = dst[4 + i] ^ (1 << 7)
		}
		for j := byte(0); j < byte(8); j++ {
			if sm[i - len(m)] & (1 << (7 - j)) == byte(0) {
				rs := left(st, wlen)
				rsx := xor(st, rs, wlen)
				st = xor(w1, rsx, wlen)
			} else {
				rs := left(st, wlen)
				rsx := xor(st, rs, wlen)
				st = xor(w2, rsx, wlen)
			}

			if j < 7 {
				if st[wlen - 1] % 2 == 0 {
					dst[4 + i] = dst[4 + i] ^ (0 << (7 - j - 1))
				} else {
					dst[4 + i] = dst[4 + i] ^ (1 << (7 - j - 1))
				}
			}
		}
		if (i + 1) % wlen == 0 { 
			st = xor(st, dst[4 + i + 1 - wlen:], wlen)
		}
	}

	for k := 0; k < wlen; k++ {
		dst[4 + len(m) + len(sm) + k] = st[k]
	}

	return dst, nil
}
