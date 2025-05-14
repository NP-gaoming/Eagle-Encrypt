package core

import(
	"fmt"
)

func Decrypt(key, dtype, src string) ([]byte, error) {
	w1, w2, w3, w4, err := fromKeyToBytes(key)
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
	s1 := make([]byte, wlen)
	for i := 0; i < wlen; i++ {
		s1[i] = c[len(c) - wlen + i]
	}

	K := ((len(c) - wlen - 4) / wlen) / 3
	rs := make([]byte, 2 * K * wlen + wlen)

	// decrypt the second stage
	for j := 2 * K; j >= 0; j-- {
		var mi []byte
		if j == 2 * K {
			mi, err = eagleDecode(s1, w3, w4)
			if err != nil {
				return nil, err
			}
		} else {
			mi = s1
		}
		_mi := make([]byte, wlen)
		for t := 0; t < wlen; t++ {
			_mi[t] = mi[t] ^ c[4 + K * wlen + j * wlen + t]
		}
		_ri, err := eagleEncode(_mi, w3, w4)
		if err != nil {
			return nil, err
		}
		for t := 0; t < wlen; t++ {
			s1[t] = _ri[t]
		}
		if j < 2 * K {
			ri, err := eagleEncode(mi, w3, w4)
			if err != nil {
				return nil, err
			}
			for t := 0; t < wlen; t++ {
				rs[j * wlen + t] = ri[t]
			}
		}
	}

	// decrypt the first stage
	for i := 0; i < K; i++ {
		mi, err := eagleDecode(rs[2 * i * wlen + wlen: 2 * i * wlen + wlen + wlen], w1, w2)
		if err != nil {
			return nil, err
		}
		for t := 0; t < wlen; t++ {
			if i * wlen + t < dlen {
				dst[i * wlen + t] = mi[t] ^ c[4 + i * wlen + t]
			}
		}
	}

	return dst, nil
}
