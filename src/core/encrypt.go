package core

import(
	"fmt"
)

func Encrypt(key, etype, src string) ([]byte, error) {
	w1, w2, w3, w4, err := fromKeyToBytes(key)
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
	//dlen := 4 + len(m) + len(m) + wlen
	K := len(m) / wlen
	dlen := 4 + 3 * len(m) + 2 * wlen
	dst := make([]byte, dlen)
	dst[0] = byte(ml / (256 * 256 * 256))
	dst[1] = byte((ml / (256 * 256)) % 256)
	dst[2] = byte((ml / (256)) % (256 * 256))
	dst[3] = byte(ml % 256)

	// generate random numbers
	rs, err := genState(2 * len(m) + wlen)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}

	// generate random r1
	_r1, err := genState(wlen)
	if err != nil {
		fmt.Printf("err=%v\r\n", err)
		return nil, err
	}

	// encrypt the first stage
	for i := 0; i < K; i++ {
		mi, err := eagleDecode(rs[(2 * i) * wlen: (2 * i) * wlen + wlen], w1, w2)
		if err != nil {
			return nil, err
		}
		for j := 0; j < wlen; j++ {
			dst[4 + i * wlen + j] = mi[j] ^ m[i * wlen + j]
		}
	}

	// encrypt the second stage
	for i := 0; i < 2 * K + 1; i++ {
		mi, err := eagleDecode(rs[i * wlen: i * wlen + wlen], w3, w4)
		if err != nil {
			return nil, err
		}
		_mi, err := eagleDecode(_r1, w3, w4)
		if err != nil {
			return nil, err
		}
		for j := 0; j < wlen; j++ {
			dst[4 + K * wlen + i * wlen + j] = mi[j] ^ _mi[j]
		}
		_r1 = mi
	}

	for j := 0; j < wlen; j++ {
		dst[4 + 3 * K * wlen + wlen + j] = rs[2 * K * wlen + j]
	}

	return dst, nil
}
