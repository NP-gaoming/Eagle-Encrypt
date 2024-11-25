package main

import (
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	// "io"
	"os"
	"core"
	"io/ioutil"
)

var (
	app = kingpin.New("eagle", "tool for encrypt and decrypt")

	encry = app.Command("enc", "encrypt some bytes array")
	ekey = encry.Flag("key", "the hex string of the key").String()
	etype = encry.Flag("type", "the input type: text/file").String()
	esrc = encry.Flag("src", "if the input type is text, the src is the hex array to encrypted. if the input type is file, the src must be a filename").String()

	decry = app.Command("dec", "decrypt some bytes array")
	dkey = decry.Flag("key", "the hex string of the key").String()
	dtype = decry.Flag("type", "the input type: text/file").String()
	dsrc = decry.Flag("src", "if the input type is text, the src is the hex array to encrypted. if the input type is file, the src must be a filename").String()
)

var (
	
)

func main() {
	kingpin.Version("0.0.1")
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case encry.FullCommand():
		cipher, err := core.Encrypt(*ekey, *etype, *esrc)
		if err == nil {
			if *etype == "text" {
				fmt.Printf("succ: ciphertext = %v\r\n", core.ToHex(cipher))
			} else if *etype == "file" {
				outfile := *esrc + ".cipher"
				_ = ioutil.WriteFile(outfile, cipher, 0644)
			}
		}
	case decry.FullCommand():
		m, err := core.Decrypt(*dkey, *dtype, *dsrc)
		if err == nil {
			if *dtype == "text" {
				fmt.Printf("succ: plaintext = %v\r\n", core.ToHex(m))
			} else if *dtype == "file" {
				outfile := *dsrc + ".plain"
				_ = ioutil.WriteFile(outfile, m, 0644)
			}
		}
	}
}
