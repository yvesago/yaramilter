package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/mschneider82/milterclient"
	"io/ioutil"
	"log"
	"os"
)

func BuildMail(file string) []byte {

	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("From: test@example.org\r\n"))
	buf.WriteString(fmt.Sprintf("To: test@example.org\r\n"))
	buf.WriteString(fmt.Sprintf("Subject: test\r\n"))

	boundary := "my-boundary-779"
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Message-ID: <testfile@exemple.org>\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))

	buf.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString(fmt.Sprintf("\r\nsome text"))

	buf.WriteString(fmt.Sprintf("\r\n--%s\r\n", boundary))
	buf.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=%s\r\n", file))
	buf.WriteString("Content-ID: <testfile@exemple.org>\r\n\r\n")

	data := readFile(file)

	b := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(b, data)
	buf.Write(b)
	buf.WriteString(fmt.Sprintf("\r\n--%s", boundary))

	buf.WriteString("--")

	return buf.Bytes()
}

func readFile(fileName string) []byte {

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	return data
}

var Version string

/* main program */
func main() {
	var address, protocol, file string
	flag.StringVar(&address,
		"addr",
		"127.0.0.1:8125",
		"Bind to address")
	flag.StringVar(&protocol,
          "proto",
          "tcp",
          "Protocol family (unix or tcp)")
	flag.StringVar(&file,
		"file",
		"",
		"File")
	flag.Usage = func() {
		fmt.Printf("yaratest\n  Version: %s\n\n", Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if _, err := os.Stat(file); err != nil {
		log.Fatal(err)
	}


	msg := BuildMail(file)

	//fmt.Println(string(msg))

	tmpfile := "tmpfile.eml"
	ioutil.WriteFile(tmpfile, msg, 0644)

	eml, _ := os.Open(tmpfile)
	msgID := milterclient.GenMtaID(12)

	last, err := SendEmlSock(eml, protocol, address, msgID)
	if err != nil {
		log.Printf("Error sending eml to milter: %v", err)
	}

	fmt.Printf("MsgId: %s, Lastmilter code: %s\n", msgID, string(last))

}
