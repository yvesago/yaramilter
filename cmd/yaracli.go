package main

import (
	"flag"
	"fmt"
	"github.com/jhillyerd/enmime"
	"log"
	"os"
)

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
		"EML file")
	flag.Usage = func() {
		fmt.Printf("yaramilter_cli\n  Version: %s\n\n", Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if _, err := os.Stat(file); err != nil {
		log.Fatal(err)
	}


	response := "a"
	msgID := ""

	teml, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer teml.Close()
	env, e := enmime.ReadEnvelope(teml)
	if e != nil {
		log.Fatal(e)
	}

	msgID = env.GetHeader("Message-ID")

	if len(env.Attachments) > 0 {
		eml, _ := os.Open(file)
		defer eml.Close()
		last, err := SendEmlSock(eml, protocol, address, msgID)
		if err != nil {
			log.Printf("Error sending eml to milter: %v", err)
		}
		response = string(last)
	}

	fmt.Printf("MsgId: %s, Lastmilter code: %s\n", msgID, response)

}

