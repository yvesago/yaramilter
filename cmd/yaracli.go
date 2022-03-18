package main

import (
	"flag"
	"fmt"
	"github.com/jhillyerd/enmime"
//	"github.com/mschneider82/milterclient"
	"io/ioutil"
	"log"
	"os"
)

func readFile(fileName string) []byte {

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	return data
}

var (
	verbose bool
	Version string
)

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
	flag.BoolVar(&verbose,
		"verbose",
		false,
		"Verbose")
	flag.Usage = func() {
		fmt.Printf("yaracli\n  Version: %s\n\n", Version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if _, err := os.Stat(file); err != nil {
		log.Fatal(err)
	}


	response := "a"
	msgID := ""

	teml, _ := os.Open(file)
	env, e := enmime.ReadEnvelope(teml)
	if e != nil {
		log.Fatal(e)
	}

	msgID = env.GetHeader("Message-ID")

	if len(env.Attachments) > 0 {
		eml, _ := os.Open(file)
		last, err := SendEmlSock(eml, protocol, address, "fakefrom@example.com", "faketo@example.com", msgID, false, 5)
		if err != nil {
			log.Printf("Error sending eml to milter: %v", err)
		}
		response = string(last)
	}

	fmt.Printf("MsgId: %s, Lastmilter code: %s\n", msgID, response)

}



