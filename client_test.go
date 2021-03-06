package main

import (
	"fmt"
	"github.com/mschneider82/milterclient"
	"log"
	"net"
	"os"
	"testing"
)

/* main program */
func TestMilterClient(t *testing.T) {

	yaraScan, nbrules, _ := LoadYara("yara/")

	// parse commandline arguments
	protocol := "tcp"
	address := "127.0.0.1:8125"

	// bind to listening address
	socket, err := net.Listen(protocol, address)
	if err != nil {
		log.Fatal(err)
	}
	//defer socket.Close()
	cfg := Config{DefaultResponse: "y", MaxLen: 900000}
	verbose = true

	// run server
	go RunServer(socket, nbrules, yaraScan, &cfg)

	// run tests:

	emlFilePath := "simple.eml"
	eml, err := os.Open(emlFilePath)
	if err != nil {
		t.Errorf("Error opening test eml file %v: %v", emlFilePath, err)
	}
	defer eml.Close()

	msgID := milterclient.GenMtaID(12)
	last, err := milterclient.SendEml(eml, "127.0.0.1:8125", "from@unittest.de", "to@unittest.de", "", "", msgID, false, 5)
	if err != nil {
		t.Errorf("Error sending eml to milter: %v", err)
	}

	fmt.Printf("MsgId: %s, Lastmilter code: %s\n", msgID, string(last))
	if last != milterclient.SmfirAccept {
		t.Errorf("Excepted Accept from Milter, got %v", last)
	}

	emlFilePath = "message.eml"
	eml, err = os.Open(emlFilePath)
	if err != nil {
		t.Errorf("Error opening test eml file %v: %v", emlFilePath, err)
	}
	defer eml.Close()

	msgID = milterclient.GenMtaID(12)
	last, err = milterclient.SendEml(eml, "127.0.0.1:8125", "from@unittest.de", "to@unittest.de", "", "", msgID, false, 5)
	if err != nil {
		t.Errorf("Error sending eml to milter: %v", err)
	}

	fmt.Printf("MsgId: %s, Lastmilter code: %s\n", msgID, string(last))
	if last != milterclient.SmfirReplycode {
		t.Errorf("Reject from Milter with custom response message, got %v", last)
	}
}

func TestMilterResp(t *testing.T) {

	yaraScan, nbrules, _ := LoadYara("yara/")

	// parse commandline arguments
	protocol := "tcp"

	// run server

	for i, r := range []string{"a", "q", "y", "r", "t"} {
		address := fmt.Sprintf("127.0.0.1:%d", 8126+i)

		// bind to listening address
		socket, err := net.Listen(protocol, address)
		if err != nil {
			log.Fatal(err)
		}
		cfg := Config{DefaultResponse: r, MaxLen: 900000}
		verbose = true
		go RunServer(socket, nbrules, yaraScan, &cfg)
		emlFilePath := "message.eml"
		eml, err := os.Open(emlFilePath)
		if err != nil {
			t.Errorf("Error opening test eml file %v: %v", emlFilePath, err)
		}
		defer eml.Close()

		msgID := milterclient.GenMtaID(12)
		last, err := milterclient.SendEml(eml, address, "from@unittest.de", "to@unittest.de", "", "", msgID, false, 5)
		if err != nil {
			t.Errorf("Error sending eml to milter: %v", err)
		}

		fmt.Printf("MsgId: %s, Lastmilter code: %s, Expected code %s\n", msgID, string(last), r)
		if string(last) != r {
			t.Errorf("Reject from Milter with custom response message, got %v - %v", last, r)
		}
	}

}
