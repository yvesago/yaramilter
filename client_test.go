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

	yaraScan, _, _ = LoadYara("yara/")

	// parse commandline arguments
	protocol := "tcp"
	address := "127.0.0.1:8125"

	// bind to listening address
	socket, err := net.Listen(protocol, address)
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()

	// run server
	go RunServer(socket)

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
