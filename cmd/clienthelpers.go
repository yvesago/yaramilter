package main

import (
	"fmt"
	"github.com/mschneider82/milterclient"
	"io"
	"io/ioutil"
	"net"
)

// empty mtaMsgID will generate ID
func SendEmlSock(eml io.Reader, proto, milterSock, from, to, mtaMsgID string, ipv6 bool, timeoutSecs int) (byte, error) {

	msg, headers, _ := milterclient.ReadMessage(eml)

	body, _ := ioutil.ReadAll(msg.Body)

	done := make(chan byte)

	conn, err := net.Dial(proto, milterSock)

	if err != nil {
		return 0, err
	}

	defer conn.Close()

	if mtaMsgID == "" {
		mtaMsgID = milterclient.GenMtaID(12)
	}
	//fmt.Printf("MessageId: %s\n", mtaMsgID)

	Session := &milterclient.MilterSession{Sock: conn, Macros: map[string]string{"i": mtaMsgID}}

	go func() {
		err1 := Session.ReadResponses(done)
		if err1 != nil && err1.Error() != "EOF" {
			fmt.Printf("Error Reading: %v\n", err1)
		}
	}()

	messages := []*milterclient.Message{
		Session.Negotiation(),
		Session.MailFrom(from),
		Session.RcptTo(to),
	}

	for i, key := range headers.Keys {
		value := headers.Values[i]
		messages = append(messages, Session.Header(key, value))
	}

	messages = append(messages, Session.EndOfHeader())

	var remainingBody = body
	var m *milterclient.Message
	for remainingBody != nil {
		//fmt.Printf("remainingBody len: %v\n", len(remainingBody))
		m, remainingBody = Session.Body(remainingBody)
		messages = append(messages, m)
	}
	messages = append(messages, Session.EndOfBody())
	//messages = append(messages, Session.Quit())
	var lastCode byte
	lastCode, err = Session.WriteMessages(messages, timeoutSecs, done)

	return lastCode, err
}
