package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
)

//var rules *yara.Rules
var yaraScan *yara.Scanner

// EPayloadNotAllowed is an error that disallows message to pass
var EPayloadNotAllowed = errors.New("552 Message blocked due to blacklisted attachment")

func LoadYara(dir string) (*yara.Scanner, int, error) {

	var path []string
	err := filepath.Walk(dir, func(walk string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println("[ERROR]", err)
			return err
		}
		if !info.IsDir() {
			if verbose {
				log.Println("[INFO] load ", walk)
			}
			path = append(path, walk)
		}
		return nil
	})

	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, 0, errors.New("Failed to initialize YARA compiler")
	}
	for _, dir := range path {
		f, err := os.Open(dir)
		if err != nil {
			log.Println("[ERROR]", "Could not open rule file ", dir, err)
		}
		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddFile(f, namespace); err != nil {
			log.Println("[ERROR]", "Could not load rule file ", dir, err)
		}
		f.Close()
	}
	rules, _ := compiler.GetRules()
	// new scanner
	sc, _ := yara.NewScanner(rules)
	return sc, len(rules.GetRules()), nil
}

func ParseEmailMessage(r io.Reader) error {
	// get message from input stream
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return err
	}
	// get media type from email message
	media, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return err
	}
	// accept messages without attachments
	if !strings.HasPrefix(media, "multipart/") {
		return nil
	}
	// deep inspect multipart messages
	mr := multipart.NewReader(msg.Body, params["boundary"])
	//log.Println(media)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		// check if part contains a submessage
		if strings.HasPrefix(part.Header.Get("Content-Type"), "message/") {
			// recursively process submessage
			if err := ParseEmailMessage(part); err != nil {
				return err
			}
		}
		// do not process non-attachment parts
		if len(part.FileName()) == 0 {
			continue
		}

		partData, err := ioutil.ReadAll(part)
		if err != nil {
			log.Println("Error reading MIME part data -", err)
			return err
		}

		contentTransferEncoding := strings.ToUpper(part.Header.Get("Content-Transfer-Encoding"))

		filename := part.FileName()
		if verbose {
			log.Printf("[INFO] test %s file %s\n", msg.Header.Get("Message-ID"), filename)
		}
		var fileContent []byte
		switch {

		case strings.Compare(contentTransferEncoding, "BASE64") == 0:
			decodedContent, err := base64.StdEncoding.DecodeString(string(partData))
			if err != nil {
				log.Println("Error decoding base64 -", err)
			} else {
				//ioutil.WriteFile(filename, decodedContent, 0644)
				fileContent = decodedContent
			}

		case strings.Compare(contentTransferEncoding, "QUOTED-PRINTABLE") == 0:
			decodedContent, err := ioutil.ReadAll(quotedprintable.NewReader(bytes.NewReader(partData)))
			if err != nil {
				log.Println("Error decoding quoted-printable -", err)
			} else {
				// ioutil.WriteFile(filename, decodedContent, 0644)
				fileContent = decodedContent
			}

		default:
			// ioutil.WriteFile(filename, partData, 0644)
			fileContent = partData

		}

		var m yara.MatchRules
		err = yaraScan.SetCallback(&m).ScanMem(fileContent)
		if len(m) > 0 {
			if verbose {
				log.Printf("[INFO] %s rule match\n", m[0].Rule)
			}
			return EPayloadNotAllowed
		}
	}
	// accept message by default
	return nil
}
