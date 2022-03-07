package main

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
	"github.com/jhillyerd/enmime"
)

//var rules *yara.Rules
var yaraScan *yara.Scanner

// EPayloadNotAllowed is an error that disallows message to pass
var EPayloadNotAllowed = errors.New("552 Message blocked due to forbidden attachment")

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
	env, _ := enmime.ReadEnvelope(r)

	/*
		// Headers can be retrieved via Envelope.GetHeader(name).
		log.Printf("From: %v\n", env.GetHeader("From"))
		// Address-type headers can be parsed into a list of decoded mail.Address structs.
		alist, _ := env.AddressList("To")
		for _, addr := range alist {
			log.Printf("To: %s <%s>\n", addr.Name, addr.Address)
		}
		log.Printf("Subject: %v\n", env.GetHeader("Subject"))

		// The plain text body is available as mime.Text.
		log.Printf("Text Body: %v chars\n", len(env.Text))

		// The HTML body is stored in mime.HTML.
		log.Printf("HTML Body: %v chars\n", len(env.HTML))

		// mime.Inlines is a slice of inlined attacments.
		log.Printf("Inlines: %v\n", len(env.Inlines))

		// mime.Attachments contains the non-inline attachments.
		log.Printf("Attachments: %v\n", len(env.Attachments))
	*/

	for _, a := range env.Attachments {
		//log.Printf("%d\n",len(a.Content))
		//log.Printf("-%+v\n",string(a.Content))

		filename := a.FileName
		if verbose {
			log.Printf("[INFO] test %s file %s\n", env.GetHeader("Message-ID"), filename)
		}
		fileContent := a.Content

		var m yara.MatchRules
		err := yaraScan.SetCallback(&m).ScanMem(fileContent)
		if err == nil && len(m) > 0 {
			if verbose {
				log.Printf("[INFO] %s rule match\n", m[0].Rule)
			}
			return EPayloadNotAllowed
		}
	}
	// accept message by default
	return nil
}
