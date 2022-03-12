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

type Resp struct {
	code byte
	err  error
}

var resp = map[byte]*Resp{
	'a': &Resp{'a', nil}, // accept
	'y': &Resp{'y', // custom response
		errors.New("552 Message blocked due to forbidden attachment")},
	't': &Resp{'t', nil}, // tempfail
	'r': &Resp{'r', nil}, // reject
	'q': &Resp{'q', errors.New("yara")}, // quarantine
}

func TestValidYaraRule(path []string) (okRules []string) {
	for _, dir := range path {
		f, err := os.Open(dir)
		if err != nil {
			log.Println("[ERROR]", "Could not open rule file ", dir, err)
			f.Close()
			continue
		}
		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		c, _ := yara.NewCompiler()
		if err = c.AddFile(f, namespace); err == nil {
			okRules = append(okRules, dir)
		} else {
			log.Println("[ERROR]", "Could not load rule file ", dir, err)
		}
		f.Close()
	}
	return okRules
}

func LoadYara(dir string) (*yara.Scanner, int, error) {

	var path []string
	err := filepath.Walk(dir, func(walk string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println("[ERROR]", err)
			return err
		}
		if !info.IsDir() && (filepath.Ext(walk) == ".rule" ||
			filepath.Ext(walk) == ".yar" ||
			filepath.Ext(walk) == ".yara") {
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
	for _, dir := range TestValidYaraRule(path) {
		f, _ := os.Open(dir)
		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		compiler.AddFile(f, namespace)
		f.Close()
	}
	rules, _ := compiler.GetRules()
	// new scanner
	sc, _ := yara.NewScanner(rules)
	return sc, len(rules.GetRules()), nil
}

func ParseEmailMessage(r io.Reader, yaraScan *yara.Scanner, defResp byte) *Resp {
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
			for k := range m {
				log.Printf("[INFO] (%s) «%s» rule match in file «%s» in %s", string(defResp), m[k].Rule, filename, env.GetHeader("Message-ID"))
			}
			return resp[defResp]
		}
	}
	// accept message by default
	return nil
}
