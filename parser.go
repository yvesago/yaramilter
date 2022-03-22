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
	code string
	err  error
}

/*var resp = map[string]*Resp{
	"a": &Resp{"a", nil}, // accept
	"y": &Resp{"y", nil}, // custom response
	"t": &Resp{"t", nil}, // tempfail
	"r": &Resp{"r", nil}, // reject
	"q": &Resp{"q", nil}, // quarantine
}*/

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

func ResponseLevel(resp string) int {
	for k, v := range "aqytr" {
		if string(v) == resp {
			return k
		}
	}
	return 0
}

func ParseEmailMessage(r io.Reader, yaraScan *yara.Scanner, cfg *Config) *Resp {
	env, _ := enmime.ReadEnvelope(r)
	defResp := cfg.DefaultResponse
	defLevel := ResponseLevel(defResp)
	rulesResp := map[string]string{}
	for k := range cfg.RespByRule {
		rulesResp[cfg.RespByRule[k].Rule] = cfg.RespByRule[k].Resp
	}

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

	level := defLevel
	resp := defResp
	for _, a := range env.Attachments {
		//log.Printf("%d\n",len(a.Content))
		//log.Printf("-%+v\n",string(a.Content))

		filename := a.FileName
		fileContent := a.Content
		if verbose {
			log.Printf("[INFO] test %s file %s (%d)\n", env.GetHeader("Message-ID"), filename, len(fileContent))
		}
		if int64(len(fileContent)) > cfg.MaxLen {
			if verbose {
				log.Printf("[INFO] uncheck len %d file %s\n", len(fileContent), filename)
			}
			return nil
		}

		var m yara.MatchRules
		err := yaraScan.SetCallback(&m).ScanMem(fileContent)
		if err == nil && len(m) > 0 { // rule match
			for k := range m {
				if val, ok := rulesResp[m[k].Rule]; ok { // specific response for this rule
					if ResponseLevel(val) > level {
						level = ResponseLevel(val) // response will be set to higher level
						resp = val
					}
				}
				log.Printf("[INFO] (%s) «%s» rule match in file «%s» in %s", resp, m[k].Rule, filename, env.GetHeader("Message-ID"))
			}
			return &Resp{resp, nil}
		}
	}
	// accept message by default
	return nil
}
