package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/hillu/go-yara/v4"
	"github.com/phalaaxx/milter"
	"github.com/hydronica/toml"
	"log"
	"log/syslog"
	"net"
	"net/textproto"
	"os"
	"strings"
)

var (
	verbose bool
	Version string
)

/* YaraMilter object */
type YaraMilter struct {
	milter.Milter
	multipart bool
	message   *bytes.Buffer
	nbrules   int
	scanner   *yara.Scanner
	cfg *Config
}

func (YaraMilter) Init(sid, mid string) {
	return
}

func (YaraMilter) Disconnect() {
	return
}

func (YaraMilter) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (YaraMilter) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (YaraMilter) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (YaraMilter) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

/* handle headers one by one */
func (e *YaraMilter) Header(name, value string, m *milter.Modifier) (milter.Response, error) {
	// if message has multiple parts set processing flag to true
	if name == "Content-Type" && strings.HasPrefix(value, "multipart/") {
		e.multipart = true
	}
	return milter.RespContinue, nil
}

/* at end of headers initialize message buffer and add headers to it */
func (e *YaraMilter) Headers(headers textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	// return accept if not a multipart message or whithout rule
	if !e.multipart || e.nbrules == 0 {
		return milter.RespAccept, nil
	}
	// prepare message buffer
	e.message = new(bytes.Buffer)
	// print headers to message buffer
	for k, vl := range headers {
		for _, v := range vl {
			if _, err := fmt.Fprintf(e.message, "%s: %s\n", k, v); err != nil {
				return nil, err
			}
		}
	}
	if _, err := fmt.Fprintf(e.message, "\n"); err != nil {
		return nil, err
	}
	// continue with milter processing
	return milter.RespContinue, nil
}

// accept body chunk
func (e *YaraMilter) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	// save chunk to buffer
	if _, err := e.message.Write(chunk); err != nil {
		return nil, err
	}
	return milter.RespContinue, nil
}

/* Body is called when email message body has been sent */
func (e *YaraMilter) Body(m *milter.Modifier) (milter.Response, error) {
	if e.nbrules == 0 {
		return milter.RespAccept, nil
	}
	// prepare buffer
	buffer := bytes.NewReader(e.message.Bytes())
	// parse email message and get accept flag
	if err := ParseEmailMessage(buffer, e.scanner, e.cfg); err != nil {
		// Add Header
		if errh := m.AddHeader("X-YaraMilter", string(err.code)); errh != nil {
			return nil, errh
		}
		switch err.code {
		case "a":
			return milter.RespAccept, nil
		case "q":
			m.Quarantine("yara")
			return milter.RespAccept, nil
		case "y":
			return milter.NewResponseStr('y', "552 Message blocked due to forbidden attachment"), nil
		case "t":
			return milter.RespTempFail, nil
		case "r":
			return milter.RespReject, nil
		default:
			return milter.RespAccept, nil
		}
	}
	// accept message by default
	return milter.RespAccept, nil
}

/* NewObject creates new YaraMilter instance */
func RunServer(socket net.Listener, nbrules int, yaraScan *yara.Scanner, cfg *Config) {
	// declare milter init function
	init := func() (milter.Milter, milter.OptAction, milter.OptProtocol) {
		return &YaraMilter{nbrules: nbrules, scanner: yaraScan, cfg: cfg},
			milter.OptAddHeader | milter.OptChangeHeader,
			milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo
	}

	// start server
	if err := milter.RunServer(socket, init); err != nil {
		log.Fatal("[RunServer]", err)
	}
}

func readConf() *Config {

	// parse commandline arguments
	var protocol, address, dir, resp, conf string
	flag.StringVar(&conf,
		"conf",
		"",
		"Config file instead of arguments")
	flag.StringVar(&protocol,
		"proto",
		"unix",
		"Protocol family (unix or tcp)")
	flag.StringVar(&address,
		"addr",
		"/var/spool/postfix/milters/ext.sock",
		"Bind to address or unix domain socket")
	flag.StringVar(&dir,
		"dir",
		"yara/",
		"Directory with yara rules")
	flag.StringVar(&resp,
		"resp",
		"a",
		"Defaut response : a, y, t, r, q")
	flag.BoolVar(&verbose,
		"verbose",
		false,
		"Verbose")
	flag.Usage = func() {
		fmt.Printf("yaramilter\n  Version: %s\n\n", Version)
		flag.PrintDefaults()
		fmt.Println("\nDefault response:")
		fmt.Println("\ta : accept, only log matching rules")
		fmt.Println("\ty : reject with custom response")
		fmt.Println("\tt : tempfail")
		fmt.Println("\tr : reject")
		fmt.Println("\tq : quarantine")
		fmt.Println("")
	}
	flag.Parse()

	cfg := Config{}
	if conf != "" {
		_, err := toml.DecodeFile(conf, &cfg)
		if err != nil {
		log.Fatal("\nError on config file:\n", err)
		}
		dir = cfg.YaraDir
		protocol = cfg.Proto
		address = cfg.Address
		verbose = cfg.Verbose
		resp = cfg.DefaultResponse
	} else {
		cfg.YaraDir = dir
		cfg.Proto = protocol
		cfg.Address = address
		cfg.Verbose = verbose
		cfg.DefaultResponse = resp
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Fatal("missing mandatory directory with yara rules")
	}

	if !strings.Contains("aqytr", resp) {
		log.Fatal("unknown default response")
	}

	// make sure the specified protocol is either unix or tcp
	if protocol != "unix" && protocol != "tcp" {
		log.Fatal("invalid protocol name")
	}

	return &cfg
}

/* main program */
func main() {

	// select log output
	o, _ := os.Stdout.Stat()
	if (o.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		log.SetOutput(os.Stdout)
	} else {
		logwriter, e := syslog.New(syslog.LOG_MAIL|syslog.LOG_NOTICE, "yaramilter")
		if e == nil {
			log.SetFlags(0)
			log.SetOutput(logwriter)
		}
	}


	cfg := readConf()

	// make sure socket does not exist
	if cfg.Proto == "unix" {
		// ignore os.Remove errors
		os.Remove(cfg.Address)
	}

	// bind to listening address
	socket, err := net.Listen(cfg.Proto, cfg.Address)
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()

	if cfg.Proto == "unix" {
		// set mode 0660 for unix domain sockets
		if err := os.Chmod(cfg.Address, 0660); err != nil {
			log.Fatal(err)
		}
		// remove socket on exit
		defer os.Remove(cfg.Address)
	}


	yaraScan, nbrules, err := LoadYara(cfg.YaraDir)
	if err != nil {
		log.Println("[LoadYara]", err)
	}

	log.Println("[INIT]", nbrules, "YARA rules compiled")

	// run server
	go RunServer(socket, nbrules, yaraScan, cfg)

	// sleep forever
	select {}
}
