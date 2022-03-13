package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestConf(t *testing.T) {
	subCmdFlags := "-conf test_config.cfg"
	args := strings.Split(subCmdFlags, " ")
	os.Args = append([]string{os.Args[0]}, args...)

	//fmt.Printf("\nos args = %v\n", os.Args)

	cfg := readConf()
	fmt.Printf("%+v\n", cfg)
	if cfg.Address != "127.0.0.1:8125" {
		t.Errorf("Error in config file %v", cfg)
	}
	if cfg.YaraDir != "yara/" {
		t.Errorf("Error in config file %v", cfg)
	}
	if cfg.Proto != "tcp" {
		t.Errorf("Error in config file %v", cfg)
	}
	if cfg.DefaultResponse != "a" {
		t.Errorf("Error in config file %v", cfg)
	}

	rulesResp := map[string]string{}
	for k := range cfg.RespByRule {
		rulesResp[cfg.RespByRule[k].Rule] = cfg.RespByRule[k].Resp
	}
	fmt.Printf("%v\n", rulesResp)
	level := ResponseLevel(rulesResp["Microsoft_XLSX_with_Macrosheet"])
	if level != 1 {
		t.Errorf("Error in rule level %d", level)
	}

}

/*func TestFlagMain(t *testing.T) {
	subCmdFlags := "-addr 127.0.0.1:8126 "
	args := strings.Split(subCmdFlags, " ")
	os.Args = append([]string{os.Args[0]}, args...)

	fmt.Printf("\nos args = %v\n", os.Args)

	cfg := readConf()
	log.Printf("%+v\n", cfg)

	if cfg.Address != "127.0.0.1:8126" {
		t.Errorf("Error in reading args %v", os.Args)
	}
}*/
