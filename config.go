package main

type RespRule struct {
	Rule string
	Resp string
}

type Config struct {
	Verbose         bool
	Proto           string
	Address         string
	YaraDir         string
	DefaultResponse string
	MaxLen			int64
	RespByRule      []RespRule
}
