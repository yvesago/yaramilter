
LDFLAGS=-trimpath -ldflags "-w -s"

build:
	CGO_ENABLED=1 go build ${LDFLAGS}

