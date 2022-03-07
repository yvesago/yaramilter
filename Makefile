
VERSION=$(shell git describe --abbrev=0 --tags)

BUILD=$(shell git rev-parse --short HEAD)
DATE=$(shell date +%FT%T%z)


LDFLAGS=-trimpath -ldflags "-w -s -X 'main.Version=${VERSION}, git: ${BUILD}, build: ${DATE}'"

build:
	CGO_ENABLED=1 go build ${LDFLAGS}

