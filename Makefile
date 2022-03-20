
TARGET = yaramilter libyara.so.9 yaramilter_test yaramilter_cli

BINS=$(wildcard build/*)

TAG=$(shell git describe --abbrev=0 --tags 2>/dev/null;)

VERSION=$(shell v='$(TAG)'; echo "$${v:=v0.0}")

BUILD=$(shell git rev-parse --short HEAD 2>/dev/null;)
DATE=$(shell date +%FT%T%z)


LDFLAGS=-trimpath -ldflags "-w -s -X 'main.Version=${VERSION}, git: ${BUILD}, build: ${DATE}'"


yaramilter:
	@mkdir -p build
	CGO_ENABLED=1 go build ${LDFLAGS} -o build/$@
	@echo " => bin builded: build/$@"

libyara.so.9:
	ldd build/yaramilter | grep $@ | awk -F' ' '{cmd="cp " $$3 " build/"; system(cmd)}'
	@echo " => copy $@ in: build/"

yaramilter_test:
	@mkdir -p build
	CGO_ENABLED=0 go build ${LDFLAGS} -o build/$@  cmd/yaratest.go cmd/clienthelpers.go
	@echo " => bin builded: build/$@"

yaramilter_cli:
	@mkdir -p build
	CGO_ENABLED=0 go build ${LDFLAGS} -o build/$@  cmd/yaracli.go cmd/clienthelpers.go
	@echo " => bin builded: build/$@"



build: $(TARGET) sha

# List binaries
$(BINS):
	@echo "=============="
	@echo "Release text :"
	@echo " ${VERSION}, git: ${BUILD}"
	@sha256sum $@

sha: $(BINS)

clean:
	rm -rf build/
	@echo "Build cleaned"


all: build sha

.PHONY: clean build sha $(TARGET) $(BINS)
