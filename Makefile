TARGET=./dist
ARCHS=amd64 386 
GOOS=windows linux darwin
PACKAGENAME="github.com/ropnop/kerbrute"

COMMIT=`git rev-parse --short HEAD`
DATE=`date +%m/%d/%y`
GOVERSION=`go version | cut -d " " -f 3`

ifdef VERSION
	VERSION := $(VERSION)
else
	VERSION := dev
endif

LDFLAGS="-X ${PACKAGENAME}/util.GitCommit=${COMMIT} \
-X ${PACKAGENAME}/util.BuildDate=${DATE} \
-X ${PACKAGENAME}/util.GoVersion=${GOVERSION} \
-X ${PACKAGENAME}/util.Version=${VERSION} \
"

.PHONY: help windows linux mac all clean

help:           ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

windows: ## Make Windows x86 and x64 Binaries
	@for ARCH in ${ARCHS}; do \
		echo "Building for windows $${ARCH}.." ;\
		GOOS=windows GOARCH=$${ARCH} go build -ldflags ${LDFLAGS} -o ${TARGET}/kerbrute_windows_$${ARCH}.exe ;\
	done; \
	echo "Done."

linux: ## Make Linux x86 and x64 Binaries
	@for ARCH in ${ARCHS}; do \
		echo "Building for linux $${ARCH}..." ; \
		GOOS=linux GOARCH=$${ARCH} go build -ldflags ${LDFLAGS} -o ${TARGET}/kerbrute_linux_$${ARCH} ;\
	done; \
	echo "Done."

mac: ## Make Darwin (Mac) x86 and x64 Binaries
	@for ARCH in ${ARCHS}; do \
		echo "Building for mac $${ARCH}..." ; \
		GOOS=darwin GOARCH=$${ARCH} go build -ldflags ${LDFLAGS} -o ${TARGET}/kerbrute_darwin_$${ARCH} ;\
	done; \
	echo "Done."

clean: ## Delete any binaries
	@rm -f ${TARGET}/* ; \
	echo "Done."

all: ## Make Windows, Linux and Mac x86/x64 Binaries
all: clean windows linux mac


