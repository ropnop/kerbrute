TARGET=./dist
ARCHS=amd64 386 
GOOS=windows linux darwin

.PHONY: windows linux mac all clean

windows:
	@for ARCH in ${ARCHS}; do \
		echo "Building for windows $${ARCH}.." ;\
		GOOS=windows GOARCH=$${ARCH} go build -o ${TARGET}/kerbrute_windows_$${ARCH}.exe ;\
	done; \
	echo "Done."

linux:
	@for ARCH in ${ARCHS}; do \
		echo "Building for linux $${ARCH}..." ; \
		GOOS=linux GOARCH=$${ARCH} go build -o ${TARGET}/kerbrute_linux_$${ARCH} ;\
	done; \
	echo "Done."

mac:
	@for ARCH in ${ARCHS}; do \
		echo "Building for mac $${ARCH}..." ; \
		GOOS=darwin GOARCH=$${ARCH} go build -o ${TARGET}/kerbrute_darwin_$${ARCH} ;\
	done; \
	echo "Done."

clean:
	@rm ${TARGET}/* ; \
	echo "Done."

all: clean windows linux mac


