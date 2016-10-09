CC	:= gcc
GB	:= /usr/bin/gb

all:  sandboxed-tor-browser

sandboxed-tor-browser: static-assets
	gb build

static-assets: go-bindata tbb_stub
	./bin/go-bindata -nometadata  -pkg data -prefix data -o ./src/cmd/sandboxed-tor-browser/internal/data/bindata.go data/...

tbb_stub: go-bindata
	$(CC) -shared -pthread -fPIC src/tbb_stub/tbb_stub.c -Wall -Werror -Os -o data/tbb_stub.so

go-bindata:
	gb build github.com/jteeuwen/go-bindata/go-bindata
	mkdir -p data

clean:
	rm -f ./src/cmd/sandboxed-tor-browser/internal/data/bindata.go
	rm -f ./data/tbb_stub.so
	rm -Rf ./bin
	rm -Rf ./pkg
