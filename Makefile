CC	:= gcc
GB	:= /usr/bin/gb

all:  sandboxed-tor-browser

sandboxed-tor-browser: tbb_stub
	gb build

tbb_stub: asset-encoder
	$(CC) -shared -pthread -fPIC src/tbb_stub/tbb_stub.c -Wall -Werror -Os -o bin/tbb_stub.so
	./bin/asset-encoder --package sandbox --varName stub bin/tbb_stub.so src/cmd/sandboxed-tor-browser/internal/sandbox/stub.go

asset-encoder:
	gb build cmd/asset-encoder

clean:
	rm -f ./src/cmd/sandboxed-tor-browser/internal/sandbox/stub.go
	rm -Rf ./bin
	rm -Rf ./pkg
