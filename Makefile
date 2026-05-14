APP := gol
CMD := ./cmd/gol
BIN_DIR := bin
GO ?= go
GO_CACHE ?= /tmp/go-bof-gocache

.PHONY: all test test build build-linux build-windows clean

all: test build

test:
	GOOS=windows GOARCH=amd64 GOCACHE=$(GO_CACHE)-windows $(GO) test -c -o /tmp/$(APP)-cmd.test.exe $(CMD)
	GOOS=windows GOARCH=amd64 GOCACHE=$(GO_CACHE)-windows $(GO) test -c -o /tmp/$(APP)-bof.test.exe ./internal/bof

build: build-linux build-windows

build-linux:
	mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 GOCACHE=$(GO_CACHE)-linux $(GO) build -buildvcs=false -o $(BIN_DIR)/$(APP) $(CMD)

build-windows:
	mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 GOCACHE=$(GO_CACHE)-windows $(GO) build -buildvcs=false -o $(BIN_DIR)/$(APP).exe $(CMD)

clean:
	rm -rf $(BIN_DIR)
	rm -f /tmp/$(APP)-cmd.test.exe /tmp/$(APP)-bof.test.exe
