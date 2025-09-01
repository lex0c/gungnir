.RECIPEPREFIX := >

BIN_DIR := bin
BUILD_ID := $(shell uuidgen)

.PHONY: all build server client test clean

all: build

build: server client

server: | $(BIN_DIR)
>go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID)" -o $(BIN_DIR)/server ./cmd/server

client: | $(BIN_DIR)
>go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID)" -o $(BIN_DIR)/client ./cmd/client

$(BIN_DIR):
>mkdir -p $(BIN_DIR)

test:
>go test ./...

clean:
>rm -rf $(BIN_DIR)

