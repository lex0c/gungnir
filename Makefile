.RECIPEPREFIX := >

BIN_DIR := bin
BUILD_ID := $(shell uuidgen)
SEED ?= 23

.PHONY: all build server client test clean

all: build

build: server client

server: | $(BIN_DIR)
>CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID)" -o $(BIN_DIR)/server ./cmd/server

client: | $(BIN_DIR)
>CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID) -X main.seedStr=$(SEED)" -o $(BIN_DIR)/client ./cmd/client

$(BIN_DIR):
>mkdir -p $(BIN_DIR)

test:
>go test ./...

lint:
>go vet ./...

clean:
>rm -rf $(BIN_DIR)

