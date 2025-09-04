.RECIPEPREFIX := >

BIN_LOCAL_DIR := bin
BUILD_ID := $(shell uuidgen)
SEED ?= 23

BIN_NAME = gungnir
TARGET = bin/client
BIN_DIR = /bin
SERVICE_FILE = $(BIN_NAME).service
SERVICE_DIR = /etc/systemd/system

.PHONY: all build server client test clean

all: build

build: server client

server: | $(BIN_LOCAL_DIR)
>CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID)" -o $(BIN_LOCAL_DIR)/server ./cmd/server

client: | $(BIN_LOCAL_DIR)
>CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.BuildID=$(BUILD_ID) -X main.seedStr=$(SEED)" -o $(BIN_LOCAL_DIR)/client ./cmd/client

$(BIN_LOCAL_DIR):
>mkdir -p $(BIN_LOCAL_DIR)

install: client
>@echo [-] Installing gungnir
>install -m 755 $(TARGET) $(BIN_DIR)/$(BIN_NAME)
>install -m 644 $(SERVICE_FILE) $(SERVICE_DIR)/$(SERVICE_FILE)
>systemctl daemon-reload
>systemctl enable $(SERVICE_FILE)
>@echo [-] Loading gungnir
>systemctl start $(SERVICE_FILE)
>@echo [-] Done

uninstall:
>@echo [-] Uninstalling gungnir
>systemctl stop $(SERVICE_FILE)
>systemctl disable $(SERVICE_FILE)
>@echo [-] Removing gungnir files
>rm -f $(BIN_DIR)/$(BIN_NAME)
>rm -f $(SERVICE_DIR)/$(SERVICE_FILE)
>systemctl daemon-reload
>@echo [-] Done

test:
>go test ./...

lint:
>go vet ./...

clean:
>rm -rf $(BIN_LOCAL_DIR)

