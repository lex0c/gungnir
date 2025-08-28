MODULE := e2eproto

SERVER := ./server
CLIENT := ./client

BIN_SERVER := bin/server
BIN_CLIENT := bin/client

.PHONY: all build server client clean run-server run-client

all: build

build: $(BIN_SERVER) $(BIN_CLIENT)

$(BIN_SERVER):
	@echo ">> Building server"
	go build -o $(BIN_SERVER) $(SERVER)

$(BIN_CLIENT):
	@echo ">> Building client"
	go build -o $(BIN_CLIENT) $(CLIENT)

run-server: $(BIN_SERVER)
	@echo ">> Running server"
	$(BIN_SERVER)

clean:
	@echo ">> Cleaning"
	rm -rf bin/

