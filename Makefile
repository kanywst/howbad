.PHONY: build test lint vuln format demo clean

BINARY_NAME=howbad

build:
	go build -o $(BINARY_NAME) .

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

format:
	go fmt ./...
	go mod tidy

# Fake home and fake providers; never touches real credentials.
demo:
	vhs assets/demo.tape

clean:
	go clean
	rm -f $(BINARY_NAME)
