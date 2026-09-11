SCHEMAS := ../../packages/protocol/schemas

.PHONY: all build run test race lint clean docker

all: lint test build

build:
	go build -o bin/quorum-relay .

run: build
	QUORUM_SCHEMA_DIR=$(SCHEMAS) ./bin/quorum-relay

test:
	go test ./...

# -race is scoped to our own packages on purpose.
#
# khatru's notifyListeners reads rl.listeners without holding clientsMutex,
# which removeListenerId writes under it, so the end-to-end tests in package
# main trip the detector on upstream code every time. Running them under -race
# anyway would train everyone to ignore the output, which costs more than the
# coverage gains. The projector — where a missing lock is our bug to make — is
# covered.
race:
	go test -race ./internal/...

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...

clean:
	rm -rf bin data

docker:
	docker build -f Dockerfile -t quorum-relay ../..
