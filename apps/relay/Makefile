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

# Written out longhand rather than as `gofmt -l . | (! read)`, which is the
# idiom and does not work. make runs recipes under /bin/sh, and in dash `read`
# with no variable name is an error rather than a read — so the pipeline exits
# nonzero, `!` inverts it, and the target passes on unformatted files. That is
# every Debian-derived machine including the CI runner, so the check was inert
# in the one place it was supposed to be doing the work. The `tee /dev/stderr`
# it used to carry was worse than useless too: tee opens with O_TRUNC, so
# whenever stderr was a file rather than a terminal it emptied the log it was
# writing to and took the rest of the run's output with it.
lint:
	@files=`gofmt -l .`; \
	if [ -n "$$files" ]; then echo "gofmt:"; echo "$$files"; exit 1; fi
	go vet ./...

clean:
	rm -rf bin data

docker:
	docker build -f Dockerfile -t quorum-relay ../..
