# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

# Format Go files.
fmt:
    golangci-lint fmt ./...
    cd policy && golangci-lint fmt ./...

# Compile everything (the root module, then policy/, its own module).
build:
    go build ./...
    cd policy && go build ./...

# Run the tests. They never reach an AWS account: the registry is parsed
# from text and the engine runs against Pulumi mocks.
test:
    go test ./...
    cd policy && go test ./...

# Run linters. `config verify` first: `run` accepts unknown top-level
# keys silently.
lint:
    golangci-lint config verify
    golangci-lint run ./...
    cd policy && golangci-lint run ./...

# Reachable Go advisories (security.yaml, daily). NOT part of `check`: a
# standard-library advisory with no released fix would turn every pull
# request red on a finding nobody can act on.
vuln:
    govulncheck ./...
    cd policy && govulncheck ./...

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Run go mod tidy.
tidy:
    go mod tidy
    cd policy && go mod tidy

# Clean build artifacts.
clean:
    rm -rf bin/ dist/ coverage.out

# Everything CI runs on a pull request.
check: build test lint leak-canary
