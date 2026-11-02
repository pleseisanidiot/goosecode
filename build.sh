#!/bin/sh
# Build goosecode. Needs goose on PATH (or GOOSE=/path/to/goose), libcurl and OpenSSL headers.
cd "$(dirname "$0")"
GOOSE=${GOOSE:-goose}
GOOSE_CC="$PWD/cc-wrap.sh" exec "$GOOSE" build goosecode.goose --include shim.h -o goosecode
