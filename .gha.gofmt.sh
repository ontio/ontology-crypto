#!/bin/bash
#
# Fail if any tracked Go file is not formatted/import-clean.
set -euo pipefail

if ! command -v goimports >/dev/null 2>&1; then
    go install golang.org/x/tools/cmd/goimports@latest
fi
export PATH="$(go env GOPATH)/bin:${PATH}"

files=""
for d in $(go list -f '{{.Dir}}' ./... | grep -v /vendor/); do
    for f in "$d"/*.go; do
        if [ -e "$f" ]; then
            files="${files} ${f}"
        fi
    done
done

diff <(goimports -d ${files}) <(echo -n)
