#!/bin/bash
#
# Run the unit tests for every package. Stress-scale vectors are opt-in via
# -stress (see the stress CI job).
set -euo pipefail

go test ./...
