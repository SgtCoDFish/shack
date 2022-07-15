#!/usr/bin/env bash

set -eu -o pipefail

/usr/bin/time --format "%E elapsed" curl -L -o 1GB_uncached.bin https://speed.hetzner.de/1GB.bin
