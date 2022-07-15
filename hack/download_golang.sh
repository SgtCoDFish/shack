#!/usr/bin/env bash

set -eu -o pipefail

# --cacert is the cert of the service we're trying to access
# --proxy-cacert is the cert of the proxy service

# in this case, they're the same thing since we'll MitM the connection

/usr/bin/time --format "%E elapsed" curl -L -O --cacert _bin/rootCA.pem --proxy https://localhost:18121 --proxy-cacert _bin/rootCA.pem https://go.dev/dl/go1.18.4.linux-amd64.tar.gz
