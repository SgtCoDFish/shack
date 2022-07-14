#!/usr/bin/env bash

set -eu -o pipefail

if [[ -z ${1:-} ]]; then
	echo "usage: $0 <target-url>"
	exit 1
fi

cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Pod
metadata:
  generateName: dlpod-
  namespace: shack
spec:
  volumes:
  - name: trust-bundle
    configMap:
      name: cm-trust-bundle
  restartPolicy: Never
  containers:
  - name: puller
    image: quay.io/adjetstack/curlpine:latest
    imagePullPolicy: IfNotPresent
    volumeMounts:
    - name: trust-bundle
      mountPath: "/etc/trust"
      readOnly: true
    command:
    - /bin/sh
    - -c
    - /usr/bin/time curl -L -o /dev/null $1
EOF
