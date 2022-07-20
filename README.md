# Shack

A small HTTPS proxy which can intentionally [MitM](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) the connections it handles,
in order to cache responses locally.

Certificates can either be provided locally or - if running in a Kubernetes cluster - can be created with [cert-manager](https://cert-manager.io/).

Shack is useful for:

- Speeding up downloads after the first time a request has been made
- Reducing the amount of data downloaded from the internet
- Preserving local copies of assets you download
- Reducing bandwidth costs in cloud environments by reducing data downloaded from the internet
- Reducing load on servers providing assets in attempt to be a "good internet citizen"

## Running Shack in Kubernetes

Shack provides YAML manifests for a simple Kubernetes deployment, using cert-manager to issue certificates.

1. [Install cert-manager](https://cert-manager.io/docs/installation/)

2. [Install cert-manager/trust](https://cert-manager.io/docs/projects/trust/#installation)

3. Install shack:

```console
kubectl apply -f infrastructure/k8s/namespace.yaml
kubectl apply -f infrastructure/k8s/issuers.yaml

kubectl get -n shack secrets shack-root-secret -ojson | jq '.data."tls.crt"' -r | base64 -d > shack-root-cert.pem

# trust consumes the configmap from the trust namespace, which defaults to the cert-manager namespace
kubectl create configmap -n cert-manager --from-file=root.crt=shack-root-cert.pem shack-root-cm

kubectl apply -f infrastructure/k8s/trust.yaml

kubectl apply -f infrastructure/k8s/app.yaml
```

## Utilizing Shack in Your Applications

See [`puller_cached.yaml`](./infrastructure/k8s/puller_cached.yaml) for an example of using `curl` to route requests through Shack.
