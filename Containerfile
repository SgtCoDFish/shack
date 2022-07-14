FROM docker.io/golang:1.18-bullseye as build

WORKDIR /build
COPY . .

RUN make binaries

FROM docker.io/debian:bullseye as image

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl

COPY --from=build /build/_bin/shack /shack

ENTRYPOINT ["/shack"]
