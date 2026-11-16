FROM golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS gosu-build

ENV GOTOOLCHAIN=local
ARG GOSU_TAG=1.20
ARG GOSU_COMMIT=29b939aa5bd4dc588af765b8248f6e39150d2565

RUN apk add --no-cache git \
    && git init /src \
    && git -C /src remote add origin https://github.com/tianon/gosu.git \
    && git -C /src fetch --depth 1 origin "refs/tags/${GOSU_TAG}:refs/tags/${GOSU_TAG}" \
    && git -C /src checkout --detach "refs/tags/${GOSU_TAG}" \
    && test "$(git -C /src rev-parse HEAD)" = "${GOSU_COMMIT}" \
    && cd /src \
    && go mod download \
    && go mod verify \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /gosu .

FROM postgres:17-alpine@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7

COPY --from=gosu-build /gosu /usr/local/bin/gosu
RUN chmod 0755 /usr/local/bin/gosu \
    && gosu --version \
    && gosu nobody true
