FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o bcrypt .

FROM scratch
COPY --from=builder /src/bcrypt /bcrypt
USER 65534:65534
ENTRYPOINT ["/bcrypt"]
