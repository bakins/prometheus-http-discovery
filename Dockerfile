FROM circleci/golang:1.13 AS builder
 
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
ARG GO111MODULE=on
 
COPY . /src
RUN cd /src && go build -mod=vendor -o /tmp/prometheus-http-discovery .
 
FROM gcr.io/distroless/base
 
COPY --from=builder /tmp/prometheus-http-discovery /usr/bin/
 
ENTRYPOINT ["/usr/bin/prometheus-http-discovery" ]
