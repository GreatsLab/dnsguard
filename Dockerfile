# build
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /dnsguard .

# run: just the binary and CA certs (needed for DoH/DoT upstreams)
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /dnsguard /dnsguard
EXPOSE 53/udp 53/tcp 8053/tcp
USER 65534:65534
ENTRYPOINT ["/dnsguard"]
CMD ["-block", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
