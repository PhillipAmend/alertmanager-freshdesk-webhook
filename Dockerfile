
FROM golang:alpine as builder
RUN apk update && apk add git && apk add ca-certificates
RUN adduser -D -g '' appuser
COPY . $GOPATH/src/kubermatic/altermanager-freshdesk-json-git/alertmanager-freshdesk-webhook/
WORKDIR $GOPATH/src/kubermatic/altermanager-freshdesk-json-git/alertmanager-freshdesk-webhook/
RUN go get -d -v

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/alertmanager-freshdesk-webhook



FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/bin/alertmanager-freshdesk-webhook /go/bin/alertmanager-freshdesk-webhook

ENV LISTEN_ADDRESS=0.0.0.0:9095
EXPOSE 9095
USER appuser
ENTRYPOINT ["/go/bin/alertmanager-freshdesk-webhook"]
