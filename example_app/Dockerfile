# Compile Init
FROM golang:1.11 as builder

COPY . $GOPATH/src/mypackage/myapp
WORKDIR $GOPATH/src/mypackage/myapp
RUN go get -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -o /go/bin/example-app . 


FROM alpine

COPY --from=builder /go/bin/example-app /go/bin/example-app
COPY --from=builder /go/src/mypackage/myapp/ /go/bin/
EXPOSE 8080
ENTRYPOINT ["/go/bin/example-app"]
