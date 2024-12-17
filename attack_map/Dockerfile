FROM golang:latest
WORKDIR /go/src/app
COPY . .
RUN go build -o attack_map .
EXPOSE 8080/tcp
CMD ["./attack_map"]