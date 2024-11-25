FROM golang:latest
WORKDIR /go/src/app
COPY . .
RUN go build -o modbus-server .
EXPOSE 502/tcp
CMD ["./modbus-server"]