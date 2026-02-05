FROM golang:1.26rc2
WORKDIR /go/src/app
COPY . .
RUN go build -o modbus-server .
EXPOSE 502/tcp
CMD ["./modbus-server"]