FROM golang:latest
WORKDIR /go/src/app
COPY . .
RUN go build -o modbus-server .
EXPOSE 8080/tcp
CMD ["./modbus-server"]