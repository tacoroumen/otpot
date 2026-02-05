# Use the official Golang image as the base image
FROM golang:1.26rc2
WORKDIR /go/src/app
COPY . .
RUN go build -o coap-server .
EXPOSE 5683/udp
CMD ["./coap-server"]