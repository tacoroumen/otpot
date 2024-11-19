# Use the official Golang image as the base image
FROM golang:latest


# Set the working directory inside the container
WORKDIR /go/src/app

# Copy the local package files to the container's workspace
COPY . .

# Build the Go application
RUN go build -o modbus-server .

# Expose port 502 to the outside world
EXPOSE 502/tcp

# Command to run the executable
CMD ["./modbus-server"]