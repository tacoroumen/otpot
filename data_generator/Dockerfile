# Use the official Golang image as the base image
FROM golang:latest


# Set the working directory inside the container
WORKDIR /go/src/app

# Copy the local package files to the container's workspace
COPY . .

# Build the Go application
RUN go build -o data_generator .

# Expose port 502 to the outside world
EXPOSE 80

# Command to run the executable
CMD ["./data_generator"]