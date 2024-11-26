package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	coap "github.com/plgd-dev/go-coap/v3"
	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
)

func getPath(opts message.Options) string {
	path, err := opts.Path()
	if err != nil {
		log.Printf("cannot get path: %v", err)
		return ""
	}
	return path
}

func sendResponse(cc mux.Conn, token []byte, subded time.Time, obs int64) error {
	m := cc.AcquireMessage(cc.Context())
	defer cc.ReleaseMessage(m)
	m.SetCode(codes.Content)
	m.SetToken(token)
	m.SetBody(bytes.NewReader([]byte(fmt.Sprintf("Been running for %v", time.Since(subded)))))
	m.SetContentFormat(message.TextPlain)
	if obs >= 0 {
		m.SetObserve(uint32(obs))
	}
	return cc.WriteMessage(m)
}

func periodicTransmitter(cc mux.Conn, token []byte) {
	subded := time.Now()

	for obs := int64(2); ; obs++ {
		err := sendResponse(cc, token, subded, obs)
		if err != nil {
			log.Printf("Error on transmitter, stopping: %v", err)
			return
		}
		time.Sleep(time.Second)
	}
}

func main() {
	// Create a logs directory if it doesn't exist
	err := os.MkdirAll("/logs", 0777)
	if err != nil {
		fmt.Printf("Error creating logs directory: %v\n", err)
		return
	}

	// Open the log file
	logFile, err := os.OpenFile("/logs/coap.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer logFile.Close()

	// Set up multi-writer to log to both the terminal and the file
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	log.Print("CoAP server starting on port 5683")

	log.Fatal(coap.ListenAndServe("udp", "0.0.0.0:5683",
		mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
			log.Printf("Got message path=%v: %+v from %v", getPath(r.Options()), r, w.Conn().RemoteAddr())
			obs, err := r.Options().Observe()
			switch {
			case r.Code() == codes.GET && err == nil && obs == 0:
				go periodicTransmitter(w.Conn(), r.Token())
			case r.Code() == codes.GET:
				err := sendResponse(w.Conn(), r.Token(), time.Now(), -1)
				if err != nil {
					log.Printf("Error on transmitter: %v", err)
				}
			}
		})))
}
