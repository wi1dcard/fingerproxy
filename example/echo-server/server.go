package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/wi1dcard/fingerproxy/pkg/metadata"
)

func echoServer(w http.ResponseWriter, req *http.Request) {
	// create logger for this request, it outputs logs with client IP and port as prefix
	logger := log.New(os.Stdout, fmt.Sprintf("[client %s] ", req.RemoteAddr), log.LstdFlags|log.Lmsgprefix)

	// get metadata from request context
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		logger.Printf("failed to get context")
		http.Error(w, "failed to get context", http.StatusInternalServerError)
		return
	}

	// prepare response
	response := &echoResponse{
		log: logger,
		Detail: &detailResponse{
			Metadata:  data,
			UserAgent: req.UserAgent(),
		},
	}

	// calculate and add fingerprints to the response
	if err := response.fingerprintJA3(); err != nil {
		logger.Printf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := response.fingerprintJA4(); err != nil {
		logger.Printf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response.fingerrpintHTTP2()

	// print detail if -verbose is specified in CLI
	if *flagVerbose {
		detail, _ := json.Marshal(response.Detail)
		logger.Printf("detail: %s", detail)
	}

	// send HTTP response
	switch req.URL.Path {
	case "/json":
		w.Header().Set("Content-Type", "application/json")
		response.Detail = nil
		json.NewEncoder(w).Encode(response)

	case "/json/detail":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	default:
		fmt.Fprintf(w, "User-Agent: %s\n", response.Detail.UserAgent)
		fmt.Fprintf(w, "TLS ClientHello Record: %x\n", response.Detail.Metadata.ClientHelloRecord)
		fmt.Fprintf(w, "JA3 fingerprint: %s\n", response.JA3)
		fmt.Fprintf(w, "JA4 fingerprint: %s\n", response.JA4)
		fmt.Fprintf(w, "HTTP2 fingerprint: %s\n", response.HTTP2)
	}
}
