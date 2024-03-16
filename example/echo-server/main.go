package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
)

func main() {
	flagListenAddr := flag.String(
		"listen-addr",
		"localhost:8443",
		"Listening address",
	)
	flagCertFilename := flag.String(
		"cert-filename",
		"tls.crt",
		"TLS certificate filename",
	)
	flagKeyFilename := flag.String(
		"certkey-filename",
		"tls.key",
		"TLS certificate key file name",
	)
	flagVerboseLogs := flag.Bool("verbose", false, "Enable verbose logs")
	flag.Parse()

	// load TLS certs
	tlsConf := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	if tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}

	// enable verbose logs in fingerprint algorithms
	fingerprint.VerboseLogs = *flagVerboseLogs

	// shutdown on interrupt signal (ctrl + c)
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)
	server.VerboseLogs = *flagVerboseLogs

	// listen and serve
	log.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}

func echoServer(w http.ResponseWriter, req *http.Request) {
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		http.Error(w, "failed to get context", http.StatusInternalServerError)
		return
	}

	ja3, err := fingerprint.JA3Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ja4, err := fingerprint.JA4Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http2, err := fingerprint.HTTP2Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.URL.Path == "/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&map[string]any{
			"user-agent":  req.UserAgent(),
			"clienthello": fmt.Sprintf("%x", data.ClientHelloRecord),
			"ja3":         ja3,
			"ja4":         ja4,
			"http2":       http2,
		})
	} else {
		fmt.Fprintf(w, "User-Agent: %s\n", req.UserAgent())
		fmt.Fprintf(w, "TLS ClientHello Record: %x\n", data.ClientHelloRecord)
		fmt.Fprintf(w, "JA3 fingerprint: %s\n", ja3)
		fmt.Fprintf(w, "JA4 fingerprint: %s\n", ja4)
		fmt.Fprintf(w, "HTTP2 fingerprint: %s\n", http2)
	}
}
