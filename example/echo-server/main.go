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

	"github.com/dreadl0ck/tlsx"
	"github.com/wi1dcard/fingerproxy/pkg/debug"
	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/ja3"
	"github.com/wi1dcard/fingerproxy/pkg/ja4"
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
	flagBenchmarkControlGroup := flag.Bool(
		"benchmark-control-group",
		false,
		"Start a golang default TLS server as the control group for benchmarking",
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

	if *flagBenchmarkControlGroup {
		// create golang default https server
		server := &http.Server{
			Addr:      *flagListenAddr,
			Handler:   http.HandlerFunc(echoServer),
			TLSConfig: tlsConf,
		}
		go func() {
			<-ctx.Done()
			server.Shutdown(context.Background())
		}()

		// listen and serve
		log.Printf("server (benchmark control group) listening on %s", *flagListenAddr)
		err := server.ListenAndServeTLS("", "")
		log.Fatal(err)
	} else {
		// create proxyserver
		server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)
		server.VerboseLogs = *flagVerboseLogs

		// start debug server if build tag `debug` is specified
		debug.StartDebugServer()

		// listen and serve
		log.Printf("server listening on %s", *flagListenAddr)
		err := server.ListenAndServe(*flagListenAddr)
		log.Fatal(err)
	}
}

func echoServer(w http.ResponseWriter, req *http.Request) {
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		http.Error(w, "failed to get context", http.StatusInternalServerError)
		return
	}

	_ja3 := &tlsx.ClientHelloBasic{}
	err := _ja3.Unmarshal(data.ClientHelloRecord)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_ja4 := &ja4.JA4Fingerprint{}
	err = _ja4.UnmarshalBytes(data.ClientHelloRecord, 't')
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_http2, err := fingerprint.HTTP2Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.URL.Path == "/json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&map[string]any{
			"user-agent":  req.UserAgent(),
			"clienthello": fmt.Sprintf("%x", data.ClientHelloRecord),
			"ja3":         ja3.DigestHex(_ja3),
			"ja4":         _ja4.String(),
			"http2":       _http2,
			"detail": map[string]any{
				"ja3":      _ja3,
				"ja4":      _ja4,
				"http2":    data.HTTP2Frames,
				"metadata": data,
			},
		})
	} else {
		fmt.Fprintf(w, "User-Agent: %s\n", req.UserAgent())
		fmt.Fprintf(w, "TLS ClientHello Record: %x\n", data.ClientHelloRecord)
		fmt.Fprintf(w, "JA3 fingerprint: %s\n", ja3.DigestHex(_ja3))
		fmt.Fprintf(w, "JA4 fingerprint: %s\n", _ja4.String())
		fmt.Fprintf(w, "HTTP2 fingerprint: %s\n", _http2)
	}
}
