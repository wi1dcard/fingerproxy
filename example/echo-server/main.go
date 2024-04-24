package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/wi1dcard/fingerproxy/pkg/debug"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
)

var (
	flagListenAddr, flagCertFilename, flagKeyFilename *string

	flagBenchmarkControlGroup, flagVerbose, flagQuiet *bool

	tlsConf *tls.Config

	ctx, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
)

func main() {
	parseFlags()

	setupTLSConfig()

	if *flagBenchmarkControlGroup {
		runAsControlGroup()
	} else {
		run()
	}
}

func parseFlags() {
	flagListenAddr = flag.String(
		"listen-addr",
		"localhost:8443",
		"Listening address",
	)
	flagCertFilename = flag.String(
		"cert-filename",
		"tls.crt",
		"TLS certificate filename",
	)
	flagKeyFilename = flag.String(
		"certkey-filename",
		"tls.key",
		"TLS certificate key file name",
	)
	flagBenchmarkControlGroup = flag.Bool(
		"benchmark-control-group",
		false,
		"Start a golang default TLS server as the control group for benchmarking",
	)
	flagVerbose = flag.Bool("verbose", false, "Print fingerprint detail in logs, conflict with -quiet")
	flagQuiet = flag.Bool("quiet", false, "Do not print fingerprints in logs, conflict with -verbose")
	flag.Parse()

	if *flagVerbose && *flagQuiet {
		log.Fatal("-verbose and -quiet cannot be specified at the same time")
	}
}

func setupTLSConfig() {
	tlsConf = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}

	if tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}
}

func runAsControlGroup() {
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
}

func run() {
	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)

	// start debug server if build tag `debug` is specified
	debug.StartDebugServer()

	// listen and serve
	log.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}
