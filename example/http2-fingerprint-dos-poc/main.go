package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"os"
	"time"

	"github.com/wi1dcard/fingerproxy"
	"golang.org/x/net/http2"
)

/*
This program demonstrates how to craft a large HTTP2 fingerprint.

The HTTP2 fingerprint format suggested by Akamai is: "S[;]|WU|P[,]#|PS[,]", where
all priority frames in HTTP2 request are recorded and shown in the third part. This
gives attackers a chance to manually create a request with many priority frames
and generate a large HTTP2 fingerprint. This program is to reproduce that.

By design, Fingerproxy will send this large fingerprint through HTTP request headers
to downstream. That might cause the backend server run out of resource while
processing this large header. Therefore, a limit of max number of priority frames is
introduced. With Fingerproxy binary, you can set the limit in CLI flag "-max-h2-priority-frames".

See below example.
*/

const numberOfPriorityFrames = 500

func main() {
	// fingerproxy no limit, header is long:
	// url := launchFingerproxy()

	// try with the limit:
	url := launchFingerproxyWithPriorityFramesLimit()

	// reproducable with other http2 fingerprinting services:
	// url := "https://tls.browserleaks.com/http2"
	// url := "https://tls.peet.ws/api/clean"

	time.Sleep(1 * time.Second)
	sendRequest(url)
}

func launchFingerproxy() (url string) {
	os.Args = []string{os.Args[0], "-listen-addr=localhost:8443", "-forward-url=https://httpbin.org"}
	go fingerproxy.Run()
	return "https://localhost:8443/headers"
}

func launchFingerproxyWithPriorityFramesLimit() (url string) {
	os.Args = []string{os.Args[0], "-listen-addr=localhost:8443", "-forward-url=https://httpbin.org", "-max-h2-priority-frames=20"}
	go fingerproxy.Run()
	return "https://localhost:8443/headers"
}

func sendRequest(url string) {
	req, _ := http.NewRequest("GET", url, nil)

	trace := &httptrace.ClientTrace{
		GotConn: gotConn,
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	c := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := c.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	if b, err := io.ReadAll(resp.Body); err != nil {
		log.Fatal(err)
	} else {
		log.Println(string(b))
	}
}

func gotConn(info httptrace.GotConnInfo) {
	bw := bufio.NewWriter(info.Conn)
	br := bufio.NewReader(info.Conn)
	fr := http2.NewFramer(bw, br)
	for i := 1; i <= numberOfPriorityFrames; i++ {
		err := fr.WritePriority(uint32(i), http2.PriorityParam{Weight: 110})
		if err != nil {
			log.Fatal(err)
		}
	}
	bw.Flush()
}
