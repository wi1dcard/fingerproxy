package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	fingerproxyAddr      = "https://localhost:8443/"
	fingerproxyDebugAddr = "http://localhost:9036/mem"
	fingerproxyGcAddr    = "http://localhost:9036/gc"

	backendListenAddr = "localhost:8000"

	numConcurrentConns = 1000
	sleepBetweenConns  = 1 * time.Millisecond
)

var (
	waitForRequestsToBackend sync.WaitGroup
	waitForRequestsServed    sync.WaitGroup

	doneProfiling    = false
	waitForProfiling = sync.NewCond(&sync.Mutex{})
)

func slowBackend() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		waitForRequestsToBackend.Done()
		waitForProfiling.L.Lock()
		for !doneProfiling {
			waitForProfiling.Wait()
		}
		waitForProfiling.L.Unlock()
		w.WriteHeader(http.StatusOK)

		fmt.Fprint(w, r.Header.Get("X-HTTP2-Fingerprint"))
	})

	server := &http.Server{
		Addr:         backendListenAddr,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  0,
	}

	log.Printf("backend listening on %s", backendListenAddr)
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func main() {
	log.SetOutput(os.Stdout)

	log.Printf("pre-check:")
	fmt.Println(wget(fingerproxyDebugAddr))

	go slowBackend()
	time.Sleep(1 * time.Second) // wait until http server starts

	waitForRequestsToBackend.Add(numConcurrentConns)
	for i := 0; i < numConcurrentConns; i++ {
		go request(i)
		time.Sleep(sleepBetweenConns)
	}

	waitForRequestsToBackend.Wait()

	printOpenedConn()

	log.Printf("opened %d conns:", numConcurrentConns)
	fmt.Println(wget(fingerproxyDebugAddr))

	waitForProfiling.L.Lock()
	doneProfiling = true
	waitForProfiling.L.Unlock()

	waitForRequestsServed.Add(numConcurrentConns)
	waitForProfiling.Broadcast()
	waitForRequestsServed.Wait()

	printOpenedConn()

	log.Printf("conns closed:")
	fmt.Println(wget(fingerproxyDebugAddr))

	log.Printf("after gc:")
	wget(fingerproxyGcAddr)
	fmt.Println(wget(fingerproxyDebugAddr))
}

func request(i int) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		// enable http2
		ForceAttemptHTTP2: true,

		// disable connection pool
		DisableKeepAlives: true,
		MaxIdleConns:      -1,
	}

	req, err := http.NewRequest("GET", fingerproxyAddr, nil)
	if err != nil {
		panic(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic(fmt.Errorf("[%d] response code seems incorrect: %s", i, resp.Status))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if string(body) != "2:0;4:4194304;6:10485760|1073741824|0|a,m,p,s" {
		panic(fmt.Errorf("[%d] response body seems incorrect: %s", i, string(body)))
	}

	waitForRequestsServed.Done()
}
