//go:build debug

package debug

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"runtime"
	"runtime/debug"
)

const listenAddr = "localhost:9036"

func StartDebugServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		go debug.FreeOSMemory()
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/mem", func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		fmt.Fprintf(w, "Heap size: %.2f MiB\n", float64(memStats.HeapInuse)/1024/1024)
		fmt.Fprintf(w, "Stack size: %.2f MiB\n", float64(memStats.StackInuse)/1024/1024)
		fmt.Fprintf(w, "Num of goroutines: %d\n", runtime.NumGoroutine())
	})

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	log.Printf("!!! DEBUG SERVER LISTENING ON %s !!!", listenAddr)
	go http.ListenAndServe(listenAddr, mux)
}
