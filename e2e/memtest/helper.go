package main

import (
	"io"
	"log"
	"net/http"
	"os/exec"
)

func wget(addr string) string {
	resp, err := http.Get(addr)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(body)
}

func printOpenedConn() {
	out, err := exec.Command(
		"bash",
		"-c",
		"lsof -nP -i TCP@localhost:8443 -sTCP:ESTABLISHED | grep -e '->127.0.0.1:8443' | wc -l",
	).Output()

	if err != nil {
		panic(err)
	}
	log.Printf("lsof opened conns: %s", string(out))
}
