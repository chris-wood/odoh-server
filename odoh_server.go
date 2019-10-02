package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
	"github.com/chris-wood/odoh"
)


func handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	// TODO(caw): dump info about the endpoints instead
	fmt.Fprint(w, "ODOH, try /dns-query instead!")
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
}

func main() {
	timeout := 2500 * time.Millisecond
	server := odoh.Server{
		verbose:    true,
		timeout:    timeout,
		nameserver: "1.1.1.1:53",
	}

	http.HandleFunc("/dns-query/proxy", server.ProxyHandler)
	http.HandleFunc("/dns-query", server.QueryHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.HandleFunc("/", handle)

	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
