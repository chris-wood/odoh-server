package main

import (
	"encoding/base64"
	"io/ioutil"
	"fmt"
	"log"
	"time"
	"net"
	"net/http"
	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
)

type odohServer struct {
	verbose  bool
	upstream *net.UDPAddr
	timeout  time.Duration
	resolver *dnsr.Resolver
}

func (s *odohServer) queryHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		n, t     string
		response dns.Msg
		packed   []byte
		elapsed  time.Duration
	)

	log.Println("Handling /odoh request")

	switch r.Method {
	case "GET":
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			log.Println("missing dns query parameter in GET request")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		n = string(decoded)
		t = "A"
	case "POST":
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}
		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Parse the DNS message
		msg := &dns.Msg{}
		if err := msg.Unpack(body); err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if len(msg.Question) != 1 {
			log.Println("DoH only supports single queries")
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		n = msg.Question[0].Name
		t = dns.Type(msg.Question[0].Qtype).String()
	default:
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// resolve the query
	start := time.Now()
			
	// resolve the query using the internal resolver
	rrs, err := s.resolver.ResolveErr(n, t)
	elapsed = time.Now().Sub(start)
	if err == dnsr.NXDOMAIN {
		err = nil
	}

	if err != nil {
		log.Printf("%s Request for %s [%s] %s\n", r.Method, n, t, err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	for _, rr := range rrs {
		newRR, err := dns.NewRR(rr.String())
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		response.Answer = append(response.Answer, newRR)
	}

	if s.verbose {
		log.Println("Answer: ", response.Answer)
	}

	packed, err = response.Pack()
	if err != nil {
		log.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if s.verbose {
		log.Printf("%s Request for <%s/%s> (%s)\n", r.Method, n, t, elapsed.String())
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(packed)
}

func handle(w http.ResponseWriter, r *http.Request) {
	log.Println("Received / request")
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprint(w, "ODOH!")
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received /health request")
	fmt.Fprint(w, "ok")
}

func main() {
	timeout := 2500*time.Millisecond
	capacity := 1000000
	server := odohServer {
		verbose: true,
		resolver: dnsr.NewWithTimeout(capacity, timeout),
		timeout: timeout,
	}

	http.HandleFunc("/dns-query", server.queryHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.HandleFunc("/", handle)

	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
