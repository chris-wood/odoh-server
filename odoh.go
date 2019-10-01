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

func (s *odohServer) parseRequestFromGET(r *http.Request) (string, string, uint16, error) {
	encoded := r.URL.Query().Get("dns")
	if encoded == "" {
		return "", "", uint16(0), fmt.Errorf("missing dns query parameter in GET request")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", uint16(0), err
	}

	msg := &dns.Msg{}
	if err := msg.Unpack(decoded); err != nil {
		return "", "", uint16(0), err
	}
	if len(msg.Question) != 1 {
		return "", "", uint16(0), err
	}
	
	return msg.Question[0].Name, dns.Type(msg.Question[0].Qtype).String(), msg.Id, nil
}

func (s *odohServer) parseRequestFromPOST(r *http.Request) (string, string, uint16, error) {
	if r.Header.Get("Content-Type") != "application/dns-message" {
		return "", "", uint16(0), fmt.Errorf("incorrect content type, expected 'application/dns-message', got %s", r.Header.Get("Content-Type"))
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", "", uint16(0), err
	}

	// Parse the DNS message
	msg := &dns.Msg{}
	if err := msg.Unpack(body); err != nil {
		return "", "", uint16(0), err
	}
	if len(msg.Question) != 1 {
		return "", "", uint16(0), err
	}

	if s.verbose {
		log.Printf("%s Unpacked DNS message:\n %s\n", r.Method, msg)
	}

	return msg.Question[0].Name, dns.Type(msg.Question[0].Qtype).String(), msg.Id, nil
}

func (s *odohServer) parseRequest(r *http.Request) (string, string, uint16, error) {
	switch r.Method {
	case "GET":
		return s.parseRequestFromGET(r)
	case "POST":
		return s.parseRequestFromPOST(r)
	default:
		return "", "", uint16(0), fmt.Errorf("unsupported HTTP method")
	}
}

func (s *odohServer) queryHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling /odoh request")

	n, t, id, err := s.parseRequest(r)
	if err != nil {
		log.Println("Failed parsing request:", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	start := time.Now()
			
	if s.verbose {
		log.Printf("%s Resolving: %s %s %d", r.Method, n, t, id)
	}

	queryMessage := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	qtype := dns.TypeAAAA
	if t == "A" {
		qtype = dns.TypeA
	}

	queryMessage.Question[0] = dns.Question{
		Name: dns.Fqdn(n), 
		Qtype: qtype,
		Qclass: uint16(dns.ClassINET),
	}
	queryMessage.Id = dns.Id()
	queryMessage.Rcode = dns.RcodeSuccess
	queryMessage.RecursionDesired = true

	connection := new(dns.Conn)
	if connection.Conn, err = net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second); err != nil {
		log.Println("Failed connecting to 1.1.1.1:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	connection.SetWriteDeadline(time.Now().Add(2 * time.Second))

	if err := connection.WriteMsg(queryMessage); err != nil {
		log.Println("Failed sending query:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response, err := connection.ReadMsg()
	if err != nil {
		log.Println("Failed reading response:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response.Id = id

	elapsed := time.Now().Sub(start)

	// c := new(dns.Client)
	// t := new(dns.Transfer)

	// rrs, err := s.resolver.ResolveErr(n, t)
	// if err == dnsr.NXDOMAIN {
	// 	err = nil
	// }

	// if err != nil {
	// 	log.Printf("%s Request for %s [%s] %d %s\n", r.Method, n, t, id, err.Error())
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }

	// response := dns.Msg {
	// 	MsgHdr: dns.MsgHdr {
	// 		Id: id,
	// 		Response: true,
	// 		Opcode: dns.OpcodeQuery,
	// 		Rcode: dns.RcodeSuccess,
	// 	},
	// }

	// for _, rr := range rrs {
	// 	newRR, err := dns.NewRR(rr.String())
	// 	if err == nil {
	// 		response.Answer = append(response.Answer, newRR)	
	// 	} else {
	// 		log.Println("Failed creating RR from answer set:", err)
	// 	}
	// }

	// if len(response.Answer) == 0 {
	// 	log.Println("Unable to build answer set")
	// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	// 	return
	// }

	packed, err := response.Pack()
	if err != nil {
		log.Println("Failed packing answers:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if s.verbose {
		log.Printf("%s Query: qname='%s' qtype='%s' qid=%d elapsed=%s\n", r.Method, n, t, id, elapsed.String())
		log.Printf("%s Answer: ", r.Method, response.Answer)
		log.Printf("%s Full response: %s\n", r.Method, string(packed))
		log.Printf("%s Raw response: %x\n", r.Method, packed)
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
