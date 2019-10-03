package main

import (
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/hpke"
	"github.com/chris-wood/odoh"
	"log"
	"net/http"
	"time"
)

const (
	// HPKE constants
	kemID          = hpke.DHKEM_X25519
	kdfID          = hpke.KDF_HKDF_SHA256
	aeadID         = hpke.AEAD_AESGCM128
	publicKeyBytes = "85023a65b2c505cd2e92e2c427ef69df8aa8d0f18081a8090b159aafa6001413"
	skRm           = "c2dd775b50210ad308e43b3dd45c5eabc085df1398c8dce6501598c1575dbd21"

	// DNS constants
	nameServer = "1.1.1.1:53"

	// HTTP constants
	proxyEndpoint  = "/dns-query/proxy"
	targetEndpoint = "/dns-query"
	healthEndpoint = "/health"
)

type Server struct {
	odohServer odoh.Server
	endpoints  map[string]string
}

func (s Server) handle(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ODOH service")
	fmt.Fprint(w, "----------------")
	fmt.Fprintf(w, "Proxy endpoint: https://%s:%s/%s\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[proxyEndpoint])
	fmt.Fprintf(w, "Target endpoint: https://%s:%s/%s\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[targetEndpoint])
	fmt.Fprint(w, "----------------")

	fmt.Fprint(w, "Tail logs")

}

func (s Server) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
}

func main() {
	publicKeyBytes, err := hex.DecodeString(publicKeyBytes)
	if err != nil {
		log.Fatal("Failed to decode public key. Exiting now.")
	}

	secretKeyBytes, err := hex.DecodeString(skRm)
	if err != nil {
		log.Fatal("Failed to decode private key. Exiting now.")
	}

	privateKey, err := odoh.CreatePrivateKeyDeterministic(kemID, kdfID, aeadID, publicKeyBytes, secretKeyBytes)
	if err != nil {
		log.Fatal("Failed to create a private key. Exiting now.")
	}

	// TODO(caw): turn this into an ODOH object that collects rolling logs as formatted strings
	var buf bytes.Buffer
	logger := log.New(&buf, "ODOH: ", log.LstdFlags)

	odohServer := odoh.Server{
		Verbose:    true,
		Logger:     logger,
		Timeout:    2500 * time.Millisecond,
		Nameserver: nameServer,
		PrivateKey: privateKey,
	}

	endpoints := make(map[string]string)
	endpoints["Proxy"] = proxyEndpoint
	endpoints["Target"] = targetEndpoint
	endpoints["Health"] = healthEndpoint

	server := Server{
		odohServer: odohServer,
		endpoints:  endpoints,
	}

	http.HandleFunc(proxyEndpoint, server.odohServer.ProxyHandler)
	http.HandleFunc(targetEndpoint, server.odohServer.QueryHandler)
	http.HandleFunc(healthEndpoint, server.healthCheckHandler)
	http.HandleFunc("/", server.handle)

	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
