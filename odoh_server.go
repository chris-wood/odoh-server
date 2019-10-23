package main

import (
	"fmt"
	"github.com/bifurcation/hpke"
	"github.com/chris-wood/odoh"
	"log"
	"net/http"
	"time"
)

const (
	// HPKE constants
	kemID  = hpke.DHKEM_X25519
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AESGCM128
	// publicKeyBytes = "85023a65b2c505cd2e92e2c427ef69df8aa8d0f18081a8090b159aafa6001413"
	// skRm           = "c2dd775b50210ad308e43b3dd45c5eabc085df1398c8dce6501598c1575dbd21"

	// DNS constants
	nameServer = "1.1.1.1:53"

	// HTTP constants
	proxyURI       = "https://odoh-proxy-dot-odoh-254517.appspot.com"
	targetURI      = "https://odoh-target-dot-odoh-254517.appspot.com"
	queryEndpoint = "/dns-query"
	healthEndpoint = "/health"

	// WebPvD configuration
	webPvDString = `"{ "identifier" : "github.com", "expires" : "2019-08-23T06:00:00Z", "prefixes" : [ ], "dnsZones" : [ "odoh.example.com" ] }"`
)

type odohServer struct {
	endpoints map[string]string
	Verbose   bool
	target    *targetServer
	DOHURI    string
}

func (s odohServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ODOH service\n")
	fmt.Fprint(w, "----------------\n")
	fmt.Fprintf(w, "Proxy endpoint: https://%s:%s/%s{?targethost,targetpath}\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[queryEndpoint])
	fmt.Fprintf(w, "Target endpoint: https://%s:%s/%s{?dns}\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[queryEndpoint])
	fmt.Fprint(w, "----------------\n")
}

func (s odohServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
}

func main() {
	privateKey, err := odoh.CreatePrivateKey(kemID, kdfID, aeadID)
	if err != nil {
		log.Fatal("Failed to create a private key. Exiting now.")
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = queryEndpoint
	endpoints["Health"] = healthEndpoint

	target := &targetServer{
		verbose: true,
		resolver: &targetResolver{
			timeout:    2500 * time.Millisecond,
			nameserver: nameServer,
		},
		privateKey: privateKey,
	}

	server := odohServer{
		endpoints: endpoints,
		target:    target,
		DOHURI:    fmt.Sprintf("%s/%s", targetURI, queryEndpoint),
	}

	http.HandleFunc(queryEndpoint, target.queryHandler)
	http.HandleFunc(healthEndpoint, server.healthCheckHandler)
	http.HandleFunc("/", server.indexHandler)

	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
