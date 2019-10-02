package main

import (
	"fmt"
	"log"
	"encoding/hex"
	"net/http"
	"time"
	"github.com/chris-wood/odoh"
	"github.com/bifurcation/hpke"
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

const (
	kemID = hpke.DHKEM_X25519
	kdfID = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AESGCM128
	pkRm = "85023a65b2c505cd2e92e2c427ef69df8aa8d0f18081a8090b159aafa6001413"
	skRm = "c2dd775b50210ad308e43b3dd45c5eabc085df1398c8dce6501598c1575dbd21"
)

func main() {
	publicKeyBytes, err := hex.DecodeString(pkRm)
	if err != nil {
		log.Fatal("Failed to decode public key. Exiting now.")
	}

	secretKeyBytes, err := hex.DecodeString(skRm)
	if err != nil {
		log.Fatal("Failed to decode private key. Exiting now.")
	}

	privateKey, err  := odoh.CreatePrivateKeyDeterministic(kemID, kdfID, aeadID, publicKeyBytes, secretKeyBytes)
	if err != nil {
		log.Fatal("Failed to create a private key. Exiting now.")
	}

	server := odoh.Server{
		Verbose:    true,
		Timeout:    2500 * time.Millisecond,
		Nameserver: "1.1.1.1:53",
		PrivateKey: privateKey,
	}

	http.HandleFunc("/dns-query/proxy", server.ProxyHandler)
	http.HandleFunc("/dns-query", server.QueryHandler)
	http.HandleFunc("/health", healthCheckHandler)
	http.HandleFunc("/", handle)

	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
