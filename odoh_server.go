// The MIT License
//
// Copyright (c) 2019 Apple, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/chris-wood/odoh"
	"github.com/cisco/go-hpke"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	// HPKE constants
	kemID  = hpke.DHKEM_X25519
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_AESGCM128

	// HTTP constants. Fill in your proxy and target here.
	proxyURI          = "https://dnstarget.example.net"
	targetURI         = "https://dnsproxy.example.net"
	queryEndpoint     = "/dns-query"
	proxyEndpoint     = "/proxy"
	healthEndpoint    = "/health"
	publicKeyEndpoint = "/pk"

	// WebPvD configuration. Fill in your values here.
	webPvDString = `"{ "identifier" : "github.com", "expires" : "2019-08-23T06:00:00Z", "prefixes" : [ ], "dnsZones" : [ "odoh.example.net" ] }"`
)

var (
	// DNS constants. Fill in a DNS server to forward to here.
	nameServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
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
	fmt.Fprintf(w, "Proxy endpoint: https://%s:%s/%s{?targethost,targetpath}\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[proxyEndpoint])
	fmt.Fprintf(w, "Target endpoint: https://%s:%s/%s{?dns}\n", r.URL.Hostname(), r.URL.Port(), s.endpoints[queryEndpoint])
	fmt.Fprint(w, "----------------\n")
}

func (s odohServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)
	fmt.Fprint(w, "ok")
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	var seed []byte
	if seedHex := os.Getenv("SEED_SECRET_KEY"); seedHex != "" {
		log.Printf("Using Secret Key Seed : [%v]", seedHex)
		var err error
		seed, err = hex.DecodeString(seedHex)
		if err != nil {
			log.Printf("Unable to decode hex string to byte array. %v", err)
		}
	} else {
		seed = make([]byte, 16)
		rand.Read(seed)
		log.Printf("Generating a random seed for KeyPair")
	}

	var serverName string
	if serverNameSetting := os.Getenv("TARGET_INSTANCE_NAME"); serverNameSetting != "" {
		serverName = serverNameSetting
	} else {
		serverName = "server_target_localhost"
	}
	log.Printf("Setting Server Name as %v", serverName)

	var experimentID string
	if experimentID := os.Getenv("EXPERIMENT_ID"); experimentID == "" {
		experimentID = "EXP_LOCAL"
	}

	privateKey, err := odoh.DeriveFixedKeyPairFromSeed(kemID, kdfID, aeadID, seed)
	if err != nil {
		log.Fatal("Failed to create a private key. Exiting now.")
	}

	endpoints := make(map[string]string)
	endpoints["Target"] = queryEndpoint
	endpoints["Proxy"] = proxyEndpoint
	endpoints["Health"] = healthEndpoint
	endpoints["PublicKey"] = publicKeyEndpoint

	resolversInUse := make([]*targetResolver, len(nameServers))

	for index := 0; index < len(nameServers); index++ {
		resolver := &targetResolver{
			timeout: 2500 * time.Millisecond,
			nameserver: nameServers[index],
		}
		resolversInUse[index] = resolver
	}

	target := &targetServer{
		verbose:            true,
		resolver:           resolversInUse,
		odohKeyPair:        privateKey,
		telemetryClient:    getTelemetryInstance(),
		serverInstanceName: serverName,
		experimentId:       experimentID,
	}

	proxy := &proxyServer{
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1024,
				TLSHandshakeTimeout: 0 * time.Second,
			},
		},
	}

	server := odohServer{
		endpoints: endpoints,
		target:    target,
		DOHURI:    fmt.Sprintf("%s/%s", targetURI, queryEndpoint),
	}

	http.HandleFunc(queryEndpoint, target.queryHandler)
	http.HandleFunc(proxyEndpoint, proxy.proxyHandler)
	http.HandleFunc(healthEndpoint, server.healthCheckHandler)
	http.HandleFunc(publicKeyEndpoint, target.publicKeyEndpointHandler)
	http.HandleFunc("/", server.indexHandler)

	log.Printf("Listening on port %v\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
