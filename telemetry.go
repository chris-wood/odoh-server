package main

import (
	"context"
	"encoding/json"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"log"
	"net/http"
	"strings"
	"sync"
)

// This RunningTime structure contains the epoch timestamps for the following operations
// 1. Start => Epoch time at which the request is received by the ObliviousDNSHandler
// 2. TargetQueryDecryptionTime => Epoch
type RunningTime struct {
	Start int64
	TargetQueryDecryptionTime int64
	TargetQueryResolutionTime int64
	TargetAnswerEncryptionTime int64
	EndTime int64
}

type Experiment struct {
	RequestID []byte
	Resolver  string
	Timestamp RunningTime
	Status bool
	IngestedFrom string
}

func (e *Experiment) serialize() string {
	exp := &e
	response, err := json.Marshal(exp)
	if err != nil {
		log.Printf("Unable to log the information correctly.")
	}
	return string(response)
}

type telemetry struct {
	sync.RWMutex
	esClient *elasticsearch.Client
	buffer []string
}

const (
	INDEX = "telemetry"
	TYPE = "client_localhost"
)

var telemetryInstance telemetry

func getTelemetryInstance() *telemetry {
	elasticsearchTransport := elasticsearch.Config{
		Addresses: []string {
			"http://localhost:9200",
		},
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1024,
		},
	}
	var err error
	telemetryInstance.esClient, err = elasticsearch.NewClient(elasticsearchTransport)
	if err != nil {
		log.Fatalf("Unable to create an elasticsearch client connection.")
	}
	return &telemetryInstance
}

func (t *telemetry) streamDataToElastic(dataItems []string) {
	var wg sync.WaitGroup
	for index, item := range dataItems {
		wg.Add(1)
		go func(i int, message string) {
			defer wg.Done()
			req := esapi.IndexRequest{
				Index: INDEX,
				Body: strings.NewReader(message),
				Refresh: "true",
			}

			res, err := req.Do(context.Background(), t.esClient)
			if err != nil {
				log.Printf("Unable to send the request to elastic.")
			}
			defer res.Body.Close()
			if res.IsError() {
				log.Printf("[%s] Error Indexing Value [%s]", res.Status(), message)
			} else {
				log.Printf("Successfully Inserted [%s]", message)
			}
		}(index, item)
	}
	wg.Wait()
}