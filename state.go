package main

import (
	"net/http"
	"sync"
	"time"
)

type state struct {
	sync.RWMutex
	client *http.Client
}

var proxyStateInstance state

func GetProxyStateInstance() *state {
	tr := &http.Transport{
		MaxIdleConnsPerHost: 1024,
		TLSHandshakeTimeout: 0 * time.Second,
	}
	proxyStateInstance.client = &http.Client{Transport: tr}
	return &proxyStateInstance
}