package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
)

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s Handling %s\n", r.Method, r.URL.Path)

	if r.Method != "POST" {
		log.Printf("Unsupported method for %s", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	targetName := r.URL.Query().Get("targethost")
	if targetName == "" {
		log.Println("Missing proxy targethost query parameter in POST request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	targetPath := r.URL.Query().Get("targetpath")
	if targetPath == "" {
		log.Println("Missing proxy targetpath query parameter in POST request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Missing proxy message body in POST request")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	req, err := http.NewRequest("POST", "https://" + targetName + targetPath, bytes.NewReader(body))
	if err != nil {
		log.Println("Failed creating target POST request")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", r.Header.Get("Content-Type"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Failed to send proxied message")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.Write(responseBody)
}
