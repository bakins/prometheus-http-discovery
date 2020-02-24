package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
)

// based on https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config
type targetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels,omitempty"`
}

func main() {
	targets := []string{"one:8080", "two:8080", "three:8080"}

	handler := func(w http.ResponseWriter, r *http.Request) {
		t := targets[rand.Intn(len(targets))]

		w.Header().Set("Content-Type", "application/json")

		e := json.NewEncoder(w)
		_ = e.Encode([]targetGroup{{Targets: []string{t}}})
	}

	http.HandleFunc("/discover", handler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
