package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","path":"%s","method":"%s","body_size":%d}`,
			r.URL.Path, r.Method, len(body))
	})

	log.Println("Demo upstream listening on :9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("upstream error: %v", err)
	}
}
