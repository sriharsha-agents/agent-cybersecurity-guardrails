package dashboard

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Store) StartHTTP(addr string) {
	if addr == "" {
		addr = ":8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", s.hStats)
	mux.HandleFunc("/api/events", s.hEvents)
	mux.Handle("/", http.FileServer(http.Dir("dashboard/static")))
	log.Printf("[dashboard] listening on %s", addr)
	go http.ListenAndServe(addr, mux)
}

func (s *Store) hStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(s.GetStats())
}

func (s *Store) hEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(s.GetEvents())
}
