package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) handlerMetricsGet() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	})
}

func (cfg *apiConfig) handlerMetricsReset() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Store(0)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func handlerValidateChirp(res http.ResponseWriter, req *http.Request) {
	type chirp struct {
		Body string
	}

	var c chirp
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&c); err != nil {
		log.Printf("Error decoding parameters: %s", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	var status int
	var data any
	if cleaned, err := validateChirp(c.Body); err == nil {
		status = http.StatusOK
		data = struct {
			Clean string `json:"cleaned_body"`
		}{
			Clean: cleaned,
		}
	} else {
		status = http.StatusBadRequest
		data = struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)
	enc := json.NewEncoder(res)
	if err := enc.Encode(&data); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func readiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	apiCfg := apiConfig{}
	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	mux.Handle("GET /admin/metrics", apiCfg.handlerMetricsGet())
	mux.Handle("GET /api/healthz", http.HandlerFunc(readiness))

	mux.Handle("POST /admin/reset", apiCfg.handlerMetricsReset())
	mux.Handle("POST /api/validate_chirp", http.HandlerFunc(handlerValidateChirp))

	srv := http.Server{Addr: ":8080", Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln("error from server:", err)
	}
}
