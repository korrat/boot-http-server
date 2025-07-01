package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/korrat/boot-http-server/internal/database"
)

type apiConfig struct {
	db *database.Queries

	fileserverHits atomic.Int32

	platform string
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
		if cfg.platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		cfg.fileserverHits.Store(0)
		cfg.db.ClearUsers(r.Context())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func (cfg *apiConfig) handlerUsersCreate(res http.ResponseWriter, req *http.Request) {
	var params struct{ Email string }
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(req.Context(), params.Email)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(res)
	if err := enc.Encode(struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}

}

func (cfg *apiConfig) handlerChirpsCreate(res http.ResponseWriter, req *http.Request) {
	var params struct {
		Body   string    `json:"body"`
		UserId uuid.UUID `json:"user_id"`
	}
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	cleaned, err := validateChirpBody(params.Body)
	if err != nil {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusBadRequest)
		enc := json.NewEncoder(res)
		if err := enc.Encode(struct {
			Error string `json:"error"`
		}{
			Error: err.Error(),
		}); err != nil {
			log.Printf("Error encoding response: %s", err)
			return
		}
		return
	}

	chirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: params.UserId,
	})
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(res)
	if err := enc.Encode(chirpFromDB(chirp)); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) handlerChirpsGet(res http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.db.GetChirps(req.Context())
	if err != nil {
		log.Printf("Error creating chirp: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	var data []chirp
	for _, c := range chirps {
		data = append(data, chirpFromDB(c))
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(data); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func readiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("error opening database: %v", err)
	}

	platform := os.Getenv("PLATFORM")

	apiCfg := apiConfig{db: database.New(db), platform: platform}
	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	mux.Handle("GET /admin/metrics", apiCfg.handlerMetricsGet())
	mux.Handle("GET /api/chirps", http.HandlerFunc(apiCfg.handlerChirpsGet))
	mux.Handle("GET /api/healthz", http.HandlerFunc(readiness))

	mux.Handle("POST /admin/reset", apiCfg.handlerMetricsReset())
	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.handlerUsersCreate))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.handlerChirpsCreate))

	srv := http.Server{Addr: ":8080", Handler: mux}
	log.Println("starting chirpy server on", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln("error from server:", err)
	}
}
