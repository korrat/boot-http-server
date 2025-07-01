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
	"golang.org/x/crypto/bcrypt"

	"github.com/korrat/boot-http-server/internal/auth"
	"github.com/korrat/boot-http-server/internal/database"
)

type apiConfig struct {
	db *database.Queries

	fileserverHits atomic.Int32

	platform    string
	tokenSecret string
}

func (cfg *apiConfig) handlerLogin(res http.ResponseWriter, req *http.Request) {
	var params struct {
		Email    string
		Password string
		Expiry   int `json:"expires_in_seconds"`
	}

	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.GetUserByEmail(req.Context(), params.Email)
	if err == sql.ErrNoRows {
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("incorrect email or password"))
		return
	}

	if err != nil {
		log.Printf("Error fetching user: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !user.HashedPassword.Valid {
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("incorrect email or password"))
		return
	}

	if err := auth.CheckPasswordHash(params.Password, user.HashedPassword.String); err == bcrypt.ErrMismatchedHashAndPassword {
		res.WriteHeader(http.StatusUnauthorized)
		res.Write([]byte("incorrect email or password"))
		return
	} else if err != nil {
		log.Printf("Error hashing password: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if params.Expiry == 0 || 3600 < params.Expiry {
		// Default & clamp expiry to one hour
		params.Expiry = 3600
	}

	token, err := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Duration(params.Expiry)*time.Second)
	if err != nil {
		log.Printf("Error creating JWT token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
	}{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     token,
	}); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}

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

func (cfg *apiConfig) handlerUserCreate(res http.ResponseWriter, req *http.Request) {
	var params struct {
		Email    string
		Password string
	}

	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: sql.NullString{String: hashedPassword, Valid: true},
	})
	if err != nil {
		log.Printf("Error creating user: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusCreated)
	enc := json.NewEncoder(res)
	if err := enc.Encode(userFromDB(user)); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}

}

func (cfg *apiConfig) handlerChirpCreate(res http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.tokenSecret)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var params struct {
		Body string `json:"body"`
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
		UserID: userID,
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

func (cfg *apiConfig) handlerChirpGet(res http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		log.Printf("Invalid chirp ID: %v", err)
		res.WriteHeader(http.StatusBadRequest)
		return
	}

	chirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err == sql.ErrNoRows {
		res.WriteHeader(http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("Error loading chirps: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(chirpFromDB(chirp)); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) handlerChirpsGet(res http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.db.GetChirps(req.Context())
	if err != nil {
		log.Printf("Error loading chirps: %v", err)
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
	tokenSecret := os.Getenv("TOKEN_SECRET")

	apiCfg := apiConfig{
		db: database.New(db),

		platform:    platform,
		tokenSecret: tokenSecret,
	}
	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	mux.Handle("GET /admin/metrics", apiCfg.handlerMetricsGet())
	mux.Handle("GET /api/chirps", http.HandlerFunc(apiCfg.handlerChirpsGet))
	mux.Handle("GET /api/chirps/{chirpID}", http.HandlerFunc(apiCfg.handlerChirpGet))
	mux.Handle("GET /api/healthz", http.HandlerFunc(readiness))

	mux.Handle("POST /admin/reset", apiCfg.handlerMetricsReset())
	mux.Handle("POST /api/login", http.HandlerFunc(apiCfg.handlerLogin))
	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.handlerUserCreate))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.handlerChirpCreate))

	srv := http.Server{Addr: ":8080", Handler: mux}
	log.Println("starting chirpy server on", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln("error from server:", err)
	}
}
