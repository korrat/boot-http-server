package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
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
	polkaKey    string
	tokenSecret string
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
		log.Printf("Error loading chirp: %v", err)
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

func (cfg *apiConfig) handlerChirpDelete(res http.ResponseWriter, req *http.Request) {
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

	if chirp.UserID != userID {
		res.WriteHeader(http.StatusForbidden)
		return
	}

	if err := cfg.db.DeleteChirp(req.Context(), chirpID); err != nil {
		log.Printf("Error deleting chirp: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlerChirpsGet(res http.ResponseWriter, req *http.Request) {
	sort_desc := false
	if req.URL.Query().Has("sort") {
		switch req.URL.Query().Get("sort") {
		case "asc":
			break
		case "desc":
			sort_desc = true

		default:
			res.WriteHeader(http.StatusBadRequest)
			return
		}

	}

	var chirps []database.Chirp
	var err error
	if req.URL.Query().Has("author_id") {
		id, err := uuid.Parse(req.URL.Query().Get("author_id"))
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			return
		}

		chirps, err = cfg.db.GetChirpsBy(req.Context(), id)
	} else {
		chirps, err = cfg.db.GetChirps(req.Context())
	}
	if err != nil {
		log.Printf("Error loading chirps: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	var data []chirp
	for _, c := range chirps {
		data = append(data, chirpFromDB(c))
	}

	if sort_desc {
		slices.Reverse(data)
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(data); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) handlerLogin(res http.ResponseWriter, req *http.Request) {
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

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("Error creating refresh token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = cfg.db.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	})
	if err != nil {
		log.Printf("Error saving refresh token to DB: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.tokenSecret, time.Hour)
	if err != nil {
		log.Printf("Error creating JWT token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(loginFromDB(user, token, refreshToken)); err != nil {
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

func (cfg *apiConfig) handlerRefresh(res http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	userID, err := cfg.db.GetUserForRefreshToken(req.Context(), refreshToken)
	if err == sql.ErrNoRows {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Error fetching user for refresh token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	token, err := auth.MakeJWT(userID, cfg.tokenSecret, time.Hour)
	if err != nil {
		log.Printf("Error creating JWT token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(struct {
		Token string `json:"token"`
	}{
		Token: token,
	}); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) handlerRevoke(res http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := cfg.db.RevokeRefreshToken(req.Context(), refreshToken); err == sql.ErrNoRows {
		res.WriteHeader(http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Error revoking refresh token: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusNoContent)
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

func (cfg *apiConfig) handlerUserUpdate(res http.ResponseWriter, req *http.Request) {
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

	user, err := cfg.db.UpdateUser(req.Context(), database.UpdateUserParams{
		Email:          params.Email,
		HashedPassword: sql.NullString{String: hashedPassword, Valid: true},
		ID:             userID,
	})
	if err != nil {
		log.Printf("Error updating user: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(res)
	if err := enc.Encode(userFromDB(user)); err != nil {
		log.Printf("Error encoding response: %s", err)
		return
	}
}

func (cfg *apiConfig) handlerWebhooks(res http.ResponseWriter, req *http.Request) {
	key, err := auth.GetAPIKey(req.Header)
	if err != nil || key != cfg.polkaKey {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}

	var params struct {
		Event string
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		}
	}

	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&params); err != nil {
		log.Printf("Error decoding parameters: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	if params.Event != "user.upgraded" {
		res.WriteHeader(http.StatusNoContent)
		return
	}

	numRows, err := cfg.db.UpgradeUserToRed(req.Context(), params.Data.UserID)
	if err != nil {
		log.Printf("Error upgrading user to Chirpy Red: %v", err)
		res.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch numRows {
	case 0:
		// user not found
		res.WriteHeader(http.StatusNotFound)
	case 1:
		res.WriteHeader(http.StatusNoContent)

	default:
		log.Panicf("unexpected upgrade result, expected at most one affected row, got %v", numRows)
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
	polkaKey := os.Getenv("POLKA_KEY")

	apiCfg := apiConfig{
		db: database.New(db),

		platform:    platform,
		polkaKey:    polkaKey,
		tokenSecret: tokenSecret,
	}
	mux := http.NewServeMux()
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	mux.Handle("DELETE /api/chirps/{chirpID}", http.HandlerFunc(apiCfg.handlerChirpDelete))

	mux.Handle("GET /admin/metrics", apiCfg.handlerMetricsGet())
	mux.Handle("GET /api/chirps", http.HandlerFunc(apiCfg.handlerChirpsGet))
	mux.Handle("GET /api/chirps/{chirpID}", http.HandlerFunc(apiCfg.handlerChirpGet))
	mux.Handle("GET /api/healthz", http.HandlerFunc(readiness))

	mux.Handle("POST /admin/reset", apiCfg.handlerMetricsReset())
	mux.Handle("POST /api/login", http.HandlerFunc(apiCfg.handlerLogin))
	mux.Handle("POST /api/users", http.HandlerFunc(apiCfg.handlerUserCreate))
	mux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.handlerChirpCreate))
	mux.Handle("POST /api/polka/webhooks", http.HandlerFunc(apiCfg.handlerWebhooks))
	mux.Handle("POST /api/refresh", http.HandlerFunc(apiCfg.handlerRefresh))
	mux.Handle("POST /api/revoke", http.HandlerFunc(apiCfg.handlerRevoke))

	mux.Handle("PUT /api/users", http.HandlerFunc(apiCfg.handlerUserUpdate))

	srv := http.Server{Addr: ":8080", Handler: mux}
	log.Println("starting chirpy server on", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln("error from server:", err)
	}
}
