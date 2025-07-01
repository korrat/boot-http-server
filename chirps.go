package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/korrat/boot-http-server/internal/database"
)

var badWordsRegex = regexp.MustCompile("(?i)(kerfuffle|sharbert|fornax)")

type chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func chirpFromDB(c database.Chirp) chirp {
	return chirp{
		ID:        c.ID,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Body:      c.Body,
		UserID:    c.UserID,
	}
}

func validateChirpBody(chirp string) (string, error) {
	if len(chirp) > 140 {
		return "", fmt.Errorf("Chirp is too long")
	}

	return badWordsRegex.ReplaceAllLiteralString(chirp, "****"), nil
}
