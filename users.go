package main

import (
	"time"

	"github.com/google/uuid"
	"github.com/korrat/boot-http-server/internal/database"
)

type login struct {
	user

	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type user struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

func loginFromDB(u database.User, token, refreshToken string) login {
	return login{
		user:         userFromDB(u),
		Token:        token,
		RefreshToken: refreshToken,
	}
}

func userFromDB(u database.User) user {
	return user{
		ID:          u.ID,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		Email:       u.Email,
		IsChirpyRed: u.IsChirpyRed,
	}
}
