package auth_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/korrat/boot-http-server/internal/auth"
)

func TestJWTRoundtrip(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration

		wantCreationErr   bool
		wantValidationErr bool
	}{
		{
			name:        "Successful roundtrip",
			userID:      uuid.New(),
			tokenSecret: "very secret string",
			expiresIn:   24 * time.Hour,
		},
		{
			name:        "Empty key",
			userID:      uuid.New(),
			tokenSecret: "",
			expiresIn:   24 * time.Hour,
		},

		{
			name:        "Expired token",
			userID:      uuid.New(),
			tokenSecret: "very secret string",
			expiresIn:   0,

			wantValidationErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, gotCreationErr := auth.MakeJWT(tt.userID, tt.tokenSecret, tt.expiresIn)
			if gotCreationErr != nil {
				if !tt.wantCreationErr {
					t.Errorf("ValidateJWT() failed: %v", gotCreationErr)
				}
				return
			}
			if tt.wantCreationErr {
				t.Fatal("MakeJWT() succeeded unexpectedly")
			}

			got, gotValidationErr := auth.ValidateJWT(token, tt.tokenSecret)
			if gotValidationErr != nil {
				if !tt.wantValidationErr {
					t.Errorf("ValidateJWT() failed: %v", gotValidationErr)
				}
				return
			}
			if tt.wantValidationErr {
				t.Fatal("ValidateJWT() succeeded unexpectedly")
			}

			if tt.userID != got {
				t.Errorf("JWT roundtrip failed: got %v, want %v", got, tt.userID)
			}
		})
	}
}
