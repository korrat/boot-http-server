package auth_test

import (
	"github.com/korrat/boot-http-server/internal/auth"
	"testing"
)

func TestHashPassword(t *testing.T) {
	t.Skip()

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		password string
		want     string
		wantErr  bool
	}{
		{
			password: "",
			want:     "$2a$10$5LbsjC3lGF8NIjNzGH15zuzQEVY7AICXg1rgST4KT.VdBH8fqTy3.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := auth.HashPassword(tt.password)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("HashPassword() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("HashPassword() succeeded unexpectedly")
			}
			if tt.want != got {
				t.Errorf("HashPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
