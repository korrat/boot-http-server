package auth_test

import (
	"net/http"
	"testing"

	"github.com/korrat/boot-http-server/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		headers http.Header
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:    "Empty headers",
			headers: http.Header{},

			wantErr: true,
		},
		{
			name:    "Empty header value",
			headers: http.Header{"Authorization": []string{""}},

			wantErr: true,
		},
		{
			name:    "Wrongly formatted header value",
			headers: http.Header{"Authorization": []string{"some value"}},

			wantErr: true,
		},
		{
			name:    "Correctly formatted header value",
			headers: http.Header{"Authorization": []string{"ApiKey some value"}},

			want: "some value",
		},
		{
			name:    "Correct empty token",
			headers: http.Header{"Authorization": []string{"ApiKey "}},

			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := auth.GetAPIKey(tt.headers)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GetBearerToken() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GetBearerToken() succeeded unexpectedly")
			}
			// TODO: update the condition below to compare got with tt.want.
			if tt.want != got {
				t.Errorf("GetBearerToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
