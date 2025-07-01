package auth

import (
	"fmt"
	"net/http"
	"strings"
)

func GetAPIKey(headers http.Header) (string, error) {
	header := headers.Get("Authorization")
	if header == "" {
		return "", fmt.Errorf("no authorization header")
	}

	token, ok := strings.CutPrefix(header, "ApiKey ")
	if !ok {
		return "", fmt.Errorf("unexpected format for authorization header")
	}

	return token, nil
}
