package main

import (
	"fmt"
	"regexp"
)

var badWordsRegex = regexp.MustCompile("(?i)(kerfuffle|sharbert|fornax)")

func validateChirp(chirp string) (string, error) {
	if len(chirp) > 140 {
		return "", fmt.Errorf("Chirp is too long")
	}

	return badWordsRegex.ReplaceAllLiteralString(chirp, "****"), nil
}
