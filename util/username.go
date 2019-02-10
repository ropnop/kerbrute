package util

import (
	"errors"
	"strings"
)

func FormatUsername(username string) (user string, err error) {
	if username == "" {
		return "", errors.New("Bad username: blank")
	}
	parts := strings.Split(username, "@")
	if len(parts) > 2 {
		return "", errors.New("Bad username: too many @ signs")
	}
	return parts[0], nil
}
