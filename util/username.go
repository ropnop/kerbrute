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

func FormatComboLine(combo string) (username string, password string, err error) {
	parts := strings.SplitN(combo, ":", 2)
	if len(parts) == 0 {
		err = errors.New("Bad format - missing ':'")
		return "", "", err
	}
	user, err := FormatUsername(parts[0])
	if err != nil {
		return "", "", err
	}
	pass := strings.Join(parts[1:], "")
	if pass == "" {
		err = errors.New("Password is blank")
		return "", "", err
	}
	return user, pass, err

}
