package util

import (
	"os"

	"github.com/op/go-logging"
)

type Logger struct {
	Log *logging.Logger
}

func NewLogger(verbose bool) Logger {
	log := logging.MustGetLogger("kerbrute")
	format := logging.MustStringFormatter(
		`%{color}%{time:2006/01/02 15:04:05} ▶  %{message}%{color:reset}`,
	)
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)
	if verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}
	return Logger{log}
}
