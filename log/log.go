package log

import (
	"os"

	"github.com/op/go-logging"
)

// type Logger struct {
// 	*logging.Logger
// }

func NewLogger() *logging.Logger {
	log := logging.MustGetLogger("kerbrute")
	format := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	backend := logging.NewLogBackend(os.Stderr, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	logging.SetBackend(backendFormatter)
	return log
}
