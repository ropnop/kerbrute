package util

import (
	"runtime"
	"time"
)

var (
	Version   = "dev"
	GitCommit = "n/a"
	BuildDate = time.Now().Format("01/02/06")
	GoVersion = runtime.Version()
	Author    = "Ronnie Flathers @ropnop"
)
