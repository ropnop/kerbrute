package cmd

import (
	"context"
	"os"

	"github.com/ropnop/kerbrute/session"
	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var (
	domain           string
	domainController string
	logFileName      string
	verbose          bool
	safe             bool
	delay            int
	threads          int
	stopOnSuccess    bool
	userAsPass       = false
	logger           util.Logger
	kSession         session.KerbruteSession

	// Used for multithreading
	ctx, cancel = context.WithCancel(context.Background())
	counter     int32
	successes   int32
)

func setupSession(cmd *cobra.Command, args []string) {
	logger = util.NewLogger(verbose, logFileName)
	if domain == "" {
		logger.Log.Error("No domain specified. You must specify a full domain")
		os.Exit(1)
	}
	var err error
	kSession, err = session.NewKerbruteSession(domain, domainController, verbose, safe)
	if err != nil {
		logger.Log.Error(err.Error())
		os.Exit(1)
	}
	logger.Log.Info("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		logger.Log.Infof("\t%s\n", v)
	}
	if delay != 0 {
		logger.Log.Infof("Delay set. Using single thread and delaying %dms between attempts\n", delay)
	}
}
