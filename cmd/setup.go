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

	downgrade bool
	hashFileName string

	logger           util.Logger
	kSession         session.KerbruteSession

	// Used for multithreading
	ctx, cancel = context.WithCancel(context.Background())
	counter     int32
	successes   int32
)

func setupSession(cmd *cobra.Command, args []string) {
	logger = util.NewLogger(verbose, logFileName)
	kOptions := session.KerbruteSessionOptions{
		Domain:           domain,
		DomainController: domainController,
		Verbose:          verbose,
		SafeMode:         safe,
		HashFilename:     hashFileName,
		Downgrade: downgrade,
	}
	k, err := session.NewKerbruteSession(kOptions)
	if err != nil {
		logger.Log.Error(err)
		os.Exit(1)
	}
	kSession = k

	logger.Log.Info("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		logger.Log.Infof("\t%s\n", v)
	}
	if delay != 0 {
		logger.Log.Infof("Delay set. Using single thread and delaying %dms between attempts\n", delay)
	}
}
