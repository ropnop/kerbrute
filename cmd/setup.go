package cmd

import (
	"context"

	"github.com/ropnop/kerbrute/session"
	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var (
	domain           string
	domainController string
	verbose          bool
	safe             bool
	threads          int
	stopOnSuccess    bool
	logger           util.Logger
	kSession         session.KerbruteSession

	// Used for multithreading
	ctx, cancel = context.WithCancel(context.Background())
	counter     int32
	successes   int32
)

func setupSession(cmd *cobra.Command, args []string) {
	domain, _ = cmd.Flags().GetString("domain")
	domainController, _ = cmd.Flags().GetString("dc")
	verbose, _ = cmd.Flags().GetBool("verbose")
	safe, _ = cmd.Flags().GetBool("safe")
	kSession = session.NewKerbruteSession(domain, domainController, verbose, safe)

	logger = util.NewLogger(verbose)

	logger.Log.Info("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		logger.Log.Infof("\t%s\n", v)
	}
}
