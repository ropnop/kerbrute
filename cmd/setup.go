package cmd

import (
	"context"

	"github.com/ropnop/kerbrute/session"
	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var domain string
var domainController string
var verbose bool
var safe bool
var threads int
var stopOnSuccess bool
var logger util.Logger
var kSession session.KerbruteSession

// Used for multithreading
var ctx, cancel = context.WithCancel(context.Background())
var counter int32
var successes int32

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
