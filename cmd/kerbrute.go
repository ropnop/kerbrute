package cmd

import (
	"fmt"
	"os"

	"github.com/op/go-logging"
	"github.com/ropnop/kerbrute/session"
	"github.com/spf13/cobra"
)

var Domain string
var DomainController string
var Verbose bool
var Safe bool

var Log *logging.Logger

var KSession session.KerbruteSession

var rootCmd = &cobra.Command{
	Use:   "kerbrute",
	Short: "A tool to perform various bruteforce attacks against Windows Kerberos",
	Long: `This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts`,
}

func setupSession(cmd *cobra.Command, args []string) {
	Domain, _ = cmd.Flags().GetString("domain")
	DomainController, _ = cmd.Flags().GetString("dc")
	Verbose, _ = cmd.Flags().GetBool("verbose")
	Safe, _ = cmd.Flags().GetBool("safe")
	KSession = session.NewKerbruteSession(Domain, DomainController, Verbose, Safe)

	makeLogger(Verbose)

	Log.Info("Using KDC(s):")
	for _, v := range KSession.Kdcs {
		Log.Infof("\t%s\n", v)
	}
}

func makeLogger(verbose bool) {
	Log = logging.MustGetLogger("kerbrute")
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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&Domain, "domain", "d", "", "The full domain to use (e.g. contoso.com)")
	rootCmd.PersistentFlags().StringVar(&DomainController, "dc", "", "The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Log failures and errors")
	rootCmd.PersistentFlags().BoolVar(&Safe, "safe", false, "Safe mode. Will abort if any user comes back as locked out. Default: FALSE")

	rootCmd.MarkFlagRequired("domainController")
}
