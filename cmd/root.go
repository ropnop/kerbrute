package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Domain string
var DomainController string
var Verbose bool

var rootCmd = &cobra.Command{
	Use:   "kerbrute",
	Short: "A tool to perform various bruteforce attacks against Windows Kerberos",
	Long: `This tool is designed to assist in quickly bruteforcing valid Active Directory accounts through Kerberos Pre-Authentication.
It is designed to be used on an internal Windows domain with access to one of the Domain Controllers.
Warning: failed Kerberos Pre-Auth counts as a failed login and WILL lock out accounts`,
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
	rootCmd.PersistentFlags().BoolVar(&Verbose, "safe", false, "Safe mode. Will abort if any user comes back as locked out. Default: FALSE")

	rootCmd.MarkFlagRequired("domainController")
}
