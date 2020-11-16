package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

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
	rootCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "The full domain to use (e.g. contoso.com)")
	rootCmd.PersistentFlags().StringVar(&domainController, "dc", "", "The location of the Domain Controller (KDC) to target. If blank, will lookup via DNS")
	rootCmd.PersistentFlags().StringVarP(&logFileName, "output", "o", "", "File to write logs to. Optional.")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Log failures and errors")
	rootCmd.PersistentFlags().BoolVar(&safe, "safe", false, "Safe mode. Will abort if any user comes back as locked out. Default: FALSE")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "Threads to use")
	rootCmd.PersistentFlags().IntVarP(&delay, "delay", "", 0, "Delay in millisecond between each attempt. Will always use single thread if set")
	rootCmd.PersistentFlags().BoolVar(&downgrade, "downgrade", false, "Force downgraded encryption type (arcfour-hmac-md5)")
	rootCmd.PersistentFlags().StringVar(&hashFileName, "hash-file", "", "File to save AS-REP hashes to (if any captured), otherwise just logged")
	if delay != 0 {
		threads = 1
	}

}
