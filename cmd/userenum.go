package cmd

import (
	"github.com/spf13/cobra"
)

var userEnumCommand = &cobra.Command{
	Use:   "userenum [flags] <username_wordlist>",
	Short: "Enumerate valid domain usernames via Kerberos",
	Long: `Will enumerate valid usernames from a list by constructing AS-REQs to requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Valid usernames will be displayed on stdout.`,
	Args:   cobra.ExactArgs(1),
	PreRun: setupSession,
	Run:    userEnum,
}

func init() {
	rootCmd.AddCommand(userEnumCommand)
}

func userEnum(cmd *cobra.Command, args []string) {
	// setupSession()
	// usernamelist := args[0]
	// kSession.TestUsername("foobar")
}
