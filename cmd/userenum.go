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
	usernamelist := args[0]
	usersChan := make(chan string, threads)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(threads)

	var scanner *bufio.Scanner
	if usernamelist != "-" {
		file, err := os.Open(usernamelist)
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
		go makeEnumWorker(ctx, usersChan, &wg)
	}

	start := time.Now()

Scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break Scan
		default:
			usernameline := scanner.Text()
			username, err := util.FormatUsername(usernameline)
			if err != nil {
				logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
				continue
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
			usersChan <- username
		}
	}
	close(usersChan)
	wg.Wait()

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}

	// result, err := kSession.TestUsername(usernamelist)
	// if result {
	// 	fmt.Printf("[+] %v exists!\n", usernamelist)
	// }
	// if err != nil {
	// 	fmt.Println("erro!")
	// 	fmt.Printf(err.Error())
	// }
	// fmt.Println("Done!")
}
