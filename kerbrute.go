package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"text/template"

	"github.com/jessevdk/go-flags"
	kconfig "gopkg.in/jcmturner/gokrb5.v7/config"
)

const krb5ConfigTemplate = `[libdefaults]
dns_lookup_kdc = true
default_realm = {{.Domain}}
[realms]
{{.Domain}} = {
	kdc = "{{.DomainController}}"
	admin_server = {{.DomainController}}
}`

var opts struct {
	Domain           string `short:"d" long:"domain" required:"true" name:"domain name" description:"Full name of domain (e.g. contoso.com). Required."`
	DomainController string `long:"dc" required:"false" name:"Domain Controller (KDC)" description:"DC to target. If not supplied, will attempt to find through DNS"`
	Args             struct {
		UsernameList string `positional-arg-name:"<username_list>"`
		Password     string `positional-arg-name:"<password_to_try>"`
	} `positional-args:"yes" required:"yes"`
}

func buildKrb5Config(domain, domainController string) string {
	data := map[string]interface{}{
		"Domain":           domain,
		"DomainController": domainController,
	}
	t := template.Must(template.New("krb5ConfigString").Parse(krb5ConfigTemplate))
	builder := &strings.Builder{}
	if err := t.Execute(builder, data); err != nil {
		panic(err)
	}
	return builder.String()
}

func lookUpKDC(domain string) string {
	_, srvs, err := net.LookupSRV("kerberos", "udp", domain)
	if err != nil {
		log.Println(err)
		return ""
	}
	if len(srvs) == 0 {
		return ""
	}
	return srvs[0].Target

}

func testKDC(configstring string) {
	// fmt.Println(configstring)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs("", false)
	fmt.Println("testing kdc")
	for _, kdc := range kdcs {
		fmt.Println(kdc)
	}
	return
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
	domainController := opts.DomainController
	if opts.DomainController == "" {
		log.Println("[!] No KDC provided. Attempting to find via DNS...")
		domainController = lookUpKDC(opts.Domain)
		if domainController == "" {
			log.Fatal(fmt.Sprintf("[!] Couldn't find KDC for domain %q. Try specifing manually\n", opts.Domain))
		}
	}

	log.Printf("[+] Using KDC: %v\n", domainController)

	kconfig := buildKrb5Config(opts.Domain, domainController)
	testKDC(kconfig)

	// file, err := os.Open(opts.Args.UsernameList)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer file.Close()

	// scanner := bufio.NewScanner(file)
	// for scanner.Scan() {
	// 	log.Println("Line: ", scanner.Text())
	// }

	// if err := scanner.Err(); err != nil {
	// 	log.Fatal(err)
	// }

}
