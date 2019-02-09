package main

import (
	"html/template"
	"log"
	"strings"

	kclient "gopkg.in/jcmturner/gokrb5.v7/client"
	kconfig "gopkg.in/jcmturner/gokrb5.v7/config"
)

const krb5ConfigTemplateDNS = `[libdefaults]
dns_lookup_kdc = true
default_realm = {{.Realm}}
`

const krb5ConfigTemplateKDC = `[libdefaults]
default_realm = {{.Realm}}
[realms]
{{.Realm}} = {
	kdc = {{.DomainController}}
	admin_server = {{.DomainController}}
}
`

type kerbruteSession struct {
	Domain string
	Realm  string
	Kdcs   map[int]string
	Config *kconfig.Config
}

func NewKerbruteSession(domain string, domainController string) kerbruteSession {
	realm := strings.ToUpper(domain)
	configstring := buildKrb5Template(realm, domainController)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	k := kerbruteSession{domain, realm, kdcs, Config}
	return k

}

func buildKrb5Template(realm, domainController string) string {
	data := map[string]interface{}{
		"Realm":            realm,
		"DomainController": domainController,
	}
	var kTemplate string
	if domainController == "" {
		kTemplate = krb5ConfigTemplateDNS
	} else {
		kTemplate = krb5ConfigTemplateKDC
	}
	t := template.Must(template.New("krb5ConfigString").Parse(kTemplate))
	builder := &strings.Builder{}
	if err := t.Execute(builder, data); err != nil {
		panic(err)
	}
	return builder.String()
}

func (k kerbruteSession) testLogin(username, password string) (bool, error) {
	Client := kclient.NewClientWithPassword(username, strings.ToUpper(k.Domain), password, k.Config, kclient.DisablePAFXFAST(true))
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}

	err := Client.Login()
	if err != nil {
		// fmt.Printf("error logging in: %v", err)
		return false, err
	}
	return true, nil
}

func (k kerbruteSession) handleKerbError(err error) {
	log.Printf("[!] Error: %v", err.Error())
}
