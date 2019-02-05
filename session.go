package main

import (
	"html/template"
	"strings"

	kclient "gopkg.in/jcmturner/gokrb5.v7/client"
	kconfig "gopkg.in/jcmturner/gokrb5.v7/config"
)

const krb5ConfigTemplateDNS = `[libdefaults]
dns_lookup_kdc = true
default_realm = "{{.Domain}}"
`

const krb5ConfigTemplateKDC = `[realms]
{{.Domain}} = {
	kdc = "{{.DomainController}}"
	admin_server = "{{.DomainController}}"
}
`

type kerbSession struct {
	Domain string
	Kdcs   map[int]string
	Config *kconfig.Config
}

func NewKerbSession(domain string, domainController string) kerbSession {
	configstring := buildKrb5Template(strings.ToUpper(domain), domainController)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(domain, false)
	k := kerbSession{domain, kdcs, Config}
	return k

}

func buildKrb5Template(domain, domainController string) string {
	data := map[string]interface{}{
		"Domain":           domain,
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

func (k kerbSession) testLogin(username, password string) bool {
	if username == "" {
		return false
	}
	Client := kclient.NewClientWithPassword(username, strings.ToUpper(k.Domain), password, k.Config, kclient.DisablePAFXFAST(true))
	defer Client.Destroy()
	err := Client.Login()
	if err != nil {
		// fmt.Printf("error logging in: %v", err)
		return false
	} else {
		// fmt.Println("success!")
		return true
	}
}
