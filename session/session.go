package session

import (
	"fmt"
	"html/template"
	"log"
	"strings"

	kclient "gopkg.in/jcmturner/gokrb5.v7/client"
	kconfig "gopkg.in/jcmturner/gokrb5.v7/config"
)

const krb5ConfigTemplateDNS = `[libdefaults]
dns_lookup_kdc = true
default_realm = {{.Domain}}
`

const krb5ConfigTemplateKDC = `[libdefaults]
default_realm = {{.Domain}}
[realms]
{{.Domain}} = {
	kdc = {{.DomainController}}
	admin_server = {{.DomainController}}
}
`

type kerbruteSession struct {
	Domain       string
	Kdcs         map[int]string
	ConfigString string
	Config       *kconfig.Config
}

func NewKerbruteSession(domain string, domainController string) kerbruteSession {
	configstring := buildKrb5Template(strings.ToUpper(domain), domainController)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(domain, false)
	if err != nil {
		fmt.Println(err)
	}
	k := kerbruteSession{domain, kdcs, configstring, Config}
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

func (k kerbruteSession) TestLogin(username, password string) (bool, error) {
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

func (k kerbruteSession) HandleKerbError(err error) {
	log.Printf("[!] Error: %v", err.Error())
}
