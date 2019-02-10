package session

import (
	"fmt"
	"html/template"
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

type KerbruteSession struct {
	Domain       string
	Realm        string
	Kdcs         map[int]string
	ConfigString string
	Config       *kconfig.Config
	Verbose      bool
	SafeMode     bool
}

func NewKerbruteSession(domain string, domainController string, verbose bool, safemode bool) KerbruteSession {
	realm := strings.ToUpper(domain)
	configstring := buildKrb5Template(realm, domainController)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	if err != nil {
		fmt.Println(err)
	}
	k := KerbruteSession{domain, realm, kdcs, configstring, Config, verbose, safemode}
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

func (k KerbruteSession) TestLogin(username, password string) (bool, error) {
	Client := kclient.NewClientWithPassword(username, k.Realm, password, k.Config, kclient.DisablePAFXFAST(true))
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}
	err := Client.Login()
	if err != nil {
		return false, err
	}
	return true, nil
}

func (k KerbruteSession) HandleKerbError(err error) (bool, string) {
	eString := err.Error()
	if strings.Contains(eString, "Networking_Error: AS Exchange Error") {
		return false, "NETWORK ERROR - Can't talk to KDC. Aborting..."
	}
	if strings.Contains(eString, "KDC_ERROR_WRONG_REALM") {
		return false, "KDC ERROR - Wrong Realm. Try adjusting the domain? Aborting..."
	}
	if strings.Contains(eString, "client does not have a username") {
		return true, "Skipping blank username"
	}
	if strings.Contains(eString, "KDC_ERR_C_PRINCIPAL_UNKNOWN") {
		return true, "User does not exist"
	}
	if strings.Contains(eString, "KDC_ERR_PREAUTH_FAILED") {
		return true, "Invalid password"
	}
	if strings.Contains(eString, "KDC_ERR_CLIENT_REVOKED") {
		if k.SafeMode {
			return false, "USER LOCKED OUT and safe mode on! Aborting..."
		}
		return true, "USER LOCKED OUT"
	}
	return true, eString

}
