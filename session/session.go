package session

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/ropnop/gokrb5/iana/errorcode"

	kclient "github.com/ropnop/gokrb5/client"
	kconfig "github.com/ropnop/gokrb5/config"
	"github.com/ropnop/gokrb5/messages"
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

func NewKerbruteSession(domain string, domainController string, verbose bool, safemode bool) (KerbruteSession, error) {
	realm := strings.ToUpper(domain)
	configstring := buildKrb5Template(realm, domainController)
	Config, err := kconfig.NewConfigFromString(configstring)
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	if err != nil {
		err = fmt.Errorf("Couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
	}
	k := KerbruteSession{domain, realm, kdcs, configstring, Config, verbose, safemode}
	return k, err

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
	Client := kclient.NewClientWithPassword(username, k.Realm, password, k.Config, kclient.DisablePAFXFAST(true), kclient.AssumePreAuthentication(true))
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}
	err := Client.Login()
	if err != nil {
		if strings.Contains(err.Error(), "Password has expired") {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func (k KerbruteSession) TestUsername(username string) (bool, error) {
	cl := kclient.NewClientWithPassword(username, k.Realm, "foobar", k.Config, kclient.DisablePAFXFAST(true))

	req, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		fmt.Printf(err.Error())
	}
	b, err := req.Marshal()
	if err != nil {
		return false, err
	}
	rb, err := cl.SendToKDC(b, k.Realm)
	if err != nil {
		if e, ok := err.(messages.KRBError); ok {
			if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
				return true, nil
			}
		}
	}
	// if we made it here, we got an AS REP, meaning pre-auth was probably not required. try to unmarshal it to make sure format is right
	var ASRep messages.ASRep
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return false, err
	}
	// AS REP was valid, user therefore exists (don't bother trying to decrypt)
	return true, err

}

func (k KerbruteSession) HandleKerbError(err error) (bool, string) {
	eString := err.Error()
	if strings.Contains(eString, "Networking_Error: AS Exchange Error") {
		return false, "NETWORK ERROR - Can't talk to KDC. Aborting..."
	}
	if strings.Contains(eString, "KDC_ERR_WRONG_REALM") {
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
	if strings.Contains(eString, " AS_REP is not valid or client password/keytab incorrect") {
		return true, "Got AS-REP (no pre-auth) but couldn't decrypt - bad password"
	}
	return true, eString

}
