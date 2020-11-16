package session

import (
	"fmt"
	"strings"
)

func (k KerbruteSession) HandleKerbError(err error) (bool, string) {
	eString := err.Error()

	// handle non KRB errors
	if strings.Contains(eString, "client does not have a username") {
		return true, "Skipping blank username"
	}
	if strings.Contains(eString, "Networking_Error: AS Exchange Error") {
		return false, "NETWORK ERROR - Can't talk to KDC. Aborting..."
	}
	if strings.Contains(eString, " AS_REP is not valid or client password/keytab incorrect") {
		return true, "Got AS-REP (no pre-auth) but couldn't decrypt - bad password"
	}

	// handle KRB errors
	if strings.Contains(eString, "KDC_ERR_WRONG_REALM") {
		return false, "KDC ERROR - Wrong Realm. Try adjusting the domain? Aborting..."
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
	if strings.Contains(eString, "KRB_AP_ERR_SKEW Clock skew too great") {
		return true, "Clock skew too great"
	}

	return false, eString
}

// TestLoginError returns true for certain KRB Errors that only happen when the password is correct
// The correct credentials we're passed, but the error prevented a successful TGT from being retrieved
func (k KerbruteSession) TestLoginError(err error) (bool, error) {
	eString := err.Error()
	if strings.Contains(eString, "Password has expired") {
		// user's password expired, but it's valid!
		return true, fmt.Errorf("User's password has expired")
	}
	if strings.Contains(eString, "Clock skew too great") {
		// clock skew off, but that means password worked since PRE-AUTH was successful
		return true, fmt.Errorf("Clock skew is too great")
	}
	return false, err
}
