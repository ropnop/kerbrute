package util

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ropnop/gokrb5/v8/iana/patype"
	"github.com/ropnop/gokrb5/v8/messages"
)

func ASRepToHashcat(asrep messages.ASRep) (string, error) {
	etype := asrep.EncPart.EType
	cipher := asrep.EncPart.Cipher
	if len(cipher) == 0 {
		return "", fmt.Errorf("AS-REP etype %d has empty ciphertext", etype)
	}

	switch etype {
	case 23: // RC4-HMAC: 16-byte checksum followed by encrypted data.
		// Hashcat requires at least 32 bytes of encrypted data.
		if len(cipher) < 48 {
			return "", fmt.Errorf("AS-REP etype 23 ciphertext is too short for hashcat: need at least 48 bytes, got %d", len(cipher))
		}
		if len(cipher) > 20495 {
			return "", fmt.Errorf("AS-REP etype 23 ciphertext is too long for hashcat: at most 20495 bytes, got %d", len(cipher))
		}
	case 17, 18: // AES128 and AES256 append a 12-byte integrity tag.
		// Hashcat requires at least 32 bytes of encrypted data before the tag.
		if len(cipher) < 44 {
			return "", fmt.Errorf("AS-REP AES etype %d ciphertext is too short: need at least 44 bytes, got %d", etype, len(cipher))
		}
		if len(cipher) > 20492 {
			return "", fmt.Errorf("AS-REP AES etype %d ciphertext is too long for hashcat: at most 20492 bytes, got %d", etype, len(cipher))
		}
	default:
		return "", fmt.Errorf("AS-REP etype %d is unsupported for hashcat export", etype)
	}

	name := asrep.CName.PrincipalNameString()
	if name == "" || asrep.CRealm == "" {
		return "", fmt.Errorf("AS-REP etype %d is missing a client principal or realm", etype)
	}
	if etype == 23 {
		if len(name)+1+len(asrep.CRealm) >= 2048 || !utf8.ValidString(name) || !utf8.ValidString(asrep.CRealm) || strings.ContainsAny(name, ":\r\n\x00") || strings.ContainsAny(asrep.CRealm, ":\r\n\x00") {
			return "", fmt.Errorf("AS-REP etype 23 client principal or realm cannot be represented in hashcat format")
		}
		return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
			etype,
			name,
			asrep.CRealm,
			hex.EncodeToString(cipher[:16]),
			hex.EncodeToString(cipher[16:])), nil
	}

	salt, hasSaltInfo, err := aesSalt(asrep)
	if err != nil {
		return "", err
	}
	checksumStart := len(cipher) - 12
	checksum := hex.EncodeToString(cipher[checksumStart:])
	encrypted := hex.EncodeToString(cipher[:checksumStart])
	if !hasSaltInfo && len(asrep.CName.NameString) == 1 && asrep.CRealm == strings.ToUpper(asrep.CRealm) && validAESField(name) && validAESField(asrep.CRealm) {
		return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s", etype, name, asrep.CRealm, checksum, encrypted), nil
	}
	if !hasSaltInfo {
		salt = asrep.CName.GetSalt(asrep.CRealm)
	}
	if !validAESField(salt) {
		return "", fmt.Errorf("AS-REP AES etype %d salt cannot be represented in hashcat format", etype)
	}
	return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s", etype, salt, encrypted, checksum), nil
}

func validAESField(value string) bool {
	return len(value) > 0 && len(value) <= 512 && utf8.ValidString(value) && !strings.ContainsAny(value, "$\r\n\x00")
}

// aesSalt uses the most specific salt information provided in the AS-REP.
func aesSalt(asrep messages.ASRep) (string, bool, error) {
	for _, pa := range asrep.PAData {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, err := pa.GetETypeInfo2()
		if err != nil {
			return "", false, fmt.Errorf("AS-REP etype %d has malformed PA-ETYPE-INFO2 data", asrep.EncPart.EType)
		}
		for _, entry := range info {
			if entry.EType != asrep.EncPart.EType {
				continue
			}
			if len(entry.S2KParams) != 0 && !bytes.Equal(entry.S2KParams, []byte{0, 0, 16, 0}) {
				return "", false, fmt.Errorf("AS-REP AES etype %d uses string-to-key parameters unsupported by hashcat", asrep.EncPart.EType)
			}
			return entry.Salt, true, nil
		}
	}
	for _, pa := range asrep.PAData {
		if pa.PADataType != patype.PA_ETYPE_INFO {
			continue
		}
		info, err := pa.GetETypeInfo()
		if err != nil {
			return "", false, fmt.Errorf("AS-REP etype %d has malformed PA-ETYPE-INFO data", asrep.EncPart.EType)
		}
		for _, entry := range info {
			if entry.EType == asrep.EncPart.EType {
				salt := string(entry.Salt)
				return salt, true, nil
			}
		}
	}
	for _, pa := range asrep.PAData {
		if pa.PADataType == patype.PA_PW_SALT {
			salt := string(pa.PADataValue)
			return salt, true, nil
		}
	}
	return "", false, nil
}
