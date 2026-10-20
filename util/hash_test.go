package util

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"github.com/ropnop/gokrb5/v8/iana/patype"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/gokrb5/v8/types"
)

func syntheticASRep(etype int32, cipher []byte) messages.ASRep {
	var rep messages.ASRep
	rep.EncPart.EType = etype
	rep.EncPart.Cipher = cipher
	rep.CName.NameString = []string{"synthetic"}
	rep.CRealm = "EXAMPLE.TEST"
	return rep
}

func TestASRepToHashcat(t *testing.T) {
	rc4 := make([]byte, 48)
	for i := range rc4 {
		rc4[i] = byte(i)
	}
	const rc4Hash = "$krb5asrep$23$synthetic@EXAMPLE.TEST:000102030405060708090a0b0c0d0e0f$101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	aes := make([]byte, 44)
	for i := range aes {
		aes[i] = byte(i)
	}
	const aesHash = "$synthetic$EXAMPLE.TEST$202122232425262728292a2b$000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	tests := []struct {
		name    string
		etype   int32
		cipher  []byte
		want    string
		wantErr string
	}{
		{"RC4 at minimum", 23, rc4, rc4Hash, ""},
		{"RC4 above minimum", 23, append(append([]byte(nil), rc4...), 0x30), rc4Hash + "30", ""},
		{"RC4 empty", 23, nil, "", "empty ciphertext"},
		{"RC4 one byte", 23, make([]byte, 1), "", "need at least 48 bytes"},
		{"RC4 before checksum boundary", 23, make([]byte, 15), "", "need at least 48 bytes"},
		{"RC4 at checksum boundary", 23, make([]byte, 16), "", "need at least 48 bytes"},
		{"RC4 below cryptographic minimum", 23, make([]byte, 23), "", "need at least 48 bytes"},
		{"RC4 above cryptographic minimum", 23, make([]byte, 24), "", "need at least 48 bytes"},
		{"RC4 below hashcat minimum", 23, make([]byte, 47), "", "need at least 48 bytes"},
		{"RC4 above hashcat maximum", 23, make([]byte, 20496), "", "at most 20495 bytes"},
		{"AES128 empty", 17, nil, "", "empty ciphertext"},
		{"AES128 truncated", 17, make([]byte, 27), "", "need at least 44 bytes"},
		{"AES128 below minimum", 17, make([]byte, 43), "", "need at least 44 bytes"},
		{"AES128 at minimum", 17, aes, "$krb5asrep$17" + aesHash, ""},
		{"AES128 above minimum", 17, append(append([]byte(nil), aes...), 0x2c), "$krb5asrep$17$synthetic$EXAMPLE.TEST$2122232425262728292a2b2c$000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", ""},
		{"AES128 above maximum", 17, make([]byte, 20493), "", "at most 20492 bytes"},
		{"AES256 empty", 18, nil, "", "empty ciphertext"},
		{"AES256 truncated", 18, make([]byte, 27), "", "need at least 44 bytes"},
		{"AES256 below minimum", 18, make([]byte, 43), "", "need at least 44 bytes"},
		{"AES256 at minimum", 18, aes, "$krb5asrep$18" + aesHash, ""},
		{"AES256 above maximum", 18, make([]byte, 20493), "", "at most 20492 bytes"},
		{"unsupported zero", 0, []byte{1}, "", "etype 0 is unsupported"},
		{"unsupported negative", -1, []byte{1}, "", "etype -1 is unsupported"},
		{"unsupported DES", 3, []byte{1}, "", "etype 3 is unsupported"},
		{"unsupported unknown", 999, []byte{1}, "", "etype 999 is unsupported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ASRepToHashcat(syntheticASRep(tt.etype, tt.cipher))
			if got != tt.want {
				t.Errorf("hash = %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestASRepToHashcatMissingIdentity(t *testing.T) {
	for _, etype := range []int32{23, 17, 18} {
		for _, field := range []string{"principal", "realm"} {
			t.Run(fmt.Sprintf("%s/etype %d", field, etype), func(t *testing.T) {
				cipherLength := 44
				if etype == 23 {
					cipherLength = 48
				}
				rep := syntheticASRep(etype, make([]byte, cipherLength))
				if field == "principal" {
					rep.CName.NameString = nil
				} else {
					rep.CRealm = ""
				}
				hash, err := ASRepToHashcat(rep)
				if hash != "" || err == nil || !strings.Contains(err.Error(), "missing a client principal or realm") {
					t.Errorf("got hash %q and error %v", hash, err)
				}
			})
		}
	}
}

func TestASRepToHashcatErrorDoesNotExposeCiphertext(t *testing.T) {
	cipher := bytes.Repeat([]byte("secret-ciphertext"), 3)[:43]
	for _, etype := range []int32{17, 18, 99} {
		_, err := ASRepToHashcat(syntheticASRep(etype, cipher))
		if err == nil || strings.Contains(err.Error(), string(cipher)) {
			t.Errorf("etype %d returned unsafe error: %v", etype, err)
		}
	}
}

func TestASRepToHashcatAESIdentityValidation(t *testing.T) {
	tests := []struct {
		name  string
		user  string
		realm string
	}{
		{"user delimiter", "machine$", "EXAMPLE.TEST"},
		{"realm delimiter", "synthetic", "EXAMPLE$TEST"},
		{"user newline", "synthetic\nname", "EXAMPLE.TEST"},
		{"realm newline", "synthetic", "EXAMPLE\nTEST"},
		{"user too long", strings.Repeat("a", 513), "EXAMPLE.TEST"},
		{"realm too long", "synthetic", strings.Repeat("a", 513)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := syntheticASRep(17, make([]byte, 44))
			rep.CName.NameString = []string{tt.user}
			rep.CRealm = tt.realm
			hash, err := ASRepToHashcat(rep)
			if hash != "" || err == nil || !strings.Contains(err.Error(), "cannot be represented") {
				t.Errorf("got hash %q and error %v", hash, err)
			}
		})
	}
}

func TestASRepToHashcatAESMaximumLength(t *testing.T) {
	for _, etype := range []int32{17, 18} {
		hash, err := ASRepToHashcat(syntheticASRep(etype, make([]byte, 20492)))
		if err != nil || len(hash) == 0 {
			t.Errorf("etype %d: expected a hash at the maximum length, got %d bytes and %v", etype, len(hash), err)
		}
	}
}

func TestASRepToHashcatRC4MaximumLength(t *testing.T) {
	hash, err := ASRepToHashcat(syntheticASRep(23, make([]byte, 20495)))
	if err != nil || len(hash) == 0 {
		t.Errorf("expected an RC4 hash at the maximum length, got %d bytes and %v", len(hash), err)
	}
}

func TestASRepToHashcatRC4IdentityValidation(t *testing.T) {
	for _, name := range []string{"bad:name", "bad\nname", "bad\x00name"} {
		rep := syntheticASRep(23, make([]byte, 48))
		rep.CName.NameString = []string{name}
		hash, err := ASRepToHashcat(rep)
		if hash != "" || err == nil || !strings.Contains(err.Error(), "cannot be represented") {
			t.Errorf("name %q: got hash %q and error %v", name, hash, err)
		}
	}
}

func TestASRepToHashcatAESSalt(t *testing.T) {
	cipher := make([]byte, 44)
	for i := range cipher {
		cipher[i] = byte(i)
	}
	const encrypted = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const checksum = "202122232425262728292a2b"

	for _, etype := range []int32{17, 18} {
		t.Run(fmt.Sprintf("etype %d explicit salt", etype), func(t *testing.T) {
			rep := syntheticASRep(etype, cipher)
			rep.PAData = []types.PAData{etypeInfo2PA(t, types.ETypeInfo2Entry{EType: etype, Salt: "CUSTOM-SALT", S2KParams: []byte{0, 0, 16, 0}})}
			hash, err := ASRepToHashcat(rep)
			want := fmt.Sprintf("$krb5asrep$%d$CUSTOM-SALT$%s$%s", etype, encrypted, checksum)
			if err != nil || hash != want {
				t.Errorf("hash = %q, error = %v; want %q", hash, err, want)
			}
		})
	}

	for _, tt := range []struct {
		name   string
		paData types.PAData
		want   string
	}{
		{"PA-ETYPE-INFO", etypeInfoPA(t, types.ETypeInfoEntry{EType: 17, Salt: []byte("OLDER-SALT")}), "OLDER-SALT"},
		{"PA-PW-SALT", types.PAData{PADataType: patype.PA_PW_SALT, PADataValue: []byte("LEGACY-SALT")}, "LEGACY-SALT"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rep := syntheticASRep(17, cipher)
			rep.PAData = []types.PAData{tt.paData}
			hash, err := ASRepToHashcat(rep)
			want := "$krb5asrep$17$" + tt.want + "$" + encrypted + "$" + checksum
			if err != nil || hash != want {
				t.Errorf("hash = %q, error = %v; want %q", hash, err, want)
			}
		})
	}

	for _, tt := range []struct {
		name  string
		realm string
		parts []string
		want  string
	}{
		{"multiple principal parts", "EXAMPLE.TEST", []string{"service", "synthetic"}, "EXAMPLE.TESTservicesynthetic"},
		{"mixed case realm", "Example.Test", []string{"synthetic"}, "Example.Testsynthetic"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rep := syntheticASRep(17, cipher)
			rep.CRealm = tt.realm
			rep.CName.NameString = tt.parts
			hash, err := ASRepToHashcat(rep)
			want := "$krb5asrep$17$" + tt.want + "$" + encrypted + "$" + checksum
			if err != nil || hash != want {
				t.Errorf("hash = %q, error = %v; want %q", hash, err, want)
			}
		})
	}
}

func TestASRepToHashcatAESInvalidSaltInfo(t *testing.T) {
	tests := []struct {
		name    string
		paData  types.PAData
		wantErr string
	}{
		{"unsupported iterations", etypeInfo2PA(t, types.ETypeInfo2Entry{EType: 17, S2KParams: []byte{0, 0, 16, 1}}), "unsupported by hashcat"},
		{"invalid parameter length", etypeInfo2PA(t, types.ETypeInfo2Entry{EType: 17, S2KParams: []byte{1}}), "unsupported by hashcat"},
		{"invalid salt delimiter", etypeInfo2PA(t, types.ETypeInfo2Entry{EType: 17, Salt: "BAD$SALT"}), "cannot be represented"},
		{"empty PA-ETYPE-INFO2 salt", etypeInfo2PA(t, types.ETypeInfo2Entry{EType: 17}), "cannot be represented"},
		{"empty PA-ETYPE-INFO salt", etypeInfoPA(t, types.ETypeInfoEntry{EType: 17}), "cannot be represented"},
		{"empty PA-PW-SALT", types.PAData{PADataType: patype.PA_PW_SALT}, "cannot be represented"},
		{"NUL in salt", types.PAData{PADataType: patype.PA_PW_SALT, PADataValue: []byte{'A', 0, 'B'}}, "cannot be represented"},
		{"malformed PA-ETYPE-INFO2", types.PAData{PADataType: patype.PA_ETYPE_INFO2, PADataValue: []byte{0xff}}, "malformed PA-ETYPE-INFO2"},
		{"malformed PA-ETYPE-INFO", types.PAData{PADataType: patype.PA_ETYPE_INFO, PADataValue: []byte{0xff}}, "malformed PA-ETYPE-INFO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := syntheticASRep(17, make([]byte, 44))
			rep.PAData = []types.PAData{tt.paData}
			hash, err := ASRepToHashcat(rep)
			if hash != "" || err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("hash = %q, error = %v; want %q", hash, err, tt.wantErr)
			}
		})
	}
}

func etypeInfo2PA(t *testing.T, entries ...types.ETypeInfo2Entry) types.PAData {
	t.Helper()
	value, err := asn1.Marshal(types.ETypeInfo2(entries))
	if err != nil {
		t.Fatal(err)
	}
	return types.PAData{PADataType: patype.PA_ETYPE_INFO2, PADataValue: value}
}

func etypeInfoPA(t *testing.T, entries ...types.ETypeInfoEntry) types.PAData {
	t.Helper()
	value, err := asn1.Marshal(types.ETypeInfo(entries))
	if err != nil {
		t.Fatal(err)
	}
	return types.PAData{PADataType: patype.PA_ETYPE_INFO, PADataValue: value}
}
