package session

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/op/go-logging"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/kerbrute/util"
)

func TestDumpASRepHashReportsDiscoveryIndependently(t *testing.T) {
	tests := []struct {
		name       string
		etype      int32
		cipher     []byte
		wantExport bool
		wantError  string
	}{
		{"RC4 export", 23, bytes.Repeat([]byte{0x42}, 48), true, ""},
		{"AES128 export", 17, bytes.Repeat([]byte{0x42}, 44), true, ""},
		{"AES256 export", 18, bytes.Repeat([]byte{0x42}, 44), true, ""},
		{"truncated RC4", 23, []byte("secret"), false, "ciphertext is too short"},
		{"truncated AES128", 17, []byte("secret"), false, "ciphertext is too short"},
		{"unsupported etype", 99, []byte("secret"), false, "unsupported for hashcat export"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logging.SetBackend(logging.NewLogBackend(&output, "", 0))
			logging.SetLevel(logging.DEBUG, "")
			log := util.Logger{Log: logging.MustGetLogger("asrep-test")}

			file, err := ioutil.TempFile("", "kerbrute-asrep-test-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(file.Name())
			defer file.Close()

			var rep messages.ASRep
			rep.CName.NameString = []string{"synthetic"}
			rep.CRealm = "EXAMPLE.TEST"
			rep.EncPart.EType = tt.etype
			rep.EncPart.Cipher = tt.cipher
			session := KerbruteSession{Logger: &log, HashFile: file}
			session.DumpASRepHash(rep)

			logs := output.String()
			if !strings.Contains(logs, "synthetic has no pre auth required") {
				t.Errorf("discovery missing from logs: %q", logs)
			}
			if tt.wantError != "" && !strings.Contains(logs, tt.wantError) {
				t.Errorf("export diagnostic missing from logs: %q", logs)
			}
			if strings.Contains(logs, string(tt.cipher)) {
				t.Errorf("raw ciphertext exposed in logs")
			}
			content, err := ioutil.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantExport {
				prefix := fmt.Sprintf("$krb5asrep$%d$", tt.etype)
				if !strings.Contains(logs, "Dumping hash to crack offline") || !strings.HasPrefix(string(content), prefix) {
					t.Errorf("AS-REP export missing: logs %q, file %q", logs, content)
				}
			} else if len(content) != 0 || strings.Contains(logs, "Dumping hash to crack offline") {
				t.Errorf("unexpected export: logs %q, file %q", logs, content)
			}
		})
	}
}
