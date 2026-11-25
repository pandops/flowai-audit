package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// trustFiles writes a CA certificate and a NATS user credentials file.
type trustFiles struct {
	dir, natsCA, dbCA, creds, jwtOnly, seedOnly, userJWT string
}

func writeTrustFiles(t *testing.T) trustFiles {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	claims := jwt.NewUserClaims(userPub)
	claims.Name = "audit"
	token, err := claims.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatal(err)
	}
	f := trustFiles{dir: dir, userJWT: token}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	f.natsCA = write("nats-ca.pem", caPEM)
	f.dbCA = write("db-ca.pem", caPEM)
	f.creds = write("audit.creds", creds)
	jwtPart := string(creds)[:strings.Index(string(creds), "************************* IMPORTANT")]
	f.jwtOnly = write("jwt-only.creds", []byte(jwtPart))
	f.seedOnly = write("seed-only.creds", []byte("-----BEGIN USER NKEY SEED-----\n"+string(seed)+"\n------END USER NKEY SEED------\n"))
	return f
}

// validYAML is a complete production configuration over f.
func validYAML(f trustFiles) string {
	return `db:
  host: pg.flowai.svc
  port: 5432
  user: audit
  password: pg-password-value
  ca_file: ` + f.dbCA + `
nats:
  url: tls://nats.flowai.svc:4222
  ca_file: ` + f.natsCA + `
  credentials_file: ` + f.creds + `
http:
  listen: ":8080"
cursor_keys:
  - id: 1
    secret: "` + strings.Repeat("ab", 32) + `"
active_cursor_key_id: 1
`
}
