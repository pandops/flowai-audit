// Package config loads audit's YAML configuration.
package config

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gopkg.in/yaml.v3"

	"github.com/pandops/flowai-audit/internal/cursor"
	"github.com/pandops/flowai-audit/internal/migrations"
)

// Defaults.
const (
	DefaultSchema         = "audit_schema"
	DefaultDatabase       = "flowai"
	DefaultSSLMode        = "verify-full"
	DefaultListen         = ":8080"
	DefaultInboxPrefix    = "_INBOX.audit"
	DefaultRequestTimeout = 5 * time.Second
)

// DB is the PostgreSQL connection configuration.
type DB struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"`
	Schema       string `yaml:"schema"`
	Name         string `yaml:"name"`
	SSLMode      string `yaml:"sslmode"`
	CAFile       string `yaml:"ca_file"`
}

// NATS is the broker connection configuration.
type NATS struct {
	URL             string `yaml:"url"`
	CAFile          string `yaml:"ca_file"`
	CredentialsFile string `yaml:"credentials_file"`
	InboxPrefix     string `yaml:"inbox_prefix"`
	RequestTimeout  string `yaml:"request_timeout"`
}

// HTTP is the probe listener configuration.
type HTTP struct {
	Listen string `yaml:"listen"`
}

// CursorKey is one configured cursor HMAC key; secret is hex.
type CursorKey struct {
	ID         int64  `yaml:"id"`
	Secret     string `yaml:"secret"`
	SecretFile string `yaml:"secret_file"`
}

// Config is the whole service configuration.
type Config struct {
	DB                DB          `yaml:"db"`
	NATS              NATS        `yaml:"nats"`
	HTTP              HTTP        `yaml:"http"`
	CursorKeys        []CursorKey `yaml:"cursor_keys"`
	ActiveCursorKeyID int64       `yaml:"active_cursor_key_id"`
}

// Loaded is a validated configuration with its secrets read from files.
type Loaded struct {
	Config
	DBPassword     string
	NATSUserJWT    string
	NATSUserSeed   []byte
	NATSCAPEM      []byte
	DBCAPEM        []byte
	CursorSecrets  map[int64][]byte
	RequestTimeout time.Duration
	Keyring        *cursor.Keyring
}

// Load reads, defaults and validates the YAML file at path.
func Load(path string) (Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Loaded{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data, filepath.Dir(path))
}

// Parse defaults and validates YAML data; relative files resolve against baseDir.
func Parse(data []byte, baseDir string) (Loaded, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Loaded{}, fmt.Errorf("parse config: %w", err)
	}
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(baseDir, p)
	}
	l := Loaded{Config: c, CursorSecrets: map[int64][]byte{}}

	db := &l.DB
	if db.Schema == "" {
		db.Schema = DefaultSchema
	}
	if db.Name == "" {
		db.Name = DefaultDatabase
	}
	if db.SSLMode == "" {
		db.SSLMode = DefaultSSLMode
	}
	switch {
	case db.Host == "":
		return Loaded{}, errors.New("db.host is required")
	case db.Port < 1 || db.Port > 65535:
		return Loaded{}, errors.New("db.port is required")
	case db.User == "":
		return Loaded{}, errors.New("db.user is required")
	case db.SSLMode != DefaultSSLMode:
		return Loaded{}, errors.New("db.sslmode must be verify-full")
	case !migrations.ValidSchema(db.Schema):
		return Loaded{}, errors.New("db.schema is not a valid schema name")
	}
	switch {
	case db.Password != "" && db.PasswordFile != "":
		return Loaded{}, errors.New("db.password and db.password_file are exclusive")
	case db.PasswordFile != "":
		raw, err := os.ReadFile(resolve(db.PasswordFile))
		if err != nil {
			return Loaded{}, fmt.Errorf("read db.password_file: %w", err)
		}
		l.DBPassword = strings.TrimRight(string(raw), "\r\n")
	default:
		l.DBPassword = db.Password
	}
	if l.DBPassword == "" {
		return Loaded{}, errors.New("db.password is required")
	}
	db.CAFile = resolve(db.CAFile)
	var err error
	if l.DBCAPEM, err = readCA(db.CAFile, "db.ca_file"); err != nil {
		return Loaded{}, err
	}

	n := &l.NATS
	u, err := url.Parse(n.URL)
	if n.URL == "" || err != nil || u.Scheme != "tls" || u.Host == "" {
		return Loaded{}, errors.New("nats.url must be a tls:// URL")
	}
	n.CAFile = resolve(n.CAFile)
	if l.NATSCAPEM, err = readCA(n.CAFile, "nats.ca_file"); err != nil {
		return Loaded{}, err
	}
	n.CredentialsFile = resolve(n.CredentialsFile)
	if l.NATSUserJWT, l.NATSUserSeed, err = readCreds(n.CredentialsFile); err != nil {
		return Loaded{}, err
	}
	if n.InboxPrefix == "" {
		n.InboxPrefix = DefaultInboxPrefix
	}
	l.RequestTimeout = DefaultRequestTimeout
	if n.RequestTimeout != "" {
		if l.RequestTimeout, err = time.ParseDuration(n.RequestTimeout); err != nil || l.RequestTimeout <= 0 {
			return Loaded{}, errors.New("nats.request_timeout is not a positive duration")
		}
	}

	if l.HTTP.Listen == "" {
		l.HTTP.Listen = DefaultListen
	}

	var keys []cursor.Key
	for _, k := range l.CursorKeys {
		hexSecret := k.Secret
		if k.SecretFile != "" {
			if k.Secret != "" {
				return Loaded{}, fmt.Errorf("cursor key %d: secret and secret_file are exclusive", k.ID)
			}
			raw, err := os.ReadFile(resolve(k.SecretFile))
			if err != nil {
				return Loaded{}, fmt.Errorf("cursor key %d: read secret_file: %w", k.ID, err)
			}
			hexSecret = strings.TrimSpace(string(raw))
		}
		secret, err := hex.DecodeString(hexSecret)
		if err != nil {
			return Loaded{}, fmt.Errorf("cursor key %d: secret is not hex", k.ID)
		}
		keys = append(keys, cursor.Key{ID: k.ID, Secret: secret})
		l.CursorSecrets[k.ID] = secret
	}
	if l.Keyring, err = cursor.NewKeyring(l.ActiveCursorKeyID, keys); err != nil {
		return Loaded{}, err
	}
	return l, nil
}

func readCA(path, key string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s is required", key)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", key)
	}
	return raw, nil
}

func readCreds(path string) (string, []byte, error) {
	if path == "" {
		return "", nil, errors.New("nats.credentials_file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("read nats.credentials_file: %w", err)
	}
	token, err := jwt.ParseDecoratedJWT(raw)
	if err != nil {
		return "", nil, errors.New("nats.credentials_file holds no user JWT")
	}
	claims, err := jwt.DecodeUserClaims(token)
	if err != nil {
		return "", nil, errors.New("nats.credentials_file holds no valid user JWT")
	}
	kp, err := jwt.ParseDecoratedUserNKey(raw)
	if err != nil {
		return "", nil, errors.New("nats.credentials_file holds no user seed")
	}
	pub, err := kp.PublicKey()
	if err != nil || pub != claims.Subject {
		return "", nil, errors.New("nats.credentials_file seed does not match its JWT")
	}
	seed, err := kp.Seed()
	if err != nil {
		return "", nil, errors.New("nats.credentials_file holds no user seed")
	}
	if _, err := nkeys.FromSeed(seed); err != nil {
		return "", nil, errors.New("nats.credentials_file holds no user seed")
	}
	return token, seed, nil
}

// DSN returns the pgx connection string of l.
func (l Loaded) DSN() string {
	q := func(s string) string {
		if s != "" && !strings.ContainsAny(s, " '\\\t\n") {
			return s
		}
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	parts := []string{
		"host=" + q(l.DB.Host),
		"port=" + strconv.Itoa(l.DB.Port),
		"user=" + q(l.DB.User),
		"password=" + q(l.DBPassword),
		"dbname=" + q(l.DB.Name),
		"sslmode=" + l.DB.SSLMode,
		"sslrootcert=" + q(l.DB.CAFile),
		"search_path=" + l.DB.Schema,
	}
	return strings.Join(parts, " ")
}
