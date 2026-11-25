// Package cursor issues and verifies opaque, HMAC-protected pagination
// cursors for audit reads.
//
// Token format: base64url(payload) "." base64url(HMAC-SHA256(secret, base64url(payload))),
// unpadded. payload is the JSON object
// {"v":1,"k":<key_id>,"op":<operation>,"team":<team_id>,"operator":<operator_id>,
//
//	"search":<search>,"order":<ordering>,"dir":"forward","at":<occurred_at unix µs>,"id":<audit_id>}.
package cursor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pandops/flowai-audit/internal/ids"
)

// ErrInvalid is returned for every cursor that must be rejected.
var ErrInvalid = errors.New("invalid cursor")

// MinSecretBytes is the shortest accepted HMAC key.
const MinSecretBytes = 32

// Key is one configured cursor HMAC key.
type Key struct {
	ID     int64
	Secret []byte
}

// Binding is the read context a cursor is bound to.
type Binding struct {
	Operation  string
	TeamID     int64
	OperatorID int64
	Search     string
	Ordering   string
	Direction  string
}

// Position is the last row of the previous page.
type Position struct {
	OccurredAtMicros int64
	AuditID          int64
}

// Keyring signs with the active key and verifies with every configured key.
type Keyring struct {
	active int64
	keys   map[int64][]byte
}

type payload struct {
	V        int             `json:"v"`
	K        json.RawMessage `json:"k"`
	Op       string          `json:"op"`
	Team     int64           `json:"team"`
	Operator int64           `json:"operator"`
	Search   string          `json:"search"`
	Order    string          `json:"order"`
	Dir      string          `json:"dir"`
	At       int64           `json:"at"`
	ID       int64           `json:"id"`
}

// NewKeyring builds a keyring; active must name one of keys.
func NewKeyring(active int64, keys []Key) (*Keyring, error) {
	k := &Keyring{active: active, keys: map[int64][]byte{}}
	for _, key := range keys {
		if key.ID < 1 {
			return nil, fmt.Errorf("cursor key_id %d is not a positive integer", key.ID)
		}
		if _, dup := k.keys[key.ID]; dup {
			return nil, fmt.Errorf("cursor key_id %d is configured twice", key.ID)
		}
		if len(key.Secret) < MinSecretBytes {
			return nil, fmt.Errorf("cursor key %d is shorter than %d bytes", key.ID, MinSecretBytes)
		}
		k.keys[key.ID] = append([]byte(nil), key.Secret...)
	}
	if _, ok := k.keys[active]; !ok || active < 1 {
		return nil, fmt.Errorf("active cursor key_id %d is not configured", active)
	}
	return k, nil
}

func sign(secret []byte, body string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return mac.Sum(nil)
}

// Encode issues a cursor for pos bound to b.
func (k *Keyring) Encode(b Binding, pos Position) (string, error) {
	raw, err := json.Marshal(payload{V: 1, K: json.RawMessage(fmt.Sprint(k.active)), Op: b.Operation, Team: b.TeamID,
		Operator: b.OperatorID, Search: b.Search, Order: b.Ordering, Dir: b.Direction, At: pos.OccurredAtMicros, ID: pos.AuditID})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + base64.RawURLEncoding.EncodeToString(sign(k.keys[k.active], body)), nil
}

// Decode verifies token against b and returns its position.
func (k *Keyring) Decode(token string, b Binding) (Position, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || body == "" || sig == "" || strings.Contains(sig, ".") {
		return Position{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Position{}, ErrInvalid
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Position{}, ErrInvalid
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Position{}, ErrInvalid
	}
	keyID, err := ids.ParseJSON(p.K)
	if err != nil {
		return Position{}, ErrInvalid
	}
	secret, ok := k.keys[keyID]
	if !ok || !hmac.Equal(gotSig, sign(secret, body)) {
		return Position{}, ErrInvalid
	}
	if p.V != 1 || p.Op != b.Operation || p.Team != b.TeamID || p.Operator != b.OperatorID ||
		p.Search != b.Search || p.Order != b.Ordering || p.Dir != b.Direction || p.ID < 1 {
		return Position{}, ErrInvalid
	}
	return Position{OccurredAtMicros: p.At, AuditID: p.ID}, nil
}
