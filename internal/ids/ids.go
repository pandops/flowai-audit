// Package ids parses FlowAI integer identifiers: positive 64-bit integers.
package ids

import (
	"errors"
	"strconv"
	"strings"
)

// ErrInvalid reports an identifier that is not a positive int64.
var ErrInvalid = errors.New("invalid identifier")

// ParseDecimal parses a decimal token without sign or leading zeros.
func ParseDecimal(s string) (int64, error) {
	if s == "" || len(s) > 19 || s[0] == '0' {
		return 0, ErrInvalid
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalid
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 1 {
		return 0, ErrInvalid
	}
	return v, nil
}

// ParseJSON parses a raw JSON value that must be a JSON number holding a
// positive int64 (no fraction, no exponent, no string).
func ParseJSON(raw []byte) (int64, error) {
	return ParseDecimal(strings.TrimSpace(string(raw)))
}
