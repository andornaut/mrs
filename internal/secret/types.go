package secret

import (
	"bytes"
	"regexp"
	"sort"
	"unicode"
	"unicode/utf8"

	"github.com/andornaut/mrs/internal/crypto"
)

// secret is one secret's plaintext. It is bytes rather than a string so that it
// can be wiped: a string is immutable, so a secret held as one stays in memory
// until the collector runs, and every copy made along the way stays with it.
type secret []byte

// Key returns the secret's first line, which is what a search matches on. It
// shares the secret's memory, so wiping the secret wipes the key with it.
func (s secret) Key() []byte {
	if i := bytes.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (s secret) Less(o secret) bool {
	return lessFold(s.Key(), o.Key())
}

// lessFold reports whether a sorts before b, ignoring case. It folds as it
// reads, rather than lowercasing both first, which would leave an unwipeable
// copy of two keys behind for every comparison a sort makes.
func lessFold(a, b []byte) bool {
	for len(a) > 0 && len(b) > 0 {
		ra, na := utf8.DecodeRune(a)
		rb, nb := utf8.DecodeRune(b)
		la, lb := unicode.ToLower(ra), unicode.ToLower(rb)
		if la != lb {
			return la < lb
		}
		a, b = a[na:], b[nb:]
	}
	return len(a) < len(b)
}

func (s secret) MatchKey(r regexp.Regexp) bool {
	return r.Match(s.Key())
}

func (s secret) MatchKeyAndValue(r regexp.Regexp) bool {
	return r.Match(s)
}

// secretList is the secrets of one vault, sorted by key.
type secretList struct {
	secrets []secret
}

func newSecretList(secrets []secret) *secretList {
	s := &secretList{secrets}
	sort.Sort(s)
	return s
}

// Wipe zeroes every secret in the secretList. A secretList built by a search
// holds the same secrets as the one it was searched from, so wiping either
// wipes both.
func (s *secretList) Wipe() {
	for _, secret := range s.secrets {
		crypto.Wipe(secret)
	}
}

// Combined returns a new secretList with the given secrets appended
func (s *secretList) Combined(o *secretList) *secretList {
	merged := make([]secret, len(s.secrets)+len(o.secrets))
	copy(merged, s.secrets)
	copy(merged[len(s.secrets):], o.secrets)
	return newSecretList(merged)
}

// SearchKeys returns secrets whose keys match the given regular expression
func (s *secretList) SearchKeys(r regexp.Regexp) *secretList {
	return s.search(r, func(s secret, r regexp.Regexp) bool {
		return s.MatchKey(r)
	})
}

// SearchKeysAndValues returns secrets whose keys or value match the given regular expression
func (s *secretList) SearchKeysAndValues(r regexp.Regexp) *secretList {
	return s.search(r, func(s secret, r regexp.Regexp) bool {
		return s.MatchKeyAndValue(r)
	})
}

func (s *secretList) search(r regexp.Regexp, match func(secret, regexp.Regexp) bool) *secretList {
	var secrets []secret
	for _, secret := range s.secrets {
		if match(secret, r) {
			secrets = append(secrets, secret)
		}
	}
	return newSecretList(secrets)
}

// Bytes returns the secrets as a vault is written: each ends in a newline, and
// a blank line separates one from the next. It is a copy, sized once so that
// growing it cannot leave a half-filled buffer behind, and the caller is
// responsible for wiping it.
func (s *secretList) Bytes() []byte {
	if len(s.secrets) == 0 {
		return nil
	}
	n := len(s.secrets) - 1
	for _, secret := range s.secrets {
		n += len(secret)
	}
	out := make([]byte, 0, n)
	for i, secret := range s.secrets {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, secret...)
	}
	return out
}

// Len is part of sort.Interface.
func (s *secretList) Len() int {
	return len(s.secrets)
}

// Less is part of sort.Interface. It is implemented by calling the "by" closure in the sorter
func (s *secretList) Less(i, j int) bool {
	return s.secrets[i].Less(s.secrets[j])
}

// Swap is part of sort.Interface
func (s *secretList) Swap(i, j int) {
	s.secrets[i], s.secrets[j] = s.secrets[j], s.secrets[i]
}
