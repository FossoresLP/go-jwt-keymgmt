package validator

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/sha3"

	"github.com/fossoreslp/go-jwt-ed25519"
	"github.com/fossoreslp/go-jwt-keymgmt/jwk"
	"github.com/fossoreslp/go-uuid-v4"
)

type keySet struct {
	IDs       map[uuid.UUID]int
	Set       *jwk.Set
	CheckHash bool
	Hash      [64]byte
}

func (s *keySet) getKey(kid uuid.UUID) ([]byte, error) {
	if id, ok := s.IDs[kid]; ok {
		key := s.Set.Keys[id]
		if key.Crv != jwk.Ed25519 {
			return nil, ErrTokenInvalid("only Ed25519 supported")
		}
		return key.X, nil
	}
	return nil, ErrTokenInvalid("key not found")
}

var keySets map[string]*keySet

// KeyServerCertCommonName has to be set to the address of the server used to retrieve keys
var KeyServerCertCommonName string

// ValidateToken takes a JWT string and checks it's validity
func ValidateToken(t string) error {
	// Decode JWT string to token
	token, err := jwt.Decode(t)
	if err != nil {
		return ErrTokenInvalid("decode")
	}
	// Check if key ID is set and request key if it is
	if token.Header.Kid == "" {
		return ErrTokenInvalid("key ID not set")
	}
	keyUUID, err := uuid.Parse(token.Header.Kid)
	if err != nil {
		return ErrTokenInvalid("key ID not a valid UUID")
	}
	err = updateKeys(token.Header.Jku)
	if err != nil {
		return ErrTokenInvalid("failed to update key set")
	}
	key, err := keySets[token.Header.Jku].getKey(keyUUID)
	if err != nil {
		return err
	}
	return token.Validate(key)
}

func updateKeys(keyURL string) error {
	if keyURL == "" {
		return ErrKeyserverAddrNotSet("address empty")
	}
	err := checkHash(keyURL)
	if err == nil {
		return nil
	}
	resp, err := http.Get(keyURL)
	if err != nil {
		return ErrInternalError("could not get key")
	}
	defer resp.Body.Close() // nolint: errcheck
	if resp.TLS.PeerCertificates[0].Subject.CommonName != KeyServerCertCommonName {
		return ErrInternalError("token server cert invalid")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ErrInternalError("could not read body")
	}
	set := keySet{}
	err = json.Unmarshal(data, set.Set)
	if err != nil {
		return ErrInternalError("failed to parse JSON")
	}
	if set.Set.Sup {
		set.CheckHash = true
		sha3.ShakeSum256(set.Hash[:], data)
	}
	for a := range set.Set.Keys {
		set.IDs[set.Set.Keys[a].Kid] = a
	}
	keySets[keyURL] = &set
	return nil
}

func checkHash(u string) error {
	if s, ok := keySets[u]; ok {
		if !s.CheckHash {
			return ErrInternalError("hash check disabled")
		}
		resp, err := http.Get(u + "/hash")
		if err != nil {
			return ErrInternalError("request failed")
		}
		defer resp.Body.Close() // nolint: errcheck
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return ErrInternalError("failed to read response")
		}
		if resp.TLS.PeerCertificates[0].Subject.CommonName != KeyServerCertCommonName {
			return ErrInternalError("invalid common name for cert")
		}
		if !bytes.Equal(data, s.Hash[:]) {
			return ErrInternalError("hash not equal")
		}
		return nil
	}
	return ErrInternalError("set not loaded")
}
