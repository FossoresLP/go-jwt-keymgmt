package generator

import (
	"bytes"
	"crypto/rand"
	"errors"
	"net/http"

	"golang.org/x/crypto/ed25519"

	"github.com/fossoreslp/go-jwt-ed25519"
	"github.com/fossoreslp/go-uuid-v4"
)

// Signer is the type used to store the JWT generator
type Signer struct {
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	keyID        uuid.UUID
	keyServerURL string
}

// NewKeySet takes a keyserver URL and creates a Signer with a new set of public and private keys.
// It also submits the public key to the keyserver.
func NewKeySet(keyServerURL string) (*Signer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	pubReader := bytes.NewReader(publicKey)
	resp, err := http.Post(keyServerURL, "application/octet-stream", pubReader)
	if err != nil {
		return nil, err
	}
	rawBody := make([]byte, 36)
	l, err := resp.Body.Read(rawBody)
	if err != nil {
		return nil, err
	}
	if l != 36 {
		return nil, errors.New("key ID has wrong length")
	}
	keyID, err := uuid.Parse(string(rawBody))
	if err != nil {
		return nil, err
	}
	jwt.Setup(privateKey)
	return &Signer{privateKey, publicKey, keyID, keyServerURL}, nil
}

// NewJWT takes the desired content as an argument and generates a JWT with key ID and keyserver URL set by this package.
// It may return an error in case it is not possible to generate a JWT for some reason.
func (sig *Signer) NewJWT(content interface{}) (jwt.JWT, error) {
	return jwt.NewWithKeyIDAndKeyURL(content, sig.keyID.String(), sig.keyServerURL)
}

// SafeExit should be deferred when calling NewKeySet as it securely erases the keys from memory and hopefully also from swap files in case they were paged out.
// It currently overwrites the keys with random data (or zero data in case a crypto/rand fails) 10 times. This might be overkill but it only runs once so there shouldn't be any issues.
func (sig *Signer) SafeExit() {
	for i := 0; i < 10; i++ {
		_, err := rand.Read(sig.publicKey)
		if err != nil {
			sig.publicKey = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
		}

		_, err = rand.Read(sig.privateKey)
		if err != nil {
			sig.privateKey = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
		}
	}
	if sig.publicKey == nil || sig.privateKey == nil {
		panic("something failed")
	}
}
