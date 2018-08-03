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

var privateKey ed25519.PrivateKey
var publicKey ed25519.PublicKey
var keyID uuid.UUID
var keyServerURL string

// NewKeySet takes a keyserver URL and generates a new set of public and private keys.
// It also submits the public key to the keyserver.
func NewKeySet(keyServer string) (err error) {
	keyServerURL = keyServer
	publicKey, privateKey, err = ed25519.GenerateKey(nil)
	if err != nil {
		return
	}
	pubReader := bytes.NewReader(publicKey)
	resp, err := http.Post(keyServerURL, "application/octet-stream", pubReader)
	if err != nil {
		return
	}
	rawBody := make([]byte, 36)
	l, err := resp.Body.Read(rawBody)
	if err != nil {
		return
	}
	if l != 36 {
		return errors.New("key ID has wrong length")
	}
	keyID, err = uuid.Parse(string(rawBody))
	if err != nil {
		return
	}
	jwt.Setup(privateKey)
	return nil
}

// NewJWT takes the desired content as an argument and generates a JWT with key ID and keyserver URL set by this package.
// It may return an error in case it is not possible to generate a JWT for some reason.
func NewJWT(content interface{}) (jwt.JWT, error) {
	return jwt.NewWithKeyIDAndKeyURL(content, keyID.String(), keyServerURL)
}

// SafeExit should be deferred when calling NewKeySet as it securely erases the keys from memory and hopefully also from swap files in case they were paged out.
// It currently overwrites the keys with random data (or zero data in case a crypto/rand fails) 10 times. This might be overkill but it only runs once so there shouldn't be any issues.
func SafeExit() {
	for i := 0; i < 10; i++ {
		_, err := rand.Read(publicKey)
		if err != nil {
			publicKey = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
		}

		_, err = rand.Read(privateKey)
		if err != nil {
			privateKey = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
		}
	}
	if publicKey == nil || privateKey == nil {
		panic("something failed")
	}
}
