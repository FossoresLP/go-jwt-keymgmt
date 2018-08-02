package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"

	"github.com/2tvenom/cbor"
	"github.com/fossoreslp/go-jwt-keymgmt/jwk"
	"github.com/fossoreslp/go-uuid-v4"
	"github.com/pelletier/go-toml"
)

type configuration struct {
	validationKey ed25519.PublicKey
	certPath      string
	keyPath       string
}

var config configuration
var set jwk.Set

func getKeys(w http.ResponseWriter, r *http.Request) {
	out, err := json.Marshal(set)
	if err != nil {
		HTTPWriteError(w, 500, "Key set could not be prepared for transmission.")
		return
	}
	w.Write(out) // nolint: errcheck
}

func getHash(w http.ResponseWriter, r *http.Request) {
	jsonSet, err := json.Marshal(set)
	if err != nil {
		HTTPWriteError(w, 500, "Failed to generate hash.")
		return
	}
	out := make([]byte, 64)
	sha3.ShakeSum256(out, jsonSet)
	w.Write(out) // nolint: errcheck
}

func addKey(w http.ResponseWriter, r *http.Request) {
	if len(config.validationKey) != ed25519.PublicKeySize {
		HTTPWriteError(w, 500, "This server is in READONLY mode. No keys can be added.")
	}
	var key []byte
	switch r.Header.Get("crv") {
	case "ed25519":
		key = make([]byte, ed25519.PublicKeySize)
		l, err := r.Body.Read(key)
		if err != nil || l != ed25519.PublicKeySize {
			HTTPWriteError(w, 400, "Key data is invalid.")
			return
		}
	case "ed448":
		HTTPWriteError(w, 415, "Ed448 is not supported, yet.")
		return
	default:
		HTTPWriteError(w, 415, "Key type not supported. Please use ed25519.")
		return
	}
	r.Body.Close() // nolint: errcheck
	if !ed25519.Verify(config.validationKey, key, []byte(r.Header.Get("signature"))) {
		HTTPWriteError(w, 403, "Request signature invalid or missing.")
		return
	}
	kid, err := uuid.New()
	if err != nil {
		HTTPWriteError(w, 500, "Could not generate key ID")
		return
	}
	set.Keys = append(set.Keys, *jwk.NewJWK(jwk.Ed25519, key, kid))
	var buf bytes.Buffer
	enc := cbor.NewEncoder(&buf)
	ok, err := enc.Marshal(set)
	if !ok || err != nil {
		HTTPWriteError(w, 500, "Failed to encode key set")
		return
	}
	err = ioutil.WriteFile("keys.cbor", buf.Bytes(), 0600)
	if err != nil {
		HTTPWriteError(w, 500, "Failed to store key set")
		return
	}
	w.Write([]byte(kid.String())) // nolint: errcheck
}

func main() {
	cfg, err := toml.LoadFile("config.toml")
	if err != nil {
		log.Fatalln("Could not read config file: ", err.Error())
	}
	err = cfg.Unmarshal(&config)
	if err != nil {
		log.Fatalln("Could not parse config file: ", err.Error())
	}
	if len(config.validationKey) != ed25519.PublicKeySize {
		log.Println("Could not read verification key. Entering READ ONLY mode.")
	}
	encodedKeySet, err := ioutil.ReadFile("keys.cbor")
	if err != nil && !os.IsNotExist(err) {
		log.Fatalln("Could not read key set: ", err.Error())
	}
	if !os.IsNotExist(err) {
		var buf bytes.Buffer
		enc := cbor.NewEncoder(&buf)
		ok, err := enc.Unmarshal(encodedKeySet, &set)
		if !ok || err != nil {
			log.Fatalln("Could not parse key set: ", err.Error())
		}
	}

	http.HandleFunc("/", getKeys)
	http.HandleFunc("/hash", getHash)
	http.HandleFunc("/add", addKey)

	log.Fatal(http.ListenAndServeTLS(":2461", config.certPath, config.keyPath, nil))
}

// HTTPWriteError is a helper function to send an http error.
func HTTPWriteError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	w.Write([]byte(msg)) // nolint: errcheck
}
