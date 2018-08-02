package jwk

import (
	"github.com/fossoreslp/go-uuid-v4"
)

// EdDSACurve is used to represent all curves supported in JWKs with keytype OKP as per RFC8037.
type EdDSACurve string

// Ed25519 is a twisted Edwards curve with approx. 128 bits of security.
const Ed25519 EdDSACurve = "Ed25519"

// Ed448 is an Edwards curve with approx. 224 bits of security.
const Ed448 EdDSACurve = "Ed448"

// JWK represents a JSON Web Key used for verifying JSON Web Signatures.
type JWK struct {
	Kty    string     `json:"kty"`
	Crv    EdDSACurve `json:"crv"`
	X      []byte     `json:"x"`
	Use    string     `json:"use"`
	KeyOps string     `json:"key_ops"`
	Alg    string     `json:"alg"`
	Kid    uuid.UUID  `json:"kid"`
}

// NewJWK generates a new JWK usable for verification of JSON Web Signatures.
// The recommmended curves are supplied as constants in this package.
//	jwk.Ed25519, jwk.Ed448
// You may define new curves using the type
//	jwk.EdDSACurve
// which is derived from a string.
func NewJWK(curve EdDSACurve, key []byte, keyID uuid.UUID) *JWK {
	return &JWK{"OKP", curve, key, "sig", "verify", "EdDSA", keyID}
}

// Set is a set of JSON Web Keys with an added issuer key
type Set struct {
	Iss  string `json:"iss"`
	Keys []JWK  `json:"keys"`
	Sup  bool   `json:"jwt-validator.fossores.de"`
}
