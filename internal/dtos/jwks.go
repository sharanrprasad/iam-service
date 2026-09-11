package dtos

// JWK is a single RSA public key in JSON Web Key format (RFC 7517), the shape
// GET /.well-known/jwks.json returns for RS256 verification.
type JWK struct {
	Kty string `json:"kty"` // "RSA"
	Use string `json:"use"` // "sig" — signing, never encryption
	Alg string `json:"alg"` // "RS256"
	Kid string `json:"kid"` // RFC 7638 thumbprint; stable per key, changes on rotation
	N   string `json:"n"`   // modulus, base64url, no padding
	E   string `json:"e"`   // public exponent, base64url, no padding
}

// JWKSResponse is the body of GET /.well-known/jwks.json (RFC 7517 §5).
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}
