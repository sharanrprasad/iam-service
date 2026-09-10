package dtos

import "testing"

func TestTokenRequest_Validate(t *testing.T) {
	cases := []struct {
		name  string
		req   TokenRequest
		field string // "" => valid
	}{
		{"valid auth code", TokenRequest{GrantType: "authorization_code", Code: "abc", RedirectURI: "https://a/cb", CodeVerifier: "0123456789012345678901234567890123456789012", ClientID: "spa"}, ""},
		{"auth code missing code", TokenRequest{GrantType: "authorization_code", RedirectURI: "https://a/cb", CodeVerifier: "0123456789012345678901234567890123456789012"}, "code"},
		{"auth code short verifier", TokenRequest{GrantType: "authorization_code", Code: "abc", RedirectURI: "https://a/cb", CodeVerifier: "tooshort"}, "code_verifier"},
		{"valid refresh", TokenRequest{GrantType: "refresh_token", RefreshToken: "r"}, ""},
		{"refresh missing token", TokenRequest{GrantType: "refresh_token"}, "refresh_token"},
		{"missing grant_type", TokenRequest{}, "grant_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.req.Validate()
			if c.field == "" {
				if errs != nil {
					t.Fatalf("want valid, got %v", errs)
				}
				return
			}
			if _, ok := errs[c.field]; !ok {
				t.Fatalf("want error on %q, got %v", c.field, errs)
			}
		})
	}
}
