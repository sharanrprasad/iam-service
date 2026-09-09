package dtos

import "testing"

// validReq returns an AuthorizeRequest that passes every check; each test case
// mutates one field to isolate the rule under test.
func validReq() AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "spa-web",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "billing:invoices:read openid",
		State:               "3f9c2a1b8e",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // 43 chars
		CodeChallengeMethod: "S256",
	}
}

func TestAuthorizeRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*AuthorizeRequest)
		wantField string // "" => expect valid
	}{
		{"valid", func(*AuthorizeRequest) {}, ""},
		{"missing response_type", func(r *AuthorizeRequest) { r.ResponseType = "" }, "response_type"},
		{"wrong response_type", func(r *AuthorizeRequest) { r.ResponseType = "token" }, "response_type"},
		{"missing client_id", func(r *AuthorizeRequest) { r.ClientID = "" }, "client_id"},
		{"missing redirect_uri", func(r *AuthorizeRequest) { r.RedirectURI = "" }, "redirect_uri"},
		{"relative redirect_uri", func(r *AuthorizeRequest) { r.RedirectURI = "/callback" }, "redirect_uri"},
		{"http redirect_uri", func(r *AuthorizeRequest) { r.RedirectURI = "http://app.example.com/cb" }, "redirect_uri"},
		{"http loopback redirect_uri ok", func(r *AuthorizeRequest) { r.RedirectURI = "http://127.0.0.1:8080/cb" }, ""},
		{"redirect_uri with fragment", func(r *AuthorizeRequest) { r.RedirectURI = "https://app.example.com/cb#x" }, "redirect_uri"},
		{"missing state", func(r *AuthorizeRequest) { r.State = "" }, "state"},
		{"short state", func(r *AuthorizeRequest) { r.State = "abc" }, "state"},
		{"missing code_challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "" }, "code_challenge"},
		{"short code_challenge", func(r *AuthorizeRequest) { r.CodeChallenge = "tooshort" }, "code_challenge"},
		{"plain challenge method rejected", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, "code_challenge_method"},
		{"missing challenge method", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "" }, "code_challenge_method"},
		{"empty scope ok", func(r *AuthorizeRequest) { r.Scope = "" }, ""},
		{"multi-value prompt ok", func(r *AuthorizeRequest) { r.Prompt = "login consent" }, ""},
		{"bad access_type", func(r *AuthorizeRequest) { r.AccessType = "sometimes" }, "access_type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validReq()
			tc.mutate(&req)

			errs := req.Validate()

			if tc.wantField == "" {
				if errs != nil {
					t.Fatalf("expected valid, got errors: %v", errs)
				}
				return
			}
			if _, ok := errs[tc.wantField]; !ok {
				t.Fatalf("expected an error on %q, got: %v", tc.wantField, errs)
			}
		})
	}
}
