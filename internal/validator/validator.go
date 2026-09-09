// Package validator wraps github.com/go-playground/validator with this
// project's conventions: one shared instance, error keys taken from the `form`
// struct tag, and errors flattened to a field->message map for JSON responses.
//
//	if errs := validator.Struct(req); errs != nil {
//	    // errs is map[string]string, keyed by the `form` tag name
//	}
package validator

import (
	"net/url"
	"reflect"
	"strings"

	gpv "github.com/go-playground/validator/v10"
)

var instance = newValidator()

func newValidator() *gpv.Validate {
	v := gpv.New(gpv.WithRequiredStructEnabled())

	// Use the `form` tag (the OAuth parameter name) as the field name in errors.
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		if name := strings.SplitN(f.Tag.Get("form"), ",", 2)[0]; name != "" && name != "-" {
			return name
		}
		return strings.ToLower(f.Name)
	})

	// The one rule that can't be expressed with built-in tags.
	if err := v.RegisterValidation("redirect_uri", validateRedirectURI); err != nil {
		panic(err)
	}
	return v
}

// Struct We can call the validate function from any struct.
func Struct(s any) map[string]string {
	err := instance.Struct(s)
	if err == nil {
		return nil
	}
	verrs, ok := err.(gpv.ValidationErrors)
	if !ok {
		panic(err) // non-struct argument
	}

	out := make(map[string]string, len(verrs))
	for _, fe := range verrs {
		if _, seen := out[fe.Field()]; !seen {
			out[fe.Field()] = message(fe)
		}
	}
	return out
}

// message renders a human-readable message for one failed rule.
func message(fe gpv.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "is required"
	case "min":
		return "must be at least " + fe.Param() + " characters"
	case "max":
		return "must be at most " + fe.Param() + " characters"
	case "oneof":
		return "must be one of: " + fe.Param()
	case "redirect_uri":
		return "must be an absolute https URI with no fragment (http allowed only for loopback)"
	default:
		return "is invalid"
	}
}

// validateRedirectURI enforces the transport rules for an OAuth redirect target:
// absolute, no fragment, https unless the host is a loopback address. Exact
// match against the client's registered URIs is a separate, server-side step.
func validateRedirectURI(fl gpv.FieldLevel) bool {
	raw := fl.Field().String()
	if raw == "" {
		return true // let `required` report emptiness
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return u.Scheme == "http" || u.Scheme == "https"
	default:
		return u.Scheme == "https"
	}
}
