package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// StringSlice is a []string that serializes to/from a JSON column in MySQL.
type StringSlice []string

func (s StringSlice) Value() (driver.Value, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (s *StringSlice) Scan(src any) error {
	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return fmt.Errorf("StringSlice: unsupported source type %T", src)
	}
	return json.Unmarshal(raw, s)
}

// Client represents an OAuth2 client application.
type Client struct {
	ID               string      `db:"id"`
	Name             string      `db:"name"`
	ClientSecretHash string      `db:"client_secret_hash"`
	RedirectURIs     StringSlice `db:"redirect_uris"`
	Scopes           StringSlice `db:"scopes"`
	GrantTypes       StringSlice `db:"grant_types"`
	IsFirstParty     bool        `db:"is_first_party"`
	CreatedAt        time.Time   `db:"created_at"`
}
