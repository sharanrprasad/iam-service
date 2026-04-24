-- +goose Up
-- +goose StatementBegin
CREATE TABLE oauth_clients
(
    id             CHAR(36) PRIMARY KEY,
    client_id      VARCHAR(100) UNIQUE NOT NULL, -- public identifier
    client_secret  VARCHAR(255)        NOT NULL, -- hashed
    name           VARCHAR(255)        NOT NULL,
    redirect_uris  JSON                NOT NULL, -- allowed callback URLs
    scopes         JSON                NOT NULL, -- "read:profile write:data"
    grant_types    JSON                NOT NULL, -- "authorization_code refresh_token"
    is_first_party BOOLEAN  DEFAULT FALSE,       -- skip consent screen
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE IF Exists oauth_clients
-- +goose StatementEnd
