-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS clients (
    id                CHAR(36)     PRIMARY KEY,
    name              VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255) NOT NULL,
    redirect_uris     JSON         NOT NULL,
    scopes            JSON         NOT NULL,
    grant_types       JSON         NOT NULL,
    is_first_party    TINYINT(1)   NOT NULL DEFAULT 0,
    created_at        DATETIME     DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS clients;
-- +goose StatementEnd

