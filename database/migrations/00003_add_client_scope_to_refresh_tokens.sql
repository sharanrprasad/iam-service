-- +goose Up
-- +goose StatementBegin
ALTER TABLE refresh_tokens
    ADD COLUMN client_id CHAR(36) NOT NULL DEFAULT '' AFTER user_id,
    ADD COLUMN scope     JSON     NOT NULL DEFAULT (JSON_ARRAY()) AFTER client_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE refresh_tokens
    DROP COLUMN scope,
    DROP COLUMN client_id;
-- +goose StatementEnd
