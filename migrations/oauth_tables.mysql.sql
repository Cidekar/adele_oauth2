CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS
$$
BEGIN
	NEW.updated_at = NOW();
	RETURN NEW;
END;
$$
LANGUAGE
plpgsql;

drop table if exists oauth_clients cascade;

CREATE TABLE oauth_clients (
    id SERIAL PRIMARY KEY,
    user_id integer REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    name character varying(255) NOT NULL,
    type character varying(255) NOT NULL,
    secret character varying(255) NOT NULL,
    revoked integer NOT NULL DEFAULT 0,
    redirect_url TEXT DEFAULT '',
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp BEFORE
UPDATE ON oauth_clients FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp ();

drop table if exists tokens cascade;

CREATE TABLE tokens (
    id SERIAL PRIMARY KEY,
    user_id integer REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    client_id integer REFERENCES oauth_clients (id) ON DELETE CASCADE ON UPDATE CASCADE,
    scopes TEXT DEFAULT '',
    token character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now(),
    token_hash bytea NOT NULL,
    expiry timestamp without time zone NOT NULL
);

CREATE TRIGGER set_timestamp BEFORE
UPDATE ON tokens FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp ();

drop table if exists refresh_tokens cascade;

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY,
    access_token_id integer REFERENCES tokens (id) ON DELETE CASCADE ON UPDATE CASCADE,
    token character varying(255) NOT NULL,
    expiry timestamp without time zone NOT NULL,
    token_hash bytea NOT NULL,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp BEFORE
UPDATE ON refresh_tokens FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp ();

drop table if exists authorization_tokens cascade;

CREATE TABLE authorization_tokens (
    id SERIAL PRIMARY KEY,
    user_id integer REFERENCES users (id) ON DELETE CASCADE ON UPDATE CASCADE,
    client_id integer REFERENCES oauth_clients (id) ON DELETE CASCADE ON UPDATE CASCADE,
    token character varying(255) NOT NULL,
    token_hash bytea NOT NULL,
    expiry timestamp without time zone NOT NULL,
    challenge_code TEXT DEFAULT '',
    challenge_code_method TEXT DEFAULT '',
    scopes TEXT DEFAULT '',
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);

CREATE TRIGGER set_timestamp BEFORE
UPDATE ON authorization_tokens FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp ();
