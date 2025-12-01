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

drop table if exists users cascade;

CREATE TABLE users (
    id SERIAL PRIMARY KEY, first_name character varying(255) NOT NULL, last_name character varying(255) NOT NULL, user_active integer NOT NULL DEFAULT 0, email character varying(255) NOT NULL UNIQUE, password character varying(60) NOT NULL, created_at timestamp without time zone NOT NULL DEFAULT now(), updated_at timestamp without time zone NOT NULL DEFAULT now()
);
