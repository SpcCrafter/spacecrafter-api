from yoyo import step

step("""
CREATE TABLE kms_keys (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
key_alias VARCHAR(128) NOT NULL,
key_id VARCHAR(128) NOT NULL
)
"""
)