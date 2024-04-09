from yoyo import step

step("""
CREATE TABLE aws_credentials (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
aws_access_key_id VARCHAR(128),
aws_secret_access_key VARCHAR(256),
)
"""
)
