from yoyo import step

step("""
CREATE TABLE aws_credentials (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
aws_access_key_id VARCHAR(128) NOT NULL,
aws_secret_access_key VARCHAR(256) NOT NULL,
preferred_aws_region VARCHAR(50)
)
"""
)
