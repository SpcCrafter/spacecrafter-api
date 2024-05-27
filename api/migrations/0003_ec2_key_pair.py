from yoyo import step

step("""
CREATE TABLE ec2_key_pair (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
key_pair VARCHAR(128) NOT NULL,
s3_file_path VARCHAR(128) NOT NULL
)
"""
)