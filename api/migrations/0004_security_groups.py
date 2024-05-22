from yoyo import step

step("""
CREATE TABLE security_groups (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
security_group_name VARCHAR(128),
security_group_id VARCHAR(128)
)
"""
)