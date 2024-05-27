from yoyo import step

step("""
CREATE TABLE ec2_instances (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
ec2_instance_id VARCHAR(256),
security_group INTEGER REFERENCES security_groups(id),
key_file INTEGER REFERENCES ec2_key_pair(id)
)
"""
)
