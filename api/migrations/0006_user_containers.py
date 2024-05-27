from yoyo import step

step("""
CREATE TABLE user_containers (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id),
container_name VARCHAR(128) NOT NULL,
ec2_instance INTEGER REFERENCES ec2_instances(id)
)
"""
)