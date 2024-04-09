from yoyo import step

step("""
CREATE TABLE users (
id INT AUTO_INCREMENT PRIMARY KEY, 
username VARCHAR(50) NOT NULL UNIQUE, 
password VARCHAR(255) NOT NULL, 
email VARCHAR(255) NOT NULL, 
is_active BOOLEAN NOT NULL DEFAULT TRUE
)
"""
)
