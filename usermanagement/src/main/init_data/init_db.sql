CREATE database usermanagement_db

INSERT INTO roles(role_type) VALUES ('USER')
INSERT INTO roles(role_type) VALUES ('MODERATOR')
INSERT INTO roles(role_type) VALUES ('ADMIN')

SELECT * FROM roles