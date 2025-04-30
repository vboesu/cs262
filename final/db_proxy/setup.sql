CREATE TABLE IF NOT EXISTS users (
        id VARCHAR NOT NULL, 
        username VARCHAR NOT NULL, 
        name VARCHAR NOT NULL, 
        password_hash VARCHAR NOT NULL, 
        created DATETIME NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
CREATE TABLE IF NOT EXISTS accounts (
        id VARCHAR NOT NULL, 
        user_id VARCHAR NOT NULL, 
        balance INTEGER NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES users (id)
);
CREATE TABLE IF NOT EXISTS posts (
        id VARCHAR NOT NULL, 
        user_id VARCHAR NOT NULL, 
        content VARCHAR NOT NULL, 
        created DATETIME NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES users (id)
);
CREATE TABLE IF NOT EXISTS comments (
        id VARCHAR NOT NULL, 
        post_id VARCHAR NOT NULL, 
        user_id VARCHAR NOT NULL, 
        content VARCHAR NOT NULL, 
        created DATETIME NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(post_id) REFERENCES posts (id), 
        FOREIGN KEY(user_id) REFERENCES users (id)
);
CREATE TABLE IF NOT EXISTS test (
        id VARCHAR NOT NULL, 
        test VARCHAR,
        PRIMARY KEY (id)
);