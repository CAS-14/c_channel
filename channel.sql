CREATE TABLE users(
    id INTEGER PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    level INTEGER NOT NULL,
    created INTEGER NOT NULL,
    last_login INTEGER,
    first_ip TEXT,
    last_ip TEXT
);

CREATE TABLE posts(
    id INTEGER PRIMARY KEY NOT NULL,
    board TEXT NOT NULL,
    thread INTEGER NOT NULL,
    old_filename TEXT,
    filename TEXT,
    filesize TEXT,
    fileres TEXT,
    comment TEXT,
    subject TEXT,
    author TEXT,
    mod_id INTEGER,
    parent INTEGER,
    pinned INTEGER,
    locked INTEGER,
    time INTEGER NOT NULL,
    bump INTEGER,
    ip TEXT NOT NULL,
    deletion TEXT,
    deletion_time INTEGER,
    FOREIGN KEY(parent) REFERENCES posts(id),
    FOREIGN KEY(mod_id) REFERENCES users(id)
);

CREATE TABLE bans(
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    given INTEGER NOT NULL,
    expires INTEGER NOT NULL,
    board TEXT,
    FOREIGN KEY(board) REFERENCES boards(name)
);

CREATE TABLE watchlist(
    ip TEXT NOT NULL UNIQUE,
    ban_hours INTEGER NOT NULL DEFAULT 0,
    site_bans INTEGER NOT NULL DEFAULT 0,
    board_bans INTEGER NOT NULL DEFAULT 0,
    first_banned INTEGER,
    last_banned INTEGER,
    reasons TEXT,
    note TEXT
);

CREATE TABLE boards(
    name TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    css_file TEXT,
    rules TEXT
);

CREATE TABLE logs(
    id INTEGER PRIMARY KEY NOT NULL,
    ip TEXT NOT NULL,
    user INTEGER,
    action TEXT NOT NULL,
    description TEXT NOT NULL,
    time INTEGER NOT NULL,
    FOREIGN KEY(user) REFERENCES users(id)
);