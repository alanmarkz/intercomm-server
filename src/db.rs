use rusqlite::{Connection, Result};

pub fn db_initialize() -> Result<()> {
    let conn = Connection::open("intercomm.db").expect("Failed to create or open database");

    conn.execute("PRAGMA foreign_keys = ON;", [])?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS USERS (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        avatar_url TEXT,
        name TEXT NOT NULL,
        createdAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL
    )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS USER_SESSIONS (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    jwt TEXT NOT NULL,
    jwt_life TEXT NOT NULL,
    auth_at iNTEGER DEFAULT (strftime('%s', 'now')) NOT NULL
    )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS CHATS (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    senderId TEXT NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL

    )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS MESSAGES (
    id TEXT PRIMARY KEY,
    chatId TEXT NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
    modifiedAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
    message TEXT NOT NULL
    )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS PARTICIPANTS (
    id TEXT PRIMARY KEY,
    chatId TEXT NOT NULL,
    userId TEXT NOT NULL,
    joinedAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL
    )",
        [],
    )?;

    Ok(())
}
