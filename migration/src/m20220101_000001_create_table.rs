use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20220101_000001_create_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let create_table_sql = r#"
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY NOT NULL,
                email TEXT,
                avatar_url TEXT,
                user_name TEXT,
                name TEXT,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            );

            CREATE TABLE IF NOT EXISTS USER_SESSIONS (
            id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            jwt TEXT NOT NULL,
            jwt_life TEXT NOT NULL,
            auth_at INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL
    );

    CREATE TABLE IF NOT EXISTS CHATS (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    senderId TEXT NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL

    );

    CREATE TABLE IF NOT EXISTS MESSAGES (
    id TEXT PRIMARY KEY NOT NULL,
    chatId TEXT NOT NULL,
    createdAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
    modifiedAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
    message TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS PARTICIPANTS (
    id TEXT PRIMARY KEY NOT NULL,
    chatId TEXT NOT NULL,
    userId TEXT NOT NULL,
    joinedAt INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL
    )
        "#;

        manager
            .get_connection()
            .execute_unprepared(create_table_sql)
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let drop_table_sql = r#"
    DROP TABLE IF EXISTS participants;
    DROP TABLE IF EXISTS messages;
    DROP TABLE IF EXISTS chats;
    DROP TABLE IF EXISTS user_sessions;
    DROP TABLE IF EXISTS users;
"#;
        manager
            .get_connection()
            .execute_unprepared(drop_table_sql)
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Users {
    Table,
    Id,
    Email,
    AvatarUrl,
    UserName,
    CreatedAt,
    name,
}
#[derive(Iden)]
pub enum UserSessions {
    Table,
    Id,
    UserId,
    DeviceId,
    Jwt,
    JwtLife,
    AuthAt,
}

#[derive(Iden)]
pub enum Chats {
    Table,
    Id,
    UserId,
    SenderId,
    CreatedAt,
}

#[derive(Iden)]
pub enum Messages {
    Table,
    Id,
    ChatId,
    CreatedAt,
    ModifiedAt,
    Message,
}

#[derive(Iden)]
pub enum Participants {
    Table,
    Id,
    ChatId,
    UserId,
    JoinedAt,
}
