use sea_orm::{
    ColumnTrait, DatabaseBackend, DatabaseConnection, DbBackend, EntityTrait, FromQueryResult,
    JoinType, QueryFilter, Statement,
};
use serde::{Deserialize, Serialize};

use crate::{auth::decode_jwt, chats, participants};
use sea_orm::{DbConn, QuerySelect};

pub async fn get_user_chats(token: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

    println!("{}", user_id);
    let result = Chats::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"SELECT 
            chats.id AS id, 
            friendName.name AS friend, 
            friendName.id AS friend_id,
            participants.joinedAt AS joinedAt  
        FROM 
            chats 
        LEFT JOIN 
            participants ON participants.chatId = chats.id 
        LEFT JOIN 
            users AS friendName ON friendName.id = participants.userId 
        WHERE 
            chats.user_id = $1;"#,
        [user_id.into()],
    ))
    .all(conn)
    .await;

    let user_chats = result.unwrap_or_else(|e| {
        eprintln!("Error fetching user chats: {}", e);
        Vec::new()
    });

    let user_json = serde_json::to_string(&user_chats);
    user_json.unwrap()
}

#[derive(Debug, FromQueryResult, Serialize, Deserialize)]
pub struct Chats {
    id: String,
    friend: String,
    friend_id: String,
    joinedAt: i32,
}

pub async fn post_chats(token: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;
    let user_id = decode_jwt(token).unwrap().sub;

    println!("{}", user_id);
    let result = Chats::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"SELECT 
            chats.id AS id, 
            friendName.name AS friend, 
            friendName.id AS friend_id,
            participants.joinedAt AS joinedAt  
        FROM 
            chats 
        LEFT JOIN 
            participants ON participants.chatId = chats.id 
        LEFT JOIN 
            users AS friendName ON friendName.id = participants.userId 
        WHERE 
            chats.user_id = $1;"#,
        [user_id.into()],
    ))
    .all(conn)
    .await;

    let user_chats = result.unwrap_or_else(|e| {
        eprintln!("Error fetching user chats: {}", e);
        Vec::new()
    });

    let user_json = serde_json::to_string(&user_chats);
    user_json.unwrap()
}
