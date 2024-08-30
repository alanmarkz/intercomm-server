use crate::api::ChatData;
use crate::{auth::decode_jwt, chats, participants};
use crate::{messages, users};

use cuid::{cuid1_slug, cuid2};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseBackend, DatabaseConnection, DbBackend,
    EntityTrait, FromQueryResult, JoinType, QueryFilter, QueryTrait, Statement,
};
use sea_orm::{DbConn, QuerySelect};
use serde::{Deserialize, Serialize};

pub async fn get_user_chats(token: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

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

pub async fn send_chats(token: &str, messages: ChatData, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

    let chat_id = cuid1_slug().unwrap();

    let insertChat = chats::ActiveModel {
        id: ActiveValue::set(chat_id.clone()),
        user_id: ActiveValue::set(user_id),
        sender_id: ActiveValue::set(cuid::cuid2_slug()),
        ..Default::default()
    };

    let insertMessage = messages::ActiveModel {
        id: ActiveValue::set(cuid::cuid2_slug()),
        message: ActiveValue::set(messages.message),
        chat_id: ActiveValue::set(chat_id.clone()),
        ..Default::default()
    };

    let insert_participant = participants::ActiveModel {
        id: ActiveValue::set(cuid::cuid2_slug()),
        chat_id: ActiveValue::set(chat_id),
        user_id: ActiveValue::set(messages.receiver_id),
        ..Default::default()
    };
    insertMessage.insert(conn).await;
    insertChat.insert(conn).await;
    insert_participant.insert(conn).await;

    // let user_chats = result.unwrap_or_else(|e| {
    //     eprintln!("Error fetching user chats: {}", e);
    //     Vec::new()
    // });
    "print".to_owned()
}

pub async fn get_users(token: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

    let users = users::Entity::find()
        .filter(users::Column::Id.ne(user_id))
        .all(conn)
        .await;

    let user_chats = users.unwrap_or_else(|e| {
        eprintln!("Error fetching user chats: {}", e);
        Vec::new()
    });

    let users_json = serde_json::to_string(&user_chats).unwrap(); // let user_chats = result.
    users_json
}

pub async fn fetch_messages(token: &str, receiverid: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

    let hismessages = UserMessages::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"
       WITH mychats AS (
    SELECT
        chats.id as chatid
    FROM chats
    INNER JOIN participants ON participants.chatId = chats.id
    WHERE participants.userId = $2 AND chats.user_id = $1
), counterchats AS (
    SELECT
        chats.id as chatid
    FROM chats
    INNER JOIN participants ON participants.chatId = chats.id
    WHERE participants.userId = $1 AND chats.user_id = $2
)
    SELECT 
        messages.chatId as id,
        messages.message as mymessages,
        '' as theirmessage, 
        messages.createdAt as createdAt
    FROM messages 
    WHERE 
        messages.chatId IN (SELECT chatid FROM mychats)

    UNION ALL

    SELECT 
        messages.chatId as id,
        '' as mymessages,
        messages.message as theirmessage,
        messages.createdAt as createdAt
    FROM messages 
    WHERE 
        messages.chatId IN (SELECT chatid FROM counterchats)     
    
    ORDER BY createdAt;

    "#,
        [user_id.clone().into(), receiverid.into()],
    ))
    .all(conn)
    .await;

    let his_chats: Vec<UserMessages> = hismessages.unwrap_or_else(|e| {
        eprintln!("Error fetching his messages: {}", e);
        Vec::new()
    });

    // Combine the vectors

    let users_json = serde_json::to_string(&his_chats).unwrap(); // let user_chats = result.
    users_json
}

#[derive(Debug, FromQueryResult, Serialize, Deserialize)]
struct UserMessages {
    id: String,
    mymessages: String,
    theirmessage: String,
    createdAt: i32,
}
