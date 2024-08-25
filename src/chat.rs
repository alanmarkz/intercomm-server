use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::{auth::decode_jwt, chats};

pub async fn get_user_chats(token: &str, conn: &DatabaseConnection) -> String {
    let user_id = decode_jwt(token).unwrap().sub;

    println!("{}", user_id);

    let result = chats::Entity::find()
        .filter(chats::Column::UserId.eq(user_id))
        .all(conn)
        .await;

    let user_chats = result.unwrap_or_else(|e| {
        eprintln!("Error fetching user chats: {}", e);
        Vec::new()
    });

    let user_json = serde_json::to_string(&user_chats);
    user_json.unwrap()
}
