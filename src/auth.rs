use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chrono::{DateTime, Utc};
use cuid::cuid2;
use dotenv::dotenv;
use reqwest::Client;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};
use serde::Deserialize;
use serde_json::Value;
use std::env;

use crate::user_sessions::Model as User_Sessions;
use crate::users::Model as Users;
use crate::{entities::users, user_sessions};

#[derive(Deserialize)]
pub struct GithubTokenResponse {
    pub access_token: String,
    pub token_type: String,
}

pub async fn github_authorize() -> String {
    dotenv().ok();
    let client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");

    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}",
        client_id
    );

    auth_url
}

pub async fn find_user_by_id(user_id: &str, conn: &DatabaseConnection) -> Option<Users> {
    let find_users = users::Entity::find()
        .filter(users::Column::UserName.eq(user_id))
        .one(conn)
        .await
        .unwrap();

    find_users
}

pub async fn create_user(data: Value, conn: &DatabaseConnection) -> Result<Users, DbErr> {
    let insert_user = users::ActiveModel {
        id: sea_orm::ActiveValue::Set(cuid::cuid2_slug()),
        user_name: sea_orm::ActiveValue::Set(Some(data["login"].as_str().unwrap().to_owned())),
        email: sea_orm::ActiveValue::Set(Some(data["email"].as_str().unwrap().to_owned())),
        name: sea_orm::ActiveValue::Set(Some(data["name"].as_str().unwrap().to_owned())),
        avatar_url: sea_orm::ActiveValue::Set(Some(
            data["avatar_url"].as_str().unwrap().to_owned(),
        )),
        ..Default::default()
    };

    let result = insert_user.insert(conn).await;

    result
}

pub async fn create_session(
    user: Users,
    conn: &DatabaseConnection,
) -> Result<(User_Sessions, usize), DbErr> {
    let id = cuid::cuid2_slug();

    let (jwt, exp) = create_jwt(&user.id);

    match decode_jwt(&jwt) {
        Ok(claims) => {
            println!("Subject (user ID): {}", claims.sub);
            println!("Exp: {}", claims.exp)
        }
        Err(err) => println!("Failed to decode JWT: {}", err),
    }

    let insert_session = user_sessions::ActiveModel {
        id: sea_orm::ActiveValue::Set(id),
        user_id: sea_orm::ActiveValue::Set(user.id),
        jwt: sea_orm::ActiveValue::Set(jwt),
        jwt_life: sea_orm::ActiveValue::Set(exp.to_string()),
        device_id: sea_orm::ActiveValue::Set("windows".to_owned()),
        ..Default::default()
    };

    let result = insert_session.insert(conn).await;

    Ok((result.unwrap(), exp))
}

use jsonwebtoken::{
    decode, encode, errors::Result as JwtResult, DecodingKey, EncodingKey, Header, Validation,
};
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    exp: usize, // Expiration time as a UNIX timestamp
}

// Change this to a secure secret

pub fn create_jwt(sub: &str) -> (String, usize) {
    let jwt_secret = env::var("AUTH_SECRET").expect("AUTH_SECRET not set");
    let claims = Claims {
        sub: sub.to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as usize,
    };
    let encoding_key = EncodingKey::from_secret(jwt_secret.as_ref());
    let key = encode(&Header::default(), &claims, &encoding_key).unwrap();

    (key, claims.exp)
}

pub fn decode_jwt(token: &str) -> JwtResult<Claims> {
    let jwt_secret = env::var("AUTH_SECRET").expect("AUTH_SECRET not set");
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    decode::<Claims>(token, &decoding_key, &Validation::default()).map(|data| data.claims)
}

pub fn is_token_expired(expiration_time: usize) -> bool {
    let current_time = Utc::now().timestamp();
    expiration_time as i64 > current_time
}

pub async fn authorize_user(token: &str, conn: &DatabaseConnection) -> bool {
    let claims: Claims = decode_jwt(token).unwrap();

    if is_token_expired(claims.exp) {
        println!("Token is still valid.");
    } else {
        println!("Token is expired");
        return false;
    }

    let user_id = claims.sub;

    let find_user = user_sessions::Entity::find()
        .filter(user_sessions::Column::UserId.eq(user_id))
        .one(conn)
        .await;

    match find_user {
        Ok(i) => match i {
            Some(i) => is_token_expired(i.jwt_life.parse().unwrap_or(0)),
            None => false,
        },
        Err(_) => false,
    }
}
