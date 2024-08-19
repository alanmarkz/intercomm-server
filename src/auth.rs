use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use reqwest::Client;
use rusqlite::{params, Connection, Error, OptionalExtension, Result};
use serde::Deserialize;
use serde_json::Value;
use std::env;

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

pub fn find_user_by_id(user_id: &str) -> Option<User> {
    let conn = Connection::open("intercomm.db").expect("Failed to create or open database");
    let mut stmt = conn.prepare(
        "SELECT id, name,  username, avatar_url, email, createdAt FROM users WHERE username = ?1",
    ).expect("Failed to read database");

    let user = stmt
        .query_row(params![user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                name: row.get(1)?,
                username: row.get(2)?,
                avatar_url: row.get(3)?,
                email: row.get(4)?,
                createdAt: row.get(5)?,
            })
        })
        .optional();

    user.unwrap()
}

#[derive(Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub avatar_url: String,
    pub name: String,
    pub createdAt: i32,
}

pub async fn create_user(data: Value) -> Result<usize, rusqlite::Error> {
    let conn = Connection::open("intercomm.db").expect("Error connecting to database");

    let user_id = cuid::cuid2_slug();
    let user_name = data["login"].as_str().unwrap();
    let email = data["email"].as_str().unwrap();
    let name = data["name"].as_str().unwrap();
    let avatar_url = data["avatar_url"].as_str().unwrap();

    let result = conn.execute(
        "INSERT INTO USERS (id, username, email, name, avatar_url) VALUES(?1, ?2, ?3, ?4, ?5)",
        (user_id, user_name, email, name, avatar_url),
    );

    result
}

pub async fn create_session(user: User) -> Result<(String, usize), Error> {
    let id = cuid::cuid2_slug();
    let conn = Connection::open("intercomm.db").expect("Failed to create or open database");

    let (jwt, exp) = create_jwt(&user.id);

    match decode_jwt(&jwt) {
        Ok(claims) => {
            println!("Subject (user ID): {}", claims.sub);
            println!("Exp: {}", claims.exp)
        }
        Err(err) => println!("Failed to decode JWT: {}", err),
    }

    let result = conn.execute(
        "INSERT INTO USER_SESSIONS (id, user_id, device_id, jwt, jwt_life) VALUES(?1, ?2, ?3, ?4, ?5)",
        (id, user.id,"device".to_owned() ,&jwt, exp),
    );
    match result {
        Ok(_) => Ok((jwt, exp)), // Return the JWT if the insertion was successful
        Err(e) => Err(e),        // Propagate the error if something went wrong
    }
}

use jsonwebtoken::{
    decode, encode, errors::Result as JwtResult, DecodingKey, EncodingKey, Header, Validation,
};
use serde::Serialize;
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
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
