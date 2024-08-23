use crate::auth::{self, GithubTokenResponse};
use crate::{chat, AppState};
use actix_web::web::Data;
use actix_web::{
    cookie::{time::OffsetDateTime, Cookie},
    get, web, HttpRequest, HttpResponse, Responder,
};
use reqwest::Client;

use serde::Deserialize;
use serde_json::Value;
use std::env;
#[derive(Deserialize)]

struct User {
    username: String,
    email: String,
    name: String,
}

#[get("/authuser")]
async fn auth_user() -> impl Responder {
    let res = auth::github_authorize().await;
    HttpResponse::Ok().body(format!("Push Auth {}", res))
}

#[get("/authusercallback")]
async fn github_callback(
    query: web::Query<std::collections::HashMap<String, String>>,
    data: web::Data<AppState>,
) -> impl Responder {
    let code = match query.get("code") {
        Some(code) => code,
        None => return HttpResponse::BadRequest().body("Missing code parameter"),
    };

    let conn = &data.conn;
    let client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");
    let client_secret = env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set");

    let client = Client::new();
    let token_response = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code.to_owned()),
        ])
        .send()
        .await
        .expect("Failed to get access token")
        .json::<GithubTokenResponse>()
        .await
        .expect("Failed to parse access token response");

    let token = token_response.access_token;

    // Fetch user info
    let user_info = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token))
        .header("User-Agent", "Actix OAuth Example")
        .send()
        .await
        .expect("Failed to get user info")
        .text()
        .await
        .expect("Failed to read user info");

    let struct_data: Value = serde_json::from_str(&user_info).expect("Failed to parse response");

    let user_name = struct_data["login"].as_str().unwrap();

    let is_user = auth::find_user_by_id(user_name, conn).await;

    match is_user {
        Some(user) => {
            println!("authenticating users :{:?}", user.user_name);
            match auth::create_session(user, conn).await {
                Ok((token, exp)) => {
                    let expires_at = OffsetDateTime::from_unix_timestamp(exp as i64).unwrap();
                    let cookie = Cookie::build("auth_token", token.jwt)
                        .path("/") // Set the path where the cookie is valid (optional)
                        .http_only(true)
                        .expires(expires_at) // Make the cookie HTTP-only (not accessible via JavaScript)
                        .finish();

                    HttpResponse::Ok()
                        .cookie(cookie)
                        .body("Session created successfully")
                }
                Err(err) => HttpResponse::InternalServerError()
                    .body(format!("Unable to create session: {}", err)),
            }
        }
        None => {
            println!("Creating new user");
            let status = auth::create_user(struct_data, conn).await;
            match status {
                Ok(status) => {
                    println!("User created successfully {}", status.id);
                    println!("Creating session",);
                    HttpResponse::Ok().body(format!("User Info: {}", user_info))
                }
                Err(err) => {
                    println!("Error creating user {}", err);
                    HttpResponse::InternalServerError().body(format!("Internal server error"))
                }
            }
        }
    }
}

#[get("/getchatmessages")]
async fn get_chat_messages(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let conn = &data.conn;
    // Extract the cookie named "auth_token"
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value();

        // Here you would typically validate the token (e.g., checking expiration, signature, etc.)
        // For demonstration, we'll assume the token is valid if it exists
        if auth::authorize_user(token, conn).await {
            let result = chat::get_user_chats(token, conn).await;
            return HttpResponse::Ok().body(format!("{}", result));
        } else {
            return HttpResponse::Unauthorized().body("Invalid token");
        }
    }

    // If no "auth_token" cookie is found
    HttpResponse::Unauthorized().body("No auth token found")
}

#[get("/queryuserdata")]
async fn query_user_data() -> impl Responder {
    HttpResponse::Ok().body("Authenticated")
}

#[get("/deletemessages")]
async fn delete_messages() -> impl Responder {
    HttpResponse::Ok().body("Authenticated")
}

#[get("/editmessage")]
async fn edit_message() -> impl Responder {
    HttpResponse::Ok().body("Authenticated")
}

#[get("/getusers")]
async fn get_user() -> impl Responder {
    HttpResponse::Ok().body("Authenticated")
}
