use crate::auth::{self, GithubTokenResponse};
use crate::chat::send_chats;
use crate::{chat, AppState};
use actix_web::http::header;
use actix_web::{post, rt, Error};

use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use actix_ws::AggregatedMessage;
use core::str;
use dotenv::dotenv;
use futures_util::StreamExt;
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
    dotenv().ok();
    let client_id = env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set");

    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}",
        client_id
    );

    println!("Auth request");
    // Replace with your desired URL

    HttpResponse::Found()
        .insert_header((header::LOCATION, auth_url))
        .finish()
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
    dotenv().ok();
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
                Ok(token) => HttpResponse::Found()
                    .insert_header((
                        "Location",
                        format!(
                            "http://localhost:3000/callback?token={}&expires={}",
                            token.jwt, token.jwt_life
                        ),
                    ))
                    .finish(),
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

#[derive(serde::Deserialize)]
struct AuthUserRequest {
    name: String,
    avatar_url: String,
    email: String,
}

#[get("/getchatmessages")]
async fn get_chat_messages(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let conn = &data.conn;
    // Extract the cookie named "auth_token"

    if let Some(auth_cookie) = req.cookie("authToken") {
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

#[get("/getchats")]
async fn get_chats(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let conn = &data.conn;
    // Extract the cookie named "auth_token"

    if let Some(auth_cookie) = req.cookie("authToken") {
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

#[get("/postchats")]
async fn post_chats(
    req: HttpRequest,
    body: web::Json<PostData>,
    data: web::Data<AppState>,
) -> impl Responder {
    let conn = &data.conn;
    // Extract the cookie named "auth_token"

    if let Some(auth_cookie) = req.cookie("authToken") {
        let token = auth_cookie.value();

        // Here you would typically validate the token (e.g., checking expiration, signature, etc.)
        // For demonstration, we'll assume the token is valid if it exists
        if auth::authorize_user(token, conn).await {
            let result = chat::post_chats(token, conn).await;

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

#[post("/post_messages")]
async fn post_messages(body: web::Json<TokenData>, data: web::Data<AppState>) -> impl Responder {
    // Extract the token from the query parameters

    let auth_token = &body.authToken;

    let conn = &data.conn;
    if auth::validate_token_logic(auth_token, conn).await {
        return HttpResponse::Ok().json("Token is valid");
    } else {
        return HttpResponse::Unauthorized().json("Invalid token");
    }
}

#[post("/validatetoken")]
async fn validate_token(body: web::Json<TokenData>, data: web::Data<AppState>) -> impl Responder {
    // Extract the token from the query parameters

    let auth_token = &body.authToken;

    let conn = &data.conn;
    if auth::validate_token_logic(auth_token, conn).await {
        return HttpResponse::Ok().json("Token is valid");
    } else {
        return HttpResponse::Unauthorized().json("Invalid token");
    }
}

#[get("/chat/{chatid}")]
pub async fn chat_socket(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let (res, mut session, stream) = actix_ws::handle(&req, stream)?;

    if let Some(token) = req.cookie("authToken") {
        let token = token.value();

        println!("{token}")
    }

    let mut stream = stream
        .aggregate_continuations()
        // aggregate continuation frames up to 1MiB
        .max_continuation_size(2_usize.pow(20));

    // start task but don't wait for it
    rt::spawn(async move {
        // receive messages from websocket

        while let Some(msg) = stream.next().await {
            let conn = &data.conn;
            match msg {
                Ok(AggregatedMessage::Text(text)) => {
                    if let Some(auth_cookie) = req.cookie("authToken") {
                        let token = auth_cookie.value();
                        println!("{token} stock");
                        if auth::authorize_user(token, conn).await {
                            send_chats(token, text.to_string(), conn).await;
                            session.text(text).await.unwrap()
                        }
                    }
                }

                _ => {}
            }
        }
    });

    // respond immediately with response connected to WS session
    Ok(res)
}

#[derive(Deserialize)]
struct TokenData {
    authToken: String,
}

#[derive(Deserialize)]
struct PostData {
    chat_id: String,
    friend_id: String,
    message_id: String,
}
