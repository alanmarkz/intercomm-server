use crate::auth::{self, decode_jwt, GithubTokenResponse};
use crate::chat::{fetch_messages, send_chats};
use crate::{chat, messages, AppState};
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
                            "http://192.168.0.109:3000/callback?token={}&expires={}",
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

#[get("/get_users")]
async fn get_users(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let conn = &data.conn;
    // Extract the cookie named "auth_token"

    if let Some(auth_cookie) = req.cookie("authToken") {
        let token = auth_cookie.value();

        // Here you would typically validate the token (e.g., checking expiration, signature, etc.)
        // For demonstration, we'll assume the token is valid if it exists
        if auth::authorize_user(token, conn).await {
            let result = chat::get_users(token, conn).await;

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

// #[post("/post_messages")]
// async fn post_messages(body: web::Json<TokenData>, data: web::Data<AppState>) -> impl Responder {
//     // Extract the token from the query parameters

//     let conn = &data.conn;
//     if auth::validate_token_logic(auth_token, conn).await {
//         return HttpResponse::Ok().json("Token is valid");
//     } else {
//         return HttpResponse::Unauthorized().json("Invalid token");
//     }

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

#[get("/chat_server/{h}")]
pub async fn chat_socket(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let (res, mut session, stream) = actix_ws::handle(&req, stream)?;

    println!("connected...");
    let mut stream = stream
        .aggregate_continuations()
        // aggregate continuation frames up to 1MiB
        .max_continuation_size(2_usize.pow(20));

    let b = req.uri().to_owned().to_string();

    rt::spawn(async move {
        // receive messages from websocket
        let mut a = 5; // start task but don't wait for it
        loop {
            session.text(b.as_str()).await.unwrap();
            a = a - 1;
            print!("{a}");
            if a == 0 {
                break;
            }
        }
        while let Some(msg) = stream.next().await {
            let conn = &data.conn;

            match msg {
                Ok(AggregatedMessage::Text(text)) => {
                    let mut mystream = data.socket_maps.lock().await;
                    if let Some(auth_cookie) = req.cookie("authToken") {
                        let token = auth_cookie.value();

                        let myId = decode_jwt(token).unwrap();

                        mystream.insert(myId.sub, session.clone());

                        let chat_data: ChatData = serde_json::from_str(&text).unwrap();

                        if auth::authorize_user(token, conn).await {
                            send_chats(token, &chat_data, conn).await;
                        }

                        let youstream = mystream.get_key_value(&chat_data.receiver_id).unwrap();

                        match youstream.1.to_owned().text(text).await {
                            Ok(_) => println!("Sucess"),
                            Err(e) => println!("Fuckup,{}", e),
                        };
                    }
                }

                _ => {}
            }
        }
    });

    // respond immediately with response connected to WS session
    Ok(res)
}

#[post("/get_messages")]
async fn get_messages(
    req: HttpRequest,
    body: web::Json<ReceipientData>,
    data: web::Data<AppState>,
) -> impl Responder {
    if let Some(auth_cookie) = req.cookie("authToken") {
        let conn = &data.conn;
        let token = auth_cookie.value();
        println!("{token} stock");
        let receipient_id = &body.receipient_id;

        if auth::authorize_user(token, conn).await {
            let result = fetch_messages(token, &receipient_id, conn).await;
            return HttpResponse::Ok().body(format!("{}", result));
        } else {
            return HttpResponse::Unauthorized().body("Invalid token");
        }
    }
    return HttpResponse::Unauthorized().body("Invalid token");
}

#[derive(Deserialize)]
struct TokenData {
    authToken: String,
}

#[derive(Deserialize)]
struct ReceipientData {
    receipient_id: String,
}

#[derive(Deserialize)]
struct PostData {
    chat_id: String,
    friend_id: String,
    message_id: String,
}

#[derive(Deserialize, Debug)]
pub struct ChatData {
    pub receiver_id: String,
    pub message: String,
}
