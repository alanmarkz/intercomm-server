mod api;
mod chat;
use std::{collections::HashMap, sync::Arc};

use actix_cors::Cors;
mod db_sea;
use actix_web::{http, main, middleware, web, App, HttpServer};

use sea_orm::*;

mod auth;

mod entities;
use entities::*;

#[main]
async fn main() -> std::io::Result<()> {
    println!("Starting server...");

    let db = Database::connect("sqlite://itercomm-main.db?mode=rwc")
        .await
        .unwrap();

    let state = AppState { conn: db };
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:3000")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![
                        http::header::AUTHORIZATION,
                        http::header::CONTENT_TYPE,
                    ])
                    .supports_credentials(), // You can restrict headers here
            )
            .configure(init)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}

fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(api::auth_user);
    cfg.service(api::query_user_data);

    cfg.service(api::github_callback);
    cfg.service(api::validate_token);
    cfg.service(api::chat_socket);
    cfg.service(api::get_users);
    cfg.service(api::get_messages);
}

type WebSocketSession = actix_ws::Session;
type SessionId = String;

#[derive(Clone)]
struct AppState {
    conn: DatabaseConnection,
}
