mod api;
mod chat;
use actix_cors::Cors;
mod db_sea;
use actix_web::{http, main, middleware, web, App, HttpServer};
use api::{delete_messages, edit_message};
use sea_orm::*;
mod auth;
use migration::{Migrator, MigratorTrait};
mod chat_service;
mod entities;
use entities::*;

#[main(flavor = "current_thread")]
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
            .route("/chat/{chat_id}", web::get().to(chat_service::chat_socket))
            .configure(init)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}

fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(api::auth_user);
    cfg.service(api::get_chat_messages);
    cfg.service(api::query_user_data);
    cfg.service(delete_messages);
    cfg.service(edit_message);
    cfg.service(api::get_user);
    cfg.service(api::github_callback);
    cfg.service(api::validate_token);
    cfg.service(api::get_chats);
}

#[derive(Debug, Clone)]
struct AppState {
    conn: DatabaseConnection,
}
