mod api;
mod db;
use actix_web::{main, App, HttpServer};
use api::{delete_messages, edit_message};
mod auth;

#[main]
async fn main() -> std::io::Result<()> {
    println!("Starting server...");
    match db::db_initialize() {
        Ok(_) => println!("Database initialized successfully"),
        Err(e) => eprintln!("Database initialization failed:{}", e),
    };

    HttpServer::new(|| {
        App::new()
            .service(api::auth_user)
            .service(api::get_chat_messages)
            .service(api::query_user_data)
            .service(delete_messages)
            .service(edit_message)
            .service(api::get_user)
            .service(api::github_callback)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
