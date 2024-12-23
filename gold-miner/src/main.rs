use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};

use serde::Serialize;
use tokio;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let app = Router::new().route("/", get(root));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap()
}

async fn root() -> ResponseData {
    ResponseData {
        text: "Hello world!",
        balls: vec![0, 1, 2, 3],
    }
}

#[derive(Serialize)]
struct ResponseData {
    text: &'static str,
    balls: Vec<u8>,
}

impl IntoResponse for ResponseData {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
