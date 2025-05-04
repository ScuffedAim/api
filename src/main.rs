use axum::{
    body::Body, extract::{Request, State},
    http::{header, StatusCode}, 
    middleware::{self, Next}, 
    response::Response, 
    routing::{get, MethodFilter}, Json, Router
};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sqlx::mysql::MySqlPoolOptions;
use std::sync::Arc;
mod scuffedaim;




#[derive(Debug,Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
async fn decode_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    dotenv().ok();
    let secret_key = std::env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY not set");
    let decoding_key = DecodingKey::from_secret(secret_key.as_ref());
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}
async fn authorize_current_user(auth_token: &str) -> bool {
    match decode_jwt(auth_token).await {
        Ok(claims) => {
            // Check if the token is valid and not expired
            let current_time = chrono::Utc::now().timestamp() as usize;
            claims.exp > current_time
        }
        Err(_) => false,
    }
}

async fn auth<B>(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(header::AUTHORIZATION);
    let auth_token = match auth_header {
        Some(header_value) => header_value.to_str().unwrap_or(""),
        None => return Err(StatusCode::UNAUTHORIZED),
    };
    if authorize_current_user(auth_token).await {
        Ok(next.run(req).await)
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }
}

struct AppState {
    db_pool: sqlx::MySqlPool,
}

async fn patch_members(
    State(state): State<Arc<AppState>>,
    Json(member): Json<scuffedaim::Member>,
) -> Result<Json<scuffedaim::Member>, StatusCode> {
    let pool = state.db_pool.clone();
    let result = sqlx::query("UPDATE members SET user_id = ?, skin_id = ?, discord = ?,is_admin = ? WHERE id = ?")
        .bind(member.user_id)
        .bind(member.skin_id)
        .bind(&member.discord)
        .bind(member.is_admin)
        .bind(member.id)
        .execute(&pool)
        .await
        .map_err(|err| {println!("{:#?}",err); StatusCode::INTERNAL_SERVER_ERROR})?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(member))
}
async fn delete_members(
    State(state): State<Arc<AppState>>,
    Json(member): Json<scuffedaim::Member>,
) -> Result<Json<scuffedaim::Member>, StatusCode> {
    let pool = state.db_pool.clone();
    let result = sqlx::query("DELETE FROM members WHERE id = ?")
        .bind(member.id)
        .execute(&pool)
        .await
        .map_err(|err| {println!("{:#?}",err); StatusCode::INTERNAL_SERVER_ERROR})?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(member))
}

async fn post_members(
    State(state): State<Arc<AppState>>,
    Json(member): Json<scuffedaim::Member>,
) -> Result<Json<scuffedaim::Member>, StatusCode> {
    let pool = state.db_pool.clone();
    let result = sqlx::query("INSERT INTO members (user_id,skin_id,discord,is_admin) VALUES (?, ?, ?,?)")
        .bind(member.user_id)
        .bind(member.skin_id)
        .bind(&member.discord)
        .bind(member.is_admin)
        .execute(&pool)
        .await
        .map_err(|err| {println!("{:#?}",err); StatusCode::INTERNAL_SERVER_ERROR})?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Json(member))
}

async fn members(
    State(state): State<Arc<AppState>>
) -> Result<Json<Vec<scuffedaim::Member>>, StatusCode> {
    let pool = state.db_pool.clone();
    let members = sqlx::query_as::<_, scuffedaim::Member>("SELECT * FROM members")
        .fetch_all(&pool)
        .await
        .map_err(|err| {println!("{:#?}",err); StatusCode::INTERNAL_SERVER_ERROR})?;
    Ok(Json(members))
}

async fn handler() -> &'static str {
    "Hello, World!"
}
#[tokio::main]
async fn main() {
    dotenv().ok();
    let db_url: String = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    println!("Connecting to database at {}", db_url);
    let shared_state = Arc::new(AppState {
        db_pool: MySqlPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .unwrap(),
    });


    let app = Router::new()
        .route("/", get(handler))
        // i can now maybe make a discord bot to do this shit with commands lmao
        .route("/members", get(members).post(post_members)
                                                .on(MethodFilter::PATCH, patch_members)
                                                .on(MethodFilter::DELETE, delete_members))
        .route_layer(middleware::from_fn(auth::<Body>))
        .with_state(shared_state);

    let addr: &str = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
    println!("Server stopped");
}