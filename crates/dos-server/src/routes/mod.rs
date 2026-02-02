pub mod auth;
pub mod fs;
pub mod health;
pub mod upload;

use axum::Router;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(health::router())
        .merge(auth::router(state.clone()))
        .merge(fs::router(state.clone()))
        .merge(upload::router(state))
}
