use axum::{extract::State, routing::post, Json, Router};
use dos_core::{JoinReq, JoinResp};
use uuid::Uuid;

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new().route("/auth/join", post(join)).with_state(state)
}

async fn join(State(state): State<AppState>, Json(req): Json<JoinReq>) -> Result<Json<JoinResp>, (axum::http::StatusCode, String)> {
    if req.password != state.password {
        return Err((axum::http::StatusCode::UNAUTHORIZED, "bad password".into()));
    }

    let token = format!("dos_live_{}", Uuid::new_v4());
    let share_id = "shr_local".to_string();

    {
        let mut map = state.tokens.write().unwrap();
        map.insert(token.clone(), share_id.clone());
    }

    let resp = JoinResp {
        token,
        share_id,
        expires_in: 86400,
        server_time: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
    };
    Ok(Json(resp))
}
