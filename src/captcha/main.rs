mod captcha;
mod session;

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::time::{interval, Duration};
use tower_http::{cors::CorsLayer, services::ServeDir};

use captcha::{generate_captcha, ClockTime};
use session::SessionStore;

use log::{debug, error, info, warn};

#[derive(Clone)]
struct AppState {
    session_store: SessionStore,
    templates: Arc<Tera>,
}

#[derive(Deserialize)]
struct CaptchaVerifyForm {
    hour: u8,
    minute: u8,
    session_id: String,
}

#[derive(Deserialize, Debug)]
struct CaptchaQuery {
    session_id: Option<String>,
}

// Route: GET /captcha/form - Display CAPTCHA form
async fn captcha_form_handler(
    Query(params): Query<CaptchaQuery>,
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    debug!("captcha_form_handler called with params: {:?}", params);

    let session_id = if let Some(existing_id) = params.session_id {
        debug!("Checking existing session_id: {}", existing_id);
        // Check if session exists and is valid
        if state.session_store.get_session(&existing_id).is_some() {
            info!("Reusing valid session_id: {}", existing_id);
            existing_id
        } else {
            warn!("Session_id {} not found or expired, creating new session", existing_id);
            let (time, _) = generate_captcha();
            state.session_store.create_session(time.hour, time.minute)
        }
    } else {
        info!("No session_id provided, creating new session");
        let (time, _) = generate_captcha();
        state.session_store.create_session(time.hour, time.minute)
    };

    let mut context = Context::new();
    context.insert("session_id", &session_id);

    match state.templates.render("captcha_form.html", &context) {
        Ok(html) => {
            debug!("Successfully rendered captcha_form.html for session_id: {}", session_id);
            Ok(Html(html))
        }
        Err(e) => {
            error!("Failed to render captcha_form.html: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Route: GET /captcha/image/{session_id} - Serve clock SVG image
async fn captcha_image_handler(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
) -> Response {
    debug!("captcha_image_handler called for session_id: {}", session_id);

    if let Some(session) = state.session_store.get_session(&session_id) {
        if !session.is_expired() {
            debug!("Session {} found and valid, rendering clock image", session_id);
            let time = ClockTime::new(session.correct_hour, session.correct_minute);
            let renderer = captcha::ClockRenderer::new(200.0);
            let svg = renderer.render_clock(&time);

            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "image/svg+xml")],
                svg,
            )
                .into_response();
        } else {
            warn!("Session {} is expired", session_id);
        }
    } else {
        warn!("Session {} not found", session_id);
    }

    // Return a default "expired" clock or error
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain")],
        "CAPTCHA session not found or expired",
    )
        .into_response()
}

// Route: POST /captcha/verify - Verify CAPTCHA answer
async fn captcha_verify_handler(
    State(state): State<AppState>,
    Form(form): Form<CaptchaVerifyForm>,
) -> Result<Html<String>, StatusCode> {
    debug!(
        "captcha_verify_handler called for session_id: {}, hour: {}, minute: {}",
        form.session_id, form.hour, form.minute
    );

    let mut context = Context::new();
    context.insert("session_id", &form.session_id);

    let is_valid = state.session_store.validate_and_remove(
        &form.session_id,
        form.hour,
        form.minute,
    );

    if is_valid {
        info!("CAPTCHA verified successfully for session_id: {}", form.session_id);
        context.insert("success", "✅ CAPTCHA verified successfully!");
    } else {
        warn!("CAPTCHA verification failed for session_id: {}", form.session_id);
        context.insert("error", "❌ Incorrect time or expired session. Please try again.");
        // Generate new session for retry
        let (time, _) = generate_captcha();
        let new_session_id = state.session_store.create_session(time.hour, time.minute);
        context.insert("session_id", &new_session_id);
        debug!("New session_id {} created after failed verification", new_session_id);
    }

    match state.templates.render("captcha_form.html", &context) {
        Ok(html) => {
            debug!("Successfully rendered captcha_form.html after verification");
            Ok(Html(html))
        }
        Err(e) => {
            error!("Failed to render captcha_form.html after verification: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Route: GET /captcha/widget/{session_id} - Get embeddable widget HTML
async fn captcha_widget_handler(
    Path(session_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    debug!("captcha_widget_handler called for session_id: {}", session_id);

    // Verify session exists
    if state.session_store.get_session(&session_id).is_none() {
        warn!("Session {} not found for widget", session_id);
        return Err(StatusCode::NOT_FOUND);
    }

    let mut context = Context::new();
    context.insert("session_id", &session_id);

    match state.templates.render("captcha_widget.html", &context) {
        Ok(html) => {
            debug!("Successfully rendered captcha_widget.html for session_id: {}", session_id);
            Ok(Html(html))
        }
        Err(e) => {
            error!("Failed to render captcha_widget.html: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Route: GET /captcha/new - Create new CAPTCHA session and return session ID as JSON
async fn captcha_new_handler(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    debug!("captcha_new_handler called");

    let (time, _) = generate_captcha();
    let session_id = state.session_store.create_session(time.hour, time.minute);

    let response = serde_json::json!({
        "session_id": session_id,
        "image_url": format!("/captcha/image/{}", session_id),
        "widget_url": format!("/captcha/widget/{}", session_id)
    });

    info!("New CAPTCHA session created: {}", session_id);

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], response.to_string()))
}

// Background task to cleanup expired sessions
async fn cleanup_sessions(session_store: SessionStore) {
    let mut interval = interval(Duration::from_secs(60)); // Cleanup every minute

    loop {
        interval.tick().await;
        debug!("Running session cleanup task");
        session_store.cleanup_expired();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::init();

    info!("Starting Clock CAPTCHA server...");

    // Initialize Tera templates
    let mut tera = Tera::new("templates/**/*")?;
    tera.autoescape_on(vec!["html"]);

    // Initialize session store
    let session_store = SessionStore::new();

    // Start background cleanup task
    let cleanup_store = session_store.clone();
    tokio::spawn(async move {
        cleanup_sessions(cleanup_store).await;
    });

    let app_state = AppState {
        session_store,
        templates: Arc::new(tera),
    };

    let app = Router::new()
        .route("/captcha/form", get(captcha_form_handler))
        .route("/captcha/image/:session_id", get(captcha_image_handler))
        .route("/captcha/verify", post(captcha_verify_handler))
        .route("/captcha/widget/:session_id", get(captcha_widget_handler))
        .route("/captcha/new", get(captcha_new_handler))
        .nest_service("/static", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;

    info!("🕐 Clock CAPTCHA server running on http://127.0.0.1:3000");
    info!("📋 Test the CAPTCHA at: http://127.0.0.1:3000/captcha/form");

    axum::serve(listener, app).await?;

    Ok(())
}
