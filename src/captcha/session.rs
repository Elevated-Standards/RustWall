use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use log::{debug, error, info, warn};

#[derive(Clone, Debug)]
pub struct CaptchaSession {
    pub correct_hour: u8,
    pub correct_minute: u8,
    #[allow(dead_code)]
    pub created_at: Instant,
    pub expires_at: Instant,
}

impl CaptchaSession {
    pub fn new(hour: u8, minute: u8) -> Self {
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(300); // 5 minutes expiration

        debug!(
            "Creating new CaptchaSession: hour={}, minute={}, expires_at={:?}",
            hour, minute, expires_at
        );

        Self {
            correct_hour: hour,
            correct_minute: minute,
            created_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        let expired = Instant::now() > self.expires_at;
        if expired {
            warn!(
                "CaptchaSession expired: correct_hour={}, correct_minute={}, expires_at={:?}",
                self.correct_hour, self.correct_minute, self.expires_at
            );
        }
        expired
    }

    pub fn validate_answer(&self, user_hour: u8, user_minute: u8) -> bool {
        if self.is_expired() {
            error!(
                "Attempted to validate expired session: correct_hour={}, correct_minute={}, user_hour={}, user_minute={}",
                self.correct_hour, self.correct_minute, user_hour, user_minute
            );
            return false;
        }

        // Allow some tolerance for minute precision (±2 minutes)
        let minute_diff = if self.correct_minute >= user_minute {
            self.correct_minute - user_minute
        } else {
            user_minute - self.correct_minute
        };

        let valid = self.correct_hour == user_hour && minute_diff <= 2;

        if valid {
            info!(
                "CaptchaSession validated successfully: correct_hour={}, correct_minute={}, user_hour={}, user_minute={}",
                self.correct_hour, self.correct_minute, user_hour, user_minute
            );
        } else {
            warn!(
                "CaptchaSession validation failed: correct_hour={}, correct_minute={}, user_hour={}, user_minute={}, minute_diff={}",
                self.correct_hour, self.correct_minute, user_hour, user_minute, minute_diff
            );
        }

        valid
    }
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, CaptchaSession>>,
}

impl SessionStore {
    pub fn new() -> Self {
        info!("Initializing new SessionStore");
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn create_session(&self, hour: u8, minute: u8) -> String {
        let session_id = Uuid::new_v4().to_string();
        let session = CaptchaSession::new(hour, minute);
        self.sessions.insert(session_id.clone(), session);
        info!(
            "Created new session: session_id={}, hour={}, minute={}",
            session_id, hour, minute
        );
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<CaptchaSession> {
        match self.sessions.get(session_id) {
            Some(entry) => {
                debug!("Session found: session_id={}", session_id);
                Some(entry.clone())
            }
            None => {
                warn!("Session not found: session_id={}", session_id);
                None
            }
        }
    }

    pub fn remove_session(&self, session_id: &str) -> Option<CaptchaSession> {
        match self.sessions.remove(session_id) {
            Some((_, session)) => {
                debug!("Session removed: session_id={}", session_id);
                Some(session)
            }
            None => {
                warn!("Attempted to remove non-existent session: session_id={}", session_id);
                None
            }
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let before = self.sessions.len();
        self.sessions.retain(|_, session| now <= session.expires_at);
        let after = self.sessions.len();
        let cleaned = before.saturating_sub(after);
        if cleaned > 0 {
            info!("Cleaned up {} expired sessions", cleaned);
        } else {
            debug!("No expired sessions to clean up");
        }
    }

    pub fn validate_and_remove(&self, session_id: &str, user_hour: u8, user_minute: u8) -> bool {
        match self.remove_session(session_id) {
            Some(session) => {
                debug!(
                    "Validating and removing session: session_id={}, user_hour={}, user_minute={}",
                    session_id, user_hour, user_minute
                );
                session.validate_answer(user_hour, user_minute)
            }
            None => {
                error!(
                    "Failed to validate: session not found or already removed: session_id={}",
                    session_id
                );
                false
            }
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
