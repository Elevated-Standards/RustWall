use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

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

        Self {
            correct_hour: hour,
            correct_minute: minute,
            created_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    pub fn validate_answer(&self, user_hour: u8, user_minute: u8) -> bool {
        if self.is_expired() {
            return false;
        }

        // Allow some tolerance for minute precision (±2 minutes)
        let minute_diff = if self.correct_minute >= user_minute {
            self.correct_minute - user_minute
        } else {
            user_minute - self.correct_minute
        };

        self.correct_hour == user_hour && minute_diff <= 2
    }
}

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, CaptchaSession>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn create_session(&self, hour: u8, minute: u8) -> String {
        let session_id = Uuid::new_v4().to_string();
        let session = CaptchaSession::new(hour, minute);
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<CaptchaSession> {
        self.sessions.get(session_id).map(|entry| entry.clone())
    }

    pub fn remove_session(&self, session_id: &str) -> Option<CaptchaSession> {
        self.sessions.remove(session_id).map(|(_, session)| session)
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| now <= session.expires_at);
    }

    pub fn validate_and_remove(&self, session_id: &str, user_hour: u8, user_minute: u8) -> bool {
        if let Some(session) = self.remove_session(session_id) {
            session.validate_answer(user_hour, user_minute)
        } else {
            false
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}
