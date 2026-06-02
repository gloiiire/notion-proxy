use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::ports::Clock;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_current_unix_timestamp() {
        let t = SystemClock.now_unix();
        // After 2023-01-01 (1_672_531_200) and before year 2100 (4_102_444_800).
        assert!(t > 1_672_531_200, "expected post-2023 timestamp, got {t}");
        assert!(t < 4_102_444_800, "expected pre-2100 timestamp, got {t}");
    }

    #[test]
    fn advances_with_real_time() {
        let before = SystemClock.now_unix();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let after = SystemClock.now_unix();
        assert!(after > before, "clock did not advance: {before} → {after}");
    }
}
