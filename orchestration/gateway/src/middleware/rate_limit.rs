use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Per-API-key token bucket rate limiter.
pub struct RateLimiter {
    buckets: DashMap<String, TokenBucket>,
    rate: u32,
    burst: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl RateLimiter {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            rate,
            burst,
        }
    }

    /// Try to acquire a token for the given API key.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(wait_duration)` if rate limited.
    pub fn try_acquire(&self, api_key: &str) -> Result<(), Duration> {
        let now = Instant::now();

        let mut entry = self.buckets.entry(api_key.to_string()).or_insert_with(|| {
            TokenBucket {
                tokens: self.burst as f64,
                last_refill: now,
                last_used: now,
            }
        });

        let bucket = entry.value_mut();

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate as f64).min(self.burst as f64);
        bucket.last_refill = now;
        bucket.last_used = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate wait time until 1 token is available
            let deficit = 1.0 - bucket.tokens;
            let wait_secs = deficit / self.rate as f64;
            Err(Duration::from_secs_f64(wait_secs))
        }
    }

    /// Remove inactive buckets older than the given timeout.
    pub fn cleanup(&self, inactive_timeout: Duration) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_used) < inactive_timeout);
    }

    /// Number of active buckets (for testing/monitoring).
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_under_limit() {
        let limiter = RateLimiter::new(100, 100);
        for _ in 0..50 {
            assert!(limiter.try_acquire("key-a").is_ok());
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(10, 10);
        // Exhaust the bucket
        for _ in 0..10 {
            assert!(limiter.try_acquire("key-a").is_ok());
        }
        // Next should be blocked
        let result = limiter.try_acquire("key-a");
        assert!(result.is_err());
    }

    #[test]
    fn test_per_api_key() {
        let limiter = RateLimiter::new(5, 5);
        // Exhaust key-a
        for _ in 0..5 {
            assert!(limiter.try_acquire("key-a").is_ok());
        }
        assert!(limiter.try_acquire("key-a").is_err());
        // key-b should still work
        assert!(limiter.try_acquire("key-b").is_ok());
    }

    #[test]
    fn test_retry_after_duration() {
        let limiter = RateLimiter::new(10, 1);
        assert!(limiter.try_acquire("key-a").is_ok());
        let err = limiter.try_acquire("key-a").unwrap_err();
        // Should be ~100ms (1/10 seconds)
        assert!(err.as_millis() > 0);
        assert!(err.as_millis() <= 200);
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimiter::new(100, 100);
        limiter.try_acquire("key-a").unwrap();
        limiter.try_acquire("key-b").unwrap();
        assert_eq!(limiter.bucket_count(), 2);

        // Cleanup with zero timeout removes all
        limiter.cleanup(Duration::from_secs(0));
        assert_eq!(limiter.bucket_count(), 0);
    }
}
