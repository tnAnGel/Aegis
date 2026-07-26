use std::sync::Arc;

use anyhow::Result;
use redis::{AsyncCommands, Script};

/// Atomic token-bucket implemented as a Redis Lua script. Keeps `tokens`
/// and last-refill `ts` in a single hash, refills based on wall-clock
/// elapsed time, decrements by `cost`. Returns `(allowed, retry_after_ms_or_tokens_left)`:
/// - `allowed == 1`: second value is integer tokens remaining
/// - `allowed == 0`: second value is milliseconds the caller should wait
const TOKEN_BUCKET_LUA: &str = r#"
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1]) or burst
local ts = tonumber(data[2]) or now_ms

local elapsed_ms = now_ms - ts
if elapsed_ms < 0 then elapsed_ms = 0 end
local refill = (elapsed_ms / 1000.0) * rate
tokens = math.min(burst, tokens + refill)

local ttl_ms = math.max(1000, math.ceil((burst / math.max(rate, 1)) * 2000))

if tokens < cost then
  local need = cost - tokens
  local retry_ms = math.ceil((need / math.max(rate, 1)) * 1000)
  redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now_ms)
  redis.call('PEXPIRE', KEYS[1], ttl_ms)
  return {0, retry_ms}
end

tokens = tokens - cost
redis.call('HMSET', KEYS[1], 'tokens', tokens, 'ts', now_ms)
redis.call('PEXPIRE', KEYS[1], ttl_ms)
return {1, math.floor(tokens)}
"#;

#[derive(Clone)]
pub struct ReputationStore {
    client: Arc<redis::Client>,
    token_bucket: Arc<Script>,
}

/// Outcome of a token-bucket consumption attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketOutcome {
    Allowed { tokens_left: u64 },
    Throttled { retry_after_ms: u64 },
}

impl ReputationStore {
    pub fn new(redis_url: &str) -> Result<Self> {
        Ok(Self {
            client: Arc::new(redis::Client::open(redis_url)?),
            token_bucket: Arc::new(Script::new(TOKEN_BUCKET_LUA)),
        })
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection> {
        Ok(self.client.get_multiplexed_async_connection().await?)
    }

    pub async fn incr_score(&self, key: &str, by: u32, ttl: usize) -> Result<u32> {
        let mut c = self.conn().await?;
        let v: u32 = c.incr(key, by as i64).await?;
        let _: () = c.expire(key, ttl as i64).await?;
        Ok(v)
    }

    pub async fn mark_nonce(&self, nonce: &str, ttl: usize) -> Result<bool> {
        let mut c = self.conn().await?;
        let created: bool = c.set_nx(format!("aegis:nonce:{nonce}"), "1").await?;
        if created {
            let _: () = c.expire(format!("aegis:nonce:{nonce}"), ttl as i64).await?;
        }
        Ok(created)
    }

    /// Atomic distributed token-bucket. `rate` = tokens/sec, `burst` =
    /// max tokens, `cost` = tokens this request needs (typically 1).
    /// All arithmetic runs inside Redis under EVAL, so concurrent
    /// callers across many proxy instances never overshoot the budget.
    pub async fn consume_token(
        &self,
        key: &str,
        rate: u64,
        burst: u64,
        cost: u64,
    ) -> Result<BucketOutcome> {
        let mut c = self.conn().await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let full_key = format!("aegis:tb:{key}");
        let result: Vec<i64> = self
            .token_bucket
            .key(&full_key)
            .arg(rate.max(1) as i64)
            .arg(burst.max(1) as i64)
            .arg(now_ms)
            .arg(cost.max(1) as i64)
            .invoke_async(&mut c)
            .await?;
        if result.len() < 2 {
            anyhow::bail!("unexpected token bucket reply: {result:?}");
        }
        if result[0] == 1 {
            Ok(BucketOutcome::Allowed {
                tokens_left: result[1].max(0) as u64,
            })
        } else {
            Ok(BucketOutcome::Throttled {
                retry_after_ms: result[1].max(0) as u64,
            })
        }
    }
}
