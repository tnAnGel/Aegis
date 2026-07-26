//! Slow-drip response body for honeypot tarpitting.
//!
//! Standard rejection (HTTP 403) ends the TCP connection instantly,
//! freeing the scanner to move on. Instead we hold the connection
//! open for `duration_seconds`, emitting `chunk_bytes` every 5 s
//! through a chunked-transfer-encoded body. The scanner's worker is
//! pinned waiting for "the response that's about to arrive" while
//! its concurrency pool drains.
//!
//! Implementation: a custom `http_body::Body` that returns
//! `Poll::Pending` until a wakeup timer fires, then yields one chunk
//! and re-arms. hyper handles the framing.
//!
//! On the wire (chunked):
//!
//! ```text
//! HTTP/1.1 200 OK
//! Server: Apache/2.4.41 (Ubuntu)
//! Content-Type: text/html
//! Transfer-Encoding: chunked
//!
//! 32\r\n
//! <50 bytes>\r\n             ← every 5 s
//! 32\r\n
//! <50 bytes>\r\n
//! ...
//! 0\r\n\r\n                  ← final chunk, after duration_seconds
//! ```

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body::{Body, Frame};

/// Body that emits `total_chunks` chunks of `chunk_size` bytes each,
/// with `interval` between them. Stops on its own when all chunks
/// have been sent or when the configured budget is exhausted.
pub struct TarpitBody {
    total_chunks: u32,
    chunks_sent: u32,
    chunk: Bytes,
    interval: Duration,
    next_wake: Option<Pin<Box<tokio::time::Sleep>>>,
    finished: bool,
}

impl TarpitBody {
    /// Build a tarpit body for a tarpit of `duration_seconds`
    /// emitting `chunk_bytes` every 5 s.
    pub fn new(duration_seconds: u64, chunk_bytes: usize) -> Self {
        let interval = Duration::from_secs(5);
        let total_chunks = if duration_seconds == 0 {
            0
        } else {
            // ceil(duration / interval) — last chunk may land slightly
            // after duration; the goal is "approximately N seconds".
            (duration_seconds.div_ceil(interval.as_secs())) as u32
        };
        // Chunk content: dots are cheap, look like "loading…" output,
        // and avoid triggering content-sniffing into anything fancy.
        let chunk = Bytes::from(vec![b'.'; chunk_bytes.max(1)]);
        Self {
            total_chunks,
            chunks_sent: 0,
            chunk,
            interval,
            next_wake: None,
            finished: false,
        }
    }
}

impl Body for TarpitBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        if self.chunks_sent >= self.total_chunks {
            self.finished = true;
            return Poll::Ready(None);
        }
        // First time through: arm a sleep so the first chunk also
        // takes `interval` to emit. (Instant rejection would let the
        // scanner detect tarpitting too easily.)
        let interval = self.interval;
        if self.next_wake.is_none() {
            self.next_wake = Some(Box::pin(tokio::time::sleep(interval)));
        }
        // Poll the sleep — scope the &mut borrow so we can mutate
        // other `self` fields afterwards without overlapping borrows.
        let ready = {
            let sleep = self.next_wake.as_mut().expect("just inserted");
            matches!(sleep.as_mut().poll(cx), Poll::Ready(_))
        };
        if !ready {
            return Poll::Pending;
        }
        // Sleep fired — re-arm for the next interval.
        let next_deadline = tokio::time::Instant::from_std(Instant::now() + interval);
        if let Some(sleep) = self.next_wake.as_mut() {
            sleep.as_mut().reset(next_deadline);
        }
        let chunk = self.chunk.clone();
        self.chunks_sent += 1;
        if self.chunks_sent >= self.total_chunks {
            // Last chunk; next poll will short-circuit to None and
            // hyper will emit the terminating 0-length chunk.
            self.finished = true;
        }
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // Don't advertise a size — chunked transfer is the whole point.
        http_body::SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test(start_paused = true)]
    async fn emits_correct_chunk_count_over_duration() {
        // 20 s / 5 s interval = 4 chunks.
        let mut body = TarpitBody::new(20, 10);
        let mut got = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if let Ok(data) = frame.into_data() {
                assert_eq!(data.len(), 10);
                got += 1;
            }
        }
        assert_eq!(got, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_duration_emits_nothing() {
        let mut body = TarpitBody::new(0, 10);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn chunk_bytes_is_respected() {
        let mut body = TarpitBody::new(5, 123);
        let frame = body.frame().await.unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.len(), 123);
    }
}
