use bytes::Bytes;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::SystemTime;

#[derive(Clone)]
pub struct Frame {
    pub data: Bytes,
    pub timestamp: f64,
    pub size: usize,
}

impl Frame {
    pub fn id(&self) -> String {
        format!("{:x}", self.timestamp.to_bits())
    }
}

pub struct FrameStore {
    current: Arc<RwLock<Option<Frame>>>,
}

impl FrameStore {
    pub fn new() -> Self {
        Self {
            current: Arc::new(RwLock::new(None)),
        }
    }

    pub fn update(&self, data: Vec<u8>) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let size = data.len();
        let frame = Frame {
            data: Bytes::from(data),
            timestamp,
            size,
        };

        *self.current.write() = Some(frame);
    }

    pub fn get(&self) -> Option<Frame> {
        self.current.read().clone()
    }
}

impl Clone for FrameStore {
    fn clone(&self) -> Self {
        Self {
            current: Arc::clone(&self.current),
        }
    }
}
