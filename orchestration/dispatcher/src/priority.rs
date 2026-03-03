use std::cmp::Reverse;
use std::collections::BinaryHeap;

use sincerin_common::types::ProofRequest;

/// Composite key for lexicographic priority ordering.
///
/// Ordering: lower deadline → higher priority (closest deadline first),
/// then lower request_time → higher priority (FIFO within same deadline),
/// then lower inverse_retry → higher priority (more retries = higher priority).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PriorityKey {
    pub deadline: u64,
    pub request_time: u64,
    pub inverse_retry: u32,
}

impl PriorityKey {
    /// Create a priority key from a proof request and retry count.
    ///
    /// `inverse_retry` is `u32::MAX - retry_count` so that higher retry
    /// counts produce lower values → higher priority in the min-heap.
    pub fn from_request(request: &ProofRequest, retry_count: u32) -> Self {
        Self {
            deadline: request.deadline,
            request_time: request.created_at,
            inverse_retry: u32::MAX - retry_count,
        }
    }
}

/// A bounded priority queue for proof requests.
///
/// Uses a min-heap (via `Reverse`) so that `pop()` returns the request
/// with the highest priority (smallest key).
pub struct PriorityQueue {
    heap: BinaryHeap<Reverse<(PriorityKey, ProofRequestEntry)>>,
    max_size: usize,
}

/// Wrapper for ProofRequest that implements Ord based on request_id
/// (for deterministic ordering when keys are equal).
#[derive(Debug, Clone)]
pub struct ProofRequestEntry {
    pub request: ProofRequest,
    pub retry_count: u32,
}

impl Eq for ProofRequestEntry {}

impl PartialEq for ProofRequestEntry {
    fn eq(&self, other: &Self) -> bool {
        self.request.request_id == other.request.request_id
    }
}

impl Ord for ProofRequestEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.request.request_id.cmp(&other.request.request_id)
    }
}

impl PartialOrd for ProofRequestEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PriorityQueue {
    /// Create a new priority queue with a maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            max_size,
        }
    }

    /// Push a request into the queue.
    ///
    /// If the queue is full, the request is only inserted if it has
    /// higher priority than the current lowest-priority item.
    pub fn push(&mut self, request: ProofRequest, retry_count: u32) -> bool {
        let key = PriorityKey::from_request(&request, retry_count);
        let entry = ProofRequestEntry {
            request,
            retry_count,
        };

        if self.heap.len() < self.max_size {
            self.heap.push(Reverse((key, entry)));
            true
        } else {
            // Check if new item has higher priority (smaller key) than
            // the worst item in the queue.
            // In a min-heap with Reverse, the worst item (largest key)
            // is at the bottom. We need to find and compare with it.
            // For simplicity and correctness, we push then pop the worst
            // if over capacity.
            self.heap.push(Reverse((key, entry)));
            // Remove the lowest-priority item (largest key = last in min-heap)
            // We need to rebuild to pop the max. Instead, let's keep it simple:
            // Since BinaryHeap<Reverse<T>> is a min-heap on T,
            // pop() gives us the smallest T = highest priority.
            // We want to remove the LARGEST T = lowest priority.
            // We'll collect, sort, and truncate.
            if self.heap.len() > self.max_size {
                let mut items: Vec<_> = self.heap.drain().collect();
                // Sort ascending by Reverse<T> — largest keys (lowest priority) come first.
                items.sort();
                // Remove the excess low-priority items from the front.
                let excess = items.len() - self.max_size;
                items.drain(0..excess);
                self.heap = items.into_iter().collect();
            }
            true
        }
    }

    /// Pop the highest-priority request from the queue.
    pub fn pop(&mut self) -> Option<ProofRequest> {
        self.heap.pop().map(|Reverse((_, entry))| entry.request)
    }

    /// Number of items in the queue.
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sincerin_common::types::{Priority, PrivacyLevel, ProofStatus};

    fn make_request(id: &str, deadline: u64, created_at: u64) -> ProofRequest {
        ProofRequest {
            request_id: id.to_string(),
            circuit_id: "proof-of-membership".to_string(),
            requester: "test".to_string(),
            privacy_level: PrivacyLevel::Mandatory,
            priority: Priority::Standard,
            max_fee: 0,
            deadline,
            public_inputs: serde_json::json!({}),
            created_at,
            status: ProofStatus::Pending,
        }
    }

    #[test]
    fn test_priority_deadline_first() {
        let mut q = PriorityQueue::new(100);
        q.push(make_request("r3", 3000, 100), 0);
        q.push(make_request("r1", 1000, 100), 0);
        q.push(make_request("r2", 2000, 100), 0);

        assert_eq!(q.pop().unwrap().request_id, "r1"); // deadline 1000
        assert_eq!(q.pop().unwrap().request_id, "r2"); // deadline 2000
        assert_eq!(q.pop().unwrap().request_id, "r3"); // deadline 3000
    }

    #[test]
    fn test_priority_request_time_tiebreak() {
        let mut q = PriorityQueue::new(100);
        q.push(make_request("r3", 1000, 300), 0);
        q.push(make_request("r1", 1000, 100), 0);
        q.push(make_request("r2", 1000, 200), 0);

        assert_eq!(q.pop().unwrap().request_id, "r1"); // request_time 100
        assert_eq!(q.pop().unwrap().request_id, "r2"); // request_time 200
        assert_eq!(q.pop().unwrap().request_id, "r3"); // request_time 300
    }

    #[test]
    fn test_priority_retry_escalation() {
        let mut q = PriorityQueue::new(100);
        let r0 = make_request("r0", 1000, 100);
        let r2 = make_request("r2", 1000, 100);

        q.push(r0, 0);  // retry_count = 0 → inverse_retry = MAX
        q.push(r2, 2);  // retry_count = 2 → inverse_retry = MAX-2 (lower = higher prio)

        // r2 should come first (more retries = higher priority)
        assert_eq!(q.pop().unwrap().request_id, "r2");
        assert_eq!(q.pop().unwrap().request_id, "r0");
    }

    #[test]
    fn test_priority_mixed_ordering() {
        let mut q = PriorityQueue::new(100);

        // Mix of deadlines and request times
        q.push(make_request("d2000_t400", 2000, 400), 0);
        q.push(make_request("d1000_t500_r3", 1000, 500), 3);
        q.push(make_request("d1000_t600", 1000, 600), 0);
        q.push(make_request("d1000_t500_r0", 1000, 500), 0);
        q.push(make_request("d2000_t500", 2000, 500), 0);

        let order: Vec<String> = std::iter::from_fn(|| q.pop().map(|r| r.request_id)).collect();

        assert_eq!(
            order,
            vec![
                "d1000_t500_r3",  // deadline=1000, t=500, retry=3 (highest)
                "d1000_t500_r0",  // deadline=1000, t=500, retry=0
                "d1000_t600",     // deadline=1000, t=600
                "d2000_t400",     // deadline=2000, t=400
                "d2000_t500",     // deadline=2000, t=500
            ]
        );
    }

    #[test]
    fn test_priority_queue_max_size() {
        let mut q = PriorityQueue::new(3);

        // Insert 5 requests with deadlines 5000, 4000, 3000, 2000, 1000
        q.push(make_request("r5", 5000, 100), 0);
        q.push(make_request("r4", 4000, 100), 0);
        q.push(make_request("r3", 3000, 100), 0);
        q.push(make_request("r2", 2000, 100), 0);
        q.push(make_request("r1", 1000, 100), 0);

        assert_eq!(q.len(), 3);

        // The 3 highest-priority (lowest deadline) should remain
        let order: Vec<String> = std::iter::from_fn(|| q.pop().map(|r| r.request_id)).collect();
        assert_eq!(order, vec!["r1", "r2", "r3"]);
    }

    #[test]
    fn test_priority_queue_empty() {
        let mut q = PriorityQueue::new(10);
        assert!(q.pop().is_none());
        assert!(q.is_empty());
    }

    #[test]
    fn test_priority_edge_deadline_zero() {
        let mut q = PriorityQueue::new(100);
        q.push(make_request("r_zero", 0, 100), 0);
        q.push(make_request("r_high", 1000, 100), 0);

        // deadline=0 is highest priority
        assert_eq!(q.pop().unwrap().request_id, "r_zero");
    }

    #[test]
    fn test_priority_edge_deadline_max() {
        let mut q = PriorityQueue::new(100);
        q.push(make_request("r_max", u64::MAX, 100), 0);
        q.push(make_request("r_low", 1000, 100), 0);

        // deadline=u64::MAX is lowest priority
        assert_eq!(q.pop().unwrap().request_id, "r_low");
        assert_eq!(q.pop().unwrap().request_id, "r_max");
    }
}
