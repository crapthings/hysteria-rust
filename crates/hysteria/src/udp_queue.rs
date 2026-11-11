use tokio::sync::mpsc;

// Only a closed receiver permits replacing a flow. A full queue drops the new
// datagram, preserving the existing remote session and its queued packets.
pub(crate) fn enqueue_packet(sender: &mpsc::Sender<Vec<u8>>, packet: Vec<u8>) -> Option<Vec<u8>> {
    match sender.try_send(packet) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => None,
        Err(mpsc::error::TrySendError::Closed(packet)) => Some(packet),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn full_udp_queue_preserves_receiver_and_queued_packets() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(enqueue_packet(&sender, vec![1]).is_none());
        assert!(enqueue_packet(&sender, vec![2]).is_none());
        assert!(!sender.is_closed());
        assert_eq!(receiver.recv().await, Some(vec![1]));
        assert!(enqueue_packet(&sender, vec![3]).is_none());
        assert_eq!(receiver.recv().await, Some(vec![3]));
    }

    #[test]
    fn closed_udp_queue_returns_packet_for_replacement() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        assert_eq!(enqueue_packet(&sender, vec![4]), Some(vec![4]));
    }
}
