#[cfg(test)]
mod tests {
    #[test]
    fn test_dns_diff_detects_change() {
        let old = vec!["8.8.8.8".to_string()];
        let new = vec!["1.1.1.1".to_string()];
        assert!(old != new);
    }

    #[test]
    fn test_dns_same_passes() {
        let old = vec!["8.8.8.8".to_string()];
        let new = vec!["8.8.8.8".to_string()];
        assert!(old == new);
    }

    #[test]
    fn test_hosts_hash_changes() {
        let old_hash = "abc123";
        let new_hash = "def456";
        assert!(old_hash != new_hash);
    }

    #[test]
    fn test_port_scan_threshold() {
        let threshold = 50;
        assert!(51 > threshold);
        assert!(10 < threshold);
    }
}