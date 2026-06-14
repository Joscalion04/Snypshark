"""
Unit tests for SecurityAnalyzer, StatisticalAnalyzer, TimelineAnalyzer.
Covers public API only: process_packet input → get_stats / accessor output.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

from analytics.security_analyzer import SecurityAnalyzer
from analytics.statistical_analyzer import StatisticalAnalyzer
from analytics.timeline_analyzer import TimelineAnalyzer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tcp_packet(flags: str, src_ip: str = "10.0.0.1", dst_port: str = "80") -> MagicMock:
    pkt = MagicMock()
    pkt.tcp.flags = flags
    pkt.ip.src = src_ip
    pkt.tcp.dstport = dst_port
    pkt.length = "60"
    pkt.sniff_time = None
    del pkt.icmp
    del pkt.dns
    return pkt


def _icmp_packet(size: int, src_ip: str = "10.0.0.1") -> MagicMock:
    pkt = MagicMock()
    pkt.ip.src = src_ip
    pkt.length = str(size)
    pkt.sniff_time = None
    del pkt.tcp
    del pkt.dns
    return pkt


def _dns_packet(query: str, src_ip: str = "10.0.0.1") -> MagicMock:
    pkt = MagicMock()
    pkt.ip.src = src_ip
    pkt.dns.qry_name = query
    pkt.length = "70"
    pkt.sniff_time = None
    del pkt.tcp
    del pkt.icmp
    return pkt


def _sized_packet(size: int, ts=None) -> MagicMock:
    pkt = MagicMock()
    pkt.length = str(size)
    pkt.sniff_time = ts
    pkt.layers = []
    return pkt


# ---------------------------------------------------------------------------
# SecurityAnalyzer
# ---------------------------------------------------------------------------


class TestSecurityAnalyzer:
    def test_no_threats_on_empty(self):
        sa = SecurityAnalyzer()
        stats = sa.get_stats()
        assert stats["port_scan_sources"] == 0
        assert stats["large_icmp_count"] == 0
        assert stats["malicious_domain_hits"] == 0

    def test_port_scan_below_threshold_not_flagged(self):
        sa = SecurityAnalyzer()
        src = "192.168.1.1"
        for port in range(5):  # 5 < PORT_SCAN_THRESHOLD (10)
            sa.process_packet(_tcp_packet("0x0002", src, str(port)))
        assert sa.get_port_scan_sources() == {}

    def test_port_scan_at_threshold_flagged(self):
        sa = SecurityAnalyzer()
        src = "192.168.1.1"
        for port in range(10):  # exactly PORT_SCAN_THRESHOLD
            sa.process_packet(_tcp_packet("0x0002", src, str(port)))
        scanners = sa.get_port_scan_sources()
        assert src in scanners
        assert scanners[src] == 10

    def test_port_scan_distinct_ports_counted(self):
        sa = SecurityAnalyzer()
        src = "192.168.1.2"
        # Send 20 SYN to the same port — should NOT trigger (only 1 distinct port)
        for _ in range(20):
            sa.process_packet(_tcp_packet("0x0002", src, "443"))
        assert sa.get_port_scan_sources() == {}

    def test_syn_ack_ignored(self):
        sa = SecurityAnalyzer()
        src = "10.0.0.1"
        for port in range(15):
            sa.process_packet(_tcp_packet("0x0012", src, str(port)))  # SYN+ACK
        assert sa.get_port_scan_sources() == {}

    def test_large_icmp_detected(self):
        sa = SecurityAnalyzer()
        sa.process_packet(_icmp_packet(1500))
        assert sa.get_stats()["large_icmp_count"] == 1

    def test_small_icmp_not_flagged(self):
        sa = SecurityAnalyzer()
        sa.process_packet(_icmp_packet(64))
        assert sa.get_stats()["large_icmp_count"] == 0

    def test_malicious_domain_detected(self):
        sa = SecurityAnalyzer()
        sa.process_packet(_dns_packet("malware.com"))
        stats = sa.get_stats()
        assert stats["malicious_domain_hits"] == 1
        assert stats["malicious_dns_events"][0]["domain"] == "malware.com"

    def test_benign_domain_not_flagged(self):
        sa = SecurityAnalyzer()
        sa.process_packet(_dns_packet("google.com"))
        assert sa.get_stats()["malicious_domain_hits"] == 0


# ---------------------------------------------------------------------------
# StatisticalAnalyzer
# ---------------------------------------------------------------------------


class TestStatisticalAnalyzer:
    def test_empty_stats(self):
        st = StatisticalAnalyzer()
        s = st.get_stats()
        assert s["total_packets"] == 0
        assert s["anomalous_packets"] == 0

    def test_collects_packet_sizes(self):
        st = StatisticalAnalyzer()
        for size in [100, 200, 300]:
            st.process_packet(_sized_packet(size))
        s = st.get_stats()
        assert s["total_packets"] == 3
        assert s["packet_size_min"] == 100
        assert s["packet_size_max"] == 300

    def test_anomalous_count_outlier_detected(self):
        st = StatisticalAnalyzer()
        # 98 normal packets + 2 extreme outliers
        for _ in range(98):
            st.process_packet(_sized_packet(100))
        st.process_packet(_sized_packet(50000))
        st.process_packet(_sized_packet(50000))
        assert st.get_anomalous_count() >= 1

    def test_no_anomalies_in_uniform_traffic(self):
        st = StatisticalAnalyzer()
        for _ in range(50):
            st.process_packet(_sized_packet(1000))
        assert st.get_anomalous_count() == 0

    def test_inter_arrival_computed(self):
        st = StatisticalAnalyzer()
        base = datetime(2024, 1, 1, 12, 0, 0)
        for i in range(5):
            pkt = _sized_packet(100, ts=base + timedelta(seconds=i))
            st.process_packet(pkt)
        s = st.get_stats()
        assert "inter_arrival_mean_ms" in s
        assert s["inter_arrival_mean_ms"] > 0


# ---------------------------------------------------------------------------
# TimelineAnalyzer
# ---------------------------------------------------------------------------


class TestTimelineAnalyzer:
    def test_empty_timeline(self):
        ta = TimelineAnalyzer()
        assert ta.get_stats()["timeline_records"] == 0
        assert ta.get_burst_windows() == []

    def test_records_accumulate(self):
        ta = TimelineAnalyzer()
        base = datetime(2024, 1, 1, 12, 0, 0)
        for i in range(10):
            ta.process_packet(_sized_packet(100, ts=base + timedelta(seconds=i)))
        assert ta.get_stats()["timeline_records"] == 10

    def test_get_timeline_stats_structure(self):
        ta = TimelineAnalyzer()
        base = datetime(2024, 1, 1, 12, 0, 0)
        for i in range(5):
            ta.process_packet(_sized_packet(200, ts=base + timedelta(seconds=i * 10)))
        s = ta.get_timeline_stats()
        assert "peak_traffic_time" in s
        assert "max_packets_per_window" in s
        assert s["max_packets_per_window"] >= 1

    def test_burst_windows_empty_below_threshold(self):
        # 5 packets/min is well below DDOS_THRESHOLD (1000 pkt/s)
        ta = TimelineAnalyzer()
        base = datetime(2024, 1, 1, 12, 0, 0)
        for i in range(5):
            ta.process_packet(_sized_packet(100, ts=base + timedelta(seconds=i * 10)))
        assert ta.get_burst_windows() == []
