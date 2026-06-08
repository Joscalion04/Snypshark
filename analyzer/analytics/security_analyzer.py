from collections import defaultdict
from typing import Dict, List, Set

from core.packet_processor import PacketProcessor
from config.constants import SecurityThresholds


class SecurityAnalyzer(PacketProcessor):
    """
    Threat detector that operates at packet level and produces findings
    at report time.  Detects port scans via SYN correlation, oversized
    ICMP, and DNS queries for known malicious domains.
    """

    def __init__(self):
        # src_ip -> set of distinct dst_ports where a bare SYN was seen
        self._syn_targets: Dict[str, Set[str]] = defaultdict(set)
        self._large_icmp: List[Dict] = []
        self._malicious_dns: List[Dict] = []

    # ------------------------------------------------------------------
    # PacketProcessor interface
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> None:
        self._check_port_scan(packet)
        self._check_large_icmp(packet)
        self._check_malicious_dns(packet)

    # ------------------------------------------------------------------
    # Detection routines
    # ------------------------------------------------------------------

    def _check_port_scan(self, packet) -> None:
        try:
            if not (hasattr(packet, 'tcp') and hasattr(packet, 'ip')):
                return
            flags = str(getattr(packet.tcp, 'flags', ''))
            # Bare SYN: 0x0002 (no ACK, no other flags)
            if flags not in ('0x0002', '2'):
                return
            src_ip = getattr(packet.ip, 'src', '')
            dst_port = getattr(packet.tcp, 'dstport', '')
            if src_ip and dst_port:
                self._syn_targets[src_ip].add(dst_port)
        except AttributeError:
            pass

    def _check_large_icmp(self, packet) -> None:
        try:
            if not hasattr(packet, 'icmp'):
                return
            length = int(getattr(packet, 'length', 0))
            if length > SecurityThresholds.ICMP_LARGE_THRESHOLD:
                src = getattr(packet.ip, 'src', '') if hasattr(packet, 'ip') else ''
                self._large_icmp.append({
                    'src_ip': src,
                    'length': length,
                    'timestamp': getattr(packet, 'sniff_time', None),
                })
        except (AttributeError, ValueError):
            pass

    def _check_malicious_dns(self, packet) -> None:
        try:
            if not hasattr(packet, 'dns'):
                return
            query = getattr(packet.dns, 'qry_name', '').rstrip('.').lower()
            if query in SecurityThresholds.MALICIOUS_DOMAINS:
                src = getattr(packet.ip, 'src', '') if hasattr(packet, 'ip') else ''
                self._malicious_dns.append({
                    'domain': query,
                    'src_ip': src,
                    'timestamp': getattr(packet, 'sniff_time', None),
                })
        except AttributeError:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_port_scan_sources(self) -> Dict[str, int]:
        """IPs that sent SYN to >= PORT_SCAN_THRESHOLD distinct ports."""
        return {
            ip: len(ports)
            for ip, ports in self._syn_targets.items()
            if len(ports) >= SecurityThresholds.PORT_SCAN_THRESHOLD
        }

    def get_stats(self) -> Dict:
        scanners = self.get_port_scan_sources()
        return {
            'port_scan_sources': len(scanners),
            'port_scanners': scanners,
            'large_icmp_count': len(self._large_icmp),
            'large_icmp_events': self._large_icmp,
            'malicious_domain_hits': len(self._malicious_dns),
            'malicious_dns_events': self._malicious_dns,
        }
