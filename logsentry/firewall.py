 
import iptc
import logging

logger = logging.getLogger(__name__)

class Firewall:
    """Manage firewall rules to block suspicious IPs."""
    def block_ip(self, ip: str):
        """Block an IP using iptables (Linux)."""
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, "INPUT")
            rule = iptc.Rule()
            rule.src = ip
            rule.create_target("DROP")
            chain.insert_rule(rule)
            logger.info(f"Blocked IP: {ip}")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")