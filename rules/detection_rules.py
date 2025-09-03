import re
from datetime import datetime


class RuleEngine:
    def __init__(self):
        self.rules = self.load_rules()

    def load_rules(self):
        return [
            {
                'id': 'R001',
                'name': 'Multiple Failed Logins',
                'description': 'Detect multiple failed login attempts from same source',
                'condition': self.check_failed_logins,
                'severity': 'high'
            },
            {
                'id': 'R002',
                'name': 'Port Scan Detection',
                'description': 'Detect multiple connection attempts to different ports',
                'condition': self.check_port_scan,
                'severity': 'medium'
            },
            {
                'id': 'R003',
                'name': 'Suspicious Process',
                'description': 'Detect execution of suspicious processes',
                'condition': self.check_suspicious_process,
                'severity': 'high'
            },
            {
                'id': 'R004',
                'name': 'Firewall Rule Change',
                'description': 'Detect changes to firewall rules',
                'condition': self.check_firewall_change,
                'severity': 'medium'
            },
            {
                'id': 'R005',
                'name': 'IDS Alert',
                'description': 'Detect IDS/IPS alerts',
                'condition': self.check_ids_alert,
                'severity': 'high'
            }
        ]

    def apply_rules(self, log):
        alerts = []
        for rule in self.rules:
            try:
                if rule['condition'](log):
                    alert = {
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'timestamp': datetime.now().isoformat(),
                        'description': rule['description']
                    }
                    alerts.append(alert)
            except Exception as e:
                # Log error but continue with other rules
                print(f"Error applying rule {rule['id']}: {e}")
        return alerts

    def check_failed_logins(self, log):
        if log.get('source') == 'windows' and log.get('EventID') == 4625:
            # Windows failed login event
            return True
        elif 'authentication failure' in log.get('message', '').lower():
            return True
        return False

    def check_port_scan(self, log):
        # This would be implemented with state tracking across multiple logs
        if log.get('source') == 'firewall' and log.get('action') == 'DROP':
            # Check if this is a port scan pattern
            dst_port = log.get('dst_port', 0)
            if dst_port > 1024 and dst_port < 10000:
                return True
        return False

    def check_suspicious_process(self, log):
        suspicious_processes = [
            'nc', 'netcat', 'ncat', 'wget', 'curl', 'powershell',
            'cmd', 'bash', 'ssh', 'telnet', 'ftp'
        ]

        if log.get('source') == 'windows' and log.get('EventID') == 4688:
            # Windows process creation event
            process_name = log.get('ProcessName', '').lower()
            return any(sp in process_name for sp in suspicious_processes)

        return False

    def check_firewall_change(self, log):
        if log.get('source') == 'windows' and log.get('EventID') in [4946, 4947]:
            # Windows firewall rule changes
            return True
        return False

    def check_ids_alert(self, log):
        if log.get('source') == 'ids' and log.get('severity') == 'high':
            return True
        return False