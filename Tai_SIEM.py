from flask import Flask, render_template, jsonify, request
import json
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
from elasticsearch import Elasticsearch
import logging
from logging.handlers import RotatingFileHandler
import numpy as np

# Import custom modules
from rules.detection_rules import RuleEngine
from rules.correlation_rules import CorrelationEngine
from ml.anomaly_detector import AnomalyDetector
from alerts.notifications import AlertNotifier

app = Flask(__name__)
app.config.from_pyfile('config.py')

# Initialize components
es = Elasticsearch([app.config['ELASTICSEARCH_URL']]) if app.config['USE_ELASTICSEARCH'] else None
rule_engine = RuleEngine()
correlation_engine = CorrelationEngine()
anomaly_detector = AnomalyDetector()
alert_notifier = AlertNotifier()

# Global variables for dashboard data
dashboard_data = {
    'alerts': [],
    'stats': {},
    'events': []
}


class SIEMCore:
    def __init__(self):
        self.loggers = {}
        self.setup_logging()
        self.running = False

    def setup_logging(self):
        handler = RotatingFileHandler('siem.log', maxBytes=10000000, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        self.logger = logging.getLogger('SIEMCore')
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def start_collectors(self):
        """Start all log collectors in separate threads"""
        self.running = True

        # Start Windows Event Log collector
        if app.config['COLLECT_WINDOWS_LOGS']:
            t = threading.Thread(target=self.collect_windows_logs)
            t.daemon = True
            t.start()

        # Start firewall log collector
        if app.config['COLLECT_FIREWALL_LOGS']:
            t = threading.Thread(target=self.collect_firewall_logs)
            t.daemon = True
            t.start()

        # Start IDS/IPS alert collector
        if app.config['COLLECT_IDS_LOGS']:
            t = threading.Thread(target=self.collect_ids_logs)
            t.daemon = True
            t.start()

        # Start system log collector
        t = threading.Thread(target=self.collect_system_logs)
        t.daemon = True
        t.start()

        # Start correlation engine
        t = threading.Thread(target=self.run_correlation_engine)
        t.daemon = True
        t.start()

        self.logger.info("All collectors started")

    def collect_windows_logs(self):
        """Collect Windows Event Logs"""
        # Implementation would use WinRM or similar
        while self.running:
            try:
                # Simulate Windows event logs
                simulated_logs = [
                    {
                        'EventID': 4625,  # Failed login
                        'Source': 'Security',
                        'Message': 'An account failed to log on',
                        'Username': 'ATTACKER$',
                        'IPAddress': '192.168.1.100'
                    },
                    {
                        'EventID': 4688,  # Process creation
                        'Source': 'Security',
                        'Message': 'A new process has been created',
                        'ProcessName': 'cmd.exe',
                        'Username': 'ADMINISTRATOR'
                    }
                ]

                for log in simulated_logs:
                    self.process_log(log, 'windows')

                time.sleep(app.config['WINDOWS_LOG_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Error collecting Windows logs: {e}")

    def collect_firewall_logs(self):
        """Collect firewall logs"""
        while self.running:
            try:
                # Simulate firewall logs
                simulated_logs = [
                    {
                        'action': 'DROP',
                        'protocol': 'TCP',
                        'src_ip': '10.0.0.1',
                        'dst_ip': '192.168.1.50',
                        'dst_port': 3389,
                        'rule': 'Block_RDP'
                    },
                    {
                        'action': 'ACCEPT',
                        'protocol': 'TCP',
                        'src_ip': '192.168.1.100',
                        'dst_ip': '8.8.8.8',
                        'dst_port': 53,
                        'rule': 'Allow_DNS'
                    }
                ]

                for log in simulated_logs:
                    self.process_log(log, 'firewall')

                time.sleep(app.config['FIREWALL_LOG_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Error collecting firewall logs: {e}")

    def collect_ids_logs(self):
        """Collect IDS/IPS alerts"""
        while self.running:
            try:
                # Simulate IDS logs
                simulated_logs = [
                    {
                        'signature': 'ET WEB_SERVER Possible CVE-2021-44228 Exploit M1',
                        'category': 'Attempted Administrator Privilege Gain',
                        'src_ip': '203.0.113.5',
                        'dst_ip': '192.168.1.100',
                        'severity': 'high'
                    },
                    {
                        'signature': 'ET POLICY curl User Agent',
                        'category': 'Potential Corporate Privacy Violation',
                        'src_ip': '192.168.1.50',
                        'dst_ip': 'external.com',
                        'severity': 'medium'
                    }
                ]

                for log in simulated_logs:
                    self.process_log(log, 'ids')

                time.sleep(app.config['IDS_LOG_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Error collecting IDS logs: {e}")

    def collect_system_logs(self):
        """Collect system logs"""
        while self.running:
            try:
                # Simulate system logs
                simulated_logs = [
                    {
                        'message': 'pam_unix(sshd:auth): authentication failure',
                        'user': 'root',
                        'source_ip': '192.168.1.100'
                    },
                    {
                        'message': 'Accepted password for user from',
                        'user': 'admin',
                        'source_ip': '192.168.1.10'
                    }
                ]

                for log in simulated_logs:
                    self.process_log(log, 'system')

                time.sleep(app.config['SYSTEM_LOG_INTERVAL'])
            except Exception as e:
                self.logger.error(f"Error collecting system logs: {e}")

    def process_log(self, log, source):
        """Process a single log entry"""
        # Add metadata
        log['@timestamp'] = datetime.now().isoformat()
        log['source'] = source

        # Rule-based detection
        alerts = rule_engine.apply_rules(log)

        # Anomaly detection
        anomalies = anomaly_detector.detect_anomalies(log)

        # Store in Elasticsearch if enabled
        if es:
            try:
                es.index(index='siem-logs', body=log)
            except Exception as e:
                self.logger.error(f"Error storing log in Elasticsearch: {e}")

        # Add to dashboard data
        if alerts or anomalies:
            event_data = {
                'timestamp': log['@timestamp'],
                'source': source,
                'alerts': alerts,
                'anomalies': anomalies,
                'raw_log': log
            }

            # Update dashboard data (keep only last 1000 events)
            dashboard_data['events'].append(event_data)
            if len(dashboard_data['events']) > 1000:
                dashboard_data['events'] = dashboard_data['events'][-1000:]

            # Send alerts if any
            if alerts:
                for alert in alerts:
                    alert_notifier.send_alert(alert, log)

    def run_correlation_engine(self):
        """Run correlation rules on collected events"""
        while self.running:
            try:
                if dashboard_data['events']:
                    correlated_alerts = correlation_engine.correlate_events(dashboard_data['events'])
                    for alert in correlated_alerts:
                        alert_notifier.send_alert(alert, {'correlated': True})
            except Exception as e:
                self.logger.error(f"Error in correlation engine: {e}")
            time.sleep(app.config['CORRELATION_INTERVAL'])


# Initialize SIEM core
siem_core = SIEMCore()


# Flask routes
@app.route('/')
def dashboard():
    stats = {
        'total_events': len(dashboard_data['events']),
        'alerts_last_hour': len([e for e in dashboard_data['events']
                                 if datetime.fromisoformat(
                e['timestamp'].replace('Z', '+00:00')) > datetime.now() - timedelta(hours=1)
                                 and e['alerts']]),
        'sources': list(set(e['source'] for e in dashboard_data['events']))
    }
    return render_template('dashboard.html', events=dashboard_data['events'][-20:], stats=stats)


@app.route('/api/events')
def get_events():
    limit = int(request.args.get('limit', 100))
    source = request.args.get('source', None)

    events = dashboard_data['events']
    if source:
        events = [e for e in events if e['source'] == source]

    return jsonify(events[-limit:])


@app.route('/api/alerts')
def get_alerts():
    alerts = []
    for event in dashboard_data['events']:
        if event['alerts']:
            for alert in event['alerts']:
                alerts.append({
                    'timestamp': event['timestamp'],
                    'source': event['source'],
                    'alert': alert,
                    'raw_log': event['raw_log']
                })
    return jsonify(alerts)


@app.route('/api/stats')
def get_stats():
    # Calculate various statistics
    now = datetime.now()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    recent_events = [e for e in dashboard_data['events']
                     if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) > hour_ago]

    stats = {
        'events_last_hour': len(recent_events),
        'alerts_last_hour': len([e for e in recent_events if e['alerts']]),
        'top_sources': pd.Series([e['source'] for e in recent_events]).value_counts().to_dict(),
        'alert_types': {}
    }

    # Count alert types
    for event in recent_events:
        if event['alerts']:
            for alert in event['alerts']:
                alert_type = alert.get('type', 'unknown')
                stats['alert_types'][alert_type] = stats['alert_types'].get(alert_type, 0) + 1

    return jsonify(stats)


@app.route('/start')
def start_siem():
    siem_core.start_collectors()
    return jsonify({'status': 'started'})


@app.route('/stop')
def stop_siem():
    siem_core.running = False
    return jsonify({'status': 'stopped'})


if __name__ == '__main__':
    siem_core.start_collectors()
    app.run(debug=app.config['DEBUG'], host=app.config['HOST'], port=app.config['PORT'])