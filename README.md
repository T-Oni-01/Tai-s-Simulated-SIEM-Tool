# Tai-s-Simulated-SIEM-Tool
A simulation-based Security Information and Event Management (SIEM) platform, built for education, testing, and experimentation. Instead of connecting to live systems, it generates simulated security logs (Windows, firewall, IDS/IPS, and system logs) that feed into a detection pipeline.

It’s a lightweight way to explore how a SIEM works — from log collection and rule-based detection to machine learning anomaly detection and correlation analysis — all within a controlled, demo-friendly environment.

***Features***
Simulated Log Sources
Windows Event Logs (failed logins, process creation)
Firewall activity (RDP blocks, DNS requests)
IDS/IPS alerts (exploit attempts, suspicious user agents)
System logs (authentication failures, accepted logins)

***Threat Detection***
Rule engine for detecting known attack patterns
ML anomaly detector for catching unusual behaviors
Correlation engine to link multi-source events into higher-confidence alerts

***Visualization & APIs***
Flask web dashboard with real-time events and stats
RESTful APIs to fetch events, alerts, and SIEM statistics
Alert breakdown by type, source, and time window

<img width="959" height="449" alt="First Test Run of SIEM" src="https://github.com/user-attachments/assets/dc4edf7a-26ac-454e-bbe1-4adb77d70e05" />

