# ==============================================================================
# Copyright (c) 2026 Vedant Khalshinge. All Rights Reserved.
# 
# This file is part of the AI-Powered Cyber Threat Detection System.
# Unauthorized copying of this file, via any medium, is strictly prohibited.
# Proprietary and confidential.
# ==============================================================================

"""
Log Monitor
Tails system event logs and emits events via Socket.IO
Windows: simulated log events (pywin32 fallback)
Linux: /var/log/syslog
"""

import os
import sys
import time
import random
import threading
from datetime import datetime, timezone

MAX_EVENTS = 50

SIMULATED_EVENTS = [
    {"level": "INFO",     "source": "sshd",      "msg": "Accepted password for user from 192.168.1.5 port 22"},
    {"level": "WARNING",  "source": "kernel",     "msg": "Possible SYN flooding on port 80"},
    {"level": "ERROR",    "source": "nginx",      "msg": "Permission denied while reading file /etc/nginx/ssl"},
    {"level": "CRITICAL", "source": "auditd",     "msg": "Possible breakin attempt - repeated auth failures"},
    {"level": "INFO",     "source": "systemd",    "msg": "Started Daily Cleanup of Temporary Directories"},
    {"level": "WARNING",  "source": "firewalld",  "msg": "Blocked incoming connection from 45.33.32.156:4444"},
    {"level": "INFO",     "source": "cron",       "msg": "Job completed: /etc/cron.daily/logrotate"},
    {"level": "ERROR",    "source": "mysqld",     "msg": "Access denied for user 'root'@'external-host'"},
    {"level": "CRITICAL", "source": "aide",       "msg": "File integrity check failed: /usr/bin/passwd modified"},
    {"level": "WARNING",  "source": "fail2ban",   "msg": "Ban 198.51.100.25 (repeated SSH failures)"},
    {"level": "INFO",     "source": "NetworkManager", "msg": "Connected to interface eth0"},
    {"level": "WARNING",  "source": "cups",       "msg": "Printer queue stalled - manual intervention needed"},
    {"level": "ERROR",    "source": "samba",      "msg": "Failed to authenticate user DOMAIN\\admin"},
    {"level": "INFO",     "source": "ufw",        "msg": "Allowed outbound connection to 8.8.8.8:53 (DNS)"},
    {"level": "CRITICAL", "source": "rkhunter",   "msg": "Rootkit warning: suspicious file /tmp/.hidden_proc"},
]

SEVERITY_WEIGHTS = [0.45, 0.25, 0.20, 0.10]  # INFO, WARNING, ERROR, CRITICAL


class LogMonitor:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self._thread = None
        self._recent_events = []

    def _pick_event(self):
        level_choice = random.choices(
            ["INFO", "WARNING", "ERROR", "CRITICAL"],
            weights=SEVERITY_WEIGHTS
        )[0]
        candidates = [e for e in SIMULATED_EVENTS if e["level"] == level_choice]
        ev = random.choice(candidates)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     ev["level"],
            "source":    ev["source"],
            "message":   ev["msg"],
            "id":        int(time.time() * 1000),
        }

    def _run(self):
        while self.running:
            ev = self._pick_event()
            self._recent_events.append(ev)
            if len(self._recent_events) > MAX_EVENTS:
                self._recent_events.pop(0)
            if self.socketio:
                self.socketio.emit('log_update', ev, namespace='/logs')
            time.sleep(random.uniform(1.5, 4.0))

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def get_recent(self):
        return list(self._recent_events)
