# ==============================================================================
# Copyright (c) 2026 Vedant Khalshinge. All Rights Reserved.
# 
# This file is part of the AI-Powered Cyber Threat Detection System.
# Unauthorized copying of this file, via any medium, is strictly prohibited.
# Proprietary and confidential.
# ==============================================================================

"""
System Metrics Collector
Real-time CPU, RAM, Disk, GPU monitoring via psutil + pynvml
"""

import time
import threading
import psutil
from datetime import datetime, timezone
from collections import deque

try:
    import pynvml
    pynvml.nvmlInit()
    _GPU_AVAILABLE = True
    _GPU_COUNT = pynvml.nvmlDeviceGetCount()
except Exception:
    _GPU_AVAILABLE = False
    _GPU_COUNT = 0

HISTORY_LEN = 60  # Rolling window of 60 data points


class MetricsCollector:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self._thread = None
        self.history = {
            "cpu":    deque(maxlen=HISTORY_LEN),
            "ram":    deque(maxlen=HISTORY_LEN),
            "disk_read":  deque(maxlen=HISTORY_LEN),
            "disk_write": deque(maxlen=HISTORY_LEN),
        }
        if _GPU_AVAILABLE:
            self.history["gpu"] = deque(maxlen=HISTORY_LEN)

    def _collect(self):
        prev_disk = psutil.disk_io_counters()
        while self.running:
            ts = datetime.now(timezone.utc).isoformat()

            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            ram = mem.percent

            curr_disk = psutil.disk_io_counters()
            disk_read = (curr_disk.read_bytes - prev_disk.read_bytes) / 1024  # KB/s
            disk_write = (curr_disk.write_bytes - prev_disk.write_bytes) / 1024
            prev_disk = curr_disk

            self.history["cpu"].append(cpu)
            self.history["ram"].append(ram)
            self.history["disk_read"].append(round(disk_read, 2))
            self.history["disk_write"].append(round(disk_write, 2))

            payload = {
                "timestamp": ts,
                "cpu":       round(cpu, 1),
                "ram":       round(ram, 1),
                "ram_used_gb": round(mem.used / 1e9, 2),
                "ram_total_gb": round(mem.total / 1e9, 2),
                "disk_read_kbps":  round(disk_read, 1),
                "disk_write_kbps": round(disk_write, 1),
                "processes": len(psutil.pids()),
                "gpu":       [],
            }

            if _GPU_AVAILABLE:
                gpu_data = []
                for i in range(_GPU_COUNT):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    name = pynvml.nvmlDeviceGetName(handle)
                    if isinstance(name, bytes):
                        name = name.decode()
                    gpu_data.append({
                        "name": name,
                        "gpu_util": util.gpu,
                        "mem_used_mb": round(mem_info.used / 1e6, 1),
                        "mem_total_mb": round(mem_info.total / 1e6, 1),
                    })
                payload["gpu"] = gpu_data
                self.history["gpu"].append(gpu_data[0]["gpu_util"] if gpu_data else 0)

            if self.socketio:
                self.socketio.emit('metrics_update', payload, namespace='/metrics')

            time.sleep(2)

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._collect, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def get_history(self):
        return {k: list(v) for k, v in self.history.items()}
