"""
Flow -> NSL-KDD feature adapter.

This module builds a 41-feature vector from raw connection-like telemetry so
clients do not need to send model-ready feature arrays.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List


FEATURE_NAMES: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]


SERROR_FLAGS = {"S0", "S1", "S2", "S3"}
RERROR_FLAGS = {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return int(default)


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def _is_serror(flag: str) -> int:
    return 1 if str(flag).upper() in SERROR_FLAGS else 0


def _is_rerror(flag: str) -> int:
    return 1 if str(flag).upper() in RERROR_FLAGS else 0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Any) -> datetime:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            return _utc_now()
    try:
        raw = str(value).strip()
        if raw.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        parsed = datetime.fromisoformat(raw)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return _utc_now()


class FlowFeatureAdapter:
    """
    Stateful extractor that computes NSL-KDD style rate/count features.

    Expected raw flow payload (minimum practical fields):
    - protocol_type, service, flag, src_bytes, dst_bytes

    Better quality rate features if these are also provided:
    - timestamp, src_ip, dst_ip, src_port, dst_port
    """

    def __init__(self, short_window_seconds: int = 2, history_limit: int = 5000):
        self.short_window_seconds = max(1, int(short_window_seconds))
        self.history: Deque[Dict[str, Any]] = deque(maxlen=max(100, int(history_limit)))

    def get_schema(self) -> Dict[str, Any]:
        return {
            "feature_count": 41,
            "feature_names": FEATURE_NAMES,
            "required_raw_fields": [
                "protocol_type",
                "service",
                "flag",
                "src_bytes",
                "dst_bytes",
            ],
            "optional_raw_fields": [
                "duration",
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "wrong_fragment",
                "urgent",
                "hot",
                "num_failed_logins",
                "logged_in",
                "num_compromised",
                "root_shell",
                "su_attempted",
                "num_root",
                "num_file_creations",
                "num_shells",
                "num_access_files",
                "num_outbound_cmds",
                "is_host_login",
                "is_guest_login",
            ],
            "notes": [
                "Rate/count fields are computed from in-memory recent history.",
                "Provide timestamp/src_ip/dst_ip/src_port for better fidelity.",
                "This is an approximation layer to feed an NSL-KDD-trained model.",
            ],
        }

    def _prune(self, current_ts: datetime) -> None:
        cutoff = current_ts.timestamp() - float(self.short_window_seconds)
        while self.history and self.history[0]["ts"] < cutoff:
            self.history.popleft()

    def to_features(self, flow: Dict[str, Any]) -> Dict[int, Any]:
        if not isinstance(flow, dict):
            raise ValueError("flow payload must be a JSON object")

        protocol = str(flow.get("protocol_type", "")).strip().lower()
        service = str(flow.get("service", "")).strip().lower()
        flag = str(flow.get("flag", "")).strip().upper()
        src_bytes = _safe_int(flow.get("src_bytes"))
        dst_bytes = _safe_int(flow.get("dst_bytes"))

        if not protocol or not service or not flag:
            raise ValueError("protocol_type, service and flag are required")

        ts = _parse_ts(flow.get("timestamp"))
        ts_epoch = ts.timestamp()
        self._prune(ts)

        src_ip = str(flow.get("src_ip", "")).strip()
        dst_ip = str(flow.get("dst_ip", "")).strip()
        src_port = _safe_int(flow.get("src_port"), default=0)
        dst_port = _safe_int(flow.get("dst_port"), default=0)

        land = _safe_int(
            flow.get(
                "land",
                1 if src_ip and dst_ip and src_ip == dst_ip and src_port == dst_port else 0,
            )
        )

        current = {
            "ts": ts_epoch,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "service": service,
            "flag": flag,
        }

        short_hist = list(self.history) + [current]

        if dst_ip:
            same_host_short = [r for r in short_hist if r.get("dst_ip") == dst_ip]
            same_service_short = [
                r for r in same_host_short if r.get("service") == service
            ]
        else:
            same_host_short = short_hist
            same_service_short = [r for r in short_hist if r.get("service") == service]

        count = len(same_host_short)
        srv_count = len(same_service_short)

        serror_rate = _safe_ratio(sum(_is_serror(r.get("flag", "")) for r in same_host_short), count)
        srv_serror_rate = _safe_ratio(
            sum(_is_serror(r.get("flag", "")) for r in same_service_short), srv_count
        )
        rerror_rate = _safe_ratio(sum(_is_rerror(r.get("flag", "")) for r in same_host_short), count)
        srv_rerror_rate = _safe_ratio(
            sum(_is_rerror(r.get("flag", "")) for r in same_service_short), srv_count
        )

        same_srv_rate = _safe_ratio(srv_count, count)
        diff_srv_rate = max(0.0, 1.0 - same_srv_rate)

        same_service_global = [r for r in short_hist if r.get("service") == service]
        if src_ip:
            same_service_other_hosts = [
                r for r in same_service_global if r.get("dst_ip") and r.get("dst_ip") != src_ip
            ]
            srv_diff_host_rate = _safe_ratio(len(same_service_other_hosts), len(same_service_global))
        else:
            srv_diff_host_rate = 0.0

        long_hist = list(self.history)[-100:] + [current]
        if dst_ip:
            dst_host_records = [r for r in long_hist if r.get("dst_ip") == dst_ip]
        else:
            dst_host_records = long_hist

        dst_host_count = len(dst_host_records)
        dst_host_srv_records = [r for r in dst_host_records if r.get("service") == service]
        dst_host_srv_count = len(dst_host_srv_records)

        dst_host_same_srv_rate = _safe_ratio(dst_host_srv_count, dst_host_count)
        dst_host_diff_srv_rate = max(0.0, 1.0 - dst_host_same_srv_rate)

        dst_host_same_src_port_rate = _safe_ratio(
            sum(1 for r in dst_host_records if r.get("src_port", -1) == src_port),
            dst_host_count,
        )

        if src_ip:
            dst_host_srv_diff_host_rate = _safe_ratio(
                sum(1 for r in dst_host_srv_records if r.get("src_ip") and r.get("src_ip") != src_ip),
                dst_host_srv_count,
            )
        else:
            dst_host_srv_diff_host_rate = 0.0

        dst_host_serror_rate = _safe_ratio(
            sum(_is_serror(r.get("flag", "")) for r in dst_host_records), dst_host_count
        )
        dst_host_srv_serror_rate = _safe_ratio(
            sum(_is_serror(r.get("flag", "")) for r in dst_host_srv_records), dst_host_srv_count
        )
        dst_host_rerror_rate = _safe_ratio(
            sum(_is_rerror(r.get("flag", "")) for r in dst_host_records), dst_host_count
        )
        dst_host_srv_rerror_rate = _safe_ratio(
            sum(_is_rerror(r.get("flag", "")) for r in dst_host_srv_records), dst_host_srv_count
        )

        features = {
            0: _safe_int(flow.get("duration")),
            1: protocol,
            2: service,
            3: flag,
            4: src_bytes,
            5: dst_bytes,
            6: land,
            7: _safe_int(flow.get("wrong_fragment")),
            8: _safe_int(flow.get("urgent")),
            9: _safe_int(flow.get("hot")),
            10: _safe_int(flow.get("num_failed_logins")),
            11: _safe_int(flow.get("logged_in")),
            12: _safe_int(flow.get("num_compromised")),
            13: _safe_int(flow.get("root_shell")),
            14: _safe_int(flow.get("su_attempted")),
            15: _safe_int(flow.get("num_root")),
            16: _safe_int(flow.get("num_file_creations")),
            17: _safe_int(flow.get("num_shells")),
            18: _safe_int(flow.get("num_access_files")),
            19: _safe_int(flow.get("num_outbound_cmds")),
            20: _safe_int(flow.get("is_host_login")),
            21: _safe_int(flow.get("is_guest_login")),
            22: count,
            23: srv_count,
            24: round(serror_rate, 5),
            25: round(srv_serror_rate, 5),
            26: round(rerror_rate, 5),
            27: round(srv_rerror_rate, 5),
            28: round(same_srv_rate, 5),
            29: round(diff_srv_rate, 5),
            30: round(srv_diff_host_rate, 5),
            31: dst_host_count,
            32: dst_host_srv_count,
            33: round(dst_host_same_srv_rate, 5),
            34: round(dst_host_diff_srv_rate, 5),
            35: round(dst_host_same_src_port_rate, 5),
            36: round(dst_host_srv_diff_host_rate, 5),
            37: round(dst_host_serror_rate, 5),
            38: round(dst_host_srv_serror_rate, 5),
            39: round(dst_host_rerror_rate, 5),
            40: round(dst_host_srv_rerror_rate, 5),
        }

        self.history.append(current)
        return features
