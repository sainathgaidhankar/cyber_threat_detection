#!/usr/bin/env python3
"""
Wireshark/TShark -> cyber_threat_detection API bridge.

Reads packet stream from TShark (pcap or live interface), aggregates packets
into short-lived flows, and sends raw-flow payloads to /api/predict-flow.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class Packet:
    ts: float
    src_ip: str
    dst_ip: str
    proto: str
    src_port: int
    dst_port: int
    length: int
    syn: int
    ack: int
    rst: int
    fin: int


@dataclass
class FlowState:
    first_ts: float
    last_ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    src_bytes: int
    dst_bytes: int
    syn_seen: bool = False
    ack_seen: bool = False
    rst_seen: bool = False
    fin_seen: bool = False


def service_from_port(port: int) -> str:
    common = {
        20: "ftp_data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop_3",
        143: "imap4",
        443: "https",
    }
    return common.get(port, "other")


def protocol_from_ip_proto(value: str) -> str:
    mapping = {"6": "tcp", "17": "udp", "1": "icmp"}
    return mapping.get((value or "").strip(), "tcp")


def conn_flag(flow: FlowState) -> str:
    if flow.rst_seen:
        return "REJ"
    if flow.syn_seen and not flow.ack_seen:
        return "S0"
    if flow.syn_seen and flow.ack_seen and flow.src_bytes + flow.dst_bytes == 0:
        return "S1"
    if flow.fin_seen or (flow.src_bytes + flow.dst_bytes > 0):
        return "SF"
    return "SF"


def post_json(url: str, payload: dict, timeout: int = 10) -> Tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"error": raw}
    except URLError as exc:
        return 0, {"error": str(exc)}


def build_tshark_command(args: argparse.Namespace) -> List[str]:
    tshark_bin = resolve_tshark_bin(args.tshark_bin)
    cmd = [
        tshark_bin,
        "-n",
        "-l",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-Y",
        args.display_filter,
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ip.proto",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "frame.len",
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.ack",
        "-e",
        "tcp.flags.reset",
        "-e",
        "tcp.flags.fin",
    ]

    if args.capture_filter:
        cmd += ["-f", args.capture_filter]

    if args.pcap:
        cmd += ["-r", args.pcap]
    else:
        cmd += ["-i", args.interface]

    return cmd


def resolve_tshark_bin(user_value: str) -> str:
    if user_value:
        return user_value

    which = shutil.which("tshark")
    if which:
        return which

    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        "tshark.exe not found. Install Wireshark and add it to PATH, "
        "or pass --tshark-bin \"C:\\Program Files\\Wireshark\\tshark.exe\""
    )


def safe_int(value: str, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_packet(line: str) -> Optional[Packet]:
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 13:
        return None

    ts = parts[0].strip()
    src_ip = parts[1].strip()
    dst_ip = parts[2].strip()
    ip_proto = parts[3].strip()
    tcp_sport = safe_int(parts[4])
    tcp_dport = safe_int(parts[5])
    udp_sport = safe_int(parts[6])
    udp_dport = safe_int(parts[7])
    length = safe_int(parts[8], 0)
    syn = safe_int(parts[9], 0)
    ack = safe_int(parts[10], 0)
    rst = safe_int(parts[11], 0)
    fin = safe_int(parts[12], 0)

    if not src_ip or not dst_ip or not ts:
        return None

    proto = protocol_from_ip_proto(ip_proto)
    src_port = tcp_sport if tcp_sport else udp_sport
    dst_port = tcp_dport if tcp_dport else udp_dport

    try:
        ts_value = float(ts)
    except ValueError:
        return None

    return Packet(
        ts=ts_value,
        src_ip=src_ip,
        dst_ip=dst_ip,
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        syn=syn,
        ack=ack,
        rst=rst,
        fin=fin,
    )


def flow_key(pkt: Packet) -> Tuple[Tuple[str, str, int, int, str], bool]:
    src_endpoint = (pkt.src_ip, pkt.src_port)
    dst_endpoint = (pkt.dst_ip, pkt.dst_port)
    is_reversed = src_endpoint > dst_endpoint
    if is_reversed:
        return (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto), True
    return (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto), False


def to_payload(flow: FlowState) -> dict:
    duration = max(0.0, flow.last_ts - flow.first_ts)
    return {
        "timestamp": datetime.fromtimestamp(flow.last_ts, timezone.utc).isoformat(),
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol_type": flow.proto,
        "service": service_from_port(flow.dst_port),
        "flag": conn_flag(flow),
        "duration": duration,
        "src_bytes": flow.src_bytes,
        "dst_bytes": flow.dst_bytes,
    }


def flush_expired(
    flows: Dict[Tuple[str, str, int, int, str], FlowState],
    now_ts: float,
    flow_timeout: float,
    api_url: str,
    stats: dict,
) -> None:
    expired = [k for k, f in flows.items() if now_ts - f.last_ts >= flow_timeout]
    for key in expired:
        flow = flows.pop(key)
        status, response = post_json(api_url, to_payload(flow))
        if status == 200 and "result" in response:
            stats["sent"] += 1
            pred = response["result"].get("prediction", "unknown")
            conf = response["result"].get("confidence", 0.0)
            print(f"[ok] #{stats['sent']} pred={pred} conf={conf:.3f}")
        else:
            stats["errors"] += 1
            print(f"[err] status={status} details={response.get('error', response)}")


def run(args: argparse.Namespace) -> int:
    cmd = build_tshark_command(args)
    print("[tshark-ingest] command:", " ".join(cmd))
    print("[tshark-ingest] api_url:", args.api_url)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    flows: Dict[Tuple[str, str, int, int, str], FlowState] = {}
    stats = {"sent": 0, "errors": 0, "packets": 0}
    last_flush = time.time()

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            pkt = parse_packet(line)
            if not pkt:
                continue
            stats["packets"] += 1
            key, is_reversed = flow_key(pkt)

            flow = flows.get(key)
            if flow is None:
                flow = FlowState(
                    first_ts=pkt.ts,
                    last_ts=pkt.ts,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    proto=pkt.proto,
                    src_bytes=0,
                    dst_bytes=0,
                )
                flows[key] = flow

            flow.first_ts = min(flow.first_ts, pkt.ts)
            flow.last_ts = max(flow.last_ts, pkt.ts)
            flow.syn_seen = flow.syn_seen or bool(pkt.syn)
            flow.ack_seen = flow.ack_seen or bool(pkt.ack)
            flow.rst_seen = flow.rst_seen or bool(pkt.rst)
            flow.fin_seen = flow.fin_seen or bool(pkt.fin)

            # Directional byte attribution based on canonical flow orientation.
            if is_reversed:
                flow.dst_bytes += pkt.length
            else:
                flow.src_bytes += pkt.length

            now = time.time()
            if now - last_flush >= args.flush_interval:
                flush_expired(flows, pkt.ts, args.flow_timeout, args.api_url, stats)
                last_flush = now

        # End of pcap stream or process exit: flush remaining flows.
        if flows:
            max_ts = max(f.last_ts for f in flows.values())
            flush_expired(flows, max_ts + args.flow_timeout + 1, args.flow_timeout, args.api_url, stats)

        print(f"[stats] packets={stats['packets']} sent={stats['sent']} errors={stats['errors']}")
    finally:
        if proc.poll() is None:
            proc.terminate()

    stderr_text = ""
    if proc.stderr:
        stderr_text = proc.stderr.read().strip()
    if proc.returncode not in (0, None):
        print(f"[tshark] exited with code {proc.returncode}")
        if stderr_text:
            print(f"[tshark] stderr: {stderr_text}")
        return proc.returncode
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest traffic via TShark and call /api/predict-flow")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Path to .pcap/.pcapng file")
    src.add_argument("--interface", help="Interface name/index for live capture")
    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:5000/api/predict-flow",
        help="Prediction endpoint URL",
    )
    parser.add_argument(
        "--display-filter",
        default="ip",
        help="TShark display filter (default: ip)",
    )
    parser.add_argument(
        "--capture-filter",
        default="",
        help="Optional capture filter for live mode (BPF syntax)",
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=3.0,
        help="Idle seconds before a flow is sent for prediction",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=0.5,
        help="Seconds between expiry checks",
    )
    parser.add_argument(
        "--tshark-bin",
        default="",
        help="Full path to tshark executable (optional)",
    )
    args = parser.parse_args()
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
