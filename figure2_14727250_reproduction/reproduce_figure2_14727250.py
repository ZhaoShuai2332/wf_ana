"""
基于 14727250 数据集的 Figure 2 风格复现实验。

本脚本尽量贴近论文
"Understanding Web Fingerprinting with a Protocol-Centric Approach" 中 Figure 2
的实验思路：先把一个被选中的目标连接表示为按方向聚合的 payload/clump 序列
P0, P1, P2, ...，再分别构造 Phead(i) 和 Ptail(i)，观察不同位置对分类
性能的贡献。

需要强调的是：14727250 数据集并不是原论文的 Tranco HTTPS 数据集。本脚本中
的 P_i 是从 PCAP 中可见的 443/TCP 或 443/UDP 载荷方向片段近似构造出来的
"pseudo-payload/clump"，不是经过完整 TLS record 重组和协议语义确认的严格
TLS payload。因此报告中应使用 "Figure-2-style reproduction" 或
"pseudo-payload position contribution analysis" 这类表述。
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
import socket
import struct
import sys
import traceback
from typing import Iterable

import numpy as np
import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = Path("14727250")
DEFAULT_OUTPUT = SCRIPT_DIR / "outputs"
DEFAULT_FEATURES = DEFAULT_OUTPUT / "features" / "pseudo_payload_features.csv"

AVAILABLE_MODELS = ("logistic_regression", "random_forest", "knn", "xgboost")
DEFAULT_MODELS = "logistic_regression,random_forest,knn,xgboost"


@dataclass
class PacketEvent:
    """一个带方向的 443 载荷事件。"""

    timestamp: float
    length: int
    direction: int
    flow_key: tuple
    remote_ip: str
    proto: str


@dataclass
class Flow:
    """按五元组归并后的单条连接。"""

    key: tuple
    remote_ip: str
    proto: str
    events: list[PacketEvent]

    @property
    def start_ts(self) -> float:
        return self.events[0].timestamp

    @property
    def end_ts(self) -> float:
        return self.events[-1].timestamp

    @property
    def packet_count(self) -> int:
        return len(self.events)

    @property
    def total_bytes(self) -> int:
        return int(sum(event.length for event in self.events))


@dataclass
class Clump:
    """方向连续的一段载荷，作为 P_i 的近似单位。"""

    position: int
    direction: int
    start_ts: float
    end_ts: float
    length: int = 0
    packet_count: int = 0

    def add(self, event: PacketEvent) -> None:
        self.length += int(event.length)
        self.packet_count += 1
        self.end_ts = event.timestamp

    @property
    def duration(self) -> float:
        return max(0.0, float(self.end_ts - self.start_ts))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "在 14727250 PCAP 上运行 Figure-2-style pseudo-payload Phead/Ptail 实验。"
        )
    )
    parser.add_argument(
        "--stage",
        choices=("all", "process", "evaluate", "plot", "report"),
        default="all",
        help="运行阶段：all=处理+评估+报告；process=只抽特征；evaluate=只评估；plot=只重画图；report=只重写报告。",
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="14727250 数据集目录。")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT, help="所有结果输出目录。")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES, help="中间特征 CSV 路径。")
    parser.add_argument("--port", type=int, default=443, help="需要分析的服务端端口，默认 443。")
    parser.add_argument(
        "--length-mode",
        choices=("transport-payload", "frame"),
        default="transport-payload",
        help="载荷长度定义：transport-payload=TCP/UDP 载荷；frame=整帧长度。",
    )
    parser.add_argument(
        "--min-payload-bytes",
        type=int,
        default=1,
        help="小于该长度的 TCP/UDP 载荷会被丢弃，默认 1。",
    )
    parser.add_argument(
        "--flow-selector",
        choices=("target-largest", "target-first", "largest", "first"),
        default="target-largest",
        help="如何从一次访问中选择最接近原论文单 flow 分析的目标连接。",
    )
    parser.add_argument(
        "--target-domain-mode",
        choices=("exact", "exact-or-subdomain"),
        default="exact-or-subdomain",
        help="用 domain_ip 文件匹配目标域名 IP 的方式。",
    )
    parser.add_argument(
        "--sequence-width",
        type=int,
        default=20,
        help="每个样本最多保留多少个 P_i 位置。",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=20,
        help="Phead/Ptail 曲线评估到 P0..P(window-1)。",
    )
    parser.add_argument(
        "--feature-set",
        choices=("paper", "signed", "rich"),
        default="paper",
        help="P_i 特征集合。paper 对齐原仓库 TimeSeries 的 5 个字段。",
    )
    parser.add_argument("--models", default=DEFAULT_MODELS, help="模型列表，逗号分隔；all 表示全部。")
    parser.add_argument(
        "--primary-model",
        default="auto",
        help="用于绘制 Phead/Ptail 主图的模型；auto 表示选择完整特征 macro-F1 最高者。",
    )
    parser.add_argument(
        "--evaluation-mode",
        choices=("multiclass", "one-vs-rest"),
        default="multiclass",
        help="multiclass 较快；one-vs-rest 更接近原论文逐域名二分类，但计算量大。",
    )
    parser.add_argument("--min-samples-per-site", type=int, default=5, help="每个站点最少样本数。")
    parser.add_argument("--max-folds", type=int, default=5, help="交叉验证最大折数。")
    parser.add_argument(
        "--critical-threshold",
        type=float,
        default=0.02,
        help="关键窗口阈值：full macro-F1 减去该值。",
    )
    parser.add_argument("--model-preset", choices=("standard", "high"), default="standard")
    parser.add_argument("--seed", type=int, default=0, help="随机种子。")
    parser.add_argument("--reuse-features", action="store_true", help="已有特征时跳过 process 阶段。")
    parser.add_argument("--limit", type=int, default=0, help="调试用：最多处理多少个 PCAP。")
    parser.add_argument("--site-limit", type=int, default=0, help="调试用：只处理前 N 个站点。")
    parser.add_argument(
        "--max-visits-per-site",
        type=int,
        default=0,
        help="调试用：每个站点最多处理多少次访问。",
    )
    parser.add_argument("--workers", type=int, default=1, help="PCAP 解析并行线程数；Windows 下建议 1-8。")
    parser.add_argument("--no-progress", action="store_true", help="不显示进度条。")
    return parser.parse_args()


def parse_model_names(value: str) -> list[str]:
    names = [part.strip() for part in value.split(",") if part.strip()]
    if not names:
        raise ValueError("--models 不能为空。")
    if "all" in names:
        return list(AVAILABLE_MODELS)
    unknown = [name for name in names if name not in AVAILABLE_MODELS]
    if unknown:
        raise ValueError(f"未知模型：{', '.join(unknown)}")
    return names


def render_progress(current: int, total: int, success: int, failed: int, name: str = "") -> None:
    if total <= 0:
        return
    width = 34
    ratio = min(1.0, max(0.0, current / total))
    filled = int(round(width * ratio))
    bar = "#" * filled + "-" * (width - filled)
    suffix = f" {name[:42]:<42}" if name else ""
    sys.stdout.write(
        f"\r[{bar}] {current:>5}/{total:<5} {ratio * 100:6.2f}% "
        f"ok={success:<5} failed={failed:<5}{suffix}"
    )
    sys.stdout.flush()


def infer_site_visit(path: Path) -> tuple[str, str, str]:
    """从 14727250 的路径中恢复站点标签和 visit_id。"""

    stem = path.stem
    result_group = ""
    for parent in path.parents:
        if re.fullmatch(r"result_\d+_\d+", parent.name):
            result_group = parent.name
            break
    site = stem.replace("_", ".")
    visit_id = f"{result_group}/{stem}" if result_group else stem
    return site, visit_id, stem


def collect_pcaps(input_dir: Path, args: argparse.Namespace) -> list[Path]:
    if input_dir.is_file():
        files = [input_dir]
    else:
        files = sorted(input_dir.rglob("*.pcap")) + sorted(input_dir.rglob("*.pcapng"))

    rows = []
    for path in files:
        site, visit_id, _stem = infer_site_visit(path)
        rows.append((site, visit_id, path))

    if args.site_limit:
        selected_sites = sorted({site for site, _visit, _path in rows})[: args.site_limit]
        selected_set = set(selected_sites)
        rows = [row for row in rows if row[0] in selected_set]

    if args.max_visits_per_site:
        kept = []
        counts: dict[str, int] = {}
        for site, visit_id, path in rows:
            counts[site] = counts.get(site, 0)
            if counts[site] < args.max_visits_per_site:
                kept.append((site, visit_id, path))
                counts[site] += 1
        rows = kept

    files = [path for _site, _visit, path in rows]
    if args.limit:
        files = files[: args.limit]
    return files


def domain_matches(candidate: str, target: str, mode: str) -> bool:
    candidate = candidate.strip().strip(".").lower()
    target = target.strip().strip(".").lower()
    if not candidate or not target:
        return False
    if candidate == target:
        return True
    if mode == "exact-or-subdomain" and candidate.endswith("." + target):
        return True
    return False


def int_to_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(int(value)))
    except Exception:
        return None


def load_target_ips(pcap_path: Path, dataset_root: Path, stem: str, site: str, mode: str) -> set[str]:
    """读取同一次访问的 domain_ip 文件，提取目标站点域名对应的 IP 集合。"""

    domain_ip_file = pcap_path.parent.parent / "domain_ip" / f"{stem}.csv"
    if not domain_ip_file.exists():
        return set()

    target_ips: set[str] = set()
    try:
        with domain_ip_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if len(row) < 2:
                    continue
                domain, raw_ips = row[0], row[1]
                if not domain_matches(domain, site, mode):
                    continue
                for value in raw_ips.split(";"):
                    ip_value = int_to_ip(value.strip())
                    if ip_value:
                        target_ips.add(ip_value)
    except Exception:
        return set()
    return target_ips


def parse_pcap_events(path: Path, port: int, min_payload: int, length_mode: str) -> list[PacketEvent]:
    """从标准 PCAP 中提取 443/TCP 与 443/UDP 的有载荷数据包。

    这里使用轻量级解析器而不是 scapy/pyshark，原因是全量 14727250 数据需要反复读取
    数千个 PCAP，外部解析器启动成本较高。该解析器只处理本实验需要的字段：
    Ethernet、IPv4/IPv6、TCP/UDP 端口、时间戳和载荷长度。
    """

    def pcap_format(header: bytes) -> tuple[str, float]:
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            return "<", 1_000_000.0
        if magic == b"\xa1\xb2\xc3\xd4":
            return ">", 1_000_000.0
        if magic == b"\x4d\x3c\xb2\xa1":
            return "<", 1_000_000_000.0
        if magic == b"\xa1\xb2\x3c\x4d":
            return ">", 1_000_000_000.0
        if magic == b"\x0a\x0d\x0d\x0a":
            raise RuntimeError("暂不支持 pcapng，请先转换为标准 pcap。")
        raise RuntimeError(f"未知 PCAP magic: {magic.hex()}")

    def parse_ethernet(packet: bytes) -> tuple[int, int] | None:
        if len(packet) < 14:
            return None
        offset = 14
        eth_type = struct.unpack("!H", packet[12:14])[0]
        # 处理 802.1Q / QinQ VLAN 标签。
        while eth_type in {0x8100, 0x88A8} and len(packet) >= offset + 4:
            eth_type = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
            offset += 4
        return eth_type, offset

    def parse_ipv4(packet: bytes, offset: int) -> tuple[str, str, int, int, int] | None:
        if len(packet) < offset + 20:
            return None
        first = packet[offset]
        ihl = (first & 0x0F) * 4
        if ihl < 20 or len(packet) < offset + ihl:
            return None
        total_len = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        proto = packet[offset + 9]
        src = socket.inet_ntoa(packet[offset + 12 : offset + 16])
        dst = socket.inet_ntoa(packet[offset + 16 : offset + 20])
        payload_offset = offset + ihl
        payload_end = min(len(packet), offset + total_len) if total_len else len(packet)
        return src, dst, proto, payload_offset, payload_end

    def parse_ipv6(packet: bytes, offset: int) -> tuple[str, str, int, int, int] | None:
        if len(packet) < offset + 40:
            return None
        payload_len = struct.unpack("!H", packet[offset + 4 : offset + 6])[0]
        proto = packet[offset + 6]
        src = socket.inet_ntop(socket.AF_INET6, packet[offset + 8 : offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, packet[offset + 24 : offset + 40])
        payload_offset = offset + 40
        payload_end = min(len(packet), payload_offset + payload_len)
        return src, dst, proto, payload_offset, payload_end

    events: list[PacketEvent] = []
    with path.open("rb") as handle:
        global_header = handle.read(24)
        if len(global_header) < 24:
            return events
        endian, timestamp_scale = pcap_format(global_header)
        linktype = struct.unpack(endian + "I", global_header[20:24])[0]
        if linktype != 1:
            raise RuntimeError(f"暂不支持非 Ethernet linktype: {linktype}")

        packet_header_struct = struct.Struct(endian + "IIII")
        while True:
            packet_header = handle.read(16)
            if not packet_header:
                break
            if len(packet_header) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = packet_header_struct.unpack(packet_header)
            packet = handle.read(incl_len)
            if len(packet) < incl_len:
                break

            eth = parse_ethernet(packet)
            if eth is None:
                continue
            eth_type, ip_offset = eth
            if eth_type == 0x0800:
                parsed_ip = parse_ipv4(packet, ip_offset)
            elif eth_type == 0x86DD:
                parsed_ip = parse_ipv6(packet, ip_offset)
            else:
                continue
            if parsed_ip is None:
                continue

            ip_src, ip_dst, ip_proto, transport_offset, payload_end = parsed_ip
            if ip_proto == 6:
                if len(packet) < transport_offset + 20:
                    continue
                sport, dport = struct.unpack("!HH", packet[transport_offset : transport_offset + 4])
                tcp_header_len = ((packet[transport_offset + 12] >> 4) & 0x0F) * 4
                if tcp_header_len < 20:
                    continue
                payload_offset = transport_offset + tcp_header_len
                proto = "tcp"
            elif ip_proto == 17:
                if len(packet) < transport_offset + 8:
                    continue
                sport, dport, udp_len = struct.unpack("!HHH", packet[transport_offset : transport_offset + 6])
                payload_offset = transport_offset + 8
                payload_end = min(payload_end, transport_offset + udp_len)
                proto = "udp"
            else:
                continue

            if dport == port:
                direction = 1
                remote_ip = ip_dst
                flow_key = (proto, ip_src, int(sport), ip_dst, int(dport))
            elif sport == port:
                direction = -1
                remote_ip = ip_src
                flow_key = (proto, ip_dst, int(dport), ip_src, int(sport))
            else:
                continue

            payload_len = max(0, payload_end - payload_offset)
            length = int(incl_len if length_mode == "frame" else payload_len)
            if length < min_payload:
                continue
            events.append(
                PacketEvent(
                    timestamp=float(ts_sec) + float(ts_frac) / timestamp_scale,
                    length=length,
                    direction=direction,
                    flow_key=flow_key,
                    remote_ip=remote_ip,
                    proto=proto,
                )
            )

    events.sort(key=lambda item: item.timestamp)
    return events


def group_flows(events: Iterable[PacketEvent]) -> list[Flow]:
    grouped: dict[tuple, list[PacketEvent]] = {}
    meta: dict[tuple, tuple[str, str]] = {}
    for event in events:
        grouped.setdefault(event.flow_key, []).append(event)
        meta[event.flow_key] = (event.remote_ip, event.proto)

    flows = []
    for key, flow_events in grouped.items():
        flow_events.sort(key=lambda item: item.timestamp)
        remote_ip, proto = meta[key]
        flows.append(Flow(key=key, remote_ip=remote_ip, proto=proto, events=flow_events))
    return sorted(flows, key=lambda flow: (flow.start_ts, flow.end_ts, flow.key))


def select_flow(flows: list[Flow], target_ips: set[str], selector: str) -> tuple[Flow | None, str]:
    if not flows:
        return None, "no_flow"

    target_flows = [flow for flow in flows if flow.remote_ip in target_ips] if target_ips else []
    if selector == "target-largest":
        if target_flows:
            return max(target_flows, key=lambda flow: (flow.total_bytes, -flow.start_ts)), "target_largest"
        return max(flows, key=lambda flow: (flow.total_bytes, -flow.start_ts)), "fallback_largest_no_target_match"
    if selector == "target-first":
        if target_flows:
            return sorted(target_flows, key=lambda flow: flow.start_ts)[0], "target_first"
        return sorted(flows, key=lambda flow: flow.start_ts)[0], "fallback_first_no_target_match"
    if selector == "largest":
        return max(flows, key=lambda flow: (flow.total_bytes, -flow.start_ts)), "largest"
    if selector == "first":
        return sorted(flows, key=lambda flow: flow.start_ts)[0], "first"
    raise ValueError(f"未知 flow-selector: {selector}")


def build_clumps(flow: Flow) -> list[dict]:
    """将单条连接内连续同方向数据包聚合成 P-like clump 序列。"""

    clumps: list[Clump] = []
    current: Clump | None = None
    for event in flow.events:
        if current is None or current.direction != event.direction:
            if current is not None and current.packet_count:
                clumps.append(current)
            current = Clump(
                position=len(clumps),
                direction=event.direction,
                start_ts=event.timestamp,
                end_ts=event.timestamp,
            )
        current.add(event)
    if current is not None and current.packet_count:
        clumps.append(current)

    rows: list[dict] = []
    prev_end = clumps[0].start_ts if clumps else flow.start_ts
    for idx, clump in enumerate(clumps):
        rows.append(
            {
                "position": idx,
                "relative_timestamp": round(max(0.0, clump.start_ts - prev_end), 9),
                "duration": round(clump.duration, 9),
                "length": int(clump.length),
                "pkt_count": int(clump.packet_count),
                "direction": int(clump.direction),
                "start_time": round(max(0.0, clump.start_ts - flow.start_ts), 9),
            }
        )
        prev_end = clump.end_ts
    return rows


def row_from_pcap(path: Path, args: argparse.Namespace) -> tuple[dict | None, dict | None]:
    site, visit_id, stem = infer_site_visit(path)
    target_ips = load_target_ips(
        pcap_path=path,
        dataset_root=args.input,
        stem=stem,
        site=site,
        mode=args.target_domain_mode,
    )
    events = parse_pcap_events(path, args.port, args.min_payload_bytes, args.length_mode)
    if not events:
        return None, {"source_path": str(path), "site": site, "reason": "no_443_payload_events"}
    flows = group_flows(events)
    selected, reason = select_flow(flows, target_ips, args.flow_selector)
    if selected is None:
        return None, {"source_path": str(path), "site": site, "reason": "no_selected_flow"}
    units = build_clumps(selected)
    if not units:
        return None, {"source_path": str(path), "site": site, "reason": "selected_flow_has_no_clumps"}

    capture_start = events[0].timestamp
    row = {
        "site": site,
        "visit_id": visit_id,
        "sample_id": f"{visit_id}:{selected.key}",
        "unit_type": "pseudo_payload_clump",
        "flow_selector": args.flow_selector,
        "selection_reason": reason,
        "target_ip_count": len(target_ips),
        "selected_remote_ip": selected.remote_ip,
        "selected_proto": selected.proto,
        "flow_total_bytes": selected.total_bytes,
        "flow_packet_count": selected.packet_count,
        "flow_start_time": round(selected.start_ts - capture_start, 9),
        "flow_duration": round(max(0.0, selected.end_ts - selected.start_ts), 9),
        "position_count": len(units),
        "units_json": json.dumps(units, ensure_ascii=False),
        "source_path": str(path),
    }
    return row, None


def write_feature_rows(rows: list[dict], failures: list[dict], features_path: Path, output_dir: Path) -> None:
    features_path.parent.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    columns = [
        "site",
        "visit_id",
        "sample_id",
        "unit_type",
        "flow_selector",
        "selection_reason",
        "target_ip_count",
        "selected_remote_ip",
        "selected_proto",
        "flow_total_bytes",
        "flow_packet_count",
        "flow_start_time",
        "flow_duration",
        "position_count",
        "units_json",
        "source_path",
    ]
    with features_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    if failures:
        pd.DataFrame(failures).to_csv(
            output_dir / "features" / "extraction_failures.csv",
            index=False,
            encoding="utf-8-sig",
        )
    else:
        pd.DataFrame(columns=["source_path", "site", "reason"]).to_csv(
            output_dir / "features" / "extraction_failures.csv",
            index=False,
            encoding="utf-8-sig",
        )


def process(args: argparse.Namespace) -> None:
    files = collect_pcaps(args.input, args)
    print(f"输入目录: {args.input}")
    print(f"候选 PCAP 数量: {len(files)}")
    rows: list[dict] = []
    failures: list[dict] = []
    if not args.no_progress:
        render_progress(0, len(files), 0, 0)
    if args.workers <= 1:
        for idx, path in enumerate(files, start=1):
            try:
                row, failure = row_from_pcap(path, args)
                if row is not None:
                    rows.append(row)
                if failure is not None:
                    failures.append(failure)
            except Exception as exc:
                failures.append(
                    {
                        "source_path": str(path),
                        "site": infer_site_visit(path)[0],
                        "reason": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(limit=2),
                    }
                )
            if not args.no_progress:
                render_progress(idx, len(files), len(rows), len(failures), path.name)
    else:
        # 仅并行 PCAP 解析阶段；模型训练仍保持串行，以保证交叉验证结果稳定可复现。
        # 这里使用线程池而不是进程池，避免 Windows 下子进程启动和对象序列化导致的不稳定。
        completed = 0
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {executor.submit(row_from_pcap, path, args): path for path in files}
            for future in as_completed(future_map):
                path = future_map[future]
                completed += 1
                try:
                    row, failure = future.result()
                    if row is not None:
                        rows.append(row)
                    if failure is not None:
                        failures.append(failure)
                except Exception as exc:
                    failures.append(
                        {
                            "source_path": str(path),
                            "site": infer_site_visit(path)[0],
                            "reason": f"{type(exc).__name__}: {exc}",
                            "traceback": traceback.format_exc(limit=2),
                        }
                    )
                if not args.no_progress:
                    render_progress(completed, len(files), len(rows), len(failures), path.name)
    if not args.no_progress:
        print()
    rows.sort(key=lambda item: (item["site"], item["visit_id"]))
    failures.sort(key=lambda item: (item.get("site", ""), item.get("source_path", "")))
    write_feature_rows(rows, failures, args.features, args.output_dir)
    print(f"成功样本: {len(rows)}")
    print(f"失败样本: {len(failures)}")
    print(f"特征文件: {args.features}")


def load_rows(features_path: Path) -> list[dict]:
    df = pd.read_csv(features_path)
    rows = []
    for _, item in df.iterrows():
        try:
            units = json.loads(item["units_json"])
        except Exception:
            continue
        rows.append(
            {
                "site": str(item["site"]),
                "visit_id": str(item["visit_id"]),
                "units": units,
                "position_count": int(item["position_count"]),
                "flow_total_bytes": float(item["flow_total_bytes"]),
                "flow_duration": float(item["flow_duration"]),
                "selection_reason": str(item["selection_reason"]),
                "selected_proto": str(item["selected_proto"]),
            }
        )
    return rows


def filter_rows(rows: list[dict], min_samples: int, output_dir: Path) -> list[dict]:
    counts = pd.Series([row["site"] for row in rows]).value_counts()
    eligible = set(counts[counts >= min_samples].index)
    site_coverage = counts.rename_axis("site").reset_index(name="sample_count")
    site_coverage["eligible"] = site_coverage["site"].isin(eligible)
    (output_dir / "features").mkdir(parents=True, exist_ok=True)
    site_coverage.to_csv(
        output_dir / "features" / "site_coverage.csv",
        index=False,
        encoding="utf-8-sig",
    )
    return [row for row in rows if row["site"] in eligible]


def unit_channels(unit: dict, feature_set: str) -> np.ndarray:
    length = float(unit.get("length", 0.0))
    direction = float(unit.get("direction", 0.0))
    if feature_set == "signed":
        return np.asarray([direction * np.log1p(max(0.0, length))], dtype=float)
    if feature_set == "paper":
        return np.asarray(
            [
                float(unit.get("relative_timestamp", 0.0)),
                float(unit.get("duration", 0.0)),
                length,
                float(unit.get("pkt_count", 0.0)),
                direction,
            ],
            dtype=float,
        )
    if feature_set == "rich":
        return np.asarray(
            [
                float(unit.get("relative_timestamp", 0.0)),
                float(unit.get("duration", 0.0)),
                np.log1p(max(0.0, length)),
                np.log1p(max(0.0, float(unit.get("pkt_count", 0.0)))),
                direction,
                float(unit.get("start_time", 0.0)),
            ],
            dtype=float,
        )
    raise ValueError(f"未知 feature-set: {feature_set}")


def feature_dim(feature_set: str) -> int:
    return len(unit_channels({}, feature_set))


def masked_matrix(
    rows: list[dict],
    mode: str,
    position: int,
    sequence_width: int,
    feature_set: str,
) -> np.ndarray:
    """构造 full/Phead/Ptail 对应的二维特征矩阵。"""

    dim = feature_dim(feature_set)
    matrix = np.zeros((len(rows), sequence_width * dim), dtype=float)
    for row_idx, row in enumerate(rows):
        units = row["units"]
        if mode == "full":
            selected = units[:sequence_width]
        elif mode == "head":
            selected = units[: position + 1]
        elif mode == "tail":
            selected = units[position:]
        else:
            raise ValueError(f"未知 mask 模式: {mode}")
        selected = selected[:sequence_width]
        if not selected:
            continue
        flat = np.concatenate([unit_channels(unit, feature_set) for unit in selected])
        matrix[row_idx, : len(flat)] = flat
    return matrix


def build_model(name: str, min_class_count: int, preset: str, seed: int):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    if name == "logistic_regression":
        return make_pipeline(
            StandardScaler(),
            LogisticRegression(
                max_iter=12000 if preset == "high" else 4000,
                class_weight="balanced",
                random_state=seed,
            ),
        )
    if name == "random_forest":
        return RandomForestClassifier(
            n_estimators=1000 if preset == "high" else 350,
            max_features="sqrt",
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=-1,
        )
    if name == "knn":
        return make_pipeline(
            StandardScaler(),
            KNeighborsClassifier(n_neighbors=max(1, min(5, min_class_count - 1))),
        )
    if name == "xgboost":
        try:
            from xgboost import XGBClassifier
        except Exception as exc:
            raise RuntimeError("当前环境未安装 xgboost。") from exc
        return XGBClassifier(
            n_estimators=800 if preset == "high" else 250,
            max_depth=6 if preset == "high" else 4,
            learning_rate=0.04 if preset == "high" else 0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            tree_method="hist",
            random_state=seed,
            n_jobs=1,
        )
    raise ValueError(f"未知模型: {name}")


def prepare_cv(rows: list[dict], min_samples: int, max_folds: int, seed: int) -> dict:
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.preprocessing import LabelEncoder

    labels = pd.Series([row["site"] for row in rows])
    groups = np.asarray([row["visit_id"] for row in rows], dtype=object)
    counts = labels.value_counts()
    min_count = int(counts.min()) if not counts.empty else 0
    if min_count < min_samples:
        return {"can_run": False, "reason": f"最小类别样本数 {min_count} < {min_samples}"}

    unique_groups = pd.DataFrame({"site": labels, "group": groups}).drop_duplicates()
    min_group_count = int(unique_groups.groupby("site")["group"].size().min())
    if min_group_count < 2:
        return {"can_run": False, "reason": "每个站点的独立 visit 数不足，无法分组交叉验证。"}

    n_splits = min(max_folds, min_count, min_group_count)
    if n_splits < 2:
        return {"can_run": False, "reason": "有效折数小于 2。"}

    encoder = LabelEncoder()
    y = encoder.fit_transform(labels.to_numpy())
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    splits = list(cv.split(np.zeros(len(rows)), y, groups=groups))
    return {
        "can_run": True,
        "y": y,
        "labels": labels.to_numpy(),
        "classes": encoder.classes_,
        "groups": groups,
        "splits": splits,
        "n_splits": n_splits,
        "min_class_count": min_count,
        "strategy": "StratifiedGroupKFold",
    }


def out_of_fold_multiclass(X: np.ndarray, cv_info: dict, model_name: str, args: argparse.Namespace) -> np.ndarray:
    y = cv_info["y"]
    pred = np.full(y.shape, fill_value=-1, dtype=int)
    for train_idx, test_idx in cv_info["splits"]:
        model = build_model(model_name, cv_info["min_class_count"], args.model_preset, args.seed)
        model.fit(X[train_idx], y[train_idx])
        pred[test_idx] = np.asarray(model.predict(X[test_idx]), dtype=int)
    return pred


def evaluate_multiclass(X: np.ndarray, cv_info: dict, model_name: str, args: argparse.Namespace) -> tuple[dict, pd.DataFrame]:
    from sklearn.metrics import accuracy_score, f1_score

    y = cv_info["y"]
    pred = out_of_fold_multiclass(X, cv_info, model_name, args)
    labels = np.arange(len(cv_info["classes"]))
    per_site_scores = f1_score(y, pred, labels=labels, average=None, zero_division=0)
    per_site = pd.DataFrame({"site": cv_info["classes"], "f1": per_site_scores})
    return (
        {
            "accuracy": float(accuracy_score(y, pred)),
            "f1_macro": float(f1_score(y, pred, average="macro", zero_division=0)),
            "f1_weighted": float(f1_score(y, pred, average="weighted", zero_division=0)),
        },
        per_site,
    )


def evaluate_one_vs_rest(X: np.ndarray, cv_info: dict, model_name: str, args: argparse.Namespace) -> tuple[dict, pd.DataFrame]:
    """逐站点二分类评估。更接近原论文，但计算量明显更大。"""

    from sklearn.metrics import accuracy_score, f1_score
    from sklearn.model_selection import StratifiedGroupKFold

    labels = pd.Series(cv_info["labels"])
    groups = cv_info["groups"]
    records = []
    all_true = []
    all_pred = []
    for site in cv_info["classes"]:
        y_bin = (labels.to_numpy() == site).astype(int)
        pos_groups = len(set(groups[y_bin == 1]))
        neg_groups = len(set(groups[y_bin == 0]))
        n_splits = min(args.max_folds, int(y_bin.sum()), int((y_bin == 0).sum()), pos_groups, neg_groups)
        if n_splits < 2:
            records.append({"site": site, "f1": 0.0})
            continue
        cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=args.seed)
        pred = np.full(y_bin.shape, fill_value=-1, dtype=int)
        for train_idx, test_idx in cv.split(X, y_bin, groups):
            model = build_model(model_name, max(2, int(y_bin[train_idx].sum())), args.model_preset, args.seed)
            model.fit(X[train_idx], y_bin[train_idx])
            pred[test_idx] = np.asarray(model.predict(X[test_idx]), dtype=int)
        records.append({"site": site, "f1": float(f1_score(y_bin, pred, zero_division=0))})
        all_true.extend(y_bin.tolist())
        all_pred.extend(pred.tolist())

    per_site = pd.DataFrame(records)
    return (
        {
            "accuracy": float(accuracy_score(all_true, all_pred)) if all_true else 0.0,
            "f1_macro": float(per_site["f1"].mean()) if len(per_site) else 0.0,
            "f1_weighted": float(per_site["f1"].mean()) if len(per_site) else 0.0,
        },
        per_site,
    )


def evaluate_matrix(X: np.ndarray, cv_info: dict, model_name: str, args: argparse.Namespace) -> tuple[dict, pd.DataFrame]:
    if args.evaluation_mode == "one-vs-rest":
        return evaluate_one_vs_rest(X, cv_info, model_name, args)
    return evaluate_multiclass(X, cv_info, model_name, args)


def run_full_model_benchmarks(rows: list[dict], cv_info: dict, model_names: list[str], args: argparse.Namespace) -> pd.DataFrame:
    metrics_dir = args.output_dir / "metrics"
    model_dir = args.output_dir / "models"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)
    X = masked_matrix(rows, "full", -1, args.sequence_width, args.feature_set)
    records = []
    for model_name in model_names:
        print(f"完整 P 序列模型评估: {model_name}")
        try:
            metrics, per_site = evaluate_matrix(X, cv_info, model_name, args)
            record = {
                "model": model_name,
                "status": "completed",
                "evaluation_mode": args.evaluation_mode,
                "split_strategy": cv_info["strategy"],
                **metrics,
                "n_splits": cv_info["n_splits"],
                "reason": "",
            }
            per_site.to_csv(
                model_dir / f"{model_name}_full_per_site_f1.csv",
                index=False,
                encoding="utf-8-sig",
            )
        except Exception as exc:
            record = {
                "model": model_name,
                "status": "skipped",
                "evaluation_mode": args.evaluation_mode,
                "split_strategy": cv_info.get("strategy", ""),
                "accuracy": "",
                "f1_macro": "",
                "f1_weighted": "",
                "n_splits": cv_info.get("n_splits", ""),
                "reason": str(exc),
            }
        records.append(record)
        pd.DataFrame([record]).to_csv(
            model_dir / f"{model_name}_metrics.csv",
            index=False,
            encoding="utf-8-sig",
        )
    df = pd.DataFrame(records)
    df.to_csv(metrics_dir / "model_metrics.csv", index=False, encoding="utf-8-sig")
    return df


def select_primary_model(requested: str, metrics: pd.DataFrame) -> str:
    if requested != "auto":
        return requested
    completed = metrics[metrics["status"] == "completed"].copy()
    if completed.empty:
        raise RuntimeError("没有可用的完整模型评估结果，无法选择 primary model。")
    completed["f1_macro_num"] = pd.to_numeric(completed["f1_macro"], errors="coerce")
    return str(completed.sort_values("f1_macro_num", ascending=False).iloc[0]["model"])


def infer_critical_window(metrics_df: pd.DataFrame, threshold_drop: float) -> dict:
    full_f1 = float(metrics_df.loc[metrics_df["mask"] == "full", "f1_macro"].iloc[0])
    threshold = max(0.0, full_f1 - threshold_drop)
    start = ""
    for _, row in metrics_df[metrics_df["mask"] == "tail"].sort_values("position").iterrows():
        pos = int(row["position"])
        if pos == 0:
            continue
        if float(row["f1_macro"]) < threshold:
            start = pos - 1
            break
    end = ""
    for _, row in metrics_df[metrics_df["mask"] == "head"].sort_values("position").iterrows():
        if float(row["f1_macro"]) >= threshold:
            end = int(row["position"])
            break
    return {
        "full_f1_macro": full_f1,
        "threshold_drop": threshold_drop,
        "threshold_f1_macro": threshold,
        "critical_start_position": start,
        "critical_end_position": end,
        "critical_window": f"P{start}-P{end}" if start != "" and end != "" else "",
    }


def run_phead_ptail(rows: list[dict], cv_info: dict, primary_model: str, args: argparse.Namespace) -> None:
    metrics_dir = args.output_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    metric_records = []
    per_site_frames = []
    masks = [("full", -1)] + [(mode, pos) for pos in range(args.window_size) for mode in ("tail", "head")]
    for mode, position in masks:
        label = "full" if mode == "full" else f"P{mode}({position})"
        print(f"Phead/Ptail 评估: {label}")
        X = masked_matrix(rows, mode, position, args.sequence_width, args.feature_set)
        metrics, per_site = evaluate_matrix(X, cv_info, primary_model, args)
        metric_records.append({"mask": mode, "position": position, **metrics})
        per_site["mask"] = mode
        per_site["position"] = position
        per_site_frames.append(per_site)

    metrics_df = pd.DataFrame(metric_records)
    per_site_df = pd.concat(per_site_frames, ignore_index=True)
    summary = infer_critical_window(metrics_df, args.critical_threshold)
    metrics_df.to_csv(metrics_dir / "figure2_metrics.csv", index=False, encoding="utf-8-sig")
    per_site_df.to_csv(
        metrics_dir / "figure2_per_site_f1.csv",
        index=False,
        encoding="utf-8-sig",
    )
    pd.DataFrame([summary]).to_csv(
        metrics_dir / "critical_window_summary.csv",
        index=False,
        encoding="utf-8-sig",
    )
    write_position_summary(rows, args)
    write_figure(per_site_df, summary, primary_model, cv_info["strategy"], args)


def paper_stage_name(position: int) -> str:
    """返回论文 Figure 2 风格的横轴阶段名称。"""

    if position == 0:
        return "Client Hello"
    if position == 1:
        return "Server Hello"
    if position % 2 == 0:
        return "Client Req."
    return "Server Resp."


def paper_axis_label(position: int) -> str:
    """返回横轴上展示的 P_i 阶段标签。"""

    return f"P{position}: {paper_stage_name(position)}"


def position_interpretation(position: int, median_direction: float, median_length: float, coverage: float) -> str:
    """基于论文阶段命名和当前数据统计给出保守解释。"""

    direction_text = "客户端侧" if median_direction >= 0 else "服务端侧"
    if position == 0:
        return "Client Hello 阶段：连接内第一个客户端侧可见载荷片段，通常对应 TLS ClientHello 或 QUIC Initial 中的客户端初始握手信息。"
    if position == 1:
        return "Server Hello 阶段：连接内第一个服务端侧可见载荷片段，通常对应 TLS ServerHello/服务器早期握手响应或 QUIC Initial 响应。"
    if position == 2:
        return "Client Req. 阶段：握手后的首个客户端请求或客户端应用数据片段，近似对应原论文中的第一次客户端请求。"
    if position == 3:
        return "Server Resp. 阶段：握手后的首个服务端响应或服务端应用数据片段，近似对应原论文中的第一次服务器响应。"
    if position % 2 == 0:
        if coverage < 50:
            return "后续 Client Req. 阶段：仅部分样本存在的客户端侧后续请求片段，更多反映长连接或多轮请求差异。"
        return f"后续 Client Req. 阶段：连接内第 {position // 2} 轮客户端侧请求/上行数据片段；当前统计中主要方向为{direction_text}。"
    if coverage < 50:
        return "后续 Server Resp. 阶段：仅部分样本存在的服务端侧后续响应片段，更多反映连接尾部或长连接差异。"
    if median_length > 20000:
        return "后续 Server Resp. 阶段：服务端侧较大响应片段，可能对应资源内容返回或批量数据传输。"
    return f"后续 Server Resp. 阶段：连接内第 {(position - 1) // 2} 轮服务端侧响应/下行数据片段；当前统计中主要方向为{direction_text}。"


def write_position_summary(rows: list[dict], args: argparse.Namespace) -> None:
    records = []
    total_samples = len(rows)
    for pos in range(args.window_size):
        lengths = []
        dirs = []
        starts = []
        durations = []
        pkt_counts = []
        for row in rows:
            units = row["units"]
            if len(units) <= pos:
                continue
            unit = units[pos]
            lengths.append(float(unit.get("length", 0.0)))
            dirs.append(float(unit.get("direction", 0.0)))
            starts.append(float(unit.get("start_time", 0.0)))
            durations.append(float(unit.get("duration", 0.0)))
            pkt_counts.append(float(unit.get("pkt_count", 0.0)))
        if not lengths:
            continue
        coverage = len(lengths) / total_samples * 100.0 if total_samples else 0.0
        median_direction = float(np.median(dirs))
        median_length = float(np.median(lengths))
        records.append(
            {
                "position": pos,
                "label": f"P{pos}",
                "paper_stage": paper_stage_name(pos),
                "axis_label": paper_axis_label(pos),
                "coverage_pct": coverage,
                "length_median": median_length,
                "length_q75": float(np.quantile(lengths, 0.75)),
                "start_time_median": float(np.median(starts)),
                "duration_median": float(np.median(durations)),
                "pkt_count_median": float(np.median(pkt_counts)),
                "direction_median": median_direction,
                "stage_interpretation": position_interpretation(
                    pos, median_direction, median_length, coverage
                ),
            }
        )
    pd.DataFrame(records).to_csv(
        args.output_dir / "metrics" / "position_stage_summary.csv",
        index=False,
        encoding="utf-8-sig",
    )


def write_figure(
    per_site_df: pd.DataFrame,
    summary: dict,
    primary_model: str,
    split_strategy: str,
    args: argparse.Namespace,
) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"绘图跳过: {exc}")
        return

    plots_dir = args.output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    full = per_site_df.loc[per_site_df["mask"] == "full", "f1"].to_numpy()
    tail = [
        per_site_df.loc[
            (per_site_df["mask"] == "tail") & (per_site_df["position"] == pos),
            "f1",
        ].to_numpy()
        for pos in range(args.window_size)
    ]
    head = [
        per_site_df.loc[
            (per_site_df["mask"] == "head") & (per_site_df["position"] == pos),
            "f1",
        ].to_numpy()
        for pos in range(args.window_size)
    ]

    fig, axes = plt.subplots(
        2,
        1,
        figsize=(16.5, 8.4),
        dpi=150,
        sharex=True,
        gridspec_kw={"hspace": 0.08},
    )

    def draw_violin(ax, data: list[np.ndarray], positions: np.ndarray, color: str, title: str) -> None:
        parts = ax.violinplot(
            data,
            positions=positions,
            widths=0.75,
            showmedians=True,
            showextrema=False,
        )
        for body in parts["bodies"]:
            body.set_facecolor(color)
            body.set_edgecolor("#333333")
            body.set_alpha(0.78)
        parts["cmedians"].set_color("#111111")
        ax.axhline(
            summary["threshold_f1_macro"],
            color="#666666",
            linestyle="--",
            linewidth=1,
            label="Full macro-F1 - threshold",
        )
        ax.set_ylim(0, 1)
        ax.set_ylabel("Per-site F1")
        ax.set_title(title, loc="left", fontsize=11)
        ax.grid(axis="y", color="#dddddd", linewidth=0.7)

    draw_violin(
        axes[0],
        [full] + tail,
        np.arange(0, args.window_size + 1),
        "#f58518",
        "Ptail(i): keep pseudo-payloads Pi..end",
    )
    draw_violin(
        axes[1],
        head,
        np.arange(1, args.window_size + 1),
        "#4c78a8",
        "Phead(i): keep pseudo-payloads P0..Pi",
    )

    start = summary["critical_start_position"]
    end = summary["critical_end_position"]
    if start != "" and end != "":
        for ax in axes:
            ax.axvspan(int(start) + 0.5, int(end) + 1.5, color="#999999", alpha=0.18)
            ax.axvline(int(start) + 0.5, color="#b23a48", linestyle="--", linewidth=1.2)
            ax.axvline(int(end) + 1.5, color="#b23a48", linestyle="--", linewidth=1.2)

    axes[1].set_xticks(np.arange(0, args.window_size + 1))
    axes[1].set_xticklabels(
        ["Full"] + [paper_axis_label(idx) for idx in range(args.window_size)],
        rotation=22,
        ha="right",
        fontsize=8.5,
    )
    axes[1].set_xlabel(
        "Paper-style protocol stage labels mapped onto pseudo-payload/clump positions"
    )
    axes[0].legend(loc="lower right", frameon=False)
    fig.suptitle(
        (
            "Figure-2-style pseudo-payload contribution on 14727250 "
            f"({primary_model}, {args.evaluation_mode}, {split_strategy})"
        ),
        fontsize=13,
        y=0.985,
    )
    fig.text(
        0.5,
        0.012,
        (
            "Stage labels follow Figure 2 naming; in 14727250, P_i are direction-change "
            "clumps from selected 443 flows, not protocol-exact TLS records."
        ),
        ha="center",
        fontsize=9,
        color="#555555",
    )
    fig.subplots_adjust(top=0.90, bottom=0.24, left=0.08, right=0.98, hspace=0.10)
    fig.savefig(plots_dir / "figure2_pseudo_payload_positions.png")
    fig.savefig(plots_dir / "critical_window_f1.png")
    plt.close(fig)


def write_feature_summary(rows: list[dict], args: argparse.Namespace) -> None:
    features_dir = args.output_dir / "features"
    features_dir.mkdir(parents=True, exist_ok=True)
    summary_rows = []
    for row in rows:
        summary_rows.append(
            {
                "site": row["site"],
                "visit_id": row["visit_id"],
                "position_count": len(row["units"]),
                "flow_total_bytes": row["flow_total_bytes"],
                "flow_duration": row["flow_duration"],
                "selection_reason": row["selection_reason"],
                "selected_proto": row["selected_proto"],
            }
        )
    pd.DataFrame(summary_rows).to_csv(
        features_dir / "feature_summary.csv",
        index=False,
        encoding="utf-8-sig",
    )


def df_to_markdown(df: pd.DataFrame, max_rows: int | None = None) -> str:
    """避免依赖 tabulate，生成科研记录足够使用的 Markdown 表格。"""

    if max_rows is not None:
        df = df.head(max_rows)
    if df.empty:
        return "_empty_"
    clean = df.copy()
    for col in clean.columns:
        clean[col] = clean[col].map(lambda value: "" if pd.isna(value) else str(value))
    header = "| " + " | ".join(clean.columns) + " |"
    sep = "| " + " | ".join(["---"] * len(clean.columns)) + " |"
    body = [
        "| " + " | ".join(str(value).replace("\n", " ") for value in row) + " |"
        for row in clean.to_numpy()
    ]
    return "\n".join([header, sep] + body)


def write_report(args: argparse.Namespace) -> None:
    report_path = args.output_dir / "README.md"
    metrics_path = args.output_dir / "metrics" / "model_metrics.csv"
    summary_path = args.output_dir / "metrics" / "critical_window_summary.csv"
    stage_path = args.output_dir / "metrics" / "position_stage_summary.csv"
    plot_path = args.output_dir / "plots" / "figure2_pseudo_payload_positions.png"

    lines = [
        "# 14727250 Figure 2 风格复现实验",
        "",
        "## 实验定位",
        "",
        (
            "本目录用于在 14727250 数据集上复现 367 论文 Figure 2 的核心方法，"
            "即通过 Phead(i) / Ptail(i) 遮蔽实验观察连接内部不同位置对网站指纹分类的贡献。"
        ),
        "",
        (
            "由于 14727250 与原论文数据集不同，本文中的 P_i 被定义为目标 443 连接内按方向变化"
            "聚合得到的 pseudo-payload/clump。该定义尽量贴近原仓库 `TimeSeries._clumps()` "
            "中的方向聚合思想，但不声称每个 P_i 都严格对应 TLS 协议阶段。"
        ),
        "",
        "## 输出文件",
        "",
        "- `features/pseudo_payload_features.csv`：每个访问样本抽取出的 P-like 序列。",
        "- `features/site_coverage.csv`：各站点样本数与是否纳入评估。",
        "- `features/extraction_failures.csv`：PCAP 解析或目标连接选择失败记录。",
        "- `metrics/model_metrics.csv`：完整 P 序列下不同模型的分类指标。",
        "- `metrics/figure2_metrics.csv`：Phead/Ptail 每个位置的 macro-F1、weighted-F1 等指标。",
        "- `metrics/figure2_per_site_f1.csv`：绘制小提琴图使用的 per-site F1 分布。",
        "- `metrics/position_stage_summary.csv`：每个 P 位置的统计特征与保守阶段解释。",
        "- `plots/figure2_pseudo_payload_positions.png`：最终 Figure 2 风格复现图。",
        "",
        "## 当前结果摘要",
        "",
    ]

    if metrics_path.exists():
        metrics_df = pd.read_csv(metrics_path)
        lines.append("完整序列模型结果：")
        lines.append("")
        lines.append(df_to_markdown(metrics_df))
        lines.append("")
    if summary_path.exists():
        summary_df = pd.read_csv(summary_path)
        lines.append("关键窗口结果：")
        lines.append("")
        lines.append(df_to_markdown(summary_df))
        lines.append("")
    if stage_path.exists():
        stage_df = pd.read_csv(stage_path)
        cols = [
            "label",
            "paper_stage",
            "coverage_pct",
            "length_median",
            "direction_median",
            "stage_interpretation",
        ]
        lines.append("P 位置阶段解释摘要：")
        lines.append("")
        lines.append(df_to_markdown(stage_df[cols], max_rows=args.window_size))
        lines.append("")
    if plot_path.exists():
        lines.append(f"图像文件：`{plot_path}`")
        lines.append("")

    lines.extend(
        [
            "## 方法边界",
            "",
            (
                "该复现实验可用于支持“14727250 数据集上目标连接内部 pseudo-payload 位置贡献分析”"
                "这一表述。若要声称严格 TLS P0/P1/P2 阶段复现，还需要进一步进行 TLS record 重组、"
                "ClientHello/ServerHello/EncryptedExtensions 等消息级解析，并处理 TLS 1.3 加密握手内容不可见的问题。"
            ),
            "",
        ]
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8-sig")
    print(f"报告文件: {report_path}")


def evaluate(args: argparse.Namespace) -> None:
    rows = load_rows(args.features)
    if not rows:
        raise RuntimeError(f"未从 {args.features} 读取到有效样本。")
    raw_samples = len(rows)
    raw_sites = len(set(row["site"] for row in rows))
    rows = filter_rows(rows, args.min_samples_per_site, args.output_dir)
    if not rows:
        raise RuntimeError("过滤后没有满足 min-samples-per-site 的站点。")
    print(f"原始样本/站点: {raw_samples}/{raw_sites}")
    print(f"有效样本/站点: {len(rows)}/{len(set(row['site'] for row in rows))}")
    print(f"P-like 位置数中位数: {np.median([len(row['units']) for row in rows]):.1f}")

    write_feature_summary(rows, args)
    cv_info = prepare_cv(rows, args.min_samples_per_site, args.max_folds, args.seed)
    if not cv_info["can_run"]:
        raise RuntimeError(cv_info["reason"])

    model_names = parse_model_names(args.models)
    full_metrics = run_full_model_benchmarks(rows, cv_info, model_names, args)
    primary = select_primary_model(args.primary_model, full_metrics)
    pd.DataFrame(
        [
            {
                "requested_primary_model": args.primary_model,
                "selected_primary_model": primary,
                "evaluation_mode": args.evaluation_mode,
            }
        ]
    ).to_csv(
        args.output_dir / "metrics" / "primary_model_selection.csv",
        index=False,
        encoding="utf-8-sig",
    )
    print(f"Phead/Ptail 主模型: {primary}")
    run_phead_ptail(rows, cv_info, primary, args)
    write_report(args)
    print(f"复现图: {args.output_dir / 'plots' / 'figure2_pseudo_payload_positions.png'}")


def plot_existing(args: argparse.Namespace) -> None:
    """复用已有评估结果，只更新阶段标签、图像和报告。"""

    per_site_path = args.output_dir / "metrics" / "figure2_per_site_f1.csv"
    summary_path = args.output_dir / "metrics" / "critical_window_summary.csv"
    model_path = args.output_dir / "metrics" / "primary_model_selection.csv"
    full_metrics_path = args.output_dir / "metrics" / "model_metrics.csv"
    if not per_site_path.exists() or not summary_path.exists():
        raise FileNotFoundError("缺少 figure2_per_site_f1.csv 或 critical_window_summary.csv，无法只重画图。")

    primary_model = args.primary_model
    if primary_model == "auto" and model_path.exists():
        model_df = pd.read_csv(model_path)
        if "selected_primary_model" in model_df:
            primary_model = str(model_df["selected_primary_model"].iloc[0])
    if primary_model == "auto":
        primary_model = "unknown_model"

    split_strategy = "StratifiedGroupKFold"
    if full_metrics_path.exists():
        full_metrics = pd.read_csv(full_metrics_path)
        if "split_strategy" in full_metrics and len(full_metrics):
            split_strategy = str(full_metrics["split_strategy"].iloc[0])

    if args.features.exists():
        rows = filter_rows(load_rows(args.features), args.min_samples_per_site, args.output_dir)
        write_position_summary(rows, args)

    per_site_df = pd.read_csv(per_site_path)
    summary = pd.read_csv(summary_path).iloc[0].to_dict()
    write_figure(per_site_df, summary, primary_model, split_strategy, args)
    write_report(args)
    print(f"复现图: {args.output_dir / 'plots' / 'figure2_pseudo_payload_positions.png'}")


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "features").mkdir(parents=True, exist_ok=True)
    (args.output_dir / "metrics").mkdir(parents=True, exist_ok=True)
    (args.output_dir / "plots").mkdir(parents=True, exist_ok=True)

    if args.stage in {"all", "process"}:
        if args.reuse_features and args.features.exists():
            print(f"复用已有特征: {args.features}")
        else:
            process(args)
    if args.stage in {"all", "evaluate"}:
        if not args.features.exists():
            raise FileNotFoundError(f"特征文件不存在: {args.features}")
        evaluate(args)
    if args.stage == "plot":
        plot_existing(args)
    if args.stage == "report":
        write_report(args)


if __name__ == "__main__":
    main()
