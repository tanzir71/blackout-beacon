import argparse
import csv
import datetime as _dt
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from html import unescape
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


BEACON_VERSION = "2.0"


_DEFAULT_HTTP_PORTS = (80, 443, 8000, 8080, 3000)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _split_csv_ints(value: str) -> List[int]:
    out: List[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def _iter_file_lines(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            yield line


def _parse_target_token(token: str) -> List[str]:
    token = token.strip()
    if not token:
        return []

    if "-" in token:
        start_s, end_s = token.split("-", 1)
        start_ip = ipaddress.ip_address(start_s.strip())
        end_ip = ipaddress.ip_address(end_s.strip())
        if start_ip.version != end_ip.version:
            raise ValueError(f"Mixed IP versions in range: {token}")
        start_i = int(start_ip)
        end_i = int(end_ip)
        if end_i < start_i:
            start_i, end_i = end_i, start_i
        return [str(ipaddress.ip_address(i)) for i in range(start_i, end_i + 1)]

    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        return [str(ip) for ip in net.hosts()]

    ip = ipaddress.ip_address(token)
    return [str(ip)]


def _expand_targets(
    tokens: Sequence[str],
    file_paths: Sequence[str],
    presets: Sequence[str],
    max_targets: int,
) -> List[str]:
    expanded: List[str] = []
    seen: Set[str] = set()

    for preset in presets:
        for t in _resolve_preset(preset):
            for ip in _parse_target_token(t):
                if ip not in seen:
                    expanded.append(ip)
                    seen.add(ip)
                    if len(expanded) > max_targets:
                        raise ValueError(
                            f"Too many targets (> {max_targets}). Narrow the scope or set --max-targets."
                        )

    for p in file_paths:
        for token in _iter_file_lines(p):
            for ip in _parse_target_token(token):
                if ip not in seen:
                    expanded.append(ip)
                    seen.add(ip)
                    if len(expanded) > max_targets:
                        raise ValueError(
                            f"Too many targets (> {max_targets}). Narrow the scope or set --max-targets."
                        )

    for token in tokens:
        for ip in _parse_target_token(token):
            if ip not in seen:
                expanded.append(ip)
                seen.add(ip)
                if len(expanded) > max_targets:
                    raise ValueError(
                        f"Too many targets (> {max_targets}). Narrow the scope or set --max-targets."
                    )

    return expanded


def _resolve_preset(name: str) -> List[str]:
    key = name.strip().lower()
    presets = _bd_presets()
    if key in presets:
        return presets[key]
    raise ValueError(f"Unknown preset: {name}. Use `presets` command to list available presets.")


def _bd_presets() -> Dict[str, List[str]]:
    return {
        "bd:gp": [
            "37.111.192.0/24",
            "37.111.193.0/24",
            "37.111.194.0/24",
            "37.111.195.0/24",
            "37.111.196.0/24",
            "37.111.197.0/24",
            "37.111.198.0/24",
            "37.111.199.0/24",
            "37.111.200.0/24",
            "37.111.201.0/24",
            "37.111.202.0/24",
            "37.111.203.0/24",
            "37.111.204.0/24",
            "37.111.205.0/24",
            "37.111.206.0/24",
            "37.111.207.0/24",
            "37.111.208.0/24",
            "37.111.210.0/24",
            "37.111.211.0/24",
            "37.111.212.0/24",
            "37.111.213.0/24",
            "37.111.214.0/24",
            "37.111.215.0/24",
            "37.111.216.0/24",
            "37.111.217.0/24",
            "37.111.218.0/24",
        ],
        "bd:robi": [
            "36.255.80.0/22",
            "42.0.4.0/22",
            "58.145.184.0/22",
            "58.145.188.0/22",
            "103.25.248.0/22",
        ],
        "bd:banglalink": [
            "43.245.120.0/22",
            "43.255.20.0/22",
            "59.152.0.0/21",
            "103.15.164.0/23",
            "103.67.156.0/22",
            "103.239.4.0/22",
        ],
        "bd:teletalk": [
            "103.230.104.0/22",
            "123.253.132.0/22",
            "202.4.173.0/24",
        ],
        "bd:btcl": [
            "114.130.128.0/18",
            "123.49.0.0/18",
            "103.110.215.0/24",
        ],
        "bd:all": [
            "37.111.192.0/24",
            "37.111.193.0/24",
            "37.111.194.0/24",
            "37.111.195.0/24",
            "37.111.196.0/24",
            "37.111.197.0/24",
            "37.111.198.0/24",
            "37.111.199.0/24",
            "37.111.200.0/24",
            "37.111.201.0/24",
            "37.111.202.0/24",
            "37.111.203.0/24",
            "37.111.204.0/24",
            "37.111.205.0/24",
            "37.111.206.0/24",
            "37.111.207.0/24",
            "37.111.208.0/24",
            "37.111.210.0/24",
            "37.111.211.0/24",
            "37.111.212.0/24",
            "37.111.213.0/24",
            "37.111.214.0/24",
            "37.111.215.0/24",
            "37.111.216.0/24",
            "37.111.217.0/24",
            "37.111.218.0/24",
            "36.255.80.0/22",
            "42.0.4.0/22",
            "58.145.184.0/22",
            "58.145.188.0/22",
            "103.25.248.0/22",
            "43.245.120.0/22",
            "43.255.20.0/22",
            "59.152.0.0/21",
            "103.15.164.0/23",
            "103.67.156.0/22",
            "103.239.4.0/22",
            "103.230.104.0/22",
            "123.253.132.0/22",
            "202.4.173.0/24",
            "114.130.128.0/18",
            "123.49.0.0/18",
            "103.110.215.0/24",
        ],
    }


def ping_ip(ip: str, timeout_s: float) -> Tuple[bool, Optional[float], Optional[str]]:
    timeout_ms = max(1, int(timeout_s * 1000))
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    try:
        start = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 1.0)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    except subprocess.TimeoutExpired:
        return False, None, "ping timeout"
    except Exception as e:
        return False, None, f"ping error: {e}"

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = re.search(r"time[=<]\s*(\d+)\s*ms", out, re.IGNORECASE)
    if proc.returncode == 0 and m:
        return True, float(m.group(1)), None
    if proc.returncode == 0:
        return True, elapsed_ms, None
    return False, None, None


def is_tcp_open(ip: str, port: int, timeout_s: float) -> Tuple[bool, Optional[str]]:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True, None
    except Exception as e:
        return False, str(e)


@dataclass
class HttpProbe:
    url: str
    ok: bool
    status: Optional[int]
    title: Optional[str]
    server: Optional[str]
    error: Optional[str]


def fetch_http_title(ip: str, port: int, timeout_s: float) -> HttpProbe:
    use_tls = port == 443
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}/"

    try:
        sock = socket.create_connection((ip, port), timeout=timeout_s)
    except Exception as e:
        return HttpProbe(url=url, ok=False, status=None, title=None, server=None, error=str(e))

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)

        sock.settimeout(timeout_s)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: blackout-beacon/{BEACON_VERSION}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8", errors="replace")
        sock.sendall(req)

        chunks: List[bytes] = []
        total = 0
        max_bytes = 256 * 1024
        while total < max_bytes:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if b"</title" in data.lower():
                break

        raw = b"".join(chunks)
        head, _, body = raw.partition(b"\r\n\r\n")
        header_text = head.decode("iso-8859-1", errors="replace")
        status = None
        server = None
        first = header_text.splitlines()[0] if header_text else ""
        m = re.match(r"HTTP/\d+\.\d+\s+(\d+)", first)
        if m:
            try:
                status = int(m.group(1))
            except ValueError:
                status = None

        for line in header_text.splitlines()[1:]:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            if k.strip().lower() == "server":
                server = v.strip()[:200]
                break

        body_text = body.decode("utf-8", errors="replace")
        t = None
        m2 = _TITLE_RE.search(body_text)
        if m2:
            t = unescape(m2.group(1).strip())
            t = re.sub(r"\s+", " ", t)[:300] if t else None
        return HttpProbe(url=url, ok=True, status=status, title=t, server=server, error=None)
    except Exception as e:
        return HttpProbe(url=url, ok=False, status=None, title=None, server=None, error=str(e))
    finally:
        try:
            sock.close()
        except Exception:
            pass


@dataclass
class ScanResult:
    ip: str
    ts: str
    ping_ok: Optional[bool]
    ping_ms: Optional[float]
    open_ports: List[int]
    http: List[HttpProbe]
    error: Optional[str]


def scan_one(
    ip: str,
    *,
    do_ping: bool,
    ping_timeout_s: float,
    ports: Sequence[int],
    tcp_timeout_s: float,
    http_title: bool,
    http_timeout_s: float,
) -> ScanResult:
    ts = _now_iso()
    ping_ok = None
    ping_ms = None
    error = None

    if do_ping:
        ok, ms, perr = ping_ip(ip, timeout_s=ping_timeout_s)
        ping_ok = ok
        ping_ms = ms
        if perr:
            error = perr

    open_ports: List[int] = []
    for port in ports:
        ok, _ = is_tcp_open(ip, port, timeout_s=tcp_timeout_s)
        if ok:
            open_ports.append(port)

    http: List[HttpProbe] = []
    if http_title:
        for port in open_ports:
            if port in (80, 443, 8000, 8080, 3000):
                http.append(fetch_http_title(ip, port, timeout_s=http_timeout_s))

    return ScanResult(
        ip=ip,
        ts=ts,
        ping_ok=ping_ok,
        ping_ms=ping_ms,
        open_ports=open_ports,
        http=http,
        error=error,
    )


def _print_scan_line(res: ScanResult) -> None:
    print(_format_scan_line(res))


def _format_scan_line(res: ScanResult) -> str:
    parts = [res.ip]
    if res.ping_ok is True and res.ping_ms is not None:
        parts.append(f"ping={res.ping_ms:.0f}ms")
    elif res.ping_ok is True:
        parts.append("ping=ok")
    elif res.ping_ok is False:
        parts.append("ping=down")

    if res.open_ports:
        parts.append("ports=" + ",".join(str(p) for p in res.open_ports))

    title = None
    for h in res.http:
        if h.ok and h.title:
            title = h.title
            break
    if title:
        parts.append(f"title={title}")

    return " ".join(parts)


def _write_scan_outputs(
    results: Sequence[ScanResult],
    active_ips: Sequence[str],
    *,
    json_out: Optional[str],
    csv_out: Optional[str],
    active_ips_out: Optional[str],
) -> None:
    if active_ips_out:
        with open(active_ips_out, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(set(active_ips), key=lambda x: ipaddress.ip_address(x))))

    if json_out:
        payload = []
        for r in results:
            d = asdict(r)
            d["http"] = [asdict(h) for h in r.http]
            payload.append(d)
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    if csv_out:
        fieldnames = [
            "ip",
            "ts",
            "ping_ok",
            "ping_ms",
            "open_ports",
            "http_url",
            "http_ok",
            "http_status",
            "http_title",
            "http_server",
            "http_error",
            "error",
        ]
        with open(csv_out, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in results:
                if r.http:
                    for h in r.http:
                        w.writerow(
                            {
                                "ip": r.ip,
                                "ts": r.ts,
                                "ping_ok": r.ping_ok,
                                "ping_ms": r.ping_ms,
                                "open_ports": ",".join(str(p) for p in r.open_ports),
                                "http_url": h.url,
                                "http_ok": h.ok,
                                "http_status": h.status,
                                "http_title": h.title,
                                "http_server": h.server,
                                "http_error": h.error,
                                "error": r.error,
                            }
                        )
                else:
                    w.writerow(
                        {
                            "ip": r.ip,
                            "ts": r.ts,
                            "ping_ok": r.ping_ok,
                            "ping_ms": r.ping_ms,
                            "open_ports": ",".join(str(p) for p in r.open_ports),
                            "http_url": None,
                            "http_ok": None,
                            "http_status": None,
                            "http_title": None,
                            "http_server": None,
                            "http_error": None,
                            "error": r.error,
                        }
                    )


def run_scan(args: argparse.Namespace) -> int:
    targets = _expand_targets(
        tokens=args.targets or [],
        file_paths=args.file or [],
        presets=args.preset or [],
        max_targets=args.max_targets,
    )
    if not targets:
        print("No targets. Provide IPs/CIDRs/ranges as arguments, or use --file / --preset.", file=sys.stderr)
        return 2

    ports = _split_csv_ints(args.ports) if args.ports else []
    if args.http_title and not ports:
        ports = list(_DEFAULT_HTTP_PORTS)
    if not ports:
        ports = [80, 443]

    results: List[ScanResult] = []
    active_ips: List[str] = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {
            ex.submit(
                scan_one,
                ip,
                do_ping=args.ping,
                ping_timeout_s=args.ping_timeout,
                ports=ports,
                tcp_timeout_s=args.tcp_timeout,
                http_title=args.http_title,
                http_timeout_s=args.http_timeout,
            ): ip
            for ip in targets
        }
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception as e:
                ip = futs[fut]
                res = ScanResult(
                    ip=ip,
                    ts=_now_iso(),
                    ping_ok=None,
                    ping_ms=None,
                    open_ports=[],
                    http=[],
                    error=str(e),
                )

            results.append(res)
            if (res.ping_ok is True) or res.open_ports:
                active_ips.append(res.ip)
            if not args.quiet and ((res.ping_ok is True) or res.open_ports or args.show_all):
                _print_scan_line(res)

    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
    _write_scan_outputs(
        results,
        active_ips,
        json_out=args.json_out,
        csv_out=args.csv_out,
        active_ips_out=args.active_ips_out,
    )

    return 0


def run_presets(_: argparse.Namespace) -> int:
    presets = _bd_presets()
    for k in sorted(presets.keys()):
        print(f"{k} ({len(presets[k])} CIDRs)")
    return 0


DISCOVERY_MAGIC = "BEACON2"


@dataclass
class Peer:
    peer_id: str
    name: str
    ip: str
    tcp_port: int
    last_seen_ts: float


class ChatNode:
    def __init__(self, name: str, udp_port: int, tcp_port: int, auto_connect: bool) -> None:
        self.self_id = uuid.uuid4().hex
        self.name = name
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.auto_connect = auto_connect

        self._stop = threading.Event()
        self._peers_lock = threading.Lock()
        self._peers: Dict[str, Peer] = {}

        self._conns_lock = threading.Lock()
        self._conns: Dict[str, socket.socket] = {}

        self._print_q: "queue.Queue[str]" = queue.Queue()

    def stop(self) -> None:
        self._stop.set()
        with self._conns_lock:
            for s in list(self._conns.values()):
                try:
                    s.close()
                except Exception:
                    pass
            self._conns.clear()

    def _log(self, msg: str) -> None:
        self._print_q.put(msg)

    def drain_logs(self) -> List[str]:
        out: List[str] = []
        while True:
            try:
                msg = self._print_q.get_nowait()
            except queue.Empty:
                break
            out.append(msg)
        return out

    def pump_logs(self) -> None:
        for msg in self.drain_logs():
            print(msg)

    def run(self) -> None:
        threads = [
            threading.Thread(target=self._udp_listener, daemon=True),
            threading.Thread(target=self._udp_broadcaster, daemon=True),
            threading.Thread(target=self._tcp_server, daemon=True),
        ]
        for t in threads:
            t.start()

    def peers_snapshot(self) -> List[Peer]:
        with self._peers_lock:
            return sorted(self._peers.values(), key=lambda p: (p.name.lower(), p.ip, p.tcp_port))

    def _udp_broadcaster(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        payload = f"{DISCOVERY_MAGIC}|DISCOVER|{self.self_id}|{self.name}|{self.tcp_port}".encode("utf-8")
        while not self._stop.is_set():
            try:
                s.sendto(payload, ("255.255.255.255", self.udp_port))
            except Exception:
                pass
            self._stop.wait(2.0)
        try:
            s.close()
        except Exception:
            pass

    def _udp_listener(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", self.udp_port))
        s.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                continue

            try:
                txt = data.decode("utf-8", errors="replace")
                parts = txt.split("|")
                if len(parts) < 5:
                    continue
                magic, kind, peer_id, peer_name, tcp_port_s = parts[:5]
                if magic != DISCOVERY_MAGIC or kind != "DISCOVER":
                    continue
                if peer_id == self.self_id:
                    continue
                tcp_port = int(tcp_port_s)
            except Exception:
                continue

            ip = addr[0]
            now = time.time()
            is_new = False
            with self._peers_lock:
                prev = self._peers.get(peer_id)
                if prev is None:
                    is_new = True
                self._peers[peer_id] = Peer(
                    peer_id=peer_id, name=peer_name, ip=ip, tcp_port=tcp_port, last_seen_ts=now
                )

            if is_new:
                self._log(f"[discover] {peer_name} @ {ip}:{tcp_port}")
                if self.auto_connect:
                    threading.Thread(target=self._connect_peer, args=(peer_id,), daemon=True).start()

        try:
            s.close()
        except Exception:
            pass

    def _tcp_server(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", self.tcp_port))
        s.listen(50)
        s.settimeout(1.0)
        self._log(f"[chat] listening on tcp:{self.tcp_port}, udp-discovery:{self.udp_port}")
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
        try:
            s.close()
        except Exception:
            pass

    def _handle_conn(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        conn.settimeout(10.0)
        peer_id = None
        peer_name = None
        try:
            f = conn.makefile("rwb")
            hello = {"magic": DISCOVERY_MAGIC, "type": "hello", "id": self.self_id, "name": self.name}
            f.write((json.dumps(hello, ensure_ascii=False) + "\n").encode("utf-8"))
            f.flush()

            line = f.readline()
            if not line:
                return
            msg = json.loads(line.decode("utf-8", errors="replace"))
            if msg.get("magic") != DISCOVERY_MAGIC or msg.get("type") != "hello":
                return
            peer_id = str(msg.get("id") or "")
            peer_name = str(msg.get("name") or "peer")
            if not peer_id or peer_id == self.self_id:
                return

            with self._conns_lock:
                prev = self._conns.get(peer_id)
                if prev is not None and prev is not conn:
                    try:
                        prev.close()
                    except Exception:
                        pass
                self._conns[peer_id] = conn

            self._log(f"[connect] {peer_name} @ {addr[0]}:{addr[1]}")

            conn.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    line = f.readline()
                    if not line:
                        break
                except socket.timeout:
                    continue
                except Exception:
                    break

                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                except Exception:
                    continue
                if msg.get("magic") != DISCOVERY_MAGIC:
                    continue
                if msg.get("type") != "chat":
                    continue
                text = str(msg.get("text") or "")
                sender = str(msg.get("from") or peer_name or "peer")
                if text:
                    self._log(f"[{sender}] {text}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            if peer_id:
                with self._conns_lock:
                    if self._conns.get(peer_id) is conn:
                        self._conns.pop(peer_id, None)
            if peer_name:
                self._log(f"[disconnect] {peer_name}")

    def _connect_peer(self, peer_id: str) -> None:
        with self._peers_lock:
            p = self._peers.get(peer_id)
        if p is None:
            return

        with self._conns_lock:
            if peer_id in self._conns:
                return

        try:
            conn = socket.create_connection((p.ip, p.tcp_port), timeout=3.0)
        except Exception:
            return
        threading.Thread(target=self._handle_conn, args=(conn, (p.ip, p.tcp_port)), daemon=True).start()

    def send_all(self, text: str) -> int:
        payload = {
            "magic": DISCOVERY_MAGIC,
            "type": "chat",
            "ts": _now_iso(),
            "from": self.name,
            "text": text,
        }
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        sent = 0
        with self._conns_lock:
            conns = list(self._conns.items())
        for peer_id, conn in conns:
            try:
                conn.sendall(data)
                sent += 1
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                with self._conns_lock:
                    if self._conns.get(peer_id) is conn:
                        self._conns.pop(peer_id, None)
        return sent


def run_chat(args: argparse.Namespace) -> int:
    node = ChatNode(name=args.name, udp_port=args.udp_port, tcp_port=args.tcp_port, auto_connect=not args.no_auto_connect)
    node.run()
    print("Commands: /peers, /all <msg>, /quit")

    try:
        while True:
            node.pump_logs()
            line = sys.stdin.readline()
            if not line:
                time.sleep(0.1)
                continue
            text = line.strip()
            if not text:
                continue
            if text == "/quit":
                break
            if text == "/peers":
                peers = node.peers_snapshot()
                if not peers:
                    print("(no peers discovered yet)")
                else:
                    for i, p in enumerate(peers, 1):
                        age = int(time.time() - p.last_seen_ts)
                        print(f"{i}. {p.name} {p.ip}:{p.tcp_port} (seen {age}s ago)")
                continue
            if text.startswith("/all "):
                msg = text[5:].strip()
                if msg:
                    node.send_all(msg)
                continue

            node.send_all(text)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
    return 0


def run_gui(_: argparse.Namespace) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as e:
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(0, f"GUI unavailable:\n{e}", "Blackout Beacon", 0x10)
        except Exception:
            pass
        print(f"GUI unavailable: {e}", file=sys.stderr)
        return 2

    class GuiChat:
        def __init__(self, root: "tk.Tk") -> None:
            self.root = root
            self.node: Optional[ChatNode] = None
            self._polling = False

        def build(self, parent: "ttk.Frame") -> None:
            frm = parent
            frm.columnconfigure(1, weight=1)

            ttk.Label(frm, text="Name").grid(row=0, column=0, sticky="w", padx=8, pady=6)
            self.name_var = tk.StringVar(value=socket.gethostname())
            ttk.Entry(frm, textvariable=self.name_var).grid(row=0, column=1, sticky="ew", padx=8, pady=6)

            ttk.Label(frm, text="UDP Port").grid(row=1, column=0, sticky="w", padx=8, pady=6)
            self.udp_var = tk.IntVar(value=50504)
            ttk.Entry(frm, textvariable=self.udp_var, width=10).grid(row=1, column=1, sticky="w", padx=8, pady=6)

            ttk.Label(frm, text="TCP Port").grid(row=2, column=0, sticky="w", padx=8, pady=6)
            self.tcp_var = tk.IntVar(value=50505)
            ttk.Entry(frm, textvariable=self.tcp_var, width=10).grid(row=2, column=1, sticky="w", padx=8, pady=6)

            btns = ttk.Frame(frm)
            btns.grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=6)
            self.start_btn = ttk.Button(btns, text="Start", command=self.start)
            self.start_btn.pack(side="left")
            self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop, state="disabled")
            self.stop_btn.pack(side="left", padx=6)
            self.peers_btn = ttk.Button(btns, text="Peers", command=self.show_peers, state="disabled")
            self.peers_btn.pack(side="left", padx=6)

            log_frame = ttk.Frame(frm)
            log_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=8, pady=6)
            frm.rowconfigure(4, weight=1)
            log_frame.rowconfigure(0, weight=1)
            log_frame.columnconfigure(0, weight=1)

            self.log = tk.Text(log_frame, height=12, wrap="word")
            self.log.grid(row=0, column=0, sticky="nsew")
            sb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
            sb.grid(row=0, column=1, sticky="ns")
            self.log.configure(yscrollcommand=sb.set)

            msg_frame = ttk.Frame(frm)
            msg_frame.grid(row=5, column=0, columnspan=2, sticky="ew", padx=8, pady=6)
            msg_frame.columnconfigure(0, weight=1)
            self.msg_var = tk.StringVar(value="")
            ttk.Entry(msg_frame, textvariable=self.msg_var).grid(row=0, column=0, sticky="ew")
            ttk.Button(msg_frame, text="Send", command=self.send).grid(row=0, column=1, padx=6)

        def _append_log(self, line: str) -> None:
            self.log.insert("end", line + "\n")
            self.log.see("end")

        def start(self) -> None:
            if self.node is not None:
                return
            name = self.name_var.get().strip() or socket.gethostname()
            try:
                udp_port = int(self.udp_var.get())
                tcp_port = int(self.tcp_var.get())
            except Exception:
                messagebox.showerror("Chat", "Invalid UDP/TCP port")
                return
            try:
                self.node = ChatNode(name=name, udp_port=udp_port, tcp_port=tcp_port, auto_connect=True)
                self.node.run()
            except Exception as e:
                self.node = None
                messagebox.showerror("Chat", str(e))
                return
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.peers_btn.configure(state="normal")
            self._polling = True
            self._append_log(f"[chat] started as {name} (udp:{udp_port}, tcp:{tcp_port})")
            self._poll_logs()

        def stop(self) -> None:
            self._polling = False
            if self.node is not None:
                try:
                    self.node.stop()
                except Exception:
                    pass
                self.node = None
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.peers_btn.configure(state="disabled")
            self._append_log("[chat] stopped")

        def _poll_logs(self) -> None:
            if not self._polling:
                return
            if self.node is not None:
                for msg in self.node.drain_logs():
                    self._append_log(msg)
            self.root.after(150, self._poll_logs)

        def send(self) -> None:
            if self.node is None:
                return
            msg = self.msg_var.get().strip()
            if not msg:
                return
            self.msg_var.set("")
            self._append_log(f"[{self.node.name}] {msg}")
            try:
                self.node.send_all(msg)
            except Exception as e:
                self._append_log(f"[error] {e}")

        def show_peers(self) -> None:
            if self.node is None:
                return
            peers = self.node.peers_snapshot()
            if not peers:
                messagebox.showinfo("Peers", "No peers discovered yet.")
                return
            lines = []
            now = time.time()
            for p in peers:
                age = int(now - p.last_seen_ts)
                lines.append(f"{p.name} {p.ip}:{p.tcp_port} (seen {age}s ago)")
            messagebox.showinfo("Peers", "\n".join(lines))

    class GuiScan:
        def __init__(self, root: "tk.Tk") -> None:
            self.root = root
            self._scan_thread: Optional[threading.Thread] = None
            self._scan_q: "queue.Queue[object]" = queue.Queue()
            self._scan_running = False
            self._selected_files: List[str] = []
            self._hotkeys_bound = False
            self._stop_event: Optional[threading.Event] = None

        def build(self, parent: "ttk.Frame") -> None:
            frm = parent
            frm.rowconfigure(3, weight=1)
            frm.columnconfigure(1, weight=1)

            targets_hdr = ttk.Frame(frm)
            targets_hdr.grid(row=0, column=0, sticky="nw", padx=8, pady=6)
            ttk.Label(targets_hdr, text="Targets (one per line)").pack(anchor="w")
            ttk.Button(targets_hdr, text="Clear Targets", command=self.clear_targets).pack(anchor="w", pady=(6, 0))
            self.targets_text = tk.Text(frm, height=5, wrap="none")
            self.targets_text.grid(row=0, column=1, sticky="nsew", padx=8, pady=6)

            opts = ttk.Frame(frm)
            opts.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=2)
            opts.columnconfigure(10, weight=1)

            self.preset_var = tk.StringVar(value="")
            ttk.Label(opts, text="Preset").grid(row=0, column=0, sticky="w")
            preset_values = [""] + sorted(_bd_presets().keys())
            self.preset_combo = ttk.Combobox(opts, textvariable=self.preset_var, values=preset_values, width=16)
            self.preset_combo.grid(row=0, column=1, sticky="w", padx=6)
            self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

            ttk.Button(opts, text="Add File", command=self.add_file).grid(row=0, column=2, sticky="w", padx=6)
            ttk.Button(opts, text="Clear Files", command=self.clear_files).grid(row=0, column=3, sticky="w", padx=6)
            self.files_var = tk.StringVar(value="")
            ttk.Label(opts, textvariable=self.files_var).grid(row=0, column=4, sticky="w", padx=6)

            self.threads_var = tk.IntVar(value=200)
            ttk.Label(opts, text="Threads").grid(row=0, column=5, sticky="w", padx=6)
            ttk.Entry(opts, textvariable=self.threads_var, width=7).grid(row=0, column=6, sticky="w")

            self.ping_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(opts, text="Ping", variable=self.ping_var).grid(row=0, column=7, sticky="w", padx=6)

            self.http_var = tk.BooleanVar(value=True)
            ttk.Checkbutton(opts, text="HTTP Title", variable=self.http_var).grid(row=0, column=8, sticky="w", padx=6)

            self.ports_var = tk.StringVar(value="80,443")
            ttk.Label(opts, text="Ports").grid(row=0, column=9, sticky="w", padx=6)
            ttk.Entry(opts, textvariable=self.ports_var, width=18).grid(row=0, column=10, sticky="w")

            outs = ttk.Frame(frm)
            outs.grid(row=2, column=0, columnspan=2, sticky="ew", padx=8, pady=2)
            outs.columnconfigure(1, weight=1)
            outs.columnconfigure(4, weight=1)
            outs.columnconfigure(7, weight=1)

            ttk.Label(outs, text="JSON Out").grid(row=0, column=0, sticky="w")
            self.json_out_var = tk.StringVar(value="")
            ttk.Entry(outs, textvariable=self.json_out_var).grid(row=0, column=1, sticky="ew", padx=6)
            ttk.Button(outs, text="...", command=lambda: self.pick_save(self.json_out_var, ".json")).grid(
                row=0, column=2, padx=2
            )

            ttk.Label(outs, text="CSV Out").grid(row=0, column=3, sticky="w", padx=6)
            self.csv_out_var = tk.StringVar(value="")
            ttk.Entry(outs, textvariable=self.csv_out_var).grid(row=0, column=4, sticky="ew", padx=6)
            ttk.Button(outs, text="...", command=lambda: self.pick_save(self.csv_out_var, ".csv")).grid(
                row=0, column=5, padx=2
            )

            ttk.Label(outs, text="Active IPs").grid(row=0, column=6, sticky="w", padx=6)
            self.active_out_var = tk.StringVar(value="")
            ttk.Entry(outs, textvariable=self.active_out_var).grid(row=0, column=7, sticky="ew", padx=6)
            ttk.Button(outs, text="...", command=lambda: self.pick_save(self.active_out_var, ".txt")).grid(
                row=0, column=8, padx=2
            )

            runbar = ttk.Frame(frm)
            runbar.grid(row=4, column=0, columnspan=2, sticky="ew", padx=8, pady=6)
            self.run_btn = ttk.Button(runbar, text="Run Scan", command=self.run_scan)
            self.run_btn.pack(side="left")
            self.stop_btn = ttk.Button(runbar, text="Stop", command=self.stop_scan, state="disabled")
            self.stop_btn.pack(side="left", padx=6)
            self.status_var = tk.StringVar(value="")
            ttk.Label(runbar, textvariable=self.status_var).pack(side="left", padx=12)
            ttk.Label(runbar, text="Hotkey: Esc to stop").pack(side="left", padx=6)

            out_frame = ttk.Frame(frm)
            out_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=8, pady=6)
            frm.rowconfigure(5, weight=1)
            out_frame.rowconfigure(0, weight=1)
            out_frame.columnconfigure(0, weight=1)

            self.out_text = tk.Text(out_frame, wrap="none")
            self.out_text.grid(row=0, column=0, sticky="nsew")
            sb = ttk.Scrollbar(out_frame, orient="vertical", command=self.out_text.yview)
            sb.grid(row=0, column=1, sticky="ns")
            self.out_text.configure(yscrollcommand=sb.set)

            if not self._hotkeys_bound:
                self.root.bind_all("<Escape>", self._on_hotkey_stop, add="+")
                self._hotkeys_bound = True

        def _on_hotkey_stop(self, _evt: object) -> None:
            if self._scan_running:
                self.stop_scan()

        def add_file(self) -> None:
            paths = filedialog.askopenfilenames(title="Select target file(s)")
            if not paths:
                return
            for p in paths:
                if p not in self._selected_files:
                    self._selected_files.append(p)
            self.files_var.set("; ".join(self._selected_files))

        def clear_files(self) -> None:
            self._selected_files = []
            self.files_var.set("")

        def clear_targets(self) -> None:
            self.targets_text.delete("1.0", "end")

        def set_targets(self, lines: Sequence[str]) -> None:
            self.targets_text.delete("1.0", "end")
            if lines:
                self.targets_text.insert("1.0", "\n".join(lines))

        def _on_preset_selected(self, _evt: object) -> None:
            key = self.preset_var.get().strip()
            if not key:
                return
            presets = _bd_presets()
            if key in presets:
                self.set_targets(presets[key])

        def pick_save(self, var: "tk.StringVar", ext: str) -> None:
            p = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(ext, f"*{ext}"), ("All", "*.*")])
            if p:
                var.set(p)

        def _append_out(self, line: str) -> None:
            self.out_text.insert("end", line + "\n")
            self.out_text.see("end")

        def run_scan(self) -> None:
            if self._scan_running:
                return
            self.out_text.delete("1.0", "end")
            self.status_var.set("starting…")
            self._scan_running = True
            self.run_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")

            def worker() -> None:
                stop = threading.Event()
                self._stop_event = stop
                try:
                    raw_targets = self.targets_text.get("1.0", "end").splitlines()
                    tokens = [t.strip() for t in raw_targets if t.strip() and not t.strip().startswith("#")]
                    preset = self.preset_var.get().strip()
                    presets = [preset] if preset else []
                    targets = _expand_targets(tokens=tokens, file_paths=self._selected_files, presets=presets, max_targets=65536)
                    if not targets:
                        self._scan_q.put(("__error__", "No targets"))
                        return

                    ports_s = self.ports_var.get().strip()
                    ports = _split_csv_ints(ports_s) if ports_s else []
                    http_title = bool(self.http_var.get())
                    if http_title and not ports:
                        ports = list(_DEFAULT_HTTP_PORTS)
                    if not ports:
                        ports = [80, 443]

                    threads = int(self.threads_var.get() or 200)
                    if threads < 1:
                        threads = 1
                    if threads > 1000:
                        threads = 1000
                    do_ping = bool(self.ping_var.get())

                    results: List[ScanResult] = []
                    active_ips: List[str] = []
                    results_lock = threading.Lock()
                    active_lock = threading.Lock()
                    total = len(targets)
                    target_q: "queue.Queue[str]" = queue.Queue()
                    for ip in targets:
                        target_q.put(ip)

                    done = 0
                    done_lock = threading.Lock()

                    def scan_worker() -> None:
                        nonlocal done
                        while not stop.is_set():
                            try:
                                ip = target_q.get_nowait()
                            except queue.Empty:
                                return
                            try:
                                res = scan_one(
                                    ip,
                                    do_ping=do_ping,
                                    ping_timeout_s=1.0,
                                    ports=ports,
                                    tcp_timeout_s=0.6,
                                    http_title=http_title,
                                    http_timeout_s=1.2,
                                )
                            except Exception as e:
                                res = ScanResult(
                                    ip=ip,
                                    ts=_now_iso(),
                                    ping_ok=None,
                                    ping_ms=None,
                                    open_ports=[],
                                    http=[],
                                    error=str(e),
                                )

                            with done_lock:
                                done += 1
                                local_done = done
                            with results_lock:
                                results.append(res)
                            if (res.ping_ok is True) or res.open_ports:
                                with active_lock:
                                    active_ips.append(res.ip)
                            self._scan_q.put(("__progress__", local_done, total, res))

                    workers: List[threading.Thread] = []
                    for _ in range(min(threads, total)):
                        t = threading.Thread(target=scan_worker, daemon=True)
                        t.start()
                        workers.append(t)

                    for t in workers:
                        while t.is_alive():
                            if stop.is_set():
                                break
                            t.join(timeout=0.1)

                    stopped_early = stop.is_set()

                    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
                    _write_scan_outputs(
                        results,
                        active_ips,
                        json_out=self.json_out_var.get().strip() or None,
                        csv_out=self.csv_out_var.get().strip() or None,
                        active_ips_out=self.active_out_var.get().strip() or None,
                    )
                    if stopped_early:
                        self._scan_q.put(("__stopped__", len(results), len(set(active_ips))))
                    else:
                        self._scan_q.put(("__done__", len(results), len(set(active_ips))))
                finally:
                    self._scan_q.put(("__finish__",))

            self._scan_thread = threading.Thread(target=worker, daemon=True)
            self._scan_thread.start()
            self.root.after(100, self._poll_scan_queue)

        def _poll_scan_queue(self) -> None:
            try:
                while True:
                    msg = self._scan_q.get_nowait()
                    if not msg:
                        continue
                    tag = msg[0]
                    if tag == "__progress__":
                        done, total, res = msg[1], msg[2], msg[3]
                        self.status_var.set(f"{done}/{total}")
                        self._append_out(_format_scan_line(res))
                    elif tag == "__error__":
                        messagebox.showerror("Scan", str(msg[1]))
                    elif tag == "__done__":
                        self.status_var.set(f"done ({msg[1]} results, {msg[2]} active)")
                    elif tag == "__stopped__":
                        self.status_var.set(f"stopped ({msg[1]} results, {msg[2]} active)")
                    elif tag == "__finish__":
                        self._scan_running = False
                        self.run_btn.configure(state="normal")
                        self.stop_btn.configure(state="disabled")
                        return
            except queue.Empty:
                pass
            self.root.after(120, self._poll_scan_queue)

        def stop_scan(self) -> None:
            if self._scan_running and self._stop_event is not None:
                try:
                    self._stop_event.set()
                except Exception:
                    pass
                self.status_var.set("stopping…")
                self.stop_btn.configure(state="disabled")

    class GuiPresets:
        def __init__(self, root: "tk.Tk", apply_to_scan: "callable") -> None:
            self.root = root
            self.apply_to_scan = apply_to_scan

        def build(self, parent: "ttk.Frame") -> None:
            frm = parent
            frm.rowconfigure(0, weight=1)
            frm.columnconfigure(1, weight=1)

            presets = _bd_presets()
            self.keys = sorted(presets.keys())
            self.presets = presets

            self.listbox = tk.Listbox(frm)
            self.listbox.grid(row=0, column=0, sticky="ns", padx=8, pady=8)
            for k in self.keys:
                self.listbox.insert("end", f"{k} ({len(presets[k])})")
            self.listbox.bind("<<ListboxSelect>>", self._on_select)

            self.text = tk.Text(frm, wrap="none")
            self.text.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)

        def _on_select(self, _evt: object) -> None:
            sel = self.listbox.curselection()
            if not sel:
                return
            idx = int(sel[0])
            key = self.keys[idx]
            self.text.delete("1.0", "end")
            cidrs = self.presets[key]
            self.text.insert("end", "\n".join(cidrs))
            try:
                self.apply_to_scan(key, cidrs)
            except Exception:
                pass

    root = tk.Tk()
    root.title(f"Blackout Beacon v{BEACON_VERSION}")
    root.geometry("900x650")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True)

    scan_tab = ttk.Frame(nb)
    presets_tab = ttk.Frame(nb)
    chat_tab = ttk.Frame(nb)
    nb.add(scan_tab, text="Scan")
    nb.add(presets_tab, text="Presets")
    nb.add(chat_tab, text="Chat")

    scan_ui = GuiScan(root)
    scan_ui.build(scan_tab)
    def _apply_preset_to_scan(key: str, cidrs: Sequence[str]) -> None:
        scan_ui.preset_var.set(key)
        scan_ui.set_targets(cidrs)
        nb.select(scan_tab)

    presets_ui = GuiPresets(root, _apply_preset_to_scan)
    presets_ui.build(presets_tab)
    chat_ui = GuiChat(root)
    chat_ui.build(chat_tab)

    def on_close() -> None:
        try:
            scan_ui.stop_scan()
        except Exception:
            pass
        try:
            chat_ui.stop()
        except Exception:
            pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackout-beacon", add_help=True)
    p.add_argument("--version", action="version", version=f"blackout-beacon v{BEACON_VERSION}")

    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="High-concurrency scan with optional ping + HTTP title probing")
    scan.add_argument("targets", nargs="*", help="Targets: IP, CIDR, or range (a-b)")
    scan.add_argument("--file", action="append", default=[], help="Read targets from a file (one per line)")
    scan.add_argument("--preset", action="append", default=[], help="Use a built-in preset (see `presets` command)")
    scan.add_argument("--threads", type=int, default=200, help="Thread count (100+ supported)")
    scan.add_argument("--max-targets", type=int, default=65536, help="Safety limit for expanded targets")

    scan.add_argument("--ping", action="store_true", help="ICMP ping via system ping")
    scan.add_argument("--ping-timeout", type=float, default=1.0, help="Ping timeout (seconds)")

    scan.add_argument("--ports", type=str, default="", help="Comma-separated TCP ports to probe")
    scan.add_argument("--tcp-timeout", type=float, default=0.6, help="TCP connect timeout (seconds)")

    scan.add_argument("--http-title", action="store_true", help="Fetch HTTP(S) titles on common web ports")
    scan.add_argument("--http-timeout", type=float, default=1.2, help="HTTP probe timeout (seconds)")

    scan.add_argument("--json-out", type=str, default="", help="Write results JSON to path")
    scan.add_argument("--csv-out", type=str, default="", help="Write results CSV to path")
    scan.add_argument("--active-ips-out", type=str, default="", help="Write discovered active IPs (one per line)")

    scan.add_argument("--quiet", action="store_true", help="Suppress per-target output")
    scan.add_argument("--show-all", action="store_true", help="Print every scanned target line")
    scan.set_defaults(func=run_scan)

    presets = sub.add_parser("presets", help="List built-in presets")
    presets.set_defaults(func=run_presets)

    chat = sub.add_parser("chat", help="LAN chat: UDP discovery + TCP P2P messaging")
    chat.add_argument("--name", type=str, default=socket.gethostname(), help="Display name")
    chat.add_argument("--udp-port", type=int, default=50504, help="UDP discovery port")
    chat.add_argument("--tcp-port", type=int, default=50505, help="TCP chat port")
    chat.add_argument("--no-auto-connect", action="store_true", help="Discover peers but don't auto-connect")
    chat.set_defaults(func=run_chat)

    gui = sub.add_parser("gui", help="Optional minimal GUI (CLI remains primary)")
    gui.set_defaults(func=run_gui)

    return p


def main(argv: Sequence[str]) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "scan":
        if args.json_out == "":
            args.json_out = None
        if args.csv_out == "":
            args.csv_out = None
        if args.active_ips_out == "":
            args.active_ips_out = None

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
