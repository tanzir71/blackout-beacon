# Blackout Beacon (Beacon v2.0 CLI)

Blackout Beacon is a CLI-first toolkit for:

- High-concurrency IP scanning (100+ threads)
- HTTP(S) title probing (quickly identify web servers by page title)
- Exporting results to JSON and CSV
- Full LAN chat with UDP discovery + TCP peer-to-peer messaging

This is designed for situations where Internet connectivity is unreliable, filtered, or intermittently down — but local networks (Wi‑Fi/LAN) and/or ISP-local routing may still work.

## Requirements

- Python 3.9+ (Windows tested)

## Quick Start

From this folder:

```bash
python blackout_beacon.py --help
python blackout_beacon.py presets
```

## Optional GUI

The CLI is the primary and most reliable interface. A minimal GUI is also available as a convenience layer.

```bash
python blackout_beacon.py gui
```

On Windows, you can also launch the GUI by double-clicking `blackout_beacon_gui.pyw`.

## Scan

Scan supports targets as:

- Single IP: `192.168.68.105`
- Range: `192.168.68.1-192.168.68.254`
- CIDR: `192.168.68.0/24`
- File input: `--file ip_list.txt` (one target per line)
- Presets: `--preset bd:gp` (see `presets`)

### Examples

Scan a local /24, probe common web ports, and export JSON + CSV:

```bash
python blackout_beacon.py scan 192.168.68.0/24 --threads 200 --ping --http-title --json-out out.json --csv-out out.csv
```

Use `ip_list.txt` and output a simple list of “active” IPs (ping ok or any probed port open):

```bash
python blackout_beacon.py scan --file ip_list.txt --ports 80,443 --http-title --active-ips-out active_ips.txt
```

Scan a Bangladesh ISP preset:

```bash
python blackout_beacon.py scan --preset bd:gp --threads 300 --ports 80,443 --http-title --max-targets 200000
```

### Output

- Console: prints one line per “interesting” host by default (ping ok, open ports, or `--show-all`)
- JSON: array of results with fields: `ip`, `ts`, `ping_ok`, `ping_ms`, `open_ports`, `http[]`, `error`
- CSV: one row per IP (or one per HTTP probe if multiple titles are fetched)

## Presets (BD ISP)

List presets:

```bash
python blackout_beacon.py presets
```

Available preset keys:

- `bd:gp` (Grameenphone)
- `bd:robi` (Robi / Airtel)
- `bd:banglalink` (Banglalink)
- `bd:teletalk` (Teletalk)
- `bd:btcl` (BTCL)
- `bd:all` (union)

These presets are intentionally conservative and are meant as a starting point. Large CIDRs can expand to many hosts, so scanning them usually requires increasing `--max-targets` and/or narrowing the scope.

## LAN Chat (UDP discovery + TCP P2P)

Start chat on multiple devices on the same LAN:

```bash
python blackout_beacon.py chat --name Alice
python blackout_beacon.py chat --name Bob
```

Discovery is via UDP broadcast (default UDP port `50504`). Messaging is via TCP (default TCP port `50505`).

Chat commands:

- `/peers` list discovered peers
- `/all <msg>` send message to connected peers
- `/quit` exit

If your firewall blocks discovery or connections, allow inbound UDP `50504` and TCP `50505` (or change ports with `--udp-port` / `--tcp-port`).
