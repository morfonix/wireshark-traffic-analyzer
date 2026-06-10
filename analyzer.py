                      
"""
Wireshark Traffic Log Analyzer
================================
Анализирует экспортированные CSV/TXT логи Wireshark:
  - фильтрует шумовой трафик
  - выделяет потенциально важные события
  - группирует по IP и доменам
  - определяет подозрительную активность
  - выводит отчёт в консоль, TXT и JSON

Использование:
    python analyzer.py input.csv [опции]

Python 3.12+
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = True
except ImportError:
    COLOR_OK = False
                                                                        
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()


                                               
                    
                                               

                                
NOISE_PROTOCOLS: set[str] = {
    "ARP", "MDNS", "LLMNR", "SSDP", "DHCP", "DHCPV6",
    "NBNS", "NTP", "BROWSER", "IGMPv3", "IGMP",
}

                                        
IMPORTANT_PROTOCOLS: set[str] = {
    "HTTP", "HTTPS", "TLS", "SSL", "DNS", "TCP", "UDP",
    "FTP", "SSH", "SMTP", "IMAP", "POP3",
}

                                                         
COMMON_PORTS: set[int] = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465,
    587, 993, 995, 3306, 3389, 5432, 8080, 8443,
}

                                       
THRESHOLD_REQUESTS_PER_HOST = 200                             
THRESHOLD_DNS_QUERIES        = 150                       
THRESHOLD_FAILED_CONNECTIONS = 30                                  
THRESHOLD_LARGE_PACKET       = 65000                         
THRESHOLD_RARE_PORT_HITS     = 20                                      


                                               
                  
                                               

@dataclass
class Packet:
    """Нормализованное представление одного пакета из лога Wireshark."""
    number:    int
    timestamp: str
    src_ip:    str
    dst_ip:    str
    protocol:  str
    length:    int
    info:      str
    src_port:  Optional[int] = None
    dst_port:  Optional[int] = None
    dns_query: Optional[str] = None                          


@dataclass
class SuspiciousEvent:
    """Одна запись о подозрительной активности."""
    category:    str                       
    description: str                                     
    severity:    str                               
    details:     dict = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Итоговый объект со всей аналитикой."""
    total_packets:         int
    filtered_packets:      int
    important_packets:     int
    top_src_ips:           list[tuple[str, int]]
    top_dst_ips:           list[tuple[str, int]]
    top_dns_domains:       list[tuple[str, int]]
    top_ports:             list[tuple[int, int]]
    protocol_stats:        dict[str, int]
    suspicious_events:     list[SuspiciousEvent]
    connection_errors:     int
    large_packets:         int
    rare_port_connections: int
    analysis_time:         str


                                               
                 
                                               

class LogParser:
    """
    Читает CSV или TXT-файл, экспортированный из Wireshark,
    и возвращает список объектов Packet.

    Поддерживаемые форматы:
      • CSV: File → Export Packet Dissections → As CSV
      • TXT: File → Export Packet Dissections → As Plain Text (колонки через пробелы/таб)

    Wireshark CSV-заголовок (по умолчанию):
      "No.","Time","Source","Destination","Protocol","Length","Info"
    """

                                                            
    _COL_ALIASES: dict[str, str] = {
        "no.": "number", "no": "number",
        "time": "timestamp",
        "source": "src_ip",
        "destination": "dst_ip",
        "protocol": "protocol",
        "length": "length",
        "info": "info",
    }

    def parse(self, filepath: Path) -> list[Packet]:
        """Определяет формат и парсит файл."""
        suffix = filepath.suffix.lower()
        if suffix == ".csv":
            return self._parse_csv(filepath)
        elif suffix in (".txt", ".log", ""):
            return self._parse_txt(filepath)
        else:
                                            
            with open(filepath, encoding="utf-8", errors="replace") as f:
                first_line = f.readline()
            if "," in first_line and '"' in first_line:
                return self._parse_csv(filepath)
            return self._parse_txt(filepath)

                                                                        
    def _parse_csv(self, filepath: Path) -> list[Packet]:
        packets: list[Packet] = []
        with open(filepath, encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
                                   
            if reader.fieldnames is None:
                return packets
            col_map = {
                raw.strip().strip('"').lower(): self._COL_ALIASES.get(
                    raw.strip().strip('"').lower(), raw.strip().strip('"').lower()
                )
                for raw in reader.fieldnames
            }
            for row in reader:
                norm = {col_map.get(k.strip().strip('"').lower(), k): v.strip()
                        for k, v in row.items() if k and v}
                pkt = self._build_packet(norm)
                if pkt:
                    packets.append(pkt)
        return packets

                                                                        
    def _parse_txt(self, filepath: Path) -> list[Packet]:
        """
        TXT-формат Wireshark выглядит примерно так:
            1   0.000000   192.168.1.1  → 192.168.1.2  TCP  74  ...
        Пытаемся разобрать по пробелам (≥2 пробела как разделитель).
        """
        packets: list[Packet] = []
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip()
                if not line or line.startswith("No.") or line.startswith("Frame"):
                    continue
                                                           
                parts = re.split(r"\s{2,}|\t", line.strip())
                if len(parts) < 6:
                    continue
                norm = {
                    "number":    parts[0].strip(),
                    "timestamp": parts[1].strip(),
                    "src_ip":    parts[2].strip(),
                    "dst_ip":    parts[3].strip(),
                    "protocol":  parts[4].strip(),
                    "length":    parts[5].strip(),
                    "info":      " ".join(parts[6:]).strip() if len(parts) > 6 else "",
                }
                pkt = self._build_packet(norm)
                if pkt:
                    packets.append(pkt)
        return packets

                                                                        
    def _build_packet(self, d: dict) -> Optional[Packet]:
        """Преобразует словарь полей в объект Packet."""
        try:
            number = int(re.sub(r"\D", "", d.get("number", "0")) or 0)
            length = int(re.sub(r"\D", "", d.get("length", "0")) or 0)
            src_ip = d.get("src_ip", "").strip()
            dst_ip = d.get("dst_ip", "").strip()
            protocol = d.get("protocol", "").strip().upper()
            info = d.get("info", "").strip()
            timestamp = d.get("timestamp", "")

                                                                     
            src_port, dst_port = self._extract_ports(info)

                                 
            dns_query = self._extract_dns(protocol, info)

            return Packet(
                number=number, timestamp=timestamp,
                src_ip=src_ip, dst_ip=dst_ip,
                protocol=protocol, length=length, info=info,
                src_port=src_port, dst_port=dst_port,
                dns_query=dns_query,
            )
        except (ValueError, KeyError):
            return None

                                                                        
    @staticmethod
    def _extract_ports(info: str) -> tuple[Optional[int], Optional[int]]:
        """Ищет «порт → порт» или «порт > порт» в поле Info."""
        m = re.search(r"(\d{1,5})\s*[→>]\s*(\d{1,5})", info)
        if m:
            try:
                return int(m.group(1)), int(m.group(2))
            except ValueError:
                pass
        return None, None

                                                                        
    @staticmethod
    def _extract_dns(protocol: str, info: str) -> Optional[str]:
        """Извлекает доменное имя из DNS-пакета."""
        if "DNS" not in protocol:
            return None
                                                                
        m = re.search(r"(?:query|response)[^A-Z]*(?:A|AAAA|CNAME|MX|PTR|TXT)\s+([\w.\-]+)", info, re.IGNORECASE)
        if m:
            return m.group(1).rstrip(".")
                                                               
        m = re.search(r"([\w\-]{2,}\.[\w\-.]{2,})\s*$", info)
        if m:
            return m.group(1).rstrip(".")
        return None


                                               
                
                                               

class TrafficFilter:
    """
    Убирает «шумовой» трафик и дубликаты.
    Возвращает только потенциально важные пакеты.
    """

    def __init__(self, filter_icmp: bool = True):
        self._filter_icmp = filter_icmp
                                                             
        self._seen: set[tuple] = set()

                                                                        
    def filter(self, packets: list[Packet]) -> list[Packet]:
        """Применяет все фильтры последовательно."""
        result: list[Packet] = []
                                                                           
        freq: Counter = Counter()

        for pkt in packets:
            if self._is_noise(pkt):
                continue
            if self._is_duplicate(pkt):
                continue
            key = (pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.dst_port)
            freq[key] += 1
                                                                        
            if self._is_frequent_noise(pkt, freq[key]):
                continue
            result.append(pkt)

        return result

                                                                        
    def _is_noise(self, pkt: Packet) -> bool:
        """True, если пакет явно относится к шумовым протоколам."""
        proto = pkt.protocol.upper()
                           
        if proto in NOISE_PROTOCOLS:
            return True
                            
        if self._filter_icmp and proto.startswith("ICMP"):
            return True
                                                                   
        for noise in NOISE_PROTOCOLS:
            if noise in proto:
                return True
                                  
        broadcast = {"255.255.255.255", "0.0.0.0", "ff02::1", "ff02::2"}
        if pkt.dst_ip in broadcast or pkt.src_ip in broadcast:
            return True
        return False

                                                                        
    def _is_duplicate(self, pkt: Packet) -> bool:
        """
        Считает дубликатом пакет с той же тройкой (src, dst, info[:60]).
        TCP-ретрансмиссии и повторные ARP/DNS сворачиваются.
        """
        fingerprint = (pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.info[:60])
        if fingerprint in self._seen:
            return True
        self._seen.add(fingerprint)
        return False

                                                                        
    @staticmethod
    def _is_frequent_noise(pkt: Packet, count: int) -> bool:
        """
        Убирает многократно повторяющиеся служебные паттерны:
        например, TCP keepalive / Windows Update heartbeat.
        Порог: >50 одинаковых (src, dst, proto, port).
        """
        if count > 50 and pkt.protocol in ("TCP", "UDP") and pkt.length < 100:
            return True
        return False


                                               
               
                                               

class TrafficAnalyzer:
    """
    Группирует отфильтрованные пакеты по IP и доменам,
    считает статистику.
    """

    def __init__(self, packets: list[Packet]):
        self._packets = packets

                                                                        
    def get_top_src_ips(self, n: int = 10) -> list[tuple[str, int]]:
        c: Counter[str] = Counter(p.src_ip for p in self._packets if p.src_ip)
        return c.most_common(n)

    def get_top_dst_ips(self, n: int = 10) -> list[tuple[str, int]]:
        c: Counter[str] = Counter(p.dst_ip for p in self._packets if p.dst_ip)
        return c.most_common(n)

    def get_top_dns_domains(self, n: int = 10) -> list[tuple[str, int]]:
        c: Counter[str] = Counter(
            p.dns_query for p in self._packets if p.dns_query
        )
        return c.most_common(n)

    def get_top_ports(self, n: int = 10) -> list[tuple[int, int]]:
        ports: list[int] = []
        for p in self._packets:
            if p.dst_port:
                ports.append(p.dst_port)
        c: Counter[int] = Counter(ports)
        return c.most_common(n)

    def get_protocol_stats(self) -> dict[str, int]:
        c: Counter[str] = Counter(p.protocol for p in self._packets)
        return dict(c.most_common())

    def get_connection_errors(self) -> int:
        """Считает TCP RST, Connection Refused, ICMP unreachable."""
        count = 0
        error_patterns = re.compile(
            r"\b(RST|reset|refused|unreachable|timeout|ICMP.*unreachable)\b",
            re.IGNORECASE,
        )
        for p in self._packets:
            if error_patterns.search(p.info):
                count += 1
        return count

    def get_large_packets(self) -> int:
        return sum(1 for p in self._packets if p.length >= THRESHOLD_LARGE_PACKET)

    def get_rare_port_connections(self) -> int:
        return sum(
            1 for p in self._packets
            if p.dst_port and p.dst_port not in COMMON_PORTS
        )

                                                                        
    def packets_by_src_ip(self) -> dict[str, list[Packet]]:
        grouped: dict[str, list[Packet]] = defaultdict(list)
        for p in self._packets:
            grouped[p.src_ip].append(p)
        return dict(grouped)

    def packets_by_dst_ip(self) -> dict[str, list[Packet]]:
        grouped: dict[str, list[Packet]] = defaultdict(list)
        for p in self._packets:
            grouped[p.dst_ip].append(p)
        return dict(grouped)


                                               
                                       
                                               

class SuspiciousDetector:
    """
    Анализирует отфильтрованные пакеты и генерирует список
    потенциально подозрительных событий.
    """

    def __init__(self, packets: list[Packet], analyzer: TrafficAnalyzer):
        self._packets = packets
        self._analyzer = analyzer

                                                                        
    def detect(self) -> list[SuspiciousEvent]:
        events: list[SuspiciousEvent] = []
        events.extend(self._check_host_flood())
        events.extend(self._check_dns_flood())
        events.extend(self._check_failed_connections())
        events.extend(self._check_rare_ports())
        events.extend(self._check_large_data())
        events.extend(self._check_http_redirects())
        return events

                                                                        
    def _check_host_flood(self) -> list[SuspiciousEvent]:
        """Большое количество запросов к одному хосту."""
        events = []
        dst_counts = Counter(p.dst_ip for p in self._packets if p.dst_ip)
        for ip, count in dst_counts.items():
            if count >= THRESHOLD_REQUESTS_PER_HOST:
                severity = "HIGH" if count > THRESHOLD_REQUESTS_PER_HOST * 3 else "MEDIUM"
                events.append(SuspiciousEvent(
                    category="HOST_FLOOD",
                    description=f"Большое количество запросов к хосту {ip}: {count} пакетов",
                    severity=severity,
                    details={"dst_ip": ip, "count": count},
                ))
        return events

                                                                        
    def _check_dns_flood(self) -> list[SuspiciousEvent]:
        """Аномально большое количество DNS-запросов."""
        events = []
        dns_pkts = [p for p in self._packets if "DNS" in p.protocol]
        total_dns = len(dns_pkts)
        if total_dns >= THRESHOLD_DNS_QUERIES:
                                       
            top_domains = Counter(p.dns_query for p in dns_pkts if p.dns_query).most_common(5)
            events.append(SuspiciousEvent(
                category="DNS_FLOOD",
                description=f"Обнаружено {total_dns} DNS-запросов — возможен DNS-туннелинг или сканирование",
                severity="MEDIUM",
                details={"total_dns": total_dns, "top_domains": dict(top_domains)},
            ))
        return events

                                                                        
    def _check_failed_connections(self) -> list[SuspiciousEvent]:
        """Множество неудачных TCP-соединений (RST, refused)."""
        events = []
        error_re = re.compile(r"\b(RST|reset|refused|unreachable|timeout)\b", re.IGNORECASE)
        failed: list[Packet] = [p for p in self._packets if error_re.search(p.info)]
        count = len(failed)
        if count >= THRESHOLD_FAILED_CONNECTIONS:
                                                         
            src_counter = Counter(p.src_ip for p in failed)
            top_scanners = src_counter.most_common(3)
            events.append(SuspiciousEvent(
                category="CONNECTION_ERRORS",
                description=f"Зафиксировано {count} неудачных соединений — возможно сканирование портов",
                severity="HIGH",
                details={"count": count, "top_sources": dict(top_scanners)},
            ))
        return events

                                                                        
    def _check_rare_ports(self) -> list[SuspiciousEvent]:
        """Обращения к нестандартным/редким портам."""
        events = []
        rare: Counter[int] = Counter()
        for p in self._packets:
            if p.dst_port and p.dst_port not in COMMON_PORTS:
                rare[p.dst_port] += 1

        for port, count in rare.items():
            if count >= THRESHOLD_RARE_PORT_HITS:
                events.append(SuspiciousEvent(
                    category="RARE_PORT",
                    description=f"Необычный порт {port}: {count} обращений",
                    severity="LOW" if count < 50 else "MEDIUM",
                    details={"port": port, "count": count},
                ))
        return events

                                                                        
    def _check_large_data(self) -> list[SuspiciousEvent]:
        """Аномально большие пакеты — возможная утечка данных."""
        events = []
        large = [p for p in self._packets if p.length >= THRESHOLD_LARGE_PACKET]
        if large:
            total_bytes = sum(p.length for p in large)
            top_src = Counter(p.src_ip for p in large).most_common(3)
            events.append(SuspiciousEvent(
                category="LARGE_DATA_TRANSFER",
                description=f"Обнаружено {len(large)} пакетов размером ≥{THRESHOLD_LARGE_PACKET} байт "
                            f"(итого ~{total_bytes // 1024} КБ)",
                severity="LOW",
                details={
                    "packet_count": len(large),
                    "total_bytes": total_bytes,
                    "top_sources": dict(top_src),
                },
            ))
        return events

                                                                        
    def _check_http_redirects(self) -> list[SuspiciousEvent]:
        """HTTP-редиректы — потенциально фишинговые цепочки."""
        events = []
        redirect_re = re.compile(r"\b(301|302|307|308|Location:)\b", re.IGNORECASE)
        redirects = [p for p in self._packets if redirect_re.search(p.info)]
        if len(redirects) > 5:
            events.append(SuspiciousEvent(
                category="HTTP_REDIRECTS",
                description=f"Зафиксировано {len(redirects)} HTTP-редиректов",
                severity="LOW",
                details={"count": len(redirects)},
            ))
        return events


                                               
                       
                                               

SEVERITY_COLOR = {
    "HIGH":   Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW":    Fore.CYAN,
}

class ReportBuilder:
    """
    Формирует итоговый отчёт и сохраняет его в:
      • консоль (с цветным выводом)
      • TXT-файл
      • JSON-файл
    """

    def __init__(self, result: AnalysisResult, source_file: Path):
        self._r = result
        self._source = source_file

                                                                        
                      
                                                                        
    def print_console(self) -> None:
        r = self._r
        sep = "─" * 60

        self._h1("WIRESHARK TRAFFIC ANALYZER")
        print(f"{Fore.WHITE}Источник:   {self._source}")
        print(f"Время:      {r.analysis_time}")
        print()

                          
        self._h2("📊 ОБЩАЯ СТАТИСТИКА")
        self._kv("Всего пакетов в логе",    r.total_packets)
        self._kv("Отфильтровано (шум)",      r.filtered_packets)
        self._kv("Проанализировано",         r.important_packets)
        self._kv("Ошибки соединений",        r.connection_errors,  warn=r.connection_errors > 10)
        self._kv("Крупные пакеты",           r.large_packets,      warn=r.large_packets > 0)
        self._kv("Нестандартные порты",      r.rare_port_connections)
        print()

                
        self._h2("🌐 ТОП ИСТОЧНИКОВ (SRC IP)")
        self._table(r.top_src_ips, ("IP-адрес", "Пакетов"))

        self._h2("🎯 ТОП НАЗНАЧЕНИЙ (DST IP)")
        self._table(r.top_dst_ips, ("IP-адрес", "Пакетов"))

                 
        if r.top_dns_domains:
            self._h2("🔍 ТОП DNS-ЗАПРОСОВ")
            self._table(r.top_dns_domains, ("Домен", "Запросов"))

                    
        if r.top_ports:
            self._h2("🔌 ТОП ПОРТОВ НАЗНАЧЕНИЯ")
            self._table(r.top_ports, ("Порт", "Пакетов"))

                   
        self._h2("📦 СТАТИСТИКА ПРОТОКОЛОВ")
        for proto, cnt in sorted(r.protocol_stats.items(), key=lambda x: -x[1]):
            bar = "█" * min(cnt // 5, 40)
            print(f"  {Fore.CYAN}{proto:<12}{Style.RESET_ALL} {cnt:>6}  {Fore.GREEN}{bar}")
        print()

                                   
        self._h2("🚨 ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ")
        if not r.suspicious_events:
            print(f"  {Fore.GREEN}✓ Явных угроз не обнаружено")
        else:
            for ev in r.suspicious_events:
                color = SEVERITY_COLOR.get(ev.severity, Fore.WHITE)
                badge = f"[{ev.severity}]"
                print(f"  {color}{badge:<8}{Style.RESET_ALL} {ev.category:<25} {ev.description}")
                for k, v in ev.details.items():
                    print(f"           {Fore.WHITE}{k}: {v}")
        print()

        print(f"{Fore.WHITE}{sep}")
        print(f"{Fore.YELLOW}  Отчёты сохранены: report.txt  |  report.json")
        print(f"{sep}{Style.RESET_ALL}")

                                                                        
              
                                                                        
    def save_txt(self, out_path: Path) -> None:
        r = self._r
        lines: list[str] = []

        lines.append("=" * 60)
        lines.append("  WIRESHARK TRAFFIC ANALYZER — ОТЧЁТ")
        lines.append("=" * 60)
        lines.append(f"Источник:  {self._source}")
        lines.append(f"Время:     {r.analysis_time}")
        lines.append("")
        lines.append("ОБЩАЯ СТАТИСТИКА")
        lines.append("-" * 40)
        lines.append(f"  Всего пакетов:         {r.total_packets}")
        lines.append(f"  Отфильтровано:          {r.filtered_packets}")
        lines.append(f"  Проанализировано:       {r.important_packets}")
        lines.append(f"  Ошибки соединений:      {r.connection_errors}")
        lines.append(f"  Крупные пакеты:         {r.large_packets}")
        lines.append(f"  Нестандартные порты:    {r.rare_port_connections}")
        lines.append("")

        lines.append("ТОП ИСТОЧНИКОВ (SRC IP)")
        lines.append("-" * 40)
        for ip, cnt in r.top_src_ips:
            lines.append(f"  {ip:<20} {cnt} пак.")
        lines.append("")

        lines.append("ТОП НАЗНАЧЕНИЙ (DST IP)")
        lines.append("-" * 40)
        for ip, cnt in r.top_dst_ips:
            lines.append(f"  {ip:<20} {cnt} пак.")
        lines.append("")

        if r.top_dns_domains:
            lines.append("ТОП DNS-ДОМЕНОВ")
            lines.append("-" * 40)
            for domain, cnt in r.top_dns_domains:
                lines.append(f"  {domain:<40} {cnt}")
            lines.append("")

        if r.top_ports:
            lines.append("ТОП ПОРТОВ")
            lines.append("-" * 40)
            for port, cnt in r.top_ports:
                lines.append(f"  {port:<8} {cnt} пак.")
            lines.append("")

        lines.append("ПРОТОКОЛЫ")
        lines.append("-" * 40)
        for proto, cnt in sorted(r.protocol_stats.items(), key=lambda x: -x[1]):
            lines.append(f"  {proto:<15} {cnt}")
        lines.append("")

        lines.append("ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ")
        lines.append("-" * 40)
        if not r.suspicious_events:
            lines.append("  Явных угроз не обнаружено.")
        else:
            for ev in r.suspicious_events:
                lines.append(f"  [{ev.severity}] {ev.category}: {ev.description}")
                for k, v in ev.details.items():
                    lines.append(f"      {k}: {v}")
        lines.append("")
        lines.append("=" * 60)

        out_path.write_text("\n".join(lines), encoding="utf-8")

                                                                        
               
                                                                        
    def save_json(self, out_path: Path) -> None:
        r = self._r
        data = {
            "meta": {
                "source_file": str(self._source),
                "analysis_time": r.analysis_time,
            },
            "summary": {
                "total_packets":         r.total_packets,
                "filtered_packets":      r.filtered_packets,
                "important_packets":     r.important_packets,
                "connection_errors":     r.connection_errors,
                "large_packets":         r.large_packets,
                "rare_port_connections": r.rare_port_connections,
            },
            "top_src_ips":     [{"ip": ip, "count": c} for ip, c in r.top_src_ips],
            "top_dst_ips":     [{"ip": ip, "count": c} for ip, c in r.top_dst_ips],
            "top_dns_domains": [{"domain": d, "count": c} for d, c in r.top_dns_domains],
            "top_ports":       [{"port": p, "count": c} for p, c in r.top_ports],
            "protocol_stats":  r.protocol_stats,
            "suspicious_events": [asdict(ev) for ev in r.suspicious_events],
        }
        out_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

                                                                        
                                           
                                                                        
    def _h1(self, text: str) -> None:
        sep = "═" * 60
        print(f"\n{Fore.CYAN}{sep}")
        print(f"  {Fore.YELLOW}{text}")
        print(f"{Fore.CYAN}{sep}{Style.RESET_ALL}")

    def _h2(self, text: str) -> None:
        print(f"{Fore.CYAN}{'─' * 60}")
        print(f"{Fore.YELLOW}  {text}{Style.RESET_ALL}")

    def _kv(self, label: str, value: int, warn: bool = False) -> None:
        color = Fore.RED if warn else Fore.GREEN
        print(f"  {label:<30} {color}{value}{Style.RESET_ALL}")

    def _table(self, rows: list[tuple], headers: tuple[str, str]) -> None:
        if not rows:
            print(f"  {Fore.WHITE}(нет данных)\n")
            return
        col1, col2 = headers
        print(f"  {Fore.WHITE}{col1:<35} {col2}{Style.RESET_ALL}")
        print(f"  {'─' * 50}")
        for key, cnt in rows:
            print(f"  {Fore.CYAN}{str(key):<35}{Style.RESET_ALL} {cnt}")
        print()


                                               
                    
                                               

def build_result(
    total: int,
    filtered_packets: list[Packet],
    original_count: int,
    analyzer: TrafficAnalyzer,
    detector: SuspiciousDetector,
) -> AnalysisResult:
    """Собирает итоговый объект AnalysisResult."""
    return AnalysisResult(
        total_packets=total,
        filtered_packets=original_count - len(filtered_packets),
        important_packets=len(filtered_packets),
        top_src_ips=analyzer.get_top_src_ips(),
        top_dst_ips=analyzer.get_top_dst_ips(),
        top_dns_domains=analyzer.get_top_dns_domains(),
        top_ports=analyzer.get_top_ports(),
        protocol_stats=analyzer.get_protocol_stats(),
        suspicious_events=detector.detect(),
        connection_errors=analyzer.get_connection_errors(),
        large_packets=analyzer.get_large_packets(),
        rare_port_connections=analyzer.get_rare_port_connections(),
        analysis_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Анализатор логов Wireshark (CSV/TXT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python analyzer.py capture.csv
  python analyzer.py capture.txt --no-icmp --top 15
  python analyzer.py capture.csv --out-dir ./reports --no-color
        """,
    )
    parser.add_argument(
        "input",
        metavar="INPUT_FILE",
        help="CSV или TXT файл, экспортированный из Wireshark",
    )
    parser.add_argument(
        "--no-icmp",
        action="store_true",
        default=False,
        help="Не фильтровать ICMP (по умолчанию ICMP удаляется)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Количество элементов в топах (по умолчанию 10)",
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        metavar="DIR",
        help="Директория для сохранения отчётов (по умолчанию: текущая)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Отключить цветной вывод в консоли",
    )
    parser.add_argument(
        "--no-txt",
        action="store_true",
        help="Не сохранять TXT-отчёт",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Не сохранять JSON-отчёт",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

                                                         
    if args.no_color or not COLOR_OK:
        global Fore, Style
        class _NoColor:
            def __getattr__(self, _): return ""
        Fore = Style = _NoColor()                            

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ОШИБКА] Файл не найден: {input_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"{Fore.CYAN}[*] Читаем файл: {input_path}{Style.RESET_ALL}")

                                               
    parser_obj = LogParser()
    all_packets = parser_obj.parse(input_path)

    if not all_packets:
        print(f"{Fore.RED}[!] Не удалось распознать ни одного пакета. "
              "Проверьте формат файла.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    total = len(all_packets)
    print(f"{Fore.GREEN}[+] Загружено пакетов: {total}{Style.RESET_ALL}")

                                               
    traffic_filter = TrafficFilter(filter_icmp=not args.no_icmp)
    important = traffic_filter.filter(all_packets)
    print(f"{Fore.GREEN}[+] После фильтрации:  {len(important)}{Style.RESET_ALL}")

                                               
    analyzer = TrafficAnalyzer(important)

                                         
                                                                                
    original_get_top_src = analyzer.get_top_src_ips
    original_get_top_dst = analyzer.get_top_dst_ips
    original_get_top_dns = analyzer.get_top_dns_domains
    original_get_top_ports = analyzer.get_top_ports
    analyzer.get_top_src_ips   = lambda: original_get_top_src(args.top)                                
    analyzer.get_top_dst_ips   = lambda: original_get_top_dst(args.top)                                
    analyzer.get_top_dns_domains = lambda: original_get_top_dns(args.top)                               
    analyzer.get_top_ports     = lambda: original_get_top_ports(args.top)                              

                                               
    detector = SuspiciousDetector(important, analyzer)

                                               
    result = build_result(total, important, total, analyzer, detector)

                                               
    txt_path  = out_dir / "report.txt"
    json_path = out_dir / "report.json"

    report = ReportBuilder(result, input_path)
    report.print_console()

    if not args.no_txt:
        report.save_txt(txt_path)
        print(f"{Fore.GREEN}[+] TXT сохранён:  {txt_path}{Style.RESET_ALL}")

    if not args.no_json:
        report.save_json(json_path)
        print(f"{Fore.GREEN}[+] JSON сохранён: {json_path}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
