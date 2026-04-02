"""PCAP network forensics connector via PyShark."""

from __future__ import annotations

import os
from typing import Any

from connectors.base import BaseConnector


class PcapConnector(BaseConnector):
    """PCAP file analysis using PyShark (tshark wrapper)."""

    def __init__(self) -> None:
        self._capture = None
        self._path: str = ""

    def connect(self, path: str, **kwargs: Any) -> dict:
        import pyshark

        if not os.path.isfile(path):
            raise FileNotFoundError(f"PCAP not found: {path}")

        self._capture = pyshark.FileCapture(path, keep_packets=False)
        self._path = path
        return {
            "status": "success",
            "file": os.path.basename(path),
            "path": path,
            "size_mb": round(os.path.getsize(path) / (1024 * 1024), 1),
        }

    def disconnect(self) -> None:
        if self._capture:
            self._capture.close()
        self._capture = None

    def is_connected(self) -> bool:
        return self._capture is not None

    def get_metadata(self) -> dict:
        return {"file": os.path.basename(self._path), "path": self._path}

    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        return self.get_conversations(limit=limit)

    def get_capabilities(self) -> list[str]:
        return ["conversations", "dns_queries", "http_requests", "extract_iocs"]

    def get_conversations(self, display_filter: str = "", limit: int = 100) -> dict:
        """Get network conversations/flows."""
        import pyshark

        cap = pyshark.FileCapture(
            self._path,
            display_filter=display_filter if display_filter else None,
            keep_packets=False,
        )
        conversations: dict[str, dict] = {}
        count = 0

        try:
            for pkt in cap:
                if count >= limit * 10:
                    break
                count += 1
                try:
                    if hasattr(pkt, "ip"):
                        src = pkt.ip.src
                        dst = pkt.ip.dst
                        proto = pkt.transport_layer or "OTHER"
                        key = f"{src}->{dst}:{proto}"
                        if key not in conversations:
                            conversations[key] = {
                                "src": src, "dst": dst, "protocol": proto,
                                "packets": 0, "bytes": 0,
                            }
                        conversations[key]["packets"] += 1
                        conversations[key]["bytes"] += int(pkt.length)
                except AttributeError:
                    continue
        finally:
            cap.close()

        convs = sorted(conversations.values(), key=lambda x: x["packets"], reverse=True)
        return {"total_conversations": len(convs), "conversations": convs[:limit]}

    def get_dns_queries(self, limit: int = 200) -> list[dict]:
        """Extract DNS queries from PCAP."""
        import pyshark

        cap = pyshark.FileCapture(self._path, display_filter="dns", keep_packets=False)
        queries = []
        try:
            for pkt in cap:
                if len(queries) >= limit:
                    break
                try:
                    if hasattr(pkt, "dns"):
                        dns = pkt.dns
                        queries.append({
                            "query": getattr(dns, "qry_name", ""),
                            "type": getattr(dns, "qry_type", ""),
                            "response": getattr(dns, "a", ""),
                            "timestamp": str(pkt.sniff_time),
                        })
                except AttributeError:
                    continue
        finally:
            cap.close()
        return queries

    def get_http_requests(self, limit: int = 200) -> list[dict]:
        """Extract HTTP requests from PCAP."""
        import pyshark

        cap = pyshark.FileCapture(self._path, display_filter="http.request", keep_packets=False)
        requests_list = []
        try:
            for pkt in cap:
                if len(requests_list) >= limit:
                    break
                try:
                    if hasattr(pkt, "http"):
                        http = pkt.http
                        requests_list.append({
                            "method": getattr(http, "request_method", ""),
                            "host": getattr(http, "host", ""),
                            "uri": getattr(http, "request_uri", ""),
                            "user_agent": getattr(http, "user_agent", "")[:200],
                            "src": pkt.ip.src if hasattr(pkt, "ip") else "",
                            "dst": pkt.ip.dst if hasattr(pkt, "ip") else "",
                            "timestamp": str(pkt.sniff_time),
                        })
                except AttributeError:
                    continue
        finally:
            cap.close()
        return requests_list

    def extract_iocs(self) -> dict:
        """Extract network IOCs (unique IPs, domains, URLs)."""
        import pyshark
        import re

        ips = set()
        domains = set()
        urls = set()

        # IPs from conversations
        cap = pyshark.FileCapture(self._path, keep_packets=False)
        count = 0
        try:
            for pkt in cap:
                if count >= 10000:
                    break
                count += 1
                try:
                    if hasattr(pkt, "ip"):
                        ips.add(pkt.ip.src)
                        ips.add(pkt.ip.dst)
                except AttributeError:
                    continue
        finally:
            cap.close()

        # DNS queries
        for q in self.get_dns_queries(limit=500):
            if q.get("query"):
                domains.add(q["query"])

        # HTTP URLs
        for r in self.get_http_requests(limit=500):
            host = r.get("host", "")
            uri = r.get("uri", "")
            if host:
                domains.add(host)
                if uri:
                    urls.add(f"http://{host}{uri}")

        return {
            "unique_ips": sorted(ips),
            "unique_domains": sorted(domains),
            "unique_urls": sorted(list(urls)[:100]),
            "total_ips": len(ips),
            "total_domains": len(domains),
            "total_urls": len(urls),
        }
