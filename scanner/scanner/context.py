"""Shared per-scan context passed to every check."""

from __future__ import annotations

from dataclasses import dataclass

from .authorization import Target
from .config import ScanConfig
from .crawler.crawler import CrawlOutput
from .httpengine import SafeHTTPClient
from .models.scanresult import ScanResult


@dataclass
class ScanContext:
    target: Target
    config: ScanConfig
    client: SafeHTTPClient
    crawl: CrawlOutput
    result: ScanResult
