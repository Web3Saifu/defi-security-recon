from __future__ import annotations

import json
import ssl
import threading
import time
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener


USER_AGENT = "defi-security-recon/0.2 (evidence crawler; contact repository owner)"


class SourceError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, retryable: bool = True):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class RateLimitError(SourceError):
    pass


@dataclass(slots=True)
class HttpResponse:
    url: str
    status: int
    body: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SourceError(f"unsupported URL: {url}", retryable=False)
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise SourceError("local URLs are not allowed", retryable=False)
    try:
        address = ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise SourceError("non-public IP addresses are not allowed", retryable=False)


class HttpClient:
    def __init__(self, timeout: float = 8, retries: int = 1, max_bytes: int = 3_000_000, min_interval: float = 0.0):
        self.timeout = timeout
        self.retries = retries
        self.max_bytes = max_bytes
        self.min_interval = min_interval
        self._opener = build_opener()
        self._cache: dict[tuple[str, str], HttpResponse] = {}
        self._lock = threading.Lock()
        self._last_request = 0.0

    def _throttle(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None,
                max_bytes: int | None = None, cache: bool = True) -> HttpResponse:
        validate_public_url(url)
        cache_key = (method, url)
        if method == "GET" and cache and cache_key in self._cache:
            return self._cache[cache_key]
        request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/html,text/plain;q=0.9,*/*;q=0.5"}
        request_headers.update(headers or {})
        limit = max_bytes or self.max_bytes
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            self._throttle()
            try:
                request = Request(url, data=body, headers=request_headers, method=method)
                with self._opener.open(request, timeout=self.timeout) as response:
                    final_url = response.geturl()
                    validate_public_url(final_url)
                    payload = response.read(limit + 1)
                    if len(payload) > limit:
                        raise SourceError(f"response exceeded {limit} bytes", retryable=False)
                    result = HttpResponse(final_url, int(response.status), payload, response.headers.get_content_type(),
                                          {key.lower(): value for key, value in response.headers.items()})
                    if method == "GET" and cache:
                        self._cache[cache_key] = result
                    return result
            except HTTPError as exc:
                status = int(exc.code)
                if status in {403, 429}:
                    remaining = exc.headers.get("X-RateLimit-Remaining", "") if exc.headers else ""
                    if status == 429 or remaining == "0":
                        raise RateLimitError(f"rate limit reached for {url}", status=status) from exc
                if status in {400, 401, 404, 410, 422}:
                    raise SourceError(f"HTTP {status}: {url}", status=status, retryable=False) from exc
                last_error = exc
            except (URLError, TimeoutError, ssl.SSLError, SourceError) as exc:
                if isinstance(exc, SourceError) and not exc.retryable:
                    raise
                last_error = exc
            if attempt < self.retries:
                time.sleep(0.4 * (2**attempt))
        raise SourceError(f"failed to fetch {url}: {last_error}")

    def get(self, url: str, headers: dict[str, str] | None = None, *, params: dict[str, Any] | None = None,
            max_bytes: int | None = None, cache: bool = True) -> HttpResponse:
        if params:
            url = f"{url}?{urlencode(params)}"
        return self.request("GET", url, headers=headers, max_bytes=max_bytes, cache=cache)

    def post_json(self, url: str, payload: Any, headers: dict[str, str] | None = None) -> HttpResponse:
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or {})
        return self.request("POST", url, headers=request_headers, body=json.dumps(payload).encode("utf-8"), cache=False)
