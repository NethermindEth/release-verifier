"""Minimal HTTPS client (stdlib only) with retries and credential hygiene."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"release-verifier/{__version__}"
TIMEOUT = float(os.environ.get("RELEASE_VERIFIER_HTTP_TIMEOUT", "90"))
RETRIES = 3


class HttpError(Exception):
    def __init__(self, url: str, status: int, reason: str = "", secret: bool = False):
        shown = "<redacted>" if secret else redact_url(url)
        super().__init__(f"HTTP {status} for {shown} {reason}".strip())
        self.url = None if secret else url
        self.status = status


def redact_url(url: str) -> str:
    """Drop query strings (pre-signed download URLs carry credentials in them)."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class _StripAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """Never forward Authorization to a different host (GitHub redirects downloads to blob storage)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            for h in ("Authorization", "authorization"):
                new.headers.pop(h, None)
                new.unredirected_hdrs.pop(h, None)
        return new


_opener = urllib.request.build_opener(_StripAuthOnHostChange)


def github_headers(api: bool = True) -> dict[str, str]:
    h = {"X-GitHub-Api-Version": "2022-11-28"} if api else {}
    if api:
        h["Accept"] = "application/vnd.github+json"
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _open(url: str, headers: dict[str, str] | None, method: str, data: bytes | None):
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
    return _opener.open(req, timeout=TIMEOUT)


def request(
    url: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    retries: int = RETRIES,
    secret: bool = False,
    limit: int | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Perform a request; retries on transport errors, 429 and 5xx. Raises HttpError on final
    failure, TooLarge when ``limit`` is set and the body is longer."""
    delay = 2.0
    for attempt in range(retries + 1):
        try:
            with _open(url, headers, method, data) as resp:
                body = resp.read() if limit is None else resp.read(limit + 1)
                if limit is not None and len(body) > limit:
                    raise TooLarge(f"{'<redacted>' if secret else redact_url(url)} is larger than {limit} bytes")
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
        except urllib.error.HTTPError as e:
            retryable = e.code == 429 or e.code >= 500
            if not retryable or attempt == retries:
                body = e.read()[:300].decode("utf-8", "replace") if e.fp else ""
                err = HttpError(url, e.code, e.reason or "", secret)
                err.headers = {k.lower(): v for k, v in (e.headers or {}).items()}  # type: ignore[attr-defined]
                err.body = body  # type: ignore[attr-defined]
                raise err from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == retries:
                raise HttpError(url, 0, f"transport error: {type(e).__name__ if secret else e}", secret) from None
        log.debug("retrying %s (attempt %d)", "<redacted>" if secret else redact_url(url), attempt + 1)
        time.sleep(delay)
        delay *= 2
    raise AssertionError("unreachable")


class TooLarge(ValueError):
    """A response body over the caller's size limit (published content, so a finding, not an error)."""


def get_bytes(url: str, headers: dict[str, str] | None = None, limit: int | None = None) -> bytes:
    """Body of ``url``; with ``limit``, at most that many bytes are read (more is TooLarge)."""
    return request(url, headers, limit=limit)[2]


def get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    return json.loads(request(url, headers)[2])


def get_optional_json(url: str, headers: dict[str, str] | None = None) -> Any | None:
    try:
        return get_json(url, headers)
    except HttpError as e:
        if e.status == 404:
            return None
        raise


def post_json(url: str, payload: Any, headers: dict[str, str] | None = None) -> int:
    body = json.dumps(payload).encode()
    status, _, _ = request(url, {"Content-Type": "application/json", **(headers or {})}, "POST", body, retries=2, secret=True)
    return status


def download(url: str, dest: Path, headers: dict[str, str] | None = None) -> str:
    """Stream ``url`` to ``dest`` and return its sha256 hex digest."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    delay = 2.0
    for attempt in range(RETRIES + 1):
        h = hashlib.sha256()
        try:
            with _open(url, headers, "GET", None) as resp, open(tmp, "wb") as f:
                while chunk := resp.read(1 << 20):
                    h.update(chunk)
                    f.write(chunk)
            tmp.replace(dest)
            return h.hexdigest()
        except urllib.error.HTTPError as e:
            if not (e.code == 429 or e.code >= 500) or attempt == RETRIES:
                raise HttpError(url, e.code, e.reason or "") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == RETRIES:
                raise HttpError(url, 0, f"transport error: {e}") from None
        time.sleep(delay)
        delay *= 2
    raise AssertionError("unreachable")
