"""Isolated, bounded HTTPS downloader. Never trust DNS, redirects or filenames."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import sys
import zipfile
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit


class DownloadFailure(Exception):
    def __init__(self, status: int, detail: str):
        self.status, self.detail = status, detail
        super().__init__(detail)


def validate_url(url: str, allowed_hosts=()) -> tuple[str, str]:
    try:
        if not isinstance(url, str) or not url or len(url) > 8192:
            raise ValueError()
        if any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
            raise ValueError()
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise ValueError()
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if allowed_hosts and host not in allowed_hosts:
            raise DownloadFailure(422, "Download host is not in the server allowlist")
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
        return host, path
    except (ValueError, UnicodeError) as exc:
        raise DownloadFailure(422, "Use an HTTPS ZIP URL on port 443 without credentials or fragment") from exc


def public_addresses(host: str) -> list[str]:
    records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise DownloadFailure(502, "Download host could not be resolved")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        # Reject mapped/tunnel forms as well as private, loopback, link-local,
        # reserved, multicast and mixed public/private DNS results.
        if (not ip.is_global or ip.is_multicast or ip.is_reserved
                or (isinstance(ip, ipaddress.IPv6Address)
                    and (ip.ipv4_mapped or ip.sixtofour or ip.teredo))):
            raise DownloadFailure(422, "Download URL must resolve only to public Internet addresses")
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, timeout: float):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        # Connect to the vetted numeric IP, not the hostname: no second DNS
        # lookup of attacker-controlled names. TLS still verifies the URL host.
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def download(url: str, destination: Path, *, max_bytes: int, timeout: float,
             allowed_hosts=(), max_redirects: int = 3) -> None:
    for hop in range(max_redirects + 1):
        host, path = validate_url(url, allowed_hosts)
        addresses = public_addresses(host)
        connection = None
        response = None
        for address in addresses:
            connection = PinnedHTTPSConnection(host, address, timeout)
            try:
                connection.request("GET", path, headers={
                    "Accept": "application/zip, application/octet-stream",
                    "Accept-Encoding": "identity", "User-Agent": "KY-Skill-Scanner/1.0",
                })
                response = connection.getresponse()
                break
            except (OSError, http.client.HTTPException):
                connection.close()
        if response is None:
            raise DownloadFailure(502, "Could not download ZIP from the remote server")
        try:
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or hop == max_redirects:
                    raise DownloadFailure(502, "Download redirect is missing or exceeds the limit")
                # Every redirect gets full URL, allowlist and DNS validation.
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise DownloadFailure(502, "Remote download did not return HTTP 200")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise DownloadFailure(422, "Encoded HTTP download bodies are not supported")
            declared = response.getheader("Content-Length")
            if declared is not None:
                try:
                    size = int(declared)
                except ValueError as exc:
                    raise DownloadFailure(502, "Invalid download Content-Length") from exc
                if size < 0:
                    raise DownloadFailure(502, "Invalid download Content-Length")
                if size > max_bytes:
                    raise DownloadFailure(413, "Downloaded ZIP exceeds the size limit")
            total = 0
            # Fixed local filename; Content-Disposition and URL basename ignored.
            with destination.open("xb") as output:
                while chunk := response.read(min(65536, max_bytes - total + 1)):
                    total += len(chunk)
                    if total > max_bytes:
                        raise DownloadFailure(413, "Downloaded ZIP exceeds the size limit")
                    output.write(chunk)
            if not zipfile.is_zipfile(destination):
                raise DownloadFailure(422, "Download is not a valid ZIP (it may be a login or HTML page)")
            return
        finally:
            response.close()
            connection.close()


def main() -> int:
    try:
        config = json.load(sys.stdin)
        download(config["url"], Path("archive.zip"), max_bytes=config["max_bytes"],
                 timeout=config["timeout"], allowed_hosts=config["allowed_hosts"])
        result = {"status": 200}
    except DownloadFailure as exc:
        result = {"status": exc.status, "detail": exc.detail}
    except Exception:
        # Never echo signed URLs, response bodies or remote exception strings.
        result = {"status": 502, "detail": "ZIP download failed; check the remote file service"}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
