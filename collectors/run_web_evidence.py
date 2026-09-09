"""Fetch the content behind observed web paths and record what is exposed there.

The active layer discovers that a path exists; it never looks at what the path
serves. The shipped testbed plants two pieces of evidence that were consequently
never collected: a credentials file reachable through the /backup directory
listing, and an exposed .git/config on the development virtual host naming the
repository owner. Both are genuine observations, and both create cross-layer
links that earlier revisions instead hardcoded.

Supports --replay-dir so the collector can be exercised against saved response
bodies when the testbed is not running.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.derive import extract_credentials_from_content, parse_exposed_git_config
from core.provenance import DERIVED, OBSERVED, edge

#: Paths probed on every observed HTTP service, beyond the ones Gobuster found.
WELL_KNOWN_PATHS = ("/.git/config",)

HREF_PATTERN = re.compile(r'<a href="([^"?/][^"]*)"', re.IGNORECASE)


def fetch(url, timeout=5, replay_dir=None, vhost=None):
    """Return the body at `url`, or None.

    `vhost` sets an explicit Host header. A name-based virtual host serves
    different content at the same address, so evidence reachable only under a
    given name is not reachable without it. The vhost is part of the request
    identity and therefore part of the replay fixture name.
    """
    key = f"{url}|host={vhost}" if vhost else url
    if replay_dir:
        name = re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_") + ".body"
        path = os.path.join(replay_dir, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as source:
            return source.read()
    try:
        request = urllib.request.Request(url)
        if vhost:
            request.add_header("Host", vhost)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception as error:
        print(f"[-] {url}{f' (Host: {vhost})' if vhost else ''}: {error}")
        return None


def load_active(active_jsonl):
    """Split the active-layer records into services and web paths."""
    services, paths = [], []
    with open(active_jsonl, encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            record = json.loads(line)
            attrs = record["attrs"]
            parts = record["id"].split("-")
            ip = attrs.get("ip") or (parts[1] if len(parts) >= 3 else "")
            if attrs.get("type") == "Service" and attrs.get("service") in {"http", "https"}:
                services.append({"id": record["id"], "port": str(attrs.get("port")),
                                 "product": attrs.get("product"), "ip": ip,
                                 "service": attrs.get("service")})
            elif attrs.get("type") == "WebPath":
                target = record.get("edges", [{}])[0].get("to", "")
                paths.append({"id": record["id"], "path": attrs.get("path"),
                              "service_id": target})
    return services, paths


def service_base_url(service, host_override=None):
    host = host_override or service["ip"]
    port = service["port"]
    scheme = "https" if service.get("service") == "https" else "http"
    suffix = "" if port in {"80", "443"} else f":{port}"
    return f"{scheme}://{host}{suffix}"


def collect(active_jsonl, output_jsonl, host_override=None, replay_dir=None,
            vhosts=()):
    services, paths = load_active(active_jsonl)
    by_id = {service["id"]: service for service in services}
    all_service_ids = [service["id"] for service in services]
    records = []
    counter = 0

    # 1. Follow every observed web path and read what it serves.
    for web_path in paths:
        service = by_id.get(web_path["service_id"])
        if not service:
            continue
        base = service_base_url(service, host_override)
        listing_url = urljoin(base + "/", web_path["path"].lstrip("/") + "/")
        body = fetch(listing_url, replay_dir=replay_dir)
        if body is None:
            continue
        # A directory listing names files; fetch each and inspect it.
        for filename in HREF_PATTERN.findall(body):
            file_url = urljoin(listing_url, filename)
            content = fetch(file_url, replay_dir=replay_dir)
            if content is None:
                continue
            for found in extract_credentials_from_content(content, file_url):
                counter += 1
                records.append({
                    "id": f"cred-web-{counter}",
                    "attrs": {"type": "Credential", "username": found["username"],
                              "secret_kind": found["secret_kind"],
                              "source": found["source"], "severity": 0.7,
                              # Which observed services this credential could refer
                              # to. Empty when the exposure names no service, which
                              # is the honest answer for a generic "database" dump.
                              "names_services": _services_named_in(content, all_service_ids),
                              "origin": "identity"},
                    "edges": [edge(web_path["id"], "EXPOSED_BY", 1.0, OBSERVED,
                                   justification=f"retrieved from {file_url}")],
                })

    # 2. Probe well-known exposures on each observed HTTP service. A name-based
    #    virtual host serves different content at the same address, so each
    #    declared vhost is probed separately; `None` is the default vhost.
    for service in services:
        base = service_base_url(service, host_override)
        for vhost in (None,) + tuple(vhosts):
            for known in WELL_KNOWN_PATHS:
                body = fetch(base + known, replay_dir=replay_dir, vhost=vhost)
                parsed = parse_exposed_git_config(body or "")
                if not parsed:
                    continue
                where = f"{base}{known}" + (f" (Host: {vhost})" if vhost else "")
                counter += 1
                attrs = {"type": "Exposure", "kind": "git-config",
                         "source": where, "severity": 0.5, "origin": "active"}
                if vhost:
                    attrs["vhost"] = vhost
                edges = [edge(service["id"], "EXPOSED_BY", 1.0, OBSERVED,
                              justification=f"retrieved from {where}")]
                if parsed.get("email"):
                    attrs["email"] = parsed["email"]
                    username = parsed["email"].split("@")[0]
                    edges.append(edge(
                        f"persona-{username}", "IDENTIFIES", 0.9, DERIVED,
                        justification=(f"exposed git config at {where} records "
                                       f"user.email {parsed['email']}")))
                if parsed.get("repo_name"):
                    attrs["repo_name"] = parsed["repo_name"]
                    attrs["remote"] = parsed.get("remote")
                records.append({"id": f"exposure-git-config-{counter}",
                                "attrs": attrs, "edges": edges})

    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    return output_jsonl, len(records)


def _services_named_in(content, service_ids):
    """Return service ids whose port is mentioned in the exposed content."""
    named = []
    for service_id in service_ids:
        port = service_id.rsplit("-", 1)[-1]
        if re.search(rf"\b{re.escape(port)}\b", content or ""):
            named.append(service_id)
    return named


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active-jsonl", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--host", default=None,
                        help="Host to contact instead of the scanned IP (e.g. 127.0.0.1)")
    parser.add_argument("--replay-dir", default=None,
                        help="Read saved response bodies instead of making requests")
    parser.add_argument("--vhost", action="append", default=[],
                        help="Name-based virtual host to probe in addition to the "
                             "default one. Declared explicitly because nothing in the "
                             "collected evidence reveals which names a server answers to.")
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    output, count = collect(args.active_jsonl,
                            os.path.join(args.out_dir, "real_web.jsonl"),
                            args.host, args.replay_dir, vhosts=args.vhost)
    print(f"[+] Web evidence complete. Wrote {count} records to {output}")


if __name__ == "__main__":
    main()
