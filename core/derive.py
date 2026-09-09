"""Evidence-derived edge construction.

Each rule here takes observed evidence and returns edges, or returns nothing.
Returning nothing is a first-class outcome: a rule that cannot justify a link
must not invent one. Earlier revisions of the collectors hardcoded their
cross-layer targets (every repository secret was linked to port 3000, every
harvested email produced an FTP account), which meant the graph contained the
same cross-layer paths no matter what the scanners actually found.

Rules never store secret material. They record where an exposure was seen and
what kind of secret it was, so that a reader can go back to the artifact.
"""
import re
from urllib.parse import urlparse

from core.provenance import DERIVED, OBSERVED, edge

#: Which service products a given secret kind can plausibly authenticate to.
#: An empty set means "no service in this testbed", which is the correct answer
#: for a cloud credential in a locally hosted environment.
SECRET_KIND_TARGETS = {
    "gitea-pat": {"gitea"},
    "gitea-token": {"gitea"},
    "aws-access-key": set(),
    "synthetic-aws-key": set(),
}

CREDENTIAL_PATTERN = re.compile(
    r"^\s*(?:USER|USERNAME|LOGIN)\s*[=:]\s*(?P<user>[^\s]+)\s*$"
    r"(?:\r?\n)\s*(?:PASS|PASSWORD|PASSWD)\s*[=:]\s*(?P<password>[^\s]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

GIT_CONFIG_EMAIL = re.compile(r"^\s*email\s*=\s*(?P<email>\S+@\S+)\s*$", re.MULTILINE)
GIT_CONFIG_REMOTE = re.compile(r"^\s*url\s*=\s*(?P<url>\S+)\s*$", re.MULTILINE)


def _service_index(observed_services):
    """Map (host, port) -> service record, for services actually seen open."""
    index = {}
    for service in observed_services:
        index[(str(service.get("ip", "")), str(service.get("port", "")))] = service
    return index


def derive_repo_service_access(secret_kind, remotes, observed_services,
                               conf=0.75, etype="ENABLES_ACCESS"):
    """Link a repository secret to a service it could authenticate to.

    Three conditions must all hold, and each is checked against evidence:

    1. The repository has a remote whose host and port identify a service.
    2. That service was observed open by the active layer.
    3. The secret's kind can authenticate to that service's product.

    The synthetic AWS canary in the current testbed satisfies none of them, so
    this returns [] for it -- which is the point of the rule.
    """
    targets = SECRET_KIND_TARGETS.get(secret_kind)
    if not targets:
        return []
    index = _service_index(observed_services)
    edges = []
    seen = set()
    for remote in remotes:
        parsed = urlparse(remote)
        if not parsed.hostname or not parsed.port:
            continue
        service = index.get((parsed.hostname, str(parsed.port)))
        if service is None:
            continue
        # Product identity may come from either observation the active layer
        # made: the version probe's product string, or the service's own
        # self-description captured by http-title. Some applications are
        # reported by the version probe only as their underlying server, so
        # requiring the former alone would reject a service that plainly
        # identifies itself. Whichever observation matched is named in the
        # justification so a reader can check it.
        candidates = {
            "version probe product": str(service.get("product", "")),
            "observed http title": str(service.get("http_title", "")),
        }
        matched_on, matched_value, matched_target = None, None, None
        for source, value in candidates.items():
            lowered = value.lower()
            hit = next((t for t in targets if t in lowered), None)
            if hit:
                matched_on, matched_value, matched_target = source, value, hit
                break
        if matched_on is None:
            continue
        if service["id"] in seen:
            continue
        seen.add(service["id"])
        edges.append(edge(
            service["id"], etype, conf, DERIVED,
            justification=(f"repository remote {remote} resolves to observed service "
                           f"{service['id']} on port {parsed.port}; its {matched_on} "
                           f"is {matched_value!r}, which identifies product "
                           f"{matched_target!r}; secret kind {secret_kind} "
                           f"authenticates to that product"),
        ))
    return edges


def derive_account_access(username, observed_services, corroborations,
                          conf=0.80, severity=0.3):
    """Emit an Account node and its access edge only when corroborated.

    A corroboration is a record saying that `username` was seen in evidence tied
    to a specific service, for example a credentials file exposed through a web
    path that names the service. A harvested email address on its own is not
    corroboration that an account exists anywhere, so this returns ([], []).
    """
    by_id = {service["id"]: service for service in observed_services}
    nodes, edges = [], []
    for corroboration in corroborations:
        if corroboration.get("username") != username:
            continue
        service_id = corroboration.get("service_id")
        if service_id not in by_id:
            continue
        account_id = f"account-{username}-{by_id[service_id].get('service', 'svc')}"
        nodes.append({
            "id": account_id,
            "attrs": {"type": "Account", "username": username, "severity": severity,
                      "origin": "identity"},
            "edges": [edge(service_id, "ENABLES_ACCESS", conf, DERIVED,
                           justification=(f"username {username} appears in "
                                          f"{corroboration.get('source')}, which names "
                                          f"service {service_id}"))],
        })
        edges.append(nodes[-1]["edges"][0])
    return nodes, edges


def extract_credentials_from_content(content, source):
    """Find credential pairs in fetched content.

    The password value is deliberately not returned. A reader who needs it can
    go to `source`; the graph only needs to know an exposure exists there.
    """
    found = []
    for match in CREDENTIAL_PATTERN.finditer(content or ""):
        found.append({
            "username": match.group("user"),
            "source": source,
            "provenance": OBSERVED,
            "secret_kind": "plaintext-password",
        })
    return found


DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21"}


def derive_finding_service(location, observed_services, host_aliases=(),
                           conf=1.0, etype="VALIDATES", declines=None):
    """Match a manual finding to the service the analyst recorded testing.

    The analyst writes where they tested (`location`), not which graph node that
    is. Parsing the location and matching it against observed services makes the
    link derived rather than declared, and makes it fail visibly when a report
    names something nobody saw open.

    Host matching is explicit. The analyst reaches the testbed through a
    published address (127.0.0.1) while the scanner records the address it saw
    (the Docker gateway). Those are the same machine, but nothing in the
    evidence says so, so the equivalence must be supplied by the caller in
    `host_aliases` and is recorded in the justification. Without it a location
    on an unrelated host would match purely because the port number agreed --
    which is what an earlier revision of this rule did.

    Declines when the port is unparseable, when no observed service matches, or
    when more than one does: an ambiguous match would attach the analyst's
    finding to a service they may not have tested.
    """
    declines = declines if declines is not None else []
    parsed = urlparse(location or "")
    if not parsed.hostname:
        return []
    port = str(parsed.port) if parsed.port else DEFAULT_PORTS.get(parsed.scheme, "")
    if not port:
        declines.append(f"location {location!r}: no port and no default for its scheme")
        return []

    aliases = {str(a) for a in host_aliases}
    matches, host_mismatch = [], False
    for service in observed_services:
        if str(service.get("port")) != port:
            continue
        service_host = str(service.get("ip", ""))
        if parsed.hostname == service_host:
            matches.append((service, "same host"))
        elif parsed.hostname in aliases:
            matches.append((service, f"{parsed.hostname} declared an alias of {service_host}"))
        else:
            host_mismatch = True

    if not matches:
        reason = (f"port {port} observed but on host(s) not equal to "
                  f"{parsed.hostname!r} and no alias declared" if host_mismatch
                  else f"no observed service on port {port}")
        declines.append(f"location {location!r}: {reason}")
        return []
    if len(matches) > 1:
        declines.append(f"location {location!r}: ambiguous, matches "
                        f"{', '.join(s['id'] for s, _ in matches)}")
        return []

    service, how = matches[0]
    return [edge(service["id"], etype, conf, DERIVED,
                 justification=(f"finding location {location} names port {port}; "
                                f"observed service {service['id']} matches ({how})"))]


def parse_exposed_git_config(content):
    """Parse an exposed .git/config into the fields that tie it to a persona.

    Returns {} when the content is not a Git config, so a 404 page cannot be
    mistaken for evidence.
    """
    if not content or "[core]" not in content:
        return {}
    parsed = {}
    email = GIT_CONFIG_EMAIL.search(content)
    if email:
        parsed["email"] = email.group("email")
    remote = GIT_CONFIG_REMOTE.search(content)
    if remote:
        url = remote.group("url")
        parsed["remote"] = url
        name = url.rstrip("/").rsplit("/", 1)[-1]
        parsed["repo_name"] = name[:-4] if name.endswith(".git") else name
    return parsed
