import argparse
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET


def create_wordlist(out_dir):
    path = os.path.join(out_dir, "wordlist.txt")
    with open(path, "w", encoding="utf-8") as wordlist:
        wordlist.write("backup\n.git\nadmin\n")
    return path


#: Version probing with --version-all is exhaustive and slow; measured at ~272s
#: against four ports on the reference testbed.
NMAP_TIMEOUT = int(os.environ.get("AETHERGRAPH_NMAP_TIMEOUT", "600"))


def docker_target(target):
    return "host.docker.internal" if target in {"127.0.0.1", "localhost"} else target


def run_nmap(target, out_dir, ports="21,80"):
    """Run Nmap in Docker and return its XML output path."""
    print(f"[*] Running Nmap against {target}...")
    xml_path = os.path.join(out_dir, "nmap.xml")
    # http-title is requested because Nmap's version probe reports some HTTP
    # applications only by their underlying server ("Golang net/http server"),
    # which is insufficient to identify the product a credential could
    # authenticate to. The title is a direct observation of what the service
    # says it is, and is recorded as separate evidence rather than overwriting
    # the version probe's own finding.
    command = [
        "docker", "run", "--rm", "-v", f"{os.path.abspath(out_dir)}:/out",
        "instrumentisto/nmap", "-sV", "--version-all", "--script", "http-title",
        "-p", ports, "-oX", "/out/nmap.xml", docker_target(target)
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=NMAP_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Nmap Docker scan timed out after {NMAP_TIMEOUT} seconds") from error
    if result.returncode != 0 or not os.path.exists(xml_path):
        raise RuntimeError(f"Nmap Docker scan failed: {result.stderr.strip()}")
    return xml_path


def run_gobuster(target, port, wordlist_path, out_dir):
    """Run Gobuster in Docker and return its text output path."""
    print(f"[*] Running Gobuster against http://{target}:{port}...")
    output_name = f"gobuster_{port}.txt"
    output_path = os.path.join(out_dir, output_name)
    command = [
        "docker", "run", "--rm", "-v", f"{os.path.abspath(out_dir)}:/out",
        "secsi/gobuster", "dir", "-u", f"http://{docker_target(target)}:{port}",
        "-w", "/out/wordlist.txt", "-o", f"/out/{output_name}"
    ]
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Gobuster Docker scan timed out on port {port}") from error
    if result.returncode != 0 or not os.path.exists(output_path):
        raise RuntimeError(
            f"Gobuster Docker scan failed on port {port}: {result.stderr.strip()}"
        )
    return output_path


def parse_nmap_xml(nmap_xml):
    """Return active-layer records and discovered HTTP ports."""
    records = []
    http_ports = []
    root = ET.parse(nmap_xml).getroot()
    for host in root.findall("host"):
        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr")
        host_id = f"host-{ip}"
        records.append({
            "id": host_id,
            "attrs": {"type": "Host", "ip": ip, "asset_class": "dmz-web", "origin": "active"},
            "edges": []
        })
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name", "") if service is not None else ""
            # The service's own self-description, observed via the http-title
            # script. Kept separate from the version probe's `product` so that
            # neither observation overwrites the other.
            http_title = ""
            for script in port.findall("script"):
                if script.get("id") == "http-title":
                    http_title = (script.get("output") or "").strip()
                    break
            attrs = {
                "type": "Service", "port": port_id, "proto": port.get("protocol"),
                "service": service_name,
                "product": service.get("product", "unknown") if service is not None else "unknown",
                "version": service.get("version", "") if service is not None else "",
                "severity": 0.53 if service_name == "ftp" else 0.3,
                "asset_class": "dmz-web", "origin": "active"
            }
            if http_title:
                attrs["http_title"] = http_title
            records.append({
                "id": f"svc-{ip}-{port_id}",
                "attrs": attrs,
                "edges": [{"to": host_id, "type": "HOSTS_SERVICE", "conf": 1.0,
                           "provenance": "observed",
                           "justification": "Nmap reported this service on this host"}]
            })
            if service_name in {"http", "https"} or port_id in {"80", "443", "8080", "8443"}:
                http_ports.append((ip, port_id))
    return records, http_ports


def parse_gobuster(path, ip, port):
    """Convert Gobuster status lines into WebPath records."""
    records = []
    status_line = re.compile(r"^\s*(\S+)\s+\(Status:\s*(\d{3})\)")
    with open(path, encoding="utf-8") as gobuster_file:
        for line in gobuster_file:
            match = status_line.search(line)
            if not match:
                continue
            raw_path, status = match.groups()
            clean_path = raw_path.lstrip("/")
            records.append({
                "id": f"path-{ip}-{port}-{clean_path}",
                "attrs": {
                    "type": "WebPath", "path": f"/{clean_path}", "status": int(status),
                    "severity": 0.75 if ".git" in clean_path else 0.5, "origin": "active"
                },
                "edges": [{"to": f"svc-{ip}-{port}", "type": "SERVES_PATH", "conf": 1.0,
                           "provenance": "observed",
                           "justification": "Gobuster retrieved this path from this service"}]
            })
    return records


def parse_and_generate_jsonl(nmap_xml, gobuster_results, output_jsonl):
    """Parse Nmap and Gobuster outputs into AetherGraph JSONL records."""
    records, http_ports = parse_nmap_xml(nmap_xml)
    for ip, port in http_ports:
        gobuster_path = gobuster_results.get((ip, port))
        if gobuster_path and os.path.exists(gobuster_path):
            records.extend(parse_gobuster(gobuster_path, ip, port))
    with open(output_jsonl, "w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record) + "\n")
    print(f"[+] Active recon complete. Wrote {len(records)} nodes to {output_jsonl}")
    return output_jsonl


def main():
    parser = argparse.ArgumentParser(description="Run Dockerized active reconnaissance.")
    parser.add_argument("target", nargs="?", default="127.0.0.1")
    parser.add_argument(
        "--out-dir",
        default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "out"))
    )
    parser.add_argument("--ports", default="21,80", help="Nmap port list or range")
    args = parser.parse_args()
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    wordlist_path = create_wordlist(out_dir)
    nmap_xml = run_nmap(args.target, out_dir, args.ports)
    _, http_ports = parse_nmap_xml(nmap_xml)
    gobuster_results = {
        (host, port): run_gobuster(args.target, port, wordlist_path, out_dir)
        for host, port in http_ports
    }
    parse_and_generate_jsonl(
        nmap_xml, gobuster_results, os.path.join(out_dir, "real_active.jsonl")
    )


if __name__ == "__main__":
    main()
