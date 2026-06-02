#!/usr/bin/env python3
"""
CVE Emailer -- Environment Scanner
====================================

Run this on any machine you want to monitor. It fingerprints installed software,
running services, OS/kernel, and common runtimes, then prints a keyword list you
can paste directly into CVE Emailer (Settings -> Keywords, or the TUI Keywords screen).

Each keyword maps to one NVD search query. Severity overrides (e.g. ::CRITICAL) are
added automatically for high-value targets like databases and web servers.

Usage:
    python scan_environment.py            # print keyword list to stdout
    python scan_environment.py --json     # full JSON inventory
    python scan_environment.py --upload http://localhost:5000 --token YOUR_API_SECRET
    python scan_environment.py --out keywords.txt   # write to file

Upload with asset creation:
    python scan_environment.py --upload http://localhost:5000 --token SECRET \\
        --asset-name PROD-WEB-01 --environment production --owner web-team

No root required. Falls back gracefully when a command is unavailable.
Tested on: Windows 10/11, Ubuntu 20+, Debian 11+, RHEL/CentOS 8+, macOS 12+.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# -- Data model ----------------------------------------------------------------

@dataclass
class Software:
    name: str               # NVD-friendly product name  e.g. "nginx"
    version: Optional[str]  # e.g. "1.24.0"
    category: str           # os | runtime | web | db | container | network | tool
    severity_hint: str = "HIGH"
    source: str = ""
    cpe: str = ""           # CPE 2.3 string where known


# -- Helpers -------------------------------------------------------------------

def _run(*cmd: str, timeout: int = 6) -> str:
    """Run a command, return stdout. Returns '' on any error."""
    try:
        r = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            text=True,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _ver(raw: str) -> Optional[str]:
    """Extract the first version-like string from arbitrary output."""
    m = re.search(r'(\d+\.\d+[\.\d]*)', raw)
    return m.group(1) if m else None


def _jar_version(search_dirs: list[str], prefix: str) -> Optional[str]:
    """Find a version by scanning jar filenames matching a known prefix."""
    for d in search_dirs:
        try:
            for fn in os.listdir(d):
                if fn.startswith(prefix) and fn.endswith(".jar"):
                    ver = _ver(fn[len(prefix):])
                    if ver:
                        return ver
        except OSError:
            pass
    return None


def _kafka_version() -> Optional[str]:
    """Extract Kafka version from its jar files."""
    return _jar_version(
        ["/usr/share/kafka/libs", "/opt/kafka/libs", "/usr/local/kafka/libs",
         "/opt/kafka_*", "/usr/lib/kafka/libs"],
        "kafka_",
    )


def _zookeeper_version() -> Optional[str]:
    """Extract ZooKeeper version from its jar files."""
    return _jar_version(
        ["/usr/share/zookeeper", "/opt/zookeeper/lib", "/usr/local/zookeeper/lib",
         "/usr/lib/zookeeper"],
        "zookeeper-",
    )


# -- OS / kernel ---------------------------------------------------------------

def _collect_os() -> list[Software]:
    results = []
    system = platform.system()

    if system == "Windows":
        ver = platform.version()
        release = platform.release()
        results.append(Software(
            "Microsoft Windows", f"{release} {ver}", "os", "HIGH", "platform",
            "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
        ))
        raw = _run("wmic", "os", "get", "Caption", "/value")
        caption = re.search(r'Caption=(.+)', raw)
        if caption:
            cap = caption.group(1).strip()
            if "Server" in cap:
                results.append(Software(
                    "Windows Server", _ver(cap), "os", "CRITICAL", "wmic",
                    "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*",
                ))

    elif system == "Linux":
        kernel = platform.release()
        results.append(Software("Linux kernel", kernel, "os", "HIGH", "platform"))

        distro_id, distro_ver = "", ""
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                osrel = dict(line.strip().split("=", 1) for line in f if "=" in line)
            distro_id  = osrel.get("ID", "").strip('"').lower()
            distro_ver = osrel.get("VERSION_ID", "").strip('"')

        distro_map = {
            "ubuntu":   ("Ubuntu",                      "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"),
            "debian":   ("Debian",                      "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*"),
            "rhel":     ("Red Hat Enterprise Linux",    "cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*"),
            "centos":   ("CentOS",                      "cpe:2.3:o:centos:centos:*:*:*:*:*:*:*:*"),
            "fedora":   ("Fedora",                      "cpe:2.3:o:fedoraproject:fedora:*:*:*:*:*:*:*:*"),
            "sles":     ("SUSE Linux Enterprise",       ""),
            "opensuse": ("openSUSE",                    ""),
            "amzn":     ("Amazon Linux",                ""),
            "alpine":   ("Alpine Linux",                "cpe:2.3:o:alpinelinux:alpine_linux:*:*:*:*:*:*:*:*"),
        }
        if distro_id in distro_map:
            nvd_name, cpe = distro_map[distro_id]
            results.append(Software(nvd_name, distro_ver or None, "os", "HIGH", "/etc/os-release", cpe))
        elif distro_id:
            results.append(Software(distro_id, distro_ver or None, "os", "HIGH", "/etc/os-release"))

        # Proxmox VE -- detected via pveversion binary or /etc/pve/.version
        pve_ver: Optional[str] = None
        if _which("pveversion"):
            raw = _run("pveversion")
            # output: "pve-manager/8.2.4/..."
            m = re.search(r'pve-manager/(\S+)', raw)
            pve_ver = m.group(1).split("/")[0] if m else _ver(raw)
        if pve_ver is None and os.path.exists("/etc/pve/.version"):
            try:
                pve_ver = open("/etc/pve/.version").read().strip() or None
            except OSError:
                pass
        if pve_ver is not None or _which("pveversion") or os.path.isdir("/etc/pve"):
            results.append(Software(
                "Proxmox VE", pve_ver, "os", "CRITICAL", "pveversion",
                "cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*",
            ))

    elif system == "Darwin":
        ver = platform.mac_ver()[0]
        results.append(Software(
            "macOS", ver, "os", "HIGH", "platform",
            "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*",
        ))

    return results


# -- Runtimes ------------------------------------------------------------------

def _collect_runtimes() -> list[Software]:
    results = []

    checks = [
        # (binary, args, nvd_name, category, sev, cpe)
        ("python3", ["--version"],  "Python",   "runtime", "MEDIUM", "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
        ("python",  ["--version"],  "Python",   "runtime", "MEDIUM", "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
        ("python2", ["--version"],  "Python",   "runtime", "HIGH",   "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
        ("node",    ["--version"],  "Node.js",  "runtime", "HIGH",   "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
        ("java",    ["-version"],   "Java",     "runtime", "HIGH",   "cpe:2.3:a:oracle:java:*:*:*:*:*:*:*:*"),
        ("ruby",    ["--version"],  "Ruby",     "runtime", "MEDIUM", "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
        ("php",     ["--version"],  "PHP",      "runtime", "HIGH",   "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
        ("perl",    ["--version"],  "Perl",     "runtime", "MEDIUM", "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*"),
        ("go",      ["version"],    "Go",       "runtime", "MEDIUM", "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
        ("rustc",   ["--version"],  "Rust",     "runtime", "MEDIUM", "cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
        ("dotnet",  ["--version"],  ".NET",     "runtime", "HIGH",   "cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*"),
        ("R",       ["--version"],  "R Project","runtime", "MEDIUM", ""),
    ]

    seen: set[str] = set()
    for binary, args, nvd_name, cat, sev, cpe in checks:
        if not _which(binary):
            continue
        try:
            r = subprocess.run(
                [binary] + args,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=5, text=True,
            )
            raw = r.stdout.strip()
        except Exception:
            raw = ""
        ver = _ver(raw)
        key = nvd_name.lower()
        if key not in seen:
            seen.add(key)
            results.append(Software(nvd_name, ver, cat, sev, binary, cpe))

    return results


# -- Web servers ---------------------------------------------------------------

def _collect_web_servers() -> list[Software]:
    results = []

    if _which("nginx"):
        raw = _run("nginx", "-v") or _run("nginx", "-V")
        results.append(Software("nginx", _ver(raw), "web", "CRITICAL", "nginx -v",
                                "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"))

    for bin_ in ("apache2", "httpd"):
        if _which(bin_):
            raw = _run(bin_, "-v")
            results.append(Software("Apache HTTP Server", _ver(raw), "web", "CRITICAL", f"{bin_} -v",
                                    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"))
            break

    if _which("caddy"):
        raw = _run("caddy", "version")
        results.append(Software("Caddy", _ver(raw), "web", "HIGH", "caddy version",
                                "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"))

    if _which("lighttpd"):
        raw = _run("lighttpd", "-v")
        results.append(Software("lighttpd", _ver(raw), "web", "HIGH", "lighttpd -v",
                                "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*"))

    if _which("haproxy"):
        raw = _run("haproxy", "-v")
        results.append(Software("HAProxy", _ver(raw), "web", "HIGH", "haproxy -v",
                                "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"))

    if platform.system() == "Windows":
        raw = _run("where", "w3wp.exe")
        if raw:
            results.append(Software("IIS", None, "web", "CRITICAL", "w3wp.exe",
                                    "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*"))

    return results


# -- Databases -----------------------------------------------------------------

def _collect_databases() -> list[Software]:
    results = []

    if _which("mysql") or _which("mysqld"):
        bin_ = "mysqld" if _which("mysqld") else "mysql"
        raw = _run(bin_, "--version")
        results.append(Software("MySQL", _ver(raw), "db", "CRITICAL", f"{bin_} --version",
                                "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"))

    if _which("mariadbd") or _which("mariadb"):
        bin_ = "mariadbd" if _which("mariadbd") else "mariadb"
        raw = _run(bin_, "--version")
        results.append(Software("MariaDB", _ver(raw), "db", "CRITICAL", f"{bin_} --version",
                                "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"))

    if _which("pg_config") or _which("postgres"):
        bin_ = "pg_config" if _which("pg_config") else "postgres"
        raw = _run(bin_, "--version")
        results.append(Software("PostgreSQL", _ver(raw), "db", "CRITICAL", f"{bin_} --version",
                                "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"))

    if _which("mongod"):
        raw = _run("mongod", "--version")
        results.append(Software("MongoDB", _ver(raw), "db", "CRITICAL", "mongod --version",
                                "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"))

    if _which("redis-server") or _which("redis-cli"):
        bin_ = "redis-server" if _which("redis-server") else "redis-cli"
        raw = _run(bin_, "--version")
        results.append(Software("Redis", _ver(raw), "db", "HIGH", f"{bin_} --version",
                                "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"))

    if _which("elasticsearch"):
        raw = _run("elasticsearch", "--version")
        results.append(Software("Elasticsearch", _ver(raw), "db", "CRITICAL", "elasticsearch --version",
                                "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"))

    if _which("cqlsh") or _which("cassandra"):
        ver = None
        if _which("cqlsh"):
            raw = _run("cqlsh", "--version")
            ver = _ver(raw)
        if not ver:
            # Parse version from jar filename: apache-cassandra-4.1.3.jar
            for search_dir in ("/usr/share/cassandra/lib", "/opt/cassandra/lib", "/usr/local/cassandra/lib"):
                if os.path.isdir(search_dir):
                    for fn in os.listdir(search_dir):
                        if fn.startswith("apache-cassandra-") and fn.endswith(".jar"):
                            ver = _ver(fn)
                            break
                if ver:
                    break
        results.append(Software("Apache Cassandra", ver, "db", "HIGH", "cqlsh/cassandra",
                                "cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*"))

    if _which("influxd"):
        raw = _run("influxd", "version")
        results.append(Software("InfluxDB", _ver(raw), "db", "HIGH", "influxd version",
                                "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*"))

    if _which("rabbitmq-server") or _which("rabbitmqctl"):
        ver = None
        if _which("rabbitmqctl"):
            raw = _run("rabbitmqctl", "version")
            ver = _ver(raw)
        if not ver and _which("rabbitmq-server"):
            # rabbitmq-server prints version on stderr as part of startup; try rabbitmq-diagnostics
            if _which("rabbitmq-diagnostics"):
                raw = _run("rabbitmq-diagnostics", "server_version")
                ver = _ver(raw)
        if not ver:
            # Parse from lib dir: rabbitmq_server-3.12.6/ebin/rabbit.app
            for search_dir in ("/usr/lib/rabbitmq/lib", "/usr/local/lib/rabbitmq/lib",
                               "/opt/rabbitmq/lib"):
                if os.path.isdir(search_dir):
                    for entry in os.listdir(search_dir):
                        if entry.startswith("rabbitmq_server-"):
                            ver = _ver(entry)
                            break
                if ver:
                    break
        results.append(Software("RabbitMQ", ver, "db", "HIGH", "rabbitmqctl version",
                                "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"))

    if _which("kafka-server-start.sh") or _which("kafka-server-start"):
        ver = _kafka_version()
        results.append(Software("Apache Kafka", ver, "db", "HIGH", "kafka",
                                "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"))

    if _which("zookeeper-server-start.sh") or _which("zkServer.sh"):
        ver = _zookeeper_version()
        results.append(Software("Apache ZooKeeper", ver, "db", "HIGH", "zookeeper",
                                "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"))

    if _which("slapd"):
        raw = _run("slapd", "-V")
        results.append(Software("OpenLDAP", _ver(raw), "network", "CRITICAL", "slapd -V",
                                "cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*"))

    if _which("mosquitto"):
        raw = _run("mosquitto", "-v") or _run("mosquitto", "--help")
        # mosquitto -v prints "mosquitto version X.Y.Z" then starts listening; kill output
        ver = _ver(raw)
        results.append(Software("Mosquitto", ver, "network", "HIGH", "mosquitto -v",
                                "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"))

    if _which("nats-server"):
        raw = _run("nats-server", "-v")
        results.append(Software("NATS", _ver(raw), "network", "HIGH", "nats-server -v",
                                "cpe:2.3:a:nats:nats_server:*:*:*:*:*:*:*:*"))

    if _which("sqlite3"):
        raw = _run("sqlite3", "--version")
        results.append(Software("SQLite", _ver(raw), "db", "MEDIUM", "sqlite3 --version",
                                "cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*"))

    return results


# -- Containers & orchestration ------------------------------------------------

# Well-known Docker image names that are internal Docker infrastructure,
# not actual monitored products.
_DOCKER_INFRA_IMAGES = frozenset({
    "dockerdesktoplinuxengine", "docker-desktop", "k8s.gcr.io",
    "registry", "pause", "moby", "buildkit",
})

# Mapping from stripped image name -> (NVD product name, cpe)
_DOCKER_IMAGE_MAP = {
    "nginx":          ("nginx",          "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
    "httpd":          ("Apache HTTP Server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    "apache":         ("Apache HTTP Server", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    "mysql":          ("MySQL",          "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
    "mariadb":        ("MariaDB",        "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"),
    "postgres":       ("PostgreSQL",     "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
    "mongodb":        ("MongoDB",        "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
    "mongo":          ("MongoDB",        "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
    "redis":          ("Redis",          "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
    "elasticsearch":  ("Elasticsearch", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
    "rabbitmq":       ("RabbitMQ",       "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
    "kafka":          ("Apache Kafka",   "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"),
    "zookeeper":      ("Apache ZooKeeper", "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"),
    "node":           ("Node.js",        "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
    "python":         ("Python",         "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
    "php":            ("PHP",            "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
    "ruby":           ("Ruby",           "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
    "tomcat":         ("Apache Tomcat",  "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    "jenkins":        ("Jenkins",        "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"),
    "gitlab":         ("GitLab",         "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"),
    "grafana":        ("Grafana",        "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
    "prometheus":     ("Prometheus",     "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"),
    "kibana":         ("Kibana",         "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"),
    "vault":          ("HashiCorp Vault","cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
    "consul":         ("HashiCorp Consul","cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"),
    "traefik":        ("Traefik",        "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"),
    "haproxy":        ("HAProxy",        "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
    "memcached":      ("Memcached",      "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"),
    "activemq":       ("Apache ActiveMQ","cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"),
    "sonarqube":      ("SonarQube",      "cpe:2.3:a:sonarsource:sonarqube:*:*:*:*:*:*:*:*"),
    "keycloak":       ("Keycloak",       "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*"),
}


def _collect_containers() -> list[Software]:
    results = []

    if _which("docker"):
        raw = _run("docker", "--version")
        results.append(Software("Docker", _ver(raw), "container", "HIGH", "docker --version",
                                "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"))

        # Get running container IDs + image names
        ps_raw = _run("docker", "ps", "--format", "{{.ID}}\t{{.Image}}", timeout=8)
        seen_images: set[str] = set()
        for line in ps_raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", 1)
            cid = parts[0].strip()
            img = parts[1].strip() if len(parts) > 1 else ""
            name = img.split("/")[-1].split(":")[0].lower()
            if not name or name in _DOCKER_INFRA_IMAGES:
                continue
            if name in seen_images:
                continue
            seen_images.add(name)
            if name not in _DOCKER_IMAGE_MAP:
                continue
            nvd_name, cpe = _DOCKER_IMAGE_MAP[name]
            # Try OCI version label for real version number
            ver: Optional[str] = None
            if cid:
                label_raw = _run("docker", "inspect", "--format",
                                 "{{index .Config.Labels \"org.opencontainers.image.version\"}}",
                                 cid, timeout=5)
                ver = _ver(label_raw) if label_raw and label_raw != "<no value>" else None
            results.append(Software(nvd_name, ver, "container", "HIGH", f"docker ps ({img})", cpe))

    if _which("podman"):
        raw = _run("podman", "--version")
        results.append(Software("Podman", _ver(raw), "container", "HIGH", "podman --version",
                                "cpe:2.3:a:podman:podman:*:*:*:*:*:*:*:*"))

    if _which("kubectl"):
        raw = _run("kubectl", "version", "--client", "--short") or _run("kubectl", "version", "--client")
        results.append(Software("Kubernetes", _ver(raw), "container", "CRITICAL", "kubectl version",
                                "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"))

    if _which("helm"):
        raw = _run("helm", "version", "--short")
        results.append(Software("Helm", _ver(raw), "container", "HIGH", "helm version",
                                "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"))

    if _which("containerd"):
        raw = _run("containerd", "--version")
        results.append(Software("containerd", _ver(raw), "container", "HIGH", "containerd --version",
                                "cpe:2.3:a:docker:containerd:*:*:*:*:*:*:*:*"))

    return results


# -- Network & security tools --------------------------------------------------

def _collect_network() -> list[Software]:
    results = []

    if _which("openssl"):
        raw = _run("openssl", "version")
        results.append(Software("OpenSSL", _ver(raw), "network", "CRITICAL", "openssl version",
                                "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"))

    if _which("ssh") or _which("openssh"):
        try:
            r = subprocess.run(["ssh", "-V"], stderr=subprocess.STDOUT,
                               stdout=subprocess.PIPE, timeout=4, text=True)
            raw = r.stdout.strip()
        except Exception:
            raw = ""
        results.append(Software("OpenSSH", _ver(raw), "network", "HIGH", "ssh -V",
                                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"))

    if _which("curl"):
        raw = _run("curl", "--version")
        results.append(Software("curl", _ver(raw), "network", "MEDIUM", "curl --version",
                                "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"))

    if _which("git"):
        raw = _run("git", "--version")
        results.append(Software("Git", _ver(raw), "tool", "MEDIUM", "git --version",
                                "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*"))

    if _which("gpg2") or _which("gpg"):
        bin_ = "gpg2" if _which("gpg2") else "gpg"
        raw = _run(bin_, "--version")
        results.append(Software("GnuPG", _ver(raw), "network", "HIGH", f"{bin_} --version",
                                "cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*"))

    return results


# -- Package manager inventory (Linux) -----------------------------------------

def _collect_packages_linux() -> list[Software]:
    results = []

    interesting = {
        # pkg_name: (nvd_product_name, category, severity, cpe)
        "openssh-server":  ("OpenSSH",       "network", "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
        "openssh-client":  ("OpenSSH",       "network", "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
        "libssl3":         ("OpenSSL",        "network", "CRITICAL", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
        "openssl":         ("OpenSSL",        "network", "CRITICAL", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
        "libexpat1":       ("Expat",          "tool",    "HIGH",     "cpe:2.3:a:libexpat:expat:*:*:*:*:*:*:*:*"),
        "zlib1g":          ("zlib",           "tool",    "HIGH",     "cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"),
        "libxml2":         ("libxml2",        "tool",    "HIGH",     "cpe:2.3:a:xmlsoft:libxml2:*:*:*:*:*:*:*:*"),
        "libpng":          ("libpng",         "tool",    "HIGH",     "cpe:2.3:a:libpng:libpng:*:*:*:*:*:*:*:*"),
        "libgnutls":       ("GnuTLS",         "network", "HIGH",     "cpe:2.3:a:gnu:gnutls:*:*:*:*:*:*:*:*"),
        "sudo":            ("sudo",           "tool",    "CRITICAL", "cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*"),
        "bash":            ("GNU Bash",       "tool",    "HIGH",     "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"),
        "systemd":         ("systemd",        "tool",    "HIGH",     "cpe:2.3:a:freedesktop:systemd:*:*:*:*:*:*:*:*"),
        "bind9":           ("ISC BIND",       "network", "CRITICAL", "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"),
        "samba":           ("Samba",          "network", "CRITICAL", "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"),
        "vsftpd":          ("vsftpd",         "network", "HIGH",     "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*"),
        "postfix":         ("Postfix",        "network", "HIGH",     "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),
        "exim4":           ("Exim",           "network", "CRITICAL", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"),
        "dovecot":         ("Dovecot",        "network", "HIGH",     "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"),
        "squid":           ("Squid",          "network", "HIGH",     "cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"),
        "openvpn":         ("OpenVPN",        "network", "HIGH",     "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"),
        "ntp":             ("NTP",            "network", "HIGH",     "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*"),
        "fail2ban":        ("Fail2ban",       "tool",    "MEDIUM",   ""),
        "ansible":         ("Ansible",        "tool",    "HIGH",     "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"),
        "terraform":       ("Terraform",      "tool",    "HIGH",     "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"),
        "vault":           ("HashiCorp Vault","tool",    "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
    }

    if _which("dpkg-query"):
        for pkg, (nvd_name, cat, sev, cpe) in interesting.items():
            raw = _run("dpkg-query", "-W", "-f=${Version}", pkg)
            if raw and "not installed" not in raw and "no packages found" not in raw:
                results.append(Software(nvd_name, _ver(raw), cat, sev, f"dpkg {pkg}", cpe))
    elif _which("rpm"):
        for pkg, (nvd_name, cat, sev, cpe) in interesting.items():
            raw = _run("rpm", "-q", "--queryformat", "%{VERSION}", pkg)
            if raw and "not installed" not in raw:
                results.append(Software(nvd_name, _ver(raw), cat, sev, f"rpm {pkg}", cpe))
    elif _which("apk"):
        raw = _run("apk", "info", "-v")
        installed = {line.split("-")[0].lower() for line in raw.splitlines()}
        for pkg, (nvd_name, cat, sev, cpe) in interesting.items():
            if pkg.lower().rstrip("0123456789") in installed or pkg.lower() in installed:
                results.append(Software(nvd_name, None, cat, sev, f"apk {pkg}", cpe))

    return results


# -- Windows programs (winreg) -------------------------------------------------

def _collect_windows_programs() -> list[Software]:
    """Read installed programs from Windows registry via winreg (no subprocess)."""
    results = []
    if platform.system() != "Windows":
        return results

    try:
        import winreg
    except ImportError:
        return results

    interesting_patterns: dict[str, tuple[str, str, str, str]] = {
        "nginx":         ("nginx",               "web",       "CRITICAL", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
        "apache":        ("Apache HTTP Server",  "web",       "CRITICAL", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
        "tomcat":        ("Apache Tomcat",       "web",       "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
        "mysql":         ("MySQL",               "db",        "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
        "postgresql":    ("PostgreSQL",          "db",        "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
        "mariadb":       ("MariaDB",             "db",        "CRITICAL", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"),
        "mongodb":       ("MongoDB",             "db",        "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
        "redis":         ("Redis",               "db",        "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
        "elasticsearch": ("Elasticsearch",       "db",        "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
        "docker":        ("Docker",              "container", "HIGH",     "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
        "kubernetes":    ("Kubernetes",          "container", "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"),
        "openssl":       ("OpenSSL",             "network",   "CRITICAL", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
        "openssh":       ("OpenSSH",             "network",   "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
        "git":           ("Git",                 "tool",      "MEDIUM",   "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*"),
        "python":        ("Python",              "runtime",   "MEDIUM",   "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
        "node":          ("Node.js",             "runtime",   "HIGH",     "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
        "java":          ("Java",                "runtime",   "HIGH",     "cpe:2.3:a:oracle:java:*:*:*:*:*:*:*:*"),
        "openjdk":       ("OpenJDK",             "runtime",   "HIGH",     "cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*"),
        "php":           ("PHP",                 "runtime",   "HIGH",     "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
        "ruby":          ("Ruby",                "runtime",   "MEDIUM",   "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
        "perl":          ("Perl",                "runtime",   "MEDIUM",   "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*"),
        "7-zip":         ("7-Zip",               "tool",      "HIGH",     "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"),
        "7zip":          ("7-Zip",               "tool",      "HIGH",     "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"),
        "putty":         ("PuTTY",               "network",   "HIGH",     "cpe:2.3:a:putty:putty:*:*:*:*:*:*:*:*"),
        "winscp":        ("WinSCP",              "network",   "HIGH",     "cpe:2.3:a:winscp:winscp:*:*:*:*:*:*:*:*"),
        "filezilla":     ("FileZilla",           "network",   "HIGH",     "cpe:2.3:a:filezilla-project:filezilla:*:*:*:*:*:*:*:*"),
        "wireshark":     ("Wireshark",           "network",   "HIGH",     "cpe:2.3:a:wireshark:wireshark:*:*:*:*:*:*:*:*"),
        "nmap":          ("Nmap",                "network",   "MEDIUM",   "cpe:2.3:a:nmap:nmap:*:*:*:*:*:*:*:*"),
        "terraform":     ("Terraform",           "tool",      "HIGH",     "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"),
        "ansible":       ("Ansible",             "tool",      "HIGH",     "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"),
        "vault":         ("HashiCorp Vault",     "tool",      "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
        "vmware":        ("VMware",              "container", "CRITICAL", "cpe:2.3:a:vmware:vmware_tools:*:*:*:*:*:*:*:*"),
        "virtualbox":    ("VirtualBox",          "container", "HIGH",     "cpe:2.3:a:oracle:vm_virtualbox:*:*:*:*:*:*:*:*"),
        "splunk":        ("Splunk",              "tool",      "CRITICAL", "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*"),
        "grafana":       ("Grafana",             "tool",      "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
        "microsoft office": ("Microsoft Office","tool",      "CRITICAL", "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*"),
        "microsoft 365": ("Microsoft 365",      "tool",      "CRITICAL", "cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*"),
        "adobe acrobat": ("Adobe Acrobat",      "tool",      "CRITICAL", "cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*"),
        "google chrome": ("Google Chrome",      "tool",      "HIGH",     "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"),
        "mozilla firefox": ("Mozilla Firefox",  "tool",      "HIGH",     "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"),
        "zoom":          ("Zoom",               "tool",      "HIGH",     "cpe:2.3:a:zoom:zoom:*:*:*:*:*:*:*:*"),
    }

    uninstall_hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    seen: set[str] = set()
    for hive, path in uninstall_hives:
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, i)
                    i += 1
                except OSError:
                    break
                try:
                    subkey = winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ)
                    try:
                        display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                    except OSError:
                        winreg.CloseKey(subkey)
                        continue
                    try:
                        display_ver, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                    except OSError:
                        display_ver = ""
                    winreg.CloseKey(subkey)

                    dn_lower = str(display_name).lower()
                    for pattern, (nvd_name, cat, sev, cpe) in interesting_patterns.items():
                        if pattern in dn_lower and nvd_name not in seen:
                            seen.add(nvd_name)
                            ver = _ver(str(display_ver)) if display_ver else None
                            results.append(Software(nvd_name, ver, cat, sev, f"registry: {display_name}", cpe))
                            break
                except OSError:
                    continue
        finally:
            winreg.CloseKey(root)

    return results


# -- macOS apps ----------------------------------------------------------------

def _collect_macos_apps() -> list[Software]:
    results = []
    if platform.system() != "Darwin":
        return results

    if _which("brew"):
        raw = _run("brew", "list", "--versions", timeout=15)
        interesting = {
            "nginx":         ("nginx",              "web",       "CRITICAL", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
            "httpd":         ("Apache HTTP Server", "web",       "CRITICAL", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
            "mysql":         ("MySQL",              "db",        "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
            "postgresql":    ("PostgreSQL",         "db",        "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
            "mongodb":       ("MongoDB",            "db",        "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
            "redis":         ("Redis",              "db",        "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
            "elasticsearch": ("Elasticsearch",      "db",        "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
            "rabbitmq":      ("RabbitMQ",           "db",        "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
            "openssl":       ("OpenSSL",            "network",   "CRITICAL", "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
            "openssh":       ("OpenSSH",            "network",   "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
            "curl":          ("curl",               "network",   "MEDIUM",   "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"),
            "git":           ("Git",                "tool",      "MEDIUM",   "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*"),
            "python":        ("Python",             "runtime",   "MEDIUM",   "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
            "node":          ("Node.js",            "runtime",   "HIGH",     "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
            "openjdk":       ("OpenJDK",            "runtime",   "HIGH",     "cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*"),
            "php":           ("PHP",                "runtime",   "HIGH",     "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
            "ruby":          ("Ruby",               "runtime",   "MEDIUM",   "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
            "go":            ("Go",                 "runtime",   "MEDIUM",   "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
            "terraform":     ("Terraform",          "tool",      "HIGH",     "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"),
            "vault":         ("HashiCorp Vault",    "tool",      "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
            "docker":        ("Docker",             "container", "HIGH",     "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
            "kubectl":       ("Kubernetes",         "container", "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"),
            "helm":          ("Helm",               "container", "HIGH",     "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"),
            "podman":        ("Podman",             "container", "HIGH",     "cpe:2.3:a:podman:podman:*:*:*:*:*:*:*:*"),
            "haproxy":       ("HAProxy",            "web",       "HIGH",     "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
            "squid":         ("Squid",              "network",   "HIGH",     "cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"),
            "openvpn":       ("OpenVPN",            "network",   "HIGH",     "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"),
        }
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            pkg = parts[0].lower()
            ver = parts[1] if len(parts) > 1 else None
            if pkg in interesting:
                nvd_name, cat, sev, cpe = interesting[pkg]
                results.append(Software(nvd_name, ver, cat, sev, f"brew {pkg}", cpe))

    return results


# -- Listening ports -----------------------------------------------------------

PORT_MAP: dict[int, tuple[str, str, str, str]] = {
    22:    ("OpenSSH",             "network",   "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
    # 80/443/25 etc. are intentionally omitted — generic HTTP/SMTP are not useful NVD queries
    3306:  ("MySQL",               "db",        "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
    5432:  ("PostgreSQL",          "db",        "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
    6379:  ("Redis",               "db",        "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
    8080:  ("Apache Tomcat",       "web",       "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    8009:  ("Apache Tomcat",       "web",       "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    27017: ("MongoDB",             "db",        "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
    9200:  ("Elasticsearch",       "db",        "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
    9300:  ("Elasticsearch",       "db",        "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
    5672:  ("RabbitMQ",            "db",        "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
    15672: ("RabbitMQ",            "db",        "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
    2181:  ("Apache ZooKeeper",    "db",        "HIGH",     "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"),
    9092:  ("Apache Kafka",        "db",        "HIGH",     "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"),
    8500:  ("HashiCorp Consul",    "tool",      "HIGH",     "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"),
    8200:  ("HashiCorp Vault",     "tool",      "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
    2375:  ("Docker",              "container", "CRITICAL", "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
    2376:  ("Docker",              "container", "CRITICAL", "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
    6443:  ("Kubernetes",          "container", "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"),
    10250: ("Kubernetes",          "container", "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"),
    389:   ("LDAP",                "network",   "CRITICAL", ""),
    636:   ("LDAP",                "network",   "CRITICAL", ""),
    3389:  ("RDP",                 "network",   "CRITICAL", "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"),
    5985:  ("WinRM",               "network",   "HIGH",     ""),
    5986:  ("WinRM",               "network",   "HIGH",     ""),
    1433:  ("Microsoft SQL Server","db",        "CRITICAL", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"),
    1521:  ("Oracle Database",     "db",        "CRITICAL", "cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*"),
    5601:  ("Kibana",              "db",        "HIGH",     "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"),
    9090:  ("Prometheus",          "tool",      "MEDIUM",   "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"),
    3000:  ("Grafana",             "tool",      "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
    8161:  ("Apache ActiveMQ",     "db",        "CRITICAL", "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"),
    61616: ("Apache ActiveMQ",     "db",        "CRITICAL", "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"),
    11211: ("Memcached",           "db",        "HIGH",     "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"),
    4369:  ("RabbitMQ",            "db",        "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
    8888:  ("Jupyter Notebook",    "tool",      "HIGH",     "cpe:2.3:a:jupyter:notebook:*:*:*:*:*:*:*:*"),
    50070: ("Apache Hadoop",       "db",        "HIGH",     "cpe:2.3:a:apache:hadoop:*:*:*:*:*:*:*:*"),
    8088:  ("Apache Hadoop",       "db",        "HIGH",     "cpe:2.3:a:apache:hadoop:*:*:*:*:*:*:*:*"),
    2049:  ("NFS",                 "network",   "HIGH",     ""),
}


def _collect_listening_services() -> list[Software]:
    """Map well-known listening ports to software names."""
    listening_ports: set[int] = set()

    raw = _run("ss", "-tlnp")
    if raw:
        for line in raw.splitlines():
            m = re.search(r':(\d+)\s', line)
            if m and ("LISTEN" in line or "0.0.0.0" in line or ":::" in line):
                listening_ports.add(int(m.group(1)))
    else:
        raw = _run("netstat", "-tlnp") or _run("netstat", "-an")
        for line in raw.splitlines():
            m = re.search(r'[:\.](\d+)\s', line)
            if m and "LISTEN" in line:
                listening_ports.add(int(m.group(1)))

    if platform.system() == "Windows":
        raw = _run("netstat", "-ano")
        for line in raw.splitlines():
            if "LISTENING" in line:
                m = re.search(r':(\d+)\s', line)
                if m:
                    listening_ports.add(int(m.group(1)))

    results = []
    seen_names: set[str] = set()
    for port in sorted(listening_ports):
        if port in PORT_MAP:
            nvd_name, cat, sev, cpe = PORT_MAP[port]
            if nvd_name not in seen_names:
                seen_names.add(nvd_name)
                results.append(Software(nvd_name, None, cat, sev, f"port {port}", cpe))

    return results


# -- pip package inventory -----------------------------------------------------

# High-value pip packages that have real CVE histories in NVD
_PIP_INTERESTING: dict[str, tuple[str, str, str, str]] = {
    "cryptography":     ("cryptography",        "tool",    "HIGH",     "cpe:2.3:a:cryptography.io:cryptography:*:*:*:*:*:*:*:*"),
    "paramiko":         ("paramiko",            "network", "HIGH",     "cpe:2.3:a:paramiko:paramiko:*:*:*:*:*:*:*:*"),
    "requests":         ("Python Requests",     "tool",    "MEDIUM",   "cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*"),
    "urllib3":          ("urllib3",             "tool",    "HIGH",     "cpe:2.3:a:urllib3_project:urllib3:*:*:*:*:*:*:*:*"),
    "Pillow":           ("Pillow",              "tool",    "HIGH",     "cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*"),
    "Jinja2":           ("Jinja2",              "tool",    "HIGH",     "cpe:2.3:a:palletsprojects:jinja:*:*:*:*:*:*:*:*"),
    "Django":           ("Django",              "tool",    "HIGH",     "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"),
    "Flask":            ("Flask",               "tool",    "HIGH",     "cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*"),
    "fastapi":          ("FastAPI",             "tool",    "HIGH",     "cpe:2.3:a:fastapi_project:fastapi:*:*:*:*:*:*:*:*"),
    "aiohttp":          ("aiohttp",             "tool",    "HIGH",     "cpe:2.3:a:aiohttp_project:aiohttp:*:*:*:*:*:*:*:*"),
    "PyYAML":           ("PyYAML",              "tool",    "HIGH",     "cpe:2.3:a:pyyaml:pyyaml:*:*:*:*:*:*:*:*"),
    "lxml":             ("lxml",                "tool",    "HIGH",     "cpe:2.3:a:lxml:lxml:*:*:*:*:*:*:*:*"),
    "sqlalchemy":       ("SQLAlchemy",          "tool",    "MEDIUM",   "cpe:2.3:a:sqlalchemy:sqlalchemy:*:*:*:*:*:*:*:*"),
    "boto3":            ("boto3",               "tool",    "MEDIUM",   ""),
    "ansible":          ("Ansible",             "tool",    "HIGH",     "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"),
    "Werkzeug":         ("Werkzeug",            "tool",    "HIGH",     "cpe:2.3:a:palletsprojects:werkzeug:*:*:*:*:*:*:*:*"),
    "celery":           ("Celery",              "tool",    "HIGH",     "cpe:2.3:a:celeryproject:celery:*:*:*:*:*:*:*:*"),
    "gunicorn":         ("Gunicorn",            "web",     "HIGH",     "cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*"),
    "uvicorn":          ("uvicorn",             "web",     "HIGH",     ""),
    "httpx":            ("httpx",               "tool",    "MEDIUM",   ""),
    "pyOpenSSL":        ("pyOpenSSL",           "network", "HIGH",     "cpe:2.3:a:pyopenssl_project:pyopenssl:*:*:*:*:*:*:*:*"),
    "pycryptodome":     ("PyCryptodome",        "tool",    "HIGH",     "cpe:2.3:a:pycryptodome:pycryptodome:*:*:*:*:*:*:*:*"),
    "jwt":              ("PyJWT",               "tool",    "HIGH",     "cpe:2.3:a:pyjwt_project:pyjwt:*:*:*:*:*:*:*:*"),
    "PyJWT":            ("PyJWT",               "tool",    "HIGH",     "cpe:2.3:a:pyjwt_project:pyjwt:*:*:*:*:*:*:*:*"),
    "redis":            ("redis-py",            "tool",    "MEDIUM",   ""),
    "numpy":            ("NumPy",               "tool",    "MEDIUM",   "cpe:2.3:a:numpy:numpy:*:*:*:*:*:*:*:*"),
    "scipy":            ("SciPy",               "tool",    "MEDIUM",   "cpe:2.3:a:scipy:scipy:*:*:*:*:*:*:*:*"),
    "tensorflow":       ("TensorFlow",          "tool",    "HIGH",     "cpe:2.3:a:google:tensorflow:*:*:*:*:*:*:*:*"),
    "torch":            ("PyTorch",             "tool",    "HIGH",     "cpe:2.3:a:pytorch:pytorch:*:*:*:*:*:*:*:*"),
    "scrapy":           ("Scrapy",              "tool",    "HIGH",     "cpe:2.3:a:scrapy:scrapy:*:*:*:*:*:*:*:*"),
}


def _collect_pip_packages() -> list[Software]:
    """Enumerate installed pip packages and return high-value ones."""
    results = []
    for python_bin in ("pip3", "pip", "python3", "python"):
        if not _which(python_bin):
            continue
        if python_bin.startswith("pip"):
            raw = _run(python_bin, "list", "--format=json", timeout=15)
        else:
            raw = _run(python_bin, "-m", "pip", "list", "--format=json", timeout=15)
        if not raw or not raw.strip().startswith("["):
            continue
        try:
            pkgs = json.loads(raw)
        except Exception:
            continue
        installed = {p["name"]: p.get("version", "") for p in pkgs if isinstance(p, dict)}
        seen: set[str] = set()
        for pkg_name, ver_str in installed.items():
            # Match case-insensitively
            match_key = next((k for k in _PIP_INTERESTING if k.lower() == pkg_name.lower()), None)
            if match_key and match_key not in seen:
                seen.add(match_key)
                nvd_name, cat, sev, cpe = _PIP_INTERESTING[match_key]
                results.append(Software(nvd_name, _ver(ver_str), cat, sev, f"pip {pkg_name}", cpe))
        break  # one successful pip run is enough
    return results


# -- systemctl service detection (Linux) ---------------------------------------

# Map systemd service unit names -> (NVD product name, category, severity, CPE)
_SYSTEMD_SERVICE_MAP: dict[str, tuple[str, str, str, str]] = {
    "nginx":            ("nginx",               "web",     "CRITICAL", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
    "nginx.service":    ("nginx",               "web",     "CRITICAL", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
    "apache2":          ("Apache HTTP Server",  "web",     "CRITICAL", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    "httpd":            ("Apache HTTP Server",  "web",     "CRITICAL", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    "mysql":            ("MySQL",               "db",      "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
    "mysqld":           ("MySQL",               "db",      "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"),
    "mariadb":          ("MariaDB",             "db",      "CRITICAL", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"),
    "postgresql":       ("PostgreSQL",          "db",      "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
    "mongod":           ("MongoDB",             "db",      "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"),
    "redis":            ("Redis",               "db",      "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
    "redis-server":     ("Redis",               "db",      "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"),
    "elasticsearch":    ("Elasticsearch",       "db",      "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"),
    "rabbitmq-server":  ("RabbitMQ",            "db",      "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"),
    "kafka":            ("Apache Kafka",        "db",      "HIGH",     "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"),
    "zookeeper":        ("Apache ZooKeeper",    "db",      "HIGH",     "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"),
    "docker":           ("Docker",              "container","HIGH",    "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
    "containerd":       ("containerd",          "container","HIGH",    "cpe:2.3:a:docker:containerd:*:*:*:*:*:*:*:*"),
    "sshd":             ("OpenSSH",             "network", "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
    "named":            ("ISC BIND",            "network", "CRITICAL", "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"),
    "bind9":            ("ISC BIND",            "network", "CRITICAL", "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"),
    "postfix":          ("Postfix",             "network", "HIGH",     "cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"),
    "exim4":            ("Exim",                "network", "CRITICAL", "cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"),
    "dovecot":          ("Dovecot",             "network", "HIGH",     "cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"),
    "squid":            ("Squid",               "network", "HIGH",     "cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"),
    "openvpn":          ("OpenVPN",             "network", "HIGH",     "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"),
    "vault":            ("HashiCorp Vault",     "tool",    "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
    "consul":           ("HashiCorp Consul",    "tool",    "HIGH",     "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"),
    "traefik":          ("Traefik",             "web",     "HIGH",     "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"),
    "mosquitto":        ("Mosquitto",           "network", "HIGH",     "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"),
    "nats-server":      ("NATS",                "network", "HIGH",     "cpe:2.3:a:nats:nats_server:*:*:*:*:*:*:*:*"),
    "slapd":            ("OpenLDAP",            "network", "CRITICAL", "cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*"),
    "influxd":          ("InfluxDB",            "db",      "HIGH",     "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*"),
    "grafana-server":   ("Grafana",             "tool",    "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
    "prometheus":       ("Prometheus",          "tool",    "MEDIUM",   "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"),
    "kibana":           ("Kibana",              "db",      "HIGH",     "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"),
    "jenkins":          ("Jenkins",             "tool",    "CRITICAL", "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"),
    "gitlab-runsvdir":  ("GitLab",              "tool",    "CRITICAL", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"),
    "tomcat":           ("Apache Tomcat",       "web",     "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    "tomcat9":          ("Apache Tomcat",       "web",     "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    "tomcat10":         ("Apache Tomcat",       "web",     "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"),
    "cassandra":        ("Apache Cassandra",    "db",      "HIGH",     "cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*"),
    "memcached":        ("Memcached",           "db",      "HIGH",     "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"),
    "haproxy":          ("HAProxy",             "web",     "HIGH",     "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
    "samba":            ("Samba",               "network", "CRITICAL", "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"),
    "smbd":             ("Samba",               "network", "CRITICAL", "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"),
    "vsftpd":           ("vsftpd",              "network", "HIGH",     "cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*"),
    "nfs-server":       ("NFS",                 "network", "HIGH",     ""),
    "rpcbind":          ("rpcbind",             "network", "HIGH",     ""),
    "cups":             ("CUPS",                "network", "HIGH",     "cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*"),
    "ntpd":             ("NTP",                 "network", "HIGH",     "cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*"),
    "chronyd":          ("Chrony",              "network", "HIGH",     "cpe:2.3:a:tuxfamily:chrony:*:*:*:*:*:*:*:*"),
    "pveproxy":         ("Proxmox VE",          "os",      "CRITICAL", "cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"),
    "pvedaemon":        ("Proxmox VE",          "os",      "CRITICAL", "cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"),
    "pve-cluster":      ("Proxmox VE",          "os",      "CRITICAL", "cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"),
    "corosync":         ("Corosync",            "network", "HIGH",     "cpe:2.3:a:corosync:corosync:*:*:*:*:*:*:*:*"),
}


def _collect_systemd_services() -> list[Software]:
    """Detect running services via systemctl on Linux."""
    if platform.system() != "Linux":
        return []
    if not _which("systemctl"):
        return []
    raw = _run("systemctl", "list-units", "--type=service", "--state=running",
               "--no-legend", "--no-pager", timeout=10)
    if not raw:
        return []
    results = []
    seen: set[str] = set()
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        unit = parts[0].rstrip(".service")
        # Try exact match first, then with .service suffix
        entry = _SYSTEMD_SERVICE_MAP.get(unit) or _SYSTEMD_SERVICE_MAP.get(unit + ".service")
        if entry:
            nvd_name, cat, sev, cpe = entry
            if nvd_name not in seen:
                seen.add(nvd_name)
                results.append(Software(nvd_name, None, cat, sev, f"systemctl ({unit})", cpe))
    return results


# -- Standalone tool binaries (commonly installed outside package managers) ----

def _collect_standalone_tools() -> list[Software]:
    """Detect tools typically installed as single binaries to /usr/local/bin."""
    results = []

    if _which("ansible"):
        raw = _run("ansible", "--version")
        results.append(Software("Ansible", _ver(raw), "tool", "HIGH", "ansible --version",
                                "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"))

    if _which("terraform"):
        raw = _run("terraform", "version")
        results.append(Software("Terraform", _ver(raw), "tool", "HIGH", "terraform version",
                                "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"))

    if _which("vault"):
        raw = _run("vault", "version")
        results.append(Software("HashiCorp Vault", _ver(raw), "tool", "CRITICAL", "vault version",
                                "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"))

    if _which("consul"):
        raw = _run("consul", "version")
        results.append(Software("HashiCorp Consul", _ver(raw), "tool", "HIGH", "consul version",
                                "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"))

    if _which("nomad"):
        raw = _run("nomad", "version")
        results.append(Software("HashiCorp Nomad", _ver(raw), "tool", "HIGH", "nomad version",
                                "cpe:2.3:a:hashicorp:nomad:*:*:*:*:*:*:*:*"))

    if _which("packer"):
        raw = _run("packer", "version")
        results.append(Software("HashiCorp Packer", _ver(raw), "tool", "HIGH", "packer version",
                                "cpe:2.3:a:hashicorp:packer:*:*:*:*:*:*:*:*"))

    if _which("traefik"):
        raw = _run("traefik", "version")
        results.append(Software("Traefik", _ver(raw), "web", "HIGH", "traefik version",
                                "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"))

    if _which("grafana") or _which("grafana-server"):
        bin_ = "grafana" if _which("grafana") else "grafana-server"
        raw = _run(bin_, "-v") or _run(bin_, "--version")
        results.append(Software("Grafana", _ver(raw), "tool", "HIGH", f"{bin_} -v",
                                "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"))

    if _which("prometheus"):
        raw = _run("prometheus", "--version")
        results.append(Software("Prometheus", _ver(raw), "tool", "MEDIUM", "prometheus --version",
                                "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"))

    if _which("etcd"):
        raw = _run("etcd", "--version")
        results.append(Software("etcd", _ver(raw), "tool", "HIGH", "etcd --version",
                                "cpe:2.3:a:etcd:etcd:*:*:*:*:*:*:*:*"))

    return results


# -- snap packages (Linux) -----------------------------------------------------

_SNAP_INTERESTING: dict[str, tuple[str, str, str, str]] = {
    "lxd":        ("LXD",            "container", "HIGH",     "cpe:2.3:a:linuxcontainers:lxd:*:*:*:*:*:*:*:*"),
    "microk8s":   ("MicroK8s",       "container", "CRITICAL", "cpe:2.3:a:canonical:microk8s:*:*:*:*:*:*:*:*"),
    "multipass":  ("Multipass",      "container", "HIGH",     ""),
    "kubectl":    ("Kubernetes",     "container", "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"),
    "helm":       ("Helm",           "container", "HIGH",     "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"),
    "docker":     ("Docker",         "container", "HIGH",     "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"),
    "vault":      ("HashiCorp Vault","tool",      "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"),
    "terraform":  ("Terraform",      "tool",      "HIGH",     "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"),
    "grafana":    ("Grafana",        "tool",      "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"),
}


def _collect_snap_packages() -> list[Software]:
    if platform.system() != "Linux" or not _which("snap"):
        return []
    raw = _run("snap", "list", "--unicode=never", timeout=12)
    if not raw:
        return []
    results = []
    seen: set[str] = set()
    for line in raw.splitlines()[1:]:  # skip header
        parts = line.split()
        if not parts:
            continue
        snap_name = parts[0].lower()
        ver_str = parts[1] if len(parts) > 1 else ""
        if snap_name in _SNAP_INTERESTING and snap_name not in seen:
            seen.add(snap_name)
            nvd_name, cat, sev, cpe = _SNAP_INTERESTING[snap_name]
            results.append(Software(nvd_name, _ver(ver_str), cat, sev, f"snap {snap_name}", cpe))
    return results


# -- Dedup & format ------------------------------------------------------------

def _dedup(items: list[Software]) -> list[Software]:
    """Keep the most informative entry per product name.
    Prefers entries with a version; among those, prefers one with a CPE.
    """
    best: dict[str, Software] = {}
    for item in items:
        key = item.name.lower()
        existing = best.get(key)
        if existing is None:
            best[key] = item
        elif item.version and not existing.version:
            best[key] = item
        elif item.version and existing.version:
            # Both have versions — prefer the one with a CPE
            if item.cpe and not existing.cpe:
                best[key] = item
        elif item.cpe and not existing.cpe:
            best[key] = item
    return list(best.values())


_GENERIC_NAMES = frozenset({
    "http server", "https server", "smtp server", "dns server",
    "ftp server", "telnet",
})


def _to_keywords(items: list[Software]) -> list[str]:
    """Convert discovered software to CVE Emailer keyword strings."""
    cat_sev = {
        "os":        "HIGH",
        "runtime":   "MEDIUM",
        "web":       "CRITICAL",
        "db":        "CRITICAL",
        "container": "HIGH",
        "network":   "HIGH",
        "tool":      "HIGH",
    }
    lines = []
    for item in sorted(items, key=lambda x: x.name.lower()):
        # Skip generic port-only names -- they produce unactionable NVD noise
        if item.name.lower() in _GENERIC_NAMES:
            continue
        sev = item.severity_hint or cat_sev.get(item.category, "HIGH")
        kw = item.name
        if item.version:
            # NVD searches work better without patch version noise
            short_ver = ".".join(item.version.split(".")[:2])
            kw = f"{item.name} {short_ver}"
        lines.append(f"{kw}::{sev}")
    return lines


def _build_os_cpe(items: list[Software]) -> str:
    """Return the CPE of the primary OS entry, used as the asset CPE."""
    for item in items:
        if item.category == "os" and item.cpe:
            return item.cpe
    for item in items:
        if item.cpe:
            return item.cpe
    return ""


# -- Main ----------------------------------------------------------------------

def collect_all() -> list[Software]:
    collectors = [
        _collect_os,
        _collect_runtimes,
        _collect_web_servers,
        _collect_databases,
        _collect_containers,
        _collect_network,
        _collect_listening_services,
        _collect_standalone_tools,
        _collect_pip_packages,
    ]
    if platform.system() == "Linux":
        collectors.append(_collect_packages_linux)
        collectors.append(_collect_systemd_services)
        collectors.append(_collect_snap_packages)
    elif platform.system() == "Windows":
        collectors.append(_collect_windows_programs)
    elif platform.system() == "Darwin":
        collectors.append(_collect_macos_apps)

    all_items: list[Software] = []
    # Run collectors in parallel -- each one is I/O-bound (subprocesses / registry reads)
    with ThreadPoolExecutor(max_workers=len(collectors)) as pool:
        futures = {pool.submit(fn): fn.__name__ for fn in collectors}
        for future in as_completed(futures):
            try:
                all_items.extend(future.result())
            except Exception:
                pass

    return _dedup(all_items)


def _upload(items: list[Software], base: str, token: str, append: bool,
            asset_name: str, environment: str, owner: str, asset_tags: str) -> int:
    """Upload keywords and create/update asset record. Returns 0 on success."""
    import urllib.request
    import urllib.error

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _api(path: str, payload: dict | None = None) -> dict:
        url = f"{base}{path}"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if payload is not None:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        else:
            req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    # -- 1. Create / update asset record ---------------------------------------
    asset_cpe = _build_os_cpe(items)
    # Merge user-provided tags with discovered categories
    discovered_cats = ",".join(sorted({i.category for i in items}))
    tags = ",".join(filter(None, [discovered_cats, asset_tags]))

    print(f"Saving asset '{asset_name}'...", file=sys.stderr)
    try:
        # Check if asset already exists by name
        existing_assets = _api("/api/assets")
        asset_id = None
        if isinstance(existing_assets, list):
            for a in existing_assets:
                if a.get("name") == asset_name:
                    asset_id = a.get("id")
                    print(f"  Found existing asset id={asset_id}", file=sys.stderr)
                    break

        asset_payload: dict = {
            "name":            asset_name,
            "cpe":             asset_cpe,
            "tags":            tags,
            "owner":           owner,
            "environment":     environment,
            "last_scanned_at": now,
            "scan_source":     "scan_environment.py",
        }
        if asset_id is not None:
            asset_payload["id"] = asset_id

        result = _api("/api/assets", asset_payload)
        if result.get("ok"):
            print(f"  Asset saved (id={result.get('id')})", file=sys.stderr)
        else:
            print(f"  Asset save returned: {result}", file=sys.stderr)
    except Exception as exc:
        print(f"  Asset save error: {exc}", file=sys.stderr)

    # -- 2. Build keyword payload (append or replace) --------------------------
    new_kws = _to_keywords(items)

    if append:
        print("Fetching existing keywords for merge...", file=sys.stderr)
        try:
            cfg = _api("/api/config")
            existing_raw = cfg.get("DEFAULT__keywords", {}).get("value", "")
            existing_kws = [k.strip() for k in existing_raw.splitlines() if k.strip()]

            # Update-in-place: scanner is authoritative for products it finds
            existing_map: dict[str, str] = {}
            for kw in existing_kws:
                kname = kw.split("::")[0].strip().lower()
                existing_map[kname] = kw
            for kw in new_kws:
                kname = kw.split("::")[0].strip().lower()
                existing_map[kname] = kw
            merged = list(existing_map.values())
            net_new = sum(1 for kw in new_kws if kw.split("::")[0].strip().lower()
                          not in {e.split("::")[0].strip().lower() for e in existing_kws})
            print(f"  {len(existing_kws)} existing + {net_new} net new keywords", file=sys.stderr)
            keywords_payload = "\n".join(merged)
        except Exception as exc:
            print(f"  Could not fetch existing keywords: {exc}", file=sys.stderr)
            keywords_payload = "\n".join(new_kws)
    else:
        keywords_payload = "\n".join(new_kws)

    # -- 3. Upload keywords ----------------------------------------------------
    print(f"Uploading {keywords_payload.count(chr(10)) + 1} keywords...", file=sys.stderr)
    try:
        result = _api("/api/config", {"DEFAULT__keywords": keywords_payload})
        if result.get("ok"):
            print(f"Done. Uploaded to {base}", file=sys.stderr)
        else:
            print(f"Keywords upload returned: {result}", file=sys.stderr)
            return 1
    except Exception as exc:
        print(f"Keywords upload error: {exc}", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan this machine and output CVE Emailer keywords.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--json",         action="store_true", help="Full JSON inventory instead of keyword list")
    parser.add_argument("--out",          metavar="FILE",      help="Write output to file instead of stdout")
    parser.add_argument("--upload",       metavar="URL",       help="Upload to a running CVE Emailer dashboard (e.g. http://localhost:5000)")
    parser.add_argument("--token",        metavar="SECRET",    help="API_SECRET bearer token for --upload")
    parser.add_argument("--append",       action="store_true", help="With --upload: merge into existing keywords instead of replacing")
    parser.add_argument("--asset-name",   metavar="NAME",      default=platform.node(),
                        help="Asset name in the inventory (default: hostname)")
    parser.add_argument("--environment",  metavar="ENV",       default="production",
                        choices=["production", "staging", "development", "dmz"],
                        help="Asset environment (default: production)")
    parser.add_argument("--owner",        metavar="TEAM",      default="",
                        help="Owner/team name for the asset record")
    parser.add_argument("--asset-tags",   metavar="TAGS",      default="",
                        help="Extra comma-separated tags to attach to the asset")
    args = parser.parse_args()

    items = collect_all()

    if args.json:
        output = json.dumps([asdict(i) for i in items], indent=2)
    else:
        keywords = _to_keywords(items)
        output = "\n".join(keywords)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output + "\n")
        print(f"Wrote {len(items)} entries to {args.out}", file=sys.stderr)
    else:
        print(output)

    if args.upload:
        return _upload(
            items,
            base=args.upload.rstrip("/"),
            token=args.token or "",
            append=args.append,
            asset_name=args.asset_name,
            environment=args.environment,
            owner=args.owner,
            asset_tags=args.asset_tags or "",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
