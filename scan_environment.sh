#!/usr/bin/env bash
# CVE Emailer -- Linux/macOS Environment Scanner
# ================================================
#
# Fingerprints installed software, running services, OS/kernel, and common
# runtimes, then either prints a CVE Emailer keyword list or uploads it
# directly to a running dashboard -- creating/updating an Asset record so
# CVEs are automatically correlated to this host.
#
# Usage:
#   ./scan_environment.sh                               # print keyword list
#   ./scan_environment.sh --json                        # full JSON inventory
#   ./scan_environment.sh --out keywords.txt            # write to file
#   ./scan_environment.sh --upload http://host:5000 \
#       --token SECRET                                  # upload to dashboard
#   ./scan_environment.sh --upload http://host:5000 \
#       --token SECRET --asset-name PROD-WEB-01 \
#       --environment production --owner web-team \
#       --append                                        # merge with existing
#
# No root required. Falls back gracefully when a command is unavailable.
# Tested on: Ubuntu 20+, Debian 11+, RHEL/CentOS 8+, Fedora, Alpine, macOS 12+.

set -euo pipefail

# ---------------------------------------------------------------------------
# CLI args
# ---------------------------------------------------------------------------
UPLOAD_URL=""
TOKEN=""
OUT_FILE=""
APPEND=0
DRY_RUN=0
JSON_OUT=0
ASSET_NAME=""
ENVIRONMENT="production"
OWNER=""
ASSET_TAGS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upload)        UPLOAD_URL="$2";    shift 2 ;;
        --token)         TOKEN="$2";         shift 2 ;;
        --out)           OUT_FILE="$2";      shift 2 ;;
        --asset-name)    ASSET_NAME="$2";    shift 2 ;;
        --environment)   ENVIRONMENT="$2";   shift 2 ;;
        --owner)         OWNER="$2";         shift 2 ;;
        --asset-tags)    ASSET_TAGS="$2";    shift 2 ;;
        --append)        APPEND=1;           shift ;;
        --dry-run)       DRY_RUN=1;          shift ;;
        --json)          JSON_OUT=1;         shift ;;
        -h|--help)
            sed -n '3,25p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

ASSET_NAME="${ASSET_NAME:-$(hostname)}"

# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------
# Each discovered item is a tab-separated record:
#   name\tversion\tcategory\tseverity\tcpe\tsource
declare -a ITEMS=()

_add() {
    # _add "name" "version" "category" "severity" "cpe" "source"
    ITEMS+=("$1	$2	$3	$4	$5	$6")
}

_cmd() {
    command -v "$1" &>/dev/null
}

_ver() {
    # Extract first version-like string from input
    echo "$1" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -1
}

_run() {
    # Run a command with a timeout; return stdout+stderr. Never fails.
    local cmd="$1"; shift
    if _cmd timeout; then
        timeout 6 "$cmd" "$@" 2>&1 || true
    else
        "$cmd" "$@" 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# OS / kernel
# ---------------------------------------------------------------------------
collect_os() {
    local kernel
    kernel=$(uname -r)
    _add "Linux kernel" "$kernel" "os" "HIGH" "" "uname -r"

    if [[ -f /etc/os-release ]]; then
        local distro_id distro_ver
        distro_id=$(. /etc/os-release && echo "${ID:-}" | tr '[:upper:]' '[:lower:]')
        distro_ver=$(. /etc/os-release && echo "${VERSION_ID:-}" | tr -d '"')

        case "$distro_id" in
            ubuntu)  _add "Ubuntu"                     "$distro_ver" "os" "HIGH" "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            debian)  _add "Debian"                     "$distro_ver" "os" "HIGH" "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            rhel)    _add "Red Hat Enterprise Linux"   "$distro_ver" "os" "HIGH" "cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            centos)  _add "CentOS"                     "$distro_ver" "os" "HIGH" "cpe:2.3:o:centos:centos:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            fedora)  _add "Fedora"                     "$distro_ver" "os" "HIGH" "cpe:2.3:o:fedoraproject:fedora:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            amzn)    _add "Amazon Linux"               "$distro_ver" "os" "HIGH" "" "/etc/os-release" ;;
            alpine)  _add "Alpine Linux"               "$distro_ver" "os" "HIGH" "cpe:2.3:o:alpinelinux:alpine_linux:*:*:*:*:*:*:*:*" "/etc/os-release" ;;
            sles)    _add "SUSE Linux Enterprise"      "$distro_ver" "os" "HIGH" "" "/etc/os-release" ;;
            opensuse*) _add "openSUSE"                 "$distro_ver" "os" "HIGH" "" "/etc/os-release" ;;
            *)
                if [[ -n "$distro_id" ]]; then
                    _add "$distro_id" "$distro_ver" "os" "HIGH" "" "/etc/os-release"
                fi ;;
        esac
    fi

    # Proxmox VE
    if _cmd pveversion || [[ -d /etc/pve ]]; then
        local pve_ver=""
        if _cmd pveversion; then
            local pve_raw
            pve_raw=$(_run pveversion)
            # output: "pve-manager/8.2.4/..."
            pve_ver=$(echo "$pve_raw" | grep -oP 'pve-manager/\K[^/\s]+' | head -1 || true)
            [[ -z "$pve_ver" ]] && pve_ver=$(_ver "$pve_raw")
        fi
        [[ -z "$pve_ver" && -f /etc/pve/.version ]] && pve_ver=$(cat /etc/pve/.version 2>/dev/null || true)
        _add "Proxmox VE" "$pve_ver" "os" "CRITICAL" \
            "cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*" "pveversion"
    fi

    # macOS
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local mac_ver
        mac_ver=$(sw_vers -productVersion 2>/dev/null || true)
        _add "macOS" "$mac_ver" "os" "HIGH" "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*" "sw_vers"
    fi
}

# ---------------------------------------------------------------------------
# Runtimes
# ---------------------------------------------------------------------------
collect_runtimes() {
    local raw ver

    for bin in python3 python; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "Python" "$ver" "runtime" "MEDIUM" "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done

    if _cmd node; then
        raw=$(_run node --version)
        ver=$(_ver "$raw")
        _add "Node.js" "$ver" "runtime" "HIGH" "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*" "node --version"
    fi

    if _cmd java; then
        raw=$(_run java -version)
        ver=$(_ver "$raw")
        _add "Java" "$ver" "runtime" "HIGH" "cpe:2.3:a:oracle:java:*:*:*:*:*:*:*:*" "java -version"
    fi

    if _cmd ruby; then
        raw=$(_run ruby --version)
        ver=$(_ver "$raw")
        _add "Ruby" "$ver" "runtime" "MEDIUM" "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*" "ruby --version"
    fi

    if _cmd php; then
        raw=$(_run php --version)
        ver=$(_ver "$raw")
        _add "PHP" "$ver" "runtime" "HIGH" "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*" "php --version"
    fi

    if _cmd perl; then
        raw=$(_run perl --version)
        ver=$(_ver "$raw")
        _add "Perl" "$ver" "runtime" "MEDIUM" "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*" "perl --version"
    fi

    if _cmd go; then
        raw=$(_run go version)
        ver=$(_ver "$raw")
        _add "Go" "$ver" "runtime" "MEDIUM" "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*" "go version"
    fi

    if _cmd rustc; then
        raw=$(_run rustc --version)
        ver=$(_ver "$raw")
        _add "Rust" "$ver" "runtime" "MEDIUM" "cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*" "rustc --version"
    fi

    if _cmd dotnet; then
        raw=$(_run dotnet --version)
        ver=$(_ver "$raw")
        _add ".NET" "$ver" "runtime" "HIGH" "cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*" "dotnet --version"
    fi
}

# ---------------------------------------------------------------------------
# Web servers
# ---------------------------------------------------------------------------
collect_web_servers() {
    local raw ver

    if _cmd nginx; then
        raw=$(_run nginx -v)
        ver=$(_ver "$raw")
        _add "nginx" "$ver" "web" "CRITICAL" "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" "nginx -v"
    fi

    for bin in apache2 httpd; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" -v)
            ver=$(_ver "$raw")
            _add "Apache HTTP Server" "$ver" "web" "CRITICAL" "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" "$bin -v"
            break
        fi
    done

    if _cmd caddy; then
        raw=$(_run caddy version)
        ver=$(_ver "$raw")
        _add "Caddy" "$ver" "web" "HIGH" "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*" "caddy version"
    fi

    if _cmd lighttpd; then
        raw=$(_run lighttpd -v)
        ver=$(_ver "$raw")
        _add "lighttpd" "$ver" "web" "HIGH" "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*" "lighttpd -v"
    fi

    if _cmd haproxy; then
        raw=$(_run haproxy -v)
        ver=$(_ver "$raw")
        _add "HAProxy" "$ver" "web" "HIGH" "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*" "haproxy -v"
    fi
}

# ---------------------------------------------------------------------------
# Databases
# ---------------------------------------------------------------------------
collect_databases() {
    local raw ver

    for bin in mysqld mysql; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "MySQL" "$ver" "db" "CRITICAL" "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done

    for bin in mariadbd mariadb; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "MariaDB" "$ver" "db" "CRITICAL" "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done

    for bin in pg_config postgres psql; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "PostgreSQL" "$ver" "db" "CRITICAL" "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done

    if _cmd mongod; then
        raw=$(_run mongod --version)
        ver=$(_ver "$raw")
        _add "MongoDB" "$ver" "db" "CRITICAL" "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*" "mongod --version"
    fi

    for bin in redis-server redis-cli; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "Redis" "$ver" "db" "HIGH" "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done

    if _cmd elasticsearch; then
        raw=$(_run elasticsearch --version)
        ver=$(_ver "$raw")
        _add "Elasticsearch" "$ver" "db" "CRITICAL" "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*" "elasticsearch --version"
    fi

    if _cmd influxd; then
        raw=$(_run influxd version)
        ver=$(_ver "$raw")
        _add "InfluxDB" "$ver" "db" "HIGH" "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*" "influxd version"
    fi

    if _cmd rabbitmq-server || _cmd rabbitmqctl; then
        ver=""
        if _cmd rabbitmqctl; then
            raw=$(_run rabbitmqctl version)
            ver=$(_ver "$raw")
        fi
        if [[ -z "$ver" ]]; then
            # Parse version from lib dir: rabbitmq_server-3.12.6/
            for d in /usr/lib/rabbitmq/lib /usr/local/lib/rabbitmq/lib /opt/rabbitmq/lib; do
                [[ -d "$d" ]] || continue
                local entry
                entry=$(ls "$d" 2>/dev/null | grep '^rabbitmq_server-' | head -1 || true)
                if [[ -n "$entry" ]]; then ver=$(_ver "$entry"); break; fi
            done
        fi
        _add "RabbitMQ" "$ver" "db" "HIGH" "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*" "rabbitmqctl version"
    fi

    if _cmd cqlsh || _cmd cassandra; then
        ver=""
        if _cmd cqlsh; then
            raw=$(_run cqlsh --version)
            ver=$(_ver "$raw")
        fi
        if [[ -z "$ver" ]]; then
            # Parse from jar: apache-cassandra-4.1.3.jar
            for d in /usr/share/cassandra/lib /opt/cassandra/lib /usr/local/cassandra/lib; do
                [[ -d "$d" ]] || continue
                local jf
                jf=$(ls "$d" 2>/dev/null | grep '^apache-cassandra-' | head -1 || true)
                if [[ -n "$jf" ]]; then ver=$(_ver "$jf"); break; fi
            done
        fi
        _add "Apache Cassandra" "$ver" "db" "HIGH" "cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*" "cqlsh/cassandra"
    fi

    if _cmd kafka-server-start.sh || _cmd kafka-server-start; then
        ver=""
        for d in /usr/share/kafka/libs /opt/kafka/libs /usr/local/kafka/libs; do
            [[ -d "$d" ]] || continue
            local jf
            jf=$(ls "$d" 2>/dev/null | grep '^kafka_' | head -1 || true)
            if [[ -n "$jf" ]]; then ver=$(_ver "$jf"); break; fi
        done
        _add "Apache Kafka" "$ver" "db" "HIGH" "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*" "kafka"
    fi

    if _cmd zookeeper-server-start.sh || _cmd zkServer.sh; then
        ver=""
        for d in /usr/share/zookeeper /opt/zookeeper/lib /usr/local/zookeeper/lib /usr/lib/zookeeper; do
            [[ -d "$d" ]] || continue
            local jf
            jf=$(ls "$d" 2>/dev/null | grep '^zookeeper-' | grep '\.jar$' | head -1 || true)
            if [[ -n "$jf" ]]; then ver=$(_ver "$jf"); break; fi
        done
        _add "Apache ZooKeeper" "$ver" "db" "HIGH" "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*" "zookeeper"
    fi

    if _cmd slapd; then
        raw=$(_run slapd -V)
        _add "OpenLDAP" "$(_ver "$raw")" "network" "CRITICAL" "cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*" "slapd -V"
    fi

    if _cmd mosquitto; then
        raw=$(_run mosquitto --help 2>&1 || true)
        _add "Mosquitto" "$(_ver "$raw")" "network" "HIGH" "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*" "mosquitto"
    fi

    if _cmd nats-server; then
        raw=$(_run nats-server -v)
        _add "NATS" "$(_ver "$raw")" "network" "HIGH" "cpe:2.3:a:nats:nats_server:*:*:*:*:*:*:*:*" "nats-server -v"
    fi

    if _cmd sqlite3; then
        raw=$(_run sqlite3 --version)
        ver=$(_ver "$raw")
        _add "SQLite" "$ver" "db" "MEDIUM" "cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*" "sqlite3 --version"
    fi
}

# ---------------------------------------------------------------------------
# Containers & orchestration
# ---------------------------------------------------------------------------
# Known Docker image name -> "NVD product name|CPE"
declare -A DOCKER_IMAGE_MAP=(
    [nginx]="nginx|cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    [httpd]="Apache HTTP Server|cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    [apache]="Apache HTTP Server|cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    [mysql]="MySQL|cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"
    [mariadb]="MariaDB|cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"
    [postgres]="PostgreSQL|cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
    [mongodb]="MongoDB|cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"
    [mongo]="MongoDB|cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"
    [redis]="Redis|cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"
    [elasticsearch]="Elasticsearch|cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"
    [rabbitmq]="RabbitMQ|cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
    [kafka]="Apache Kafka|cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"
    [zookeeper]="Apache ZooKeeper|cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"
    [node]="Node.js|cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
    [python]="Python|cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"
    [php]="PHP|cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    [ruby]="Ruby|cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"
    [tomcat]="Apache Tomcat|cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
    [jenkins]="Jenkins|cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"
    [gitlab]="GitLab|cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*"
    [grafana]="Grafana|cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"
    [prometheus]="Prometheus|cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"
    [kibana]="Kibana|cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"
    [vault]="HashiCorp Vault|cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
    [consul]="HashiCorp Consul|cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"
    [traefik]="Traefik|cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
    [haproxy]="HAProxy|cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"
    [memcached]="Memcached|cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"
    [activemq]="Apache ActiveMQ|cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"
    [sonarqube]="SonarQube|cpe:2.3:a:sonarsource:sonarqube:*:*:*:*:*:*:*:*"
    [keycloak]="Keycloak|cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*"
)

# Internal Docker infrastructure names to skip entirely
_is_infra_image() {
    local name="${1,,}"
    case "$name" in
        dockerdesktoplinuxengine|docker-desktop|registry|pause|moby|buildkit|k8s.gcr.io) return 0 ;;
    esac
    return 1
}

collect_containers() {
    local raw ver

    if _cmd docker; then
        raw=$(_run docker --version)
        ver=$(_ver "$raw")
        _add "Docker" "$ver" "container" "HIGH" "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*" "docker --version"

        # Running containers -- map image names via whitelist + OCI label version
        local ps_lines
        ps_lines=$(timeout 8 docker ps --format '{{.ID}}\t{{.Image}}' 2>/dev/null || true)
        declare -A seen_images=()
        while IFS=$'\t' read -r cid img; do
            [[ -z "$img" ]] && continue
            # Strip registry prefix and tag: registry.example.com/org/name:tag -> name
            local name
            name="${img##*/}"
            name="${name%%:*}"
            name="${name,,}"
            [[ -z "$name" ]] && continue
            [[ -n "${seen_images[$name]+_}" ]] && continue
            seen_images[$name]=1
            _is_infra_image "$name" && continue
            [[ -z "${DOCKER_IMAGE_MAP[$name]+_}" ]] && continue
            local entry nvd_name cpe oci_ver
            entry="${DOCKER_IMAGE_MAP[$name]}"
            nvd_name="${entry%%|*}"
            cpe="${entry##*|}"
            # Try OCI version label for real version number
            oci_ver=""
            if [[ -n "$cid" ]]; then
                oci_ver=$(docker inspect --format \
                    '{{index .Config.Labels "org.opencontainers.image.version"}}' \
                    "$cid" 2>/dev/null || true)
                [[ "$oci_ver" == "<no value>" ]] && oci_ver=""
                oci_ver=$(_ver "$oci_ver")
            fi
            _add "$nvd_name" "$oci_ver" "container" "HIGH" "$cpe" "docker ps ($img)"
        done <<< "$ps_lines"
    fi

    if _cmd podman; then
        raw=$(_run podman --version)
        ver=$(_ver "$raw")
        _add "Podman" "$ver" "container" "HIGH" "cpe:2.3:a:podman:podman:*:*:*:*:*:*:*:*" "podman --version"
    fi

    if _cmd kubectl; then
        raw=$(_run kubectl version --client --short 2>/dev/null || _run kubectl version --client)
        ver=$(_ver "$raw")
        _add "Kubernetes" "$ver" "container" "CRITICAL" "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*" "kubectl version"
    fi

    if _cmd helm; then
        raw=$(_run helm version --short)
        ver=$(_ver "$raw")
        _add "Helm" "$ver" "container" "HIGH" "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*" "helm version"
    fi

    if _cmd containerd; then
        raw=$(_run containerd --version)
        ver=$(_ver "$raw")
        _add "containerd" "$ver" "container" "HIGH" "cpe:2.3:a:docker:containerd:*:*:*:*:*:*:*:*" "containerd --version"
    fi
}

# ---------------------------------------------------------------------------
# Network & crypto tools
# ---------------------------------------------------------------------------
collect_network() {
    local raw ver

    if _cmd openssl; then
        raw=$(_run openssl version)
        ver=$(_ver "$raw")
        _add "OpenSSL" "$ver" "network" "CRITICAL" "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*" "openssl version"
    fi

    if _cmd ssh; then
        raw=$(_run ssh -V)
        ver=$(_ver "$raw")
        _add "OpenSSH" "$ver" "network" "HIGH" "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*" "ssh -V"
    fi

    if _cmd curl; then
        raw=$(_run curl --version)
        ver=$(_ver "$raw")
        _add "curl" "$ver" "network" "MEDIUM" "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*" "curl --version"
    fi

    if _cmd git; then
        raw=$(_run git --version)
        ver=$(_ver "$raw")
        _add "Git" "$ver" "tool" "MEDIUM" "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*" "git --version"
    fi

    for bin in gpg2 gpg; do
        if _cmd "$bin"; then
            raw=$(_run "$bin" --version)
            ver=$(_ver "$raw")
            _add "GnuPG" "$ver" "network" "HIGH" "cpe:2.3:a:gnupg:gnupg:*:*:*:*:*:*:*:*" "$bin --version"
            break
        fi
    done
}

# ---------------------------------------------------------------------------
# Package manager inventory
# ---------------------------------------------------------------------------
# interesting_pkgs: "pkg_name:nvd_name:category:severity:cpe"
INTERESTING_PKGS=(
    "openssh-server:OpenSSH:network:HIGH:cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    "openssh-client:OpenSSH:network:HIGH:cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    "libssl3:OpenSSL:network:CRITICAL:cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
    "openssl:OpenSSL:network:CRITICAL:cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
    "libexpat1:Expat:tool:HIGH:cpe:2.3:a:libexpat:expat:*:*:*:*:*:*:*:*"
    "zlib1g:zlib:tool:HIGH:cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"
    "libxml2:libxml2:tool:HIGH:cpe:2.3:a:xmlsoft:libxml2:*:*:*:*:*:*:*:*"
    "libpng16-16:libpng:tool:HIGH:cpe:2.3:a:libpng:libpng:*:*:*:*:*:*:*:*"
    "libgnutls30:GnuTLS:network:HIGH:cpe:2.3:a:gnu:gnutls:*:*:*:*:*:*:*:*"
    "sudo:sudo:tool:CRITICAL:cpe:2.3:a:sudo_project:sudo:*:*:*:*:*:*:*:*"
    "bash:GNU Bash:tool:HIGH:cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"
    "systemd:systemd:tool:HIGH:cpe:2.3:a:freedesktop:systemd:*:*:*:*:*:*:*:*"
    "bind9:ISC BIND:network:CRITICAL:cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"
    "samba:Samba:network:CRITICAL:cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"
    "vsftpd:vsftpd:network:HIGH:cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*"
    "postfix:Postfix:network:HIGH:cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"
    "exim4:Exim:network:CRITICAL:cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"
    "dovecot-core:Dovecot:network:HIGH:cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"
    "squid:Squid:network:HIGH:cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"
    "openvpn:OpenVPN:network:HIGH:cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"
    "ntp:NTP:network:HIGH:cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*"
    "fail2ban:Fail2ban:tool:MEDIUM:"
    "ansible:Ansible:tool:HIGH:cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"
    "terraform:Terraform:tool:HIGH:cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"
    "vault:HashiCorp Vault:tool:CRITICAL:cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
    "wpa_supplicant:wpa_supplicant:network:HIGH:cpe:2.3:a:w1.fi:wpa_supplicant:*:*:*:*:*:*:*:*"
    "nfs-kernel-server:NFS:network:HIGH:"
    "cups:CUPS:network:HIGH:cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*"
)

collect_packages() {
    local ver entry pkg nvd_name cat sev cpe

    if _cmd dpkg-query; then
        for entry in "${INTERESTING_PKGS[@]}"; do
            IFS=':' read -r pkg nvd_name cat sev cpe <<< "$entry"
            local raw
            raw=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
            if [[ -n "$raw" && "$raw" != *"not installed"* && "$raw" != *"no packages found"* ]]; then
                ver=$(_ver "$raw")
                _add "$nvd_name" "$ver" "$cat" "$sev" "$cpe" "dpkg $pkg"
            fi
        done
    elif _cmd rpm; then
        for entry in "${INTERESTING_PKGS[@]}"; do
            IFS=':' read -r pkg nvd_name cat sev cpe <<< "$entry"
            local raw
            raw=$(rpm -q --queryformat '%{VERSION}' "$pkg" 2>/dev/null || true)
            if [[ -n "$raw" && "$raw" != *"not installed"* ]]; then
                ver=$(_ver "$raw")
                _add "$nvd_name" "$ver" "$cat" "$sev" "$cpe" "rpm $pkg"
            fi
        done
    elif _cmd apk; then
        local installed
        installed=$(apk info -v 2>/dev/null | awk -F- '{print $1}' | sort -u || true)
        for entry in "${INTERESTING_PKGS[@]}"; do
            IFS=':' read -r pkg nvd_name cat sev cpe <<< "$entry"
            if echo "$installed" | grep -qFx "$pkg" 2>/dev/null; then
                _add "$nvd_name" "" "$cat" "$sev" "$cpe" "apk $pkg"
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# Brew (macOS / Linux)
# ---------------------------------------------------------------------------
collect_brew() {
    _cmd brew || return 0

    declare -A BREW_MAP=(
        [nginx]="nginx:web:CRITICAL:cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
        [httpd]="Apache HTTP Server:web:CRITICAL:cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        [mysql]="MySQL:db:CRITICAL:cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"
        [postgresql]="PostgreSQL:db:CRITICAL:cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
        [mongodb-community]="MongoDB:db:CRITICAL:cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"
        [redis]="Redis:db:HIGH:cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"
        [elasticsearch]="Elasticsearch:db:CRITICAL:cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"
        [rabbitmq]="RabbitMQ:db:HIGH:cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
        [openssl]="OpenSSL:network:CRITICAL:cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
        [openssh]="OpenSSH:network:HIGH:cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        [curl]="curl:network:MEDIUM:cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*"
        [git]="Git:tool:MEDIUM:cpe:2.3:a:git:git:*:*:*:*:*:*:*:*"
        [python]="Python:runtime:MEDIUM:cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"
        [node]="Node.js:runtime:HIGH:cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
        [openjdk]="OpenJDK:runtime:HIGH:cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*"
        [php]="PHP:runtime:HIGH:cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
        [ruby]="Ruby:runtime:MEDIUM:cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"
        [go]="Go:runtime:MEDIUM:cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"
        [terraform]="Terraform:tool:HIGH:cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"
        [vault]="HashiCorp Vault:tool:CRITICAL:cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
        [docker]="Docker:container:HIGH:cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"
        [kubectl]="Kubernetes:container:CRITICAL:cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"
        [helm]="Helm:container:HIGH:cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"
        [haproxy]="HAProxy:web:HIGH:cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"
        [squid]="Squid:network:HIGH:cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"
        [openvpn]="OpenVPN:network:HIGH:cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"
    )

    while IFS= read -r line; do
        local pkg ver_raw
        pkg=$(echo "$line" | awk '{print $1}')
        ver_raw=$(echo "$line" | awk '{print $2}')
        pkg="${pkg,,}"
        if [[ -n "${BREW_MAP[$pkg]+_}" ]]; then
            IFS=':' read -r nvd_name cat sev cpe <<< "${BREW_MAP[$pkg]}"
            _add "$nvd_name" "$(_ver "$ver_raw")" "$cat" "$sev" "$cpe" "brew $pkg"
        fi
    done < <(brew list --versions 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# Listening ports
# ---------------------------------------------------------------------------
declare -A PORT_MAP=(
    [22]="OpenSSH:network:HIGH:cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
    [1433]="Microsoft SQL Server:db:CRITICAL:cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"
    [1521]="Oracle Database:db:CRITICAL:cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*"
    [3306]="MySQL:db:CRITICAL:cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"
    [3389]="RDP:network:CRITICAL:cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"
    [5432]="PostgreSQL:db:CRITICAL:cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
    [5601]="Kibana:tool:HIGH:cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"
    [5672]="RabbitMQ:db:HIGH:cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
    [5985]="WinRM:network:HIGH:"
    [5986]="WinRM:network:HIGH:"
    [6379]="Redis:db:HIGH:cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"
    [6443]="Kubernetes:container:CRITICAL:cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"
    [8080]="Apache Tomcat:web:CRITICAL:cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
    [8009]="Apache Tomcat:web:CRITICAL:cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
    [8200]="HashiCorp Vault:tool:CRITICAL:cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
    [8500]="HashiCorp Consul:tool:HIGH:cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"
    [9090]="Prometheus:tool:MEDIUM:cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"
    [9200]="Elasticsearch:db:CRITICAL:cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"
    [9300]="Elasticsearch:db:CRITICAL:cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"
    [10250]="Kubernetes:container:CRITICAL:cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"
    [11211]="Memcached:db:HIGH:cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"
    [15672]="RabbitMQ:db:HIGH:cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
    [27017]="MongoDB:db:CRITICAL:cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"
    [3000]="Grafana:tool:HIGH:cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"
    [389]="LDAP:network:CRITICAL:"
    [636]="LDAP:network:CRITICAL:"
    [2375]="Docker:container:CRITICAL:cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"
    [2376]="Docker:container:CRITICAL:cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"
    [8161]="Apache ActiveMQ:db:CRITICAL:cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"
    [61616]="Apache ActiveMQ:db:CRITICAL:cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"
    [8888]="Jupyter Notebook:tool:HIGH:cpe:2.3:a:jupyter:notebook:*:*:*:*:*:*:*:*"
    [50070]="Apache Hadoop:db:HIGH:cpe:2.3:a:apache:hadoop:*:*:*:*:*:*:*:*"
    [8088]="Apache Hadoop:db:HIGH:cpe:2.3:a:apache:hadoop:*:*:*:*:*:*:*:*"
    [2049]="NFS:network:HIGH:"
    [4369]="RabbitMQ:db:HIGH:cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
    [9092]="Apache Kafka:db:HIGH:cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"
    [2181]="Apache ZooKeeper:db:HIGH:cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"
)

collect_ports() {
    local ports=""

    if _cmd ss; then
        ports=$(ss -tlnp 2>/dev/null | grep -oE ':[0-9]+' | tr -d ':' | sort -un || true)
    elif _cmd netstat; then
        ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | grep -oE ':[0-9]+\s' | tr -d ': ' | sort -un || true)
    fi

    declare -A seen_port_names=()
    while IFS= read -r port; do
        [[ -z "$port" ]] && continue
        if [[ -n "${PORT_MAP[$port]+_}" ]]; then
            IFS=':' read -r nvd_name cat sev cpe <<< "${PORT_MAP[$port]}"
            if [[ -z "${seen_port_names[$nvd_name]+_}" ]]; then
                seen_port_names[$nvd_name]=1
                _add "$nvd_name" "" "$cat" "$sev" "$cpe" "port $port"
            fi
        fi
    done <<< "$ports"
}

# ---------------------------------------------------------------------------
# Dedup: keep best entry per product name
# ---------------------------------------------------------------------------
dedup_items() {
    declare -A best_name=()   # name_lower -> index
    declare -A best_has_ver=()
    declare -A best_has_cpe=()
    local final=()
    local i=0

    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        local key="${name,,}"
        local has_ver=0; [[ -n "$ver" ]] && has_ver=1
        local has_cpe=0; [[ -n "$cpe" ]] && has_cpe=1

        if [[ -z "${best_name[$key]+_}" ]]; then
            best_name[$key]=$i
            best_has_ver[$key]=$has_ver
            best_has_cpe[$key]=$has_cpe
            final+=("$item")
            ((i++))
        else
            local idx="${best_name[$key]}"
            local existing_has_ver="${best_has_ver[$key]}"
            local existing_has_cpe="${best_has_cpe[$key]}"
            local replace=0

            if [[ $has_ver -eq 1 && $existing_has_ver -eq 0 ]]; then
                replace=1
            elif [[ $has_ver -eq 1 && $existing_has_ver -eq 1 && $has_cpe -eq 1 && $existing_has_cpe -eq 0 ]]; then
                replace=1
            elif [[ $has_ver -eq 0 && $existing_has_ver -eq 0 && $has_cpe -eq 1 && $existing_has_cpe -eq 0 ]]; then
                replace=1
            fi

            if [[ $replace -eq 1 ]]; then
                final[$idx]="$item"
                best_has_ver[$key]=$has_ver
                best_has_cpe[$key]=$has_cpe
            fi
        fi
    done

    ITEMS=("${final[@]}")
}

# ---------------------------------------------------------------------------
# Generic names to skip (produce useless NVD noise)
# ---------------------------------------------------------------------------
_is_generic() {
    local name_lower="${1,,}"
    case "$name_lower" in
        "http server"|"https server"|"smtp server"|"dns server"|"ftp server"|"telnet") return 0 ;;
    esac
    return 1
}

# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
to_keywords() {
    declare -A seen_kw=()
    local lines=()

    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        _is_generic "$name" && continue
        [[ -n "${seen_kw[$name]+_}" ]] && continue
        seen_kw[$name]=1

        local kw="$name"
        if [[ -n "$ver" ]]; then
            # major.minor only
            kw="$name $(echo "$ver" | cut -d. -f1,2)"
        fi
        lines+=("${kw}::${sev}")
    done

    # Sort alphabetically
    printf '%s\n' "${lines[@]}" | sort
}

to_json() {
    echo "["
    local first=1
    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        _is_generic "$name" && continue
        [[ $first -eq 0 ]] && echo ","
        first=0
        # Minimal JSON escaping for the common case
        local esc_name="${name//\"/\\\"}"
        local esc_ver="${ver//\"/\\\"}"
        local esc_cpe="${cpe//\"/\\\"}"
        local esc_src="${src//\"/\\\"}"
        printf '  {"name":"%s","version":"%s","category":"%s","severity":"%s","cpe":"%s","source":"%s"}' \
            "$esc_name" "$esc_ver" "$cat" "$sev" "$esc_cpe" "$esc_src"
    done
    echo ""
    echo "]"
}

to_inventory_json() {
    # Emit JSON array of items that have both a version and a CPE (for CPE-based NVD scanning)
    local first=1
    echo "["
    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        [[ -z "$ver" || -z "$cpe" ]] && continue
        _is_generic "$name" && continue
        [[ $first -eq 0 ]] && echo ","
        first=0
        local esc_name="${name//\"/\\\"}"
        local esc_ver="${ver//\"/\\\"}"
        local esc_cpe="${cpe//\"/\\\"}"
        local esc_src="${src//\"/\\\"}"
        printf '  {"name":"%s","version":"%s","cpe":"%s","category":"%s","severity":"%s","source":"%s"}' \
            "$esc_name" "$esc_ver" "$esc_cpe" "$cat" "$sev" "$esc_src"
    done
    echo ""
    echo "]"
}

# ---------------------------------------------------------------------------
# Get primary OS CPE for asset record
# ---------------------------------------------------------------------------
get_os_cpe() {
    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        if [[ "$cat" == "os" && -n "$cpe" ]]; then
            echo "$cpe"
            return
        fi
    done
    # fallback: first non-empty CPE
    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        if [[ -n "$cpe" ]]; then
            echo "$cpe"
            return
        fi
    done
    echo ""
}

get_discovered_categories() {
    declare -A cats=()
    for item in "${ITEMS[@]}"; do
        IFS=$'\t' read -r name ver cat sev cpe src <<< "$item"
        cats[$cat]=1
    done
    local result
    result=$(printf '%s\n' "${!cats[@]}" | sort | tr '\n' ',' | sed 's/,$//')
    echo "$result"
}

# ---------------------------------------------------------------------------
# Upload helper -- requires curl
# ---------------------------------------------------------------------------
_CSRF_TOKEN=""

_fetch_csrf() {
    # Fetch CSRF token once and cache it in _CSRF_TOKEN
    local tmp="/tmp/_cve_csrf_$$.txt"
    curl -s -c "$tmp" "${UPLOAD_URL%/}/" -o /dev/null 2>/dev/null || true
    _CSRF_TOKEN=$(grep -oP '(?<=\tcsrf_token\t)[^\t\n]+' "$tmp" 2>/dev/null || \
                  grep 'csrf_token' "$tmp" 2>/dev/null | awk '{print $NF}' || true)
    rm -f "$tmp"
}

_api_post() {
    local path="$1"
    local body="$2"
    local url="${UPLOAD_URL%/}${path}"
    local args=(-s -X POST -H "Content-Type: application/json")
    [[ -n "$TOKEN" ]] && args+=(-H "Authorization: Bearer $TOKEN")
    if [[ -n "$_CSRF_TOKEN" ]]; then
        args+=(-H "X-CSRF-Token: $_CSRF_TOKEN" -H "Cookie: csrf_token=$_CSRF_TOKEN")
    fi
    curl "${args[@]}" -d "$body" "$url" 2>/dev/null
}

_api_get() {
    local path="$1"
    local url="${UPLOAD_URL%/}${path}"
    local args=(-s)
    [[ -n "$TOKEN" ]] && args+=(-H "Authorization: Bearer $TOKEN")
    curl "${args[@]}" "$url" 2>/dev/null
}

do_upload() {
    if ! _cmd curl; then
        echo "Error: curl is required for --upload" >&2
        return 1
    fi

    _fetch_csrf
    [[ -n "$_CSRF_TOKEN" ]] && echo "  CSRF token obtained." >&2

    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%S")

    local asset_cpe
    asset_cpe=$(get_os_cpe)

    local disc_cats
    disc_cats=$(get_discovered_categories)
    local tags=""
    if [[ -n "$disc_cats" && -n "$ASSET_TAGS" ]]; then
        tags="${disc_cats},${ASSET_TAGS}"
    elif [[ -n "$disc_cats" ]]; then
        tags="$disc_cats"
    else
        tags="$ASSET_TAGS"
    fi

    # 1. Check if asset already exists by name
    echo "  Checking existing assets..." >&2
    local existing_id=""
    local assets_json
    assets_json=$(_api_get "/api/assets")
    if [[ -n "$assets_json" ]]; then
        # Simple grep-based extraction (avoids jq dependency)
        local match_line
        match_line=$(echo "$assets_json" | tr '}' '\n' | grep "\"name\":\"${ASSET_NAME}\"" | head -1 || true)
        if [[ -n "$match_line" ]]; then
            existing_id=$(echo "$match_line" | grep -oP '"id":\K[0-9]+' | head -1 || true)
            [[ -n "$existing_id" ]] && echo "  Found existing asset id=$existing_id" >&2
        fi
    fi

    # 2. Save asset
    local id_field=""
    [[ -n "$existing_id" ]] && id_field=",\"id\":$existing_id"

    # Escape special characters for JSON
    local esc_name="${ASSET_NAME//\"/\\\"}"
    local esc_cpe="${asset_cpe//\"/\\\"}"
    local esc_tags="${tags//\"/\\\"}"
    local esc_owner="${OWNER//\"/\\\"}"
    local esc_env="${ENVIRONMENT//\"/\\\"}"

    local asset_body="{\"name\":\"${esc_name}\",\"cpe\":\"${esc_cpe}\",\"tags\":\"${esc_tags}\",\"owner\":\"${esc_owner}\",\"environment\":\"${esc_env}\",\"last_scanned_at\":\"${now}\",\"scan_source\":\"scan_environment.sh\"${id_field}}"

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY RUN] Would save asset:" >&2
        echo "  $asset_body" >&2
    else
        echo "  Saving asset '${ASSET_NAME}'..." >&2
        local result
        result=$(_api_post "/api/assets" "$asset_body")
        if echo "$result" | grep -q '"ok":true'; then
            local new_id
            new_id=$(echo "$result" | grep -oP '"id":\K[0-9]+' | head -1 || true)
            [[ -n "$new_id" ]] && existing_id="$new_id"
            echo "  Asset saved (id=${existing_id:-?})" >&2
        else
            echo "  Asset save returned: $result" >&2
        fi
    fi

    # 3. Upload software inventory (version-specific CVE matching)
    if [[ -n "$existing_id" && $DRY_RUN -eq 0 ]]; then
        echo "  Uploading software inventory..." >&2
        local inv_json
        inv_json=$(to_inventory_json)
        if [[ -n "$inv_json" ]]; then
            local inv_result
            inv_result=$(_api_post "/api/assets/${existing_id}/inventory" "{\"items\":${inv_json}}")
            if echo "$inv_result" | grep -q '"ok":true'; then
                local inv_count
                inv_count=$(echo "$inv_result" | grep -oP '"count":\K[0-9]+' | head -1 || echo "?")
                echo "  Inventory saved (${inv_count} items)" >&2
            else
                echo "  Inventory upload returned: $inv_result" >&2
            fi
        fi
    fi

    # 4. Build keyword payload
    local new_kws
    new_kws=$(to_keywords)

    local keywords_payload="$new_kws"

    if [[ $APPEND -eq 1 ]]; then
        echo "  Fetching existing keywords for merge..." >&2
        local cfg_json
        cfg_json=$(_api_get "/api/config")
        if [[ -n "$cfg_json" ]]; then
            local existing_raw
            existing_raw=$(echo "$cfg_json" | grep -oP '"DEFAULT__keywords":\{"value":"\K[^"]*' | head -1 || \
                           echo "$cfg_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('DEFAULT__keywords',{}).get('value',''))" 2>/dev/null || true)
            existing_raw="${existing_raw//\\n/$'\n'}"

            if [[ -n "$existing_raw" ]]; then
                # Build merged map: scanner overwrites existing entries for same product
                declare -A merged_map=()
                while IFS= read -r kw; do
                    kw="${kw#"${kw%%[![:space:]]*}"}"  # ltrim
                    [[ -z "$kw" ]] && continue
                    local kname="${kw%%::*}"
                    kname="${kname,,}"
                    merged_map["$kname"]="$kw"
                done <<< "$existing_raw"
                while IFS= read -r kw; do
                    [[ -z "$kw" ]] && continue
                    local kname="${kw%%::*}"
                    kname="${kname,,}"
                    merged_map["$kname"]="$kw"  # scanner always wins
                done <<< "$new_kws"

                keywords_payload=$(printf '%s\n' "${merged_map[@]}" | sort)
                local existing_count
                existing_count=$(echo "$existing_raw" | grep -c . || true)
                echo "  ${existing_count} existing + $(echo "$new_kws" | grep -c . || true) net new keywords" >&2
            fi
        fi
    fi

    local kw_count
    kw_count=$(echo "$keywords_payload" | grep -c . || true)

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  [DRY RUN] Would upload $kw_count keywords:" >&2
        echo "$keywords_payload" | head -20 | while IFS= read -r kw; do echo "    $kw" >&2; done
        [[ $(echo "$keywords_payload" | wc -l) -gt 20 ]] && echo "    ... (truncated)" >&2
        echo "  [DRY RUN] No changes were made." >&2
        return 0
    fi

    # 4. Upload keywords
    echo "  Uploading $kw_count keywords..." >&2
    local esc_kws
    esc_kws="${keywords_payload//\\/\\\\}"
    esc_kws="${esc_kws//\"/\\\"}"
    esc_kws="${esc_kws//$'\n'/\\n}"

    local kw_body="{\"DEFAULT__keywords\":\"${esc_kws}\"}"
    local result
    result=$(_api_post "/api/config" "$kw_body")
    if echo "$result" | grep -q '"ok":true'; then
        echo "  Keywords saved." >&2
    else
        echo "  Keywords upload returned: $result" >&2
        return 1
    fi

    echo "" >&2
    echo "  Done. Asset '${ASSET_NAME}' created/updated." >&2
    echo "  Browse to ${UPLOAD_URL%/}/#assets to view it." >&2
}

# ---------------------------------------------------------------------------
# Standalone tool binaries (often installed to /usr/local/bin outside pkg mgr)
# ---------------------------------------------------------------------------
collect_standalone_tools() {
    local raw ver

    if _cmd ansible; then
        raw=$(_run ansible --version)
        _add "Ansible" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*" "ansible --version"
    fi

    if _cmd terraform; then
        raw=$(_run terraform version)
        _add "Terraform" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*" "terraform version"
    fi

    if _cmd vault; then
        raw=$(_run vault version)
        _add "HashiCorp Vault" "$(_ver "$raw")" "tool" "CRITICAL" "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*" "vault version"
    fi

    if _cmd consul; then
        raw=$(_run consul version)
        _add "HashiCorp Consul" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*" "consul version"
    fi

    if _cmd nomad; then
        raw=$(_run nomad version)
        _add "HashiCorp Nomad" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:hashicorp:nomad:*:*:*:*:*:*:*:*" "nomad version"
    fi

    if _cmd traefik; then
        raw=$(_run traefik version)
        _add "Traefik" "$(_ver "$raw")" "web" "HIGH" "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*" "traefik version"
    fi

    if _cmd grafana-server || _cmd grafana; then
        local gbin; _cmd grafana-server && gbin="grafana-server" || gbin="grafana"
        raw=$(_run "$gbin" -v 2>&1 || _run "$gbin" --version 2>&1 || true)
        _add "Grafana" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*" "$gbin -v"
    fi

    if _cmd prometheus; then
        raw=$(_run prometheus --version)
        _add "Prometheus" "$(_ver "$raw")" "tool" "MEDIUM" "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*" "prometheus --version"
    fi

    if _cmd etcd; then
        raw=$(_run etcd --version)
        _add "etcd" "$(_ver "$raw")" "tool" "HIGH" "cpe:2.3:a:etcd:etcd:*:*:*:*:*:*:*:*" "etcd --version"
    fi
}

# ---------------------------------------------------------------------------
# pip package inventory (high-value packages with CVE histories)
# ---------------------------------------------------------------------------
collect_pip_packages() {
    # Only run if pip is available
    local pip_bin=""
    for b in pip3 pip; do _cmd "$b" && pip_bin="$b" && break; done
    [[ -z "$pip_bin" ]] && return 0

    local raw
    raw=$(_run "$pip_bin" list --format=json 2>/dev/null || true)
    [[ -z "$raw" || "${raw:0:1}" != "[" ]] && return 0

    # Packages worth monitoring in NVD
    declare -A PIP_MAP=(
        [cryptography]="cryptography:tool:HIGH:cpe:2.3:a:cryptography.io:cryptography:*:*:*:*:*:*:*:*"
        [paramiko]="paramiko:network:HIGH:cpe:2.3:a:paramiko:paramiko:*:*:*:*:*:*:*:*"
        [requests]="Python Requests:tool:MEDIUM:cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*"
        [urllib3]="urllib3:tool:HIGH:cpe:2.3:a:urllib3_project:urllib3:*:*:*:*:*:*:*:*"
        [pillow]="Pillow:tool:HIGH:cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*"
        [jinja2]="Jinja2:tool:HIGH:cpe:2.3:a:palletsprojects:jinja:*:*:*:*:*:*:*:*"
        [django]="Django:tool:HIGH:cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"
        [flask]="Flask:tool:HIGH:cpe:2.3:a:palletsprojects:flask:*:*:*:*:*:*:*:*"
        [fastapi]="FastAPI:tool:HIGH:"
        [aiohttp]="aiohttp:tool:HIGH:cpe:2.3:a:aiohttp_project:aiohttp:*:*:*:*:*:*:*:*"
        [pyyaml]="PyYAML:tool:HIGH:cpe:2.3:a:pyyaml:pyyaml:*:*:*:*:*:*:*:*"
        [lxml]="lxml:tool:HIGH:cpe:2.3:a:lxml:lxml:*:*:*:*:*:*:*:*"
        [ansible]="Ansible:tool:HIGH:cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*"
        [werkzeug]="Werkzeug:tool:HIGH:cpe:2.3:a:palletsprojects:werkzeug:*:*:*:*:*:*:*:*"
        [celery]="Celery:tool:HIGH:cpe:2.3:a:celeryproject:celery:*:*:*:*:*:*:*:*"
        [gunicorn]="Gunicorn:web:HIGH:cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*"
        [pyopenssl]="pyOpenSSL:network:HIGH:cpe:2.3:a:pyopenssl_project:pyopenssl:*:*:*:*:*:*:*:*"
        [pyjwt]="PyJWT:tool:HIGH:cpe:2.3:a:pyjwt_project:pyjwt:*:*:*:*:*:*:*:*"
        [numpy]="NumPy:tool:MEDIUM:cpe:2.3:a:numpy:numpy:*:*:*:*:*:*:*:*"
        [tensorflow]="TensorFlow:tool:HIGH:cpe:2.3:a:google:tensorflow:*:*:*:*:*:*:*:*"
        [torch]="PyTorch:tool:HIGH:cpe:2.3:a:pytorch:pytorch:*:*:*:*:*:*:*:*"
        [scrapy]="Scrapy:tool:HIGH:cpe:2.3:a:scrapy:scrapy:*:*:*:*:*:*:*:*"
    )

    # Parse JSON with awk (no jq/python required)
    # Each package line: {"name": "Foo", "version": "1.2.3"}
    while IFS= read -r line; do
        local pkg_name pkg_ver
        pkg_name=$(echo "$line" | grep -oP '"name":\s*"\K[^"]+' | head -1 || true)
        pkg_ver=$(echo "$line"  | grep -oP '"version":\s*"\K[^"]+' | head -1 || true)
        [[ -z "$pkg_name" ]] && continue
        local key="${pkg_name,,}"
        if [[ -n "${PIP_MAP[$key]+_}" ]]; then
            IFS=':' read -r nvd_name cat sev cpe <<< "${PIP_MAP[$key]}"
            _add "$nvd_name" "$(_ver "$pkg_ver")" "$cat" "$sev" "$cpe" "pip $pkg_name"
        fi
    done < <(echo "$raw" | tr ',' '\n' | grep '"name"')
}

# ---------------------------------------------------------------------------
# systemctl service detection (Linux only)
# ---------------------------------------------------------------------------
collect_systemd_services() {
    [[ "$(uname -s)" != "Linux" ]] && return 0
    _cmd systemctl || return 0

    declare -A SVC_MAP=(
        [nginx]="nginx:web:CRITICAL:cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
        [apache2]="Apache HTTP Server:web:CRITICAL:cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        [httpd]="Apache HTTP Server:web:CRITICAL:cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        [mysql]="MySQL:db:CRITICAL:cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"
        [mysqld]="MySQL:db:CRITICAL:cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*"
        [mariadb]="MariaDB:db:CRITICAL:cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"
        [postgresql]="PostgreSQL:db:CRITICAL:cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
        [mongod]="MongoDB:db:CRITICAL:cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"
        [redis]="Redis:db:HIGH:cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"
        [redis-server]="Redis:db:HIGH:cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*"
        [elasticsearch]="Elasticsearch:db:CRITICAL:cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*"
        [rabbitmq-server]="RabbitMQ:db:HIGH:cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*"
        [kafka]="Apache Kafka:db:HIGH:cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*"
        [zookeeper]="Apache ZooKeeper:db:HIGH:cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*"
        [docker]="Docker:container:HIGH:cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"
        [containerd]="containerd:container:HIGH:cpe:2.3:a:docker:containerd:*:*:*:*:*:*:*:*"
        [sshd]="OpenSSH:network:HIGH:cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
        [named]="ISC BIND:network:CRITICAL:cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"
        [bind9]="ISC BIND:network:CRITICAL:cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*"
        [postfix]="Postfix:network:HIGH:cpe:2.3:a:postfix:postfix:*:*:*:*:*:*:*:*"
        [exim4]="Exim:network:CRITICAL:cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*"
        [dovecot]="Dovecot:network:HIGH:cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"
        [squid]="Squid:network:HIGH:cpe:2.3:a:squid-cache:squid:*:*:*:*:*:*:*:*"
        [openvpn]="OpenVPN:network:HIGH:cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"
        [vault]="HashiCorp Vault:tool:CRITICAL:cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
        [consul]="HashiCorp Consul:tool:HIGH:cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"
        [traefik]="Traefik:web:HIGH:cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
        [mosquitto]="Mosquitto:network:HIGH:cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"
        [nats-server]="NATS:network:HIGH:cpe:2.3:a:nats:nats_server:*:*:*:*:*:*:*:*"
        [slapd]="OpenLDAP:network:CRITICAL:cpe:2.3:a:openldap:openldap:*:*:*:*:*:*:*:*"
        [influxd]="InfluxDB:db:HIGH:cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*"
        [grafana-server]="Grafana:tool:HIGH:cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"
        [prometheus]="Prometheus:tool:MEDIUM:cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"
        [kibana]="Kibana:db:HIGH:cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"
        [jenkins]="Jenkins:tool:CRITICAL:cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*"
        [tomcat9]="Apache Tomcat:web:CRITICAL:cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
        [tomcat10]="Apache Tomcat:web:CRITICAL:cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
        [cassandra]="Apache Cassandra:db:HIGH:cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*"
        [memcached]="Memcached:db:HIGH:cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"
        [haproxy]="HAProxy:web:HIGH:cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"
        [smbd]="Samba:network:CRITICAL:cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*"
        [vsftpd]="vsftpd:network:HIGH:cpe:2.3:a:vsftpd_project:vsftpd:*:*:*:*:*:*:*:*"
        [cups]="CUPS:network:HIGH:cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*"
        [ntpd]="NTP:network:HIGH:cpe:2.3:a:ntp:ntp:*:*:*:*:*:*:*:*"
        [chronyd]="Chrony:network:HIGH:cpe:2.3:a:tuxfamily:chrony:*:*:*:*:*:*:*:*"
        [etcd]="etcd:tool:HIGH:cpe:2.3:a:etcd:etcd:*:*:*:*:*:*:*:*"
        [pveproxy]="Proxmox VE:os:CRITICAL:cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"
        [pvedaemon]="Proxmox VE:os:CRITICAL:cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"
        [pve-cluster]="Proxmox VE:os:CRITICAL:cpe:2.3:a:proxmox:virtual_environment:*:*:*:*:*:*:*:*"
        [corosync]="Corosync:network:HIGH:cpe:2.3:a:corosync:corosync:*:*:*:*:*:*:*:*"
    )

    local raw
    raw=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null || true)
    [[ -z "$raw" ]] && return 0

    declare -A seen_svcs=()
    while IFS= read -r line; do
        local unit
        unit=$(echo "$line" | awk '{print $1}' | sed 's/\.service$//')
        [[ -z "$unit" ]] && continue
        if [[ -n "${SVC_MAP[$unit]+_}" ]]; then
            IFS=':' read -r nvd_name cat sev cpe <<< "${SVC_MAP[$unit]}"
            if [[ -z "${seen_svcs[$nvd_name]+_}" ]]; then
                seen_svcs[$nvd_name]=1
                _add "$nvd_name" "" "$cat" "$sev" "$cpe" "systemctl ($unit)"
            fi
        fi
    done <<< "$raw"
}

# ---------------------------------------------------------------------------
# snap packages (Linux)
# ---------------------------------------------------------------------------
collect_snap_packages() {
    [[ "$(uname -s)" != "Linux" ]] && return 0
    _cmd snap || return 0

    declare -A SNAP_MAP=(
        [lxd]="LXD:container:HIGH:cpe:2.3:a:linuxcontainers:lxd:*:*:*:*:*:*:*:*"
        [microk8s]="MicroK8s:container:CRITICAL:cpe:2.3:a:canonical:microk8s:*:*:*:*:*:*:*:*"
        [kubectl]="Kubernetes:container:CRITICAL:cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"
        [helm]="Helm:container:HIGH:cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*"
        [docker]="Docker:container:HIGH:cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*"
        [vault]="HashiCorp Vault:tool:CRITICAL:cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*"
        [terraform]="Terraform:tool:HIGH:cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*"
        [grafana]="Grafana:tool:HIGH:cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*"
    )

    local raw
    raw=$(snap list --unicode=never 2>/dev/null || true)
    [[ -z "$raw" ]] && return 0

    declare -A seen_snaps=()
    while IFS= read -r line; do
        local snap_name ver_raw
        snap_name=$(echo "$line" | awk '{print tolower($1)}')
        ver_raw=$(echo "$line" | awk '{print $2}')
        [[ -z "$snap_name" ]] && continue
        if [[ -n "${SNAP_MAP[$snap_name]+_}" && -z "${seen_snaps[$snap_name]+_}" ]]; then
            seen_snaps[$snap_name]=1
            IFS=':' read -r nvd_name cat sev cpe <<< "${SNAP_MAP[$snap_name]}"
            _add "$nvd_name" "$(_ver "$ver_raw")" "$cat" "$sev" "$cpe" "snap $snap_name"
        fi
    done < <(echo "$raw" | tail -n +2)
}

# ---------------------------------------------------------------------------
# Run all collectors
# ---------------------------------------------------------------------------
echo "CVE Emailer -- Environment Scanner" >&2
echo "Scanning $(hostname) ..." >&2
echo "" >&2

collect_os
collect_runtimes
collect_web_servers
collect_databases
collect_containers
collect_network
collect_standalone_tools
collect_pip_packages
collect_packages
collect_brew
collect_ports
collect_systemd_services
collect_snap_packages

dedup_items

item_count=${#ITEMS[@]}
echo "Found $item_count software items." >&2
echo "" >&2

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [[ $JSON_OUT -eq 1 ]]; then
    output=$(to_json)
else
    output=$(to_keywords)
fi

if [[ -n "$OUT_FILE" ]]; then
    echo "$output" > "$OUT_FILE"
    echo "Wrote output to $OUT_FILE" >&2
else
    if [[ $JSON_OUT -eq 0 ]]; then
        echo "--- Keyword List -----------------------------------" >&2
    fi
    echo "$output"
    if [[ $JSON_OUT -eq 0 ]]; then
        echo "----------------------------------------------------" >&2
        echo "" >&2
    fi
fi

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
if [[ -n "$UPLOAD_URL" ]]; then
    if [[ -z "$TOKEN" ]]; then
        echo "Warning: No --token provided. Upload may fail if API_SECRET is set on the dashboard." >&2
    fi
    echo "Uploading to $UPLOAD_URL ..." >&2
    do_upload
fi
