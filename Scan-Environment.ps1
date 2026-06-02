<#
.SYNOPSIS
    CVE Emailer -- Windows Environment Scanner

.DESCRIPTION
    Fingerprints this Windows machine (installed software, running services,
    open ports, OS/runtime versions) and either prints a keyword list ready
    to paste into CVE Emailer, or uploads it directly to the dashboard --
    creating/updating an Asset record so CVEs are automatically correlated
    to this host.

.PARAMETER DashboardUrl
    Base URL of a running CVE Emailer dashboard, e.g. http://10.0.0.5:5000
    If omitted, output is printed to stdout only.

.PARAMETER Token
    API_SECRET bearer token for authenticated uploads. Required when
    DashboardUrl is specified.

.PARAMETER AssetName
    Name to use for this machine in the Assets inventory.
    Defaults to the machine hostname.

.PARAMETER Environment
    Asset environment tag: production | staging | development | dmz
    Defaults to "production".

.PARAMETER Owner
    Owner/team name stored against the asset, e.g. "infra-team".

.PARAMETER Tags
    Comma-separated tags to attach to the asset, e.g. "windows,iis,sqlserver".

.PARAMETER OutFile
    Write keyword list to this file instead of (or in addition to) stdout.

.PARAMETER Json
    Output a full JSON inventory instead of a keyword list.

.PARAMETER Append
    When uploading, append discovered keywords to the existing keyword list
    instead of replacing it. Updates version in-place when a product is already tracked.

.PARAMETER DryRun
    Print what would be uploaded (asset record + keyword list) without sending
    any requests. Useful for verifying output before a real upload.

.EXAMPLE
    # Print keyword list
    .\Scan-Environment.ps1

.EXAMPLE
    # Upload to dashboard, create/update asset for this machine
    .\Scan-Environment.ps1 -DashboardUrl http://10.0.0.5:5000 -Token mysecret

.EXAMPLE
    # Upload with full asset metadata
    .\Scan-Environment.ps1 -DashboardUrl http://10.0.0.5:5000 -Token mysecret `
        -AssetName "PROD-WEB-01" -Environment production -Owner "web-team" `
        -Tags "iis,windows,dotnet"

.EXAMPLE
    # Write JSON inventory to file
    .\Scan-Environment.ps1 -Json -OutFile C:\temp\inventory.json

.NOTES
    No admin rights required for most checks. A few WMI queries work better
    elevated but the script degrades gracefully without them.
#>

[CmdletBinding()]
param(
    [string]$DashboardUrl  = "",
    [string]$Token         = "",
    [string]$AssetName     = $env:COMPUTERNAME,
    [string]$Environment   = "production",
    [string]$Owner         = "",
    [string]$Tags          = "",
    [string]$OutFile       = "",
    [switch]$Json,
    [switch]$Append,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# -- Data model ----------------------------------------------------------------

class Software {
    [string]$Name
    [string]$Version
    [string]$Category    # os | runtime | web | db | container | network | tool
    [string]$Severity    # CRITICAL | HIGH | MEDIUM | LOW
    [string]$Cpe         # CPE 2.3 string where known
    [string]$Source
}

function New-Software {
    param(
        [string]$Name,
        [string]$Version   = "",
        [string]$Category  = "tool",
        [string]$Severity  = "HIGH",
        [string]$Cpe       = "",
        [string]$Source    = ""
    )
    $s = [Software]::new()
    $s.Name     = $Name
    $s.Version  = $Version
    $s.Category = $Category
    $s.Severity = $Severity
    $s.Cpe      = $Cpe
    $s.Source   = $Source
    return $s
}

# -- Helpers -------------------------------------------------------------------

function Get-FirstVersion([string]$Text) {
    if ($Text -match '(\d+\.\d+[\.\d]*)') { return $Matches[1] }
    return ""
}

function Invoke-SafeCommand {
    param([string]$Command, [string[]]$Arguments, [int]$TimeoutSec = 6)
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName               = $Command
        $psi.Arguments              = $Arguments -join " "
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $null   = $proc.WaitForExit($TimeoutSec * 1000)
        return ($stdout + $stderr).Trim()
    } catch {
        return ""
    }
}

function Test-CommandExists([string]$Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# -- OS / Windows version ------------------------------------------------------

function Get-OsItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        $caption = $os.Caption        # e.g. "Microsoft Windows Server 2022 Standard"
        $build   = $os.BuildNumber
        $ver     = $os.Version

        if ($caption -match "Server") {
            $items.Add((New-Software "Windows Server" $ver "os" "CRITICAL" `
                "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*" "Win32_OperatingSystem"))
        } else {
            $items.Add((New-Software "Microsoft Windows" $ver "os" "HIGH" `
                "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*" "Win32_OperatingSystem"))
        }

        # Surface the specific Server year as a separate keyword (better NVD hits)
        foreach ($yr in @("2022","2019","2016","2012","2008")) {
            if ($caption -match $yr) {
                $items.Add((New-Software "Windows Server $yr" $ver "os" "CRITICAL" `
                    "cpe:2.3:o:microsoft:windows_server_$yr`:*:*:*:*:*:*:*:*" "Win32_OperatingSystem"))
                break
            }
        }
    } else {
        # Fallback
        $ver = [System.Environment]::OSVersion.Version.ToString()
        $items.Add((New-Software "Microsoft Windows" $ver "os" "HIGH" "" "OSVersion"))
    }

    # PowerShell version
    $psver = $PSVersionTable.PSVersion.ToString()
    $items.Add((New-Software "PowerShell" $psver "tool" "HIGH" `
        "cpe:2.3:a:microsoft:powershell:*:*:*:*:*:*:*:*" "PSVersionTable"))

    return $items
}

# -- Runtimes ------------------------------------------------------------------

function Get-RuntimeItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    $checks = @(
        @{ Bin="python";    Args="--version"; Name="Python";    Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:python:python:*:*:*:*:*:*:*:*" },
        @{ Bin="python3";   Args="--version"; Name="Python";    Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:python:python:*:*:*:*:*:*:*:*" },
        @{ Bin="node";      Args="--version"; Name="Node.js";   Cat="runtime"; Sev="HIGH";   Cpe="cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*" },
        @{ Bin="java";      Args="-version";  Name="Java";      Cat="runtime"; Sev="HIGH";   Cpe="cpe:2.3:a:oracle:java:*:*:*:*:*:*:*:*" },
        @{ Bin="php";       Args="--version"; Name="PHP";       Cat="runtime"; Sev="HIGH";   Cpe="cpe:2.3:a:php:php:*:*:*:*:*:*:*:*" },
        @{ Bin="ruby";      Args="--version"; Name="Ruby";      Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*" },
        @{ Bin="perl";      Args="--version"; Name="Perl";      Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*" },
        @{ Bin="go";        Args="version";   Name="Go";        Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*" },
        @{ Bin="rustc";     Args="--version"; Name="Rust";      Cat="runtime"; Sev="MEDIUM"; Cpe="cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*" },
        @{ Bin="dotnet";    Args="--version"; Name=".NET";      Cat="runtime"; Sev="HIGH";   Cpe="cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*" }
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($c in $checks) {
        if (-not (Test-CommandExists $c.Bin)) { continue }
        $raw = Invoke-SafeCommand $c.Bin @($c.Args)
        $ver = Get-FirstVersion $raw
        if ($seen.Add($c.Name)) {
            $items.Add((New-Software $c.Name $ver $c.Cat $c.Sev $c.Cpe "$($c.Bin) $($c.Args)"))
        }
    }

    # .NET Framework (registry, Windows-only)
    $ndpKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    if (Test-Path $ndpKey) {
        $release = (Get-ItemProperty $ndpKey -ErrorAction SilentlyContinue).Release
        $fwver = switch ($release) {
            { $_ -ge 533325 } { "4.8.1" }
            { $_ -ge 528040 } { "4.8"   }
            { $_ -ge 461808 } { "4.7.2" }
            { $_ -ge 461308 } { "4.7.1" }
            { $_ -ge 460798 } { "4.7"   }
            default           { "4.x"   }
        }
        $items.Add((New-Software ".NET Framework" $fwver "runtime" "HIGH" `
            "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*" "registry NDP"))
    }

    return $items
}

# -- Web servers ---------------------------------------------------------------

function Get-WebServerItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    # IIS -- check Windows feature / service
    $iis = Get-Service W3SVC -ErrorAction SilentlyContinue
    if ($iis) {
        $iisVer = ""
        $iisKey = "HKLM:\SOFTWARE\Microsoft\InetStp"
        if (Test-Path $iisKey) {
            $iv = Get-ItemProperty $iisKey -ErrorAction SilentlyContinue
            $iisVer = if ($iv.VersionString) { $iv.VersionString } else { "$($iv.MajorVersion).$($iv.MinorVersion)" }
        }
        $items.Add((New-Software "IIS" $iisVer "web" "CRITICAL" `
            "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*" "W3SVC service"))
    }

    # nginx
    if (Test-CommandExists "nginx") {
        $raw = Invoke-SafeCommand "nginx" @("-v")
        $items.Add((New-Software "nginx" (Get-FirstVersion $raw) "web" "CRITICAL" `
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*" "nginx -v"))
    }

    # Apache httpd
    foreach ($bin in @("httpd","apache2","apache")) {
        if (Test-CommandExists $bin) {
            $raw = Invoke-SafeCommand $bin @("-v")
            $items.Add((New-Software "Apache HTTP Server" (Get-FirstVersion $raw) "web" "CRITICAL" `
                "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" "$bin -v"))
            break
        }
    }

    # Apache Tomcat -- check common Windows service names and registry
    $tomcatSvc = Get-Service -Name "Tomcat*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($tomcatSvc) {
        $items.Add((New-Software "Apache Tomcat" "" "web" "CRITICAL" `
            "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*" "Tomcat service"))
    }

    return $items
}

# -- Databases -----------------------------------------------------------------

function Get-DatabaseItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    # SQL Server -- check services
    $sqlSvcs = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue
    foreach ($svc in $sqlSvcs) {
        # Parse version from registry
        $sqlVer = ""
        $regBase = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server"
        if (Test-Path $regBase) {
            $instances = (Get-ItemProperty "$regBase\Instance Names\SQL" -ErrorAction SilentlyContinue).PSObject.Properties |
                         Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -notmatch "^PS" }
            foreach ($inst in $instances) {
                $vKey = "$regBase\$($inst.Value)\MSSQLServer\CurrentVersion"
                $sqlVer = (Get-ItemProperty $vKey -ErrorAction SilentlyContinue).CurrentVersion
                if ($sqlVer) { break }
            }
        }
        $items.Add((New-Software "Microsoft SQL Server" $sqlVer "db" "CRITICAL" `
            "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*" $svc.Name))
        break  # one entry is enough
    }

    # MySQL
    if (Test-CommandExists "mysql") {
        $raw = Invoke-SafeCommand "mysql" @("--version")
        $items.Add((New-Software "MySQL" (Get-FirstVersion $raw) "db" "CRITICAL" `
            "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*" "mysql --version"))
    }
    $mysqlSvc = Get-Service -Name "MySQL*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mysqlSvc -and -not (Test-CommandExists "mysql")) {
        $items.Add((New-Software "MySQL" "" "db" "CRITICAL" `
            "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*" "MySQL service"))
    }

    # MariaDB
    if (Test-CommandExists "mariadb") {
        $raw = Invoke-SafeCommand "mariadb" @("--version")
        $items.Add((New-Software "MariaDB" (Get-FirstVersion $raw) "db" "CRITICAL" `
            "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*" "mariadb --version"))
    }

    # PostgreSQL
    if (Test-CommandExists "psql") {
        $raw = Invoke-SafeCommand "psql" @("--version")
        $items.Add((New-Software "PostgreSQL" (Get-FirstVersion $raw) "db" "CRITICAL" `
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*" "psql --version"))
    }
    $pgSvc = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pgSvc -and -not (Test-CommandExists "psql")) {
        $items.Add((New-Software "PostgreSQL" "" "db" "CRITICAL" `
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*" "postgresql service"))
    }

    # MongoDB
    if (Test-CommandExists "mongo") {
        $raw = Invoke-SafeCommand "mongo" @("--version")
        $items.Add((New-Software "MongoDB" (Get-FirstVersion $raw) "db" "CRITICAL" `
            "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*" "mongo --version"))
    }
    $mongoSvc = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
    if ($mongoSvc -and -not (Test-CommandExists "mongo")) {
        $items.Add((New-Software "MongoDB" "" "db" "CRITICAL" `
            "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*" "MongoDB service"))
    }

    # Redis
    if (Test-CommandExists "redis-cli") {
        $raw = Invoke-SafeCommand "redis-cli" @("--version")
        $items.Add((New-Software "Redis" (Get-FirstVersion $raw) "db" "HIGH" `
            "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*" "redis-cli --version"))
    }
    $redisSvc = Get-Service -Name "Redis" -ErrorAction SilentlyContinue
    if ($redisSvc -and -not (Test-CommandExists "redis-cli")) {
        $items.Add((New-Software "Redis" "" "db" "HIGH" `
            "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*" "Redis service"))
    }

    # Elasticsearch
    $esSvc = Get-Service -Name "elasticsearch*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($esSvc) {
        $items.Add((New-Software "Elasticsearch" "" "db" "CRITICAL" `
            "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*" "elasticsearch service"))
    }

    # RabbitMQ
    $rmqSvc = Get-Service -Name "RabbitMQ" -ErrorAction SilentlyContinue
    if ($rmqSvc) {
        $items.Add((New-Software "RabbitMQ" "" "db" "HIGH" `
            "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*" "RabbitMQ service"))
    }

    return $items
}

# -- Containers ----------------------------------------------------------------

function Get-ContainerItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    if (Test-CommandExists "docker") {
        $raw = Invoke-SafeCommand "docker" @("--version")
        $items.Add((New-Software "Docker" (Get-FirstVersion $raw) "container" "HIGH" `
            "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*" "docker --version"))

        # Running containers -- map image names against whitelist; unknown names are dropped
        $dockerImageMap = @{
            "nginx"         = @("nginx",               "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
            "httpd"         = @("Apache HTTP Server",  "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
            "apache"        = @("Apache HTTP Server",  "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
            "mysql"         = @("MySQL",               "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*")
            "mariadb"       = @("MariaDB",             "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*")
            "postgres"      = @("PostgreSQL",          "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*")
            "mongodb"       = @("MongoDB",             "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*")
            "mongo"         = @("MongoDB",             "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*")
            "redis"         = @("Redis",               "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*")
            "elasticsearch" = @("Elasticsearch",       "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*")
            "rabbitmq"      = @("RabbitMQ",            "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*")
            "kafka"         = @("Apache Kafka",        "cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*")
            "zookeeper"     = @("Apache ZooKeeper",    "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*")
            "node"          = @("Node.js",             "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*")
            "python"        = @("Python",              "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*")
            "php"           = @("PHP",                 "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")
            "ruby"          = @("Ruby",                "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*")
            "tomcat"        = @("Apache Tomcat",       "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*")
            "jenkins"       = @("Jenkins",             "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*")
            "gitlab"        = @("GitLab",              "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*")
            "grafana"       = @("Grafana",             "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*")
            "prometheus"    = @("Prometheus",          "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*")
            "kibana"        = @("Kibana",              "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*")
            "vault"         = @("HashiCorp Vault",     "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*")
            "consul"        = @("HashiCorp Consul",    "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*")
            "traefik"       = @("Traefik",             "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*")
            "haproxy"       = @("HAProxy",             "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*")
            "memcached"     = @("Memcached",           "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*")
            "activemq"      = @("Apache ActiveMQ",    "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")
            "sonarqube"     = @("SonarQube",           "cpe:2.3:a:sonarsource:sonarqube:*:*:*:*:*:*:*:*")
            "keycloak"      = @("Keycloak",            "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*")
        }
        $infraImages = [System.Collections.Generic.HashSet[string]]@(
            "dockerdesktoplinuxengine","docker-desktop","registry","pause","moby","buildkit","k8s.gcr.io"
        )

        $running = Invoke-SafeCommand "docker" @("ps","--format","{{.Image}}")
        $seenImgs = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($img in ($running -split "`n")) {
            $img = $img.Trim()
            if (-not $img) { continue }
            # Strip registry prefix and tag: registry/org/name:tag -> name
            $imgName = (($img -split "/")[-1] -split ":")[0].ToLower()
            if (-not $imgName -or $infraImages.Contains($imgName)) { continue }
            if (-not $seenImgs.Add($imgName)) { continue }
            if ($dockerImageMap.ContainsKey($imgName)) {
                $nvdName, $cpe = $dockerImageMap[$imgName]
                $items.Add((New-Software $nvdName "" "container" "HIGH" $cpe "docker ps ($img)"))
            }
            # Unknown image names are dropped -- they produce poor NVD results
        }
    }

    # Docker Desktop service (alternative detection)
    $ddSvc = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if ($ddSvc -and -not (Test-CommandExists "docker")) {
        $items.Add((New-Software "Docker" "" "container" "HIGH" `
            "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*" "com.docker.service"))
    }

    if (Test-CommandExists "kubectl") {
        $raw = Invoke-SafeCommand "kubectl" @("version","--client","--short")
        if (-not $raw) { $raw = Invoke-SafeCommand "kubectl" @("version","--client") }
        $items.Add((New-Software "Kubernetes" (Get-FirstVersion $raw) "container" "CRITICAL" `
            "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*" "kubectl version"))
    }

    if (Test-CommandExists "helm") {
        $raw = Invoke-SafeCommand "helm" @("version","--short")
        $items.Add((New-Software "Helm" (Get-FirstVersion $raw) "container" "HIGH" `
            "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*:*" "helm version"))
    }

    return $items
}

# -- Network / crypto ----------------------------------------------------------

function Get-NetworkItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    if (Test-CommandExists "openssl") {
        $raw = Invoke-SafeCommand "openssl" @("version")
        $items.Add((New-Software "OpenSSL" (Get-FirstVersion $raw) "network" "CRITICAL" `
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*" "openssl version"))
    }

    if (Test-CommandExists "ssh") {
        $raw = Invoke-SafeCommand "ssh" @("-V")
        $items.Add((New-Software "OpenSSH" (Get-FirstVersion $raw) "network" "HIGH" `
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*" "ssh -V"))
    }
    # Windows built-in OpenSSH
    $sshSvc = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshSvc) {
        $sshVer = Get-FirstVersion (Invoke-SafeCommand "ssh" @("-V"))
        $existing = $items | Where-Object { $_.Name -eq "OpenSSH" }
        if (-not $existing) {
            $items.Add((New-Software "OpenSSH" $sshVer "network" "HIGH" `
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*" "sshd service"))
        }
    }

    if (Test-CommandExists "curl") {
        $raw = Invoke-SafeCommand "curl" @("--version")
        $items.Add((New-Software "curl" (Get-FirstVersion $raw) "network" "MEDIUM" `
            "cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*" "curl --version"))
    }

    if (Test-CommandExists "git") {
        $raw = Invoke-SafeCommand "git" @("--version")
        $items.Add((New-Software "Git" (Get-FirstVersion $raw) "tool" "MEDIUM" `
            "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*" "git --version"))
    }

    # OpenVPN
    $ovpnSvc = Get-Service -Name "OpenVPN*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ovpnSvc) {
        $items.Add((New-Software "OpenVPN" "" "network" "HIGH" `
            "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*" "OpenVPN service"))
    }

    return $items
}

# -- Installed programs (registry) ---------------------------------------------

function Get-InstalledProgramItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    # Map display name substrings -> (NVD name, category, severity, CPE)
    $patterns = [ordered]@{
        "7-Zip"                    = @("7-Zip",                      "tool",       "HIGH",     "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*")
        "WinRAR"                   = @("WinRAR",                     "tool",       "HIGH",     "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*")
        "PuTTY"                    = @("PuTTY",                      "network",    "HIGH",     "cpe:2.3:a:putty:putty:*:*:*:*:*:*:*:*")
        "WinSCP"                   = @("WinSCP",                     "network",    "HIGH",     "cpe:2.3:a:winscp:winscp:*:*:*:*:*:*:*:*")
        "FileZilla"                = @("FileZilla",                  "network",    "HIGH",     "cpe:2.3:a:filezilla-project:filezilla:*:*:*:*:*:*:*:*")
        "Wireshark"                = @("Wireshark",                  "network",    "HIGH",     "cpe:2.3:a:wireshark:wireshark:*:*:*:*:*:*:*:*")
        "Nmap"                     = @("Nmap",                       "network",    "MEDIUM",   "cpe:2.3:a:nmap:nmap:*:*:*:*:*:*:*:*")
        "VirtualBox"               = @("VirtualBox",                 "container",  "HIGH",     "cpe:2.3:a:oracle:vm_virtualbox:*:*:*:*:*:*:*:*")
        "VMware"                   = @("VMware",                     "container",  "CRITICAL", "cpe:2.3:a:vmware:vmware_tools:*:*:*:*:*:*:*:*")
        "Terraform"                = @("Terraform",                  "tool",       "HIGH",     "cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:*:*:*")
        "Vault"                    = @("HashiCorp Vault",            "tool",       "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*")
        "Ansible"                  = @("Ansible",                    "tool",       "HIGH",     "cpe:2.3:a:redhat:ansible:*:*:*:*:*:*:*:*")
        "Visual Studio Code"       = @("Visual Studio Code",         "tool",       "MEDIUM",   "cpe:2.3:a:microsoft:visual_studio_code:*:*:*:*:*:*:*:*")
        "Visual Studio"            = @("Visual Studio",              "tool",       "HIGH",     "cpe:2.3:a:microsoft:visual_studio:*:*:*:*:*:*:*:*")
        "Notepad++"                = @("Notepad++",                  "tool",       "MEDIUM",   "cpe:2.3:a:notepad-plus-plus:notepad++:*:*:*:*:*:*:*:*")
        "Microsoft Office"         = @("Microsoft Office",           "tool",       "CRITICAL", "cpe:2.3:a:microsoft:office:*:*:*:*:*:*:*:*")
        "Microsoft 365"            = @("Microsoft 365",              "tool",       "CRITICAL", "cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*")
        "Adobe Acrobat"            = @("Adobe Acrobat",              "tool",       "CRITICAL", "cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*")
        "Adobe Reader"             = @("Adobe Acrobat Reader",       "tool",       "CRITICAL", "cpe:2.3:a:adobe:acrobat_reader:*:*:*:*:*:*:*:*")
        "Google Chrome"            = @("Google Chrome",              "tool",       "HIGH",     "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*")
        "Mozilla Firefox"          = @("Mozilla Firefox",            "tool",       "HIGH",     "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*")
        "Zoom"                     = @("Zoom",                       "tool",       "HIGH",     "cpe:2.3:a:zoom:zoom:*:*:*:*:*:*:*:*")
        "Slack"                    = @("Slack",                      "tool",       "MEDIUM",   "cpe:2.3:a:slack:slack:*:*:*:*:*:*:*:*")
        "Teams"                    = @("Microsoft Teams",            "tool",       "MEDIUM",   "cpe:2.3:a:microsoft:teams:*:*:*:*:*:*:*:*")
        "Splunk"                   = @("Splunk",                     "tool",       "CRITICAL", "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*")
        "Elasticsearch"            = @("Elasticsearch",              "db",         "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*")
        "Kibana"                   = @("Kibana",                     "tool",       "HIGH",     "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*")
        "Grafana"                  = @("Grafana",                    "tool",       "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*")
        "Prometheus"               = @("Prometheus",                 "tool",       "MEDIUM",   "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*")
        "Python"                   = @("Python",                     "runtime",    "MEDIUM",   "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*")
        "Node.js"                  = @("Node.js",                    "runtime",    "HIGH",     "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*")
        "OpenJDK"                  = @("OpenJDK",                    "runtime",    "HIGH",     "cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*")
        "Java "                    = @("Java",                       "runtime",    "HIGH",     "cpe:2.3:a:oracle:java:*:*:*:*:*:*:*:*")
        "PHP"                      = @("PHP",                        "runtime",    "HIGH",     "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")
        "Ruby"                     = @("Ruby",                       "runtime",    "MEDIUM",   "cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*")
        "Perl"                     = @("Perl",                       "runtime",    "MEDIUM",   "cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*")
        "Git"                      = @("Git",                        "tool",       "MEDIUM",   "cpe:2.3:a:git:git:*:*:*:*:*:*:*:*")
        "Nginx"                    = @("nginx",                      "web",        "CRITICAL", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        "Apache HTTP"              = @("Apache HTTP Server",         "web",        "CRITICAL", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        "Apache Tomcat"            = @("Apache Tomcat",              "web",        "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*")
        "HAProxy"                  = @("HAProxy",                    "web",        "HIGH",     "cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*")
        "MySQL"                    = @("MySQL",                      "db",         "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*")
        "MariaDB"                  = @("MariaDB",                    "db",         "CRITICAL", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*")
        "PostgreSQL"               = @("PostgreSQL",                 "db",         "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*")
        "MongoDB"                  = @("MongoDB",                    "db",         "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*")
        "Redis"                    = @("Redis",                      "db",         "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*")
        "RabbitMQ"                 = @("RabbitMQ",                   "db",         "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*")
        "Kubernetes"               = @("Kubernetes",                 "container",  "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*")
    }

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($path in $uninstallPaths) {
        $keys = Get-ItemProperty $path -ErrorAction SilentlyContinue
        foreach ($key in $keys) {
            $displayName = $key.DisplayName
            $displayVer  = $key.DisplayVersion
            if (-not $displayName) { continue }

            foreach ($pattern in $patterns.Keys) {
                if ($displayName -like "*$pattern*") {
                    $nvdName, $cat, $sev, $cpe = $patterns[$pattern]
                    if ($seen.Add($nvdName)) {
                        $ver = if ($displayVer) { Get-FirstVersion $displayVer } else { "" }
                        $items.Add((New-Software $nvdName $ver $cat $sev $cpe "registry: $displayName"))
                    }
                    break
                }
            }
        }
    }

    return $items
}

# -- Listening ports -----------------------------------------------------------

function Get-ListeningPortItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    $portMap = @{
        22    = @("OpenSSH",               "network",    "HIGH",     "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
        25    = @("SMTP server",            "network",    "HIGH",     "")
        53    = @("DNS server",             "network",    "CRITICAL", "")
        80    = @("HTTP server",            "web",        "HIGH",     "")
        443   = @("HTTPS server",           "web",        "HIGH",     "")
        1433  = @("Microsoft SQL Server",   "db",         "CRITICAL", "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*")
        1521  = @("Oracle Database",        "db",         "CRITICAL", "cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*")
        3306  = @("MySQL",                  "db",         "CRITICAL", "cpe:2.3:a:mysql:mysql:*:*:*:*:*:*:*:*")
        3389  = @("RDP",                    "network",    "CRITICAL", "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*")
        5432  = @("PostgreSQL",             "db",         "CRITICAL", "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*")
        5601  = @("Kibana",                 "tool",       "HIGH",     "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*")
        5672  = @("RabbitMQ",              "db",         "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*")
        5985  = @("WinRM",                  "network",    "HIGH",     "")
        5986  = @("WinRM",                  "network",    "HIGH",     "")
        6379  = @("Redis",                  "db",         "HIGH",     "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*")
        6443  = @("Kubernetes",             "container",  "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*")
        8080  = @("Apache Tomcat",          "web",        "CRITICAL", "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*")
        8200  = @("HashiCorp Vault",        "tool",       "CRITICAL", "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*")
        8443  = @("HTTPS server",           "web",        "HIGH",     "")
        8500  = @("HashiCorp Consul",       "tool",       "HIGH",     "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*")
        9200  = @("Elasticsearch",          "db",         "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*")
        9300  = @("Elasticsearch",          "db",         "CRITICAL", "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*")
        9090  = @("Prometheus",             "tool",       "MEDIUM",   "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*")
        3000  = @("Grafana",                "tool",       "HIGH",     "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*")
        27017 = @("MongoDB",                "db",         "CRITICAL", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*")
        389   = @("LDAP",                   "network",    "CRITICAL", "")
        636   = @("LDAP",                   "network",    "CRITICAL", "")
        10250 = @("Kubernetes",             "container",  "CRITICAL", "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*")
        11211 = @("Memcached",              "db",         "HIGH",     "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*")
        15672 = @("RabbitMQ",              "db",         "HIGH",     "cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*")
        8888  = @("Jupyter Notebook",       "tool",       "HIGH",     "cpe:2.3:a:jupyter:notebook:*:*:*:*:*:*:*:*")
        8161  = @("Apache ActiveMQ",        "db",         "CRITICAL", "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")
        61616 = @("Apache ActiveMQ",        "db",         "CRITICAL", "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")
    }

    # Get listening TCP ports via .NET (no external command needed)
    $listeningPorts = [System.Collections.Generic.HashSet[int]]::new()
    try {
        $connections = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
        foreach ($ep in $connections) {
            $null = $listeningPorts.Add($ep.Port)
        }
    } catch {
        # Fallback to netstat if .NET approach fails
        $raw = Invoke-SafeCommand "netstat" @("-ano")
        foreach ($line in ($raw -split "`n")) {
            if ($line -match "LISTENING" -and $line -match ':(\d+)\s') {
                $null = $listeningPorts.Add([int]$Matches[1])
            }
        }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($port in ($listeningPorts | Sort-Object)) {
        if ($portMap.ContainsKey($port)) {
            $nvdName, $cat, $sev, $cpe = $portMap[$port]
            if ($seen.Add($nvdName)) {
                $items.Add((New-Software $nvdName "" $cat $sev $cpe "port $port"))
            }
        }
    }

    return $items
}

# -- Windows roles / features --------------------------------------------------

function Get-WindowsFeatureItems {
    $items = [System.Collections.Generic.List[Software]]::new()

    # Only available on Server SKUs with ServerManager
    if (-not (Test-CommandExists "Get-WindowsFeature")) { return $items }

    $featureMap = @{
        "Web-Server"                  = @("IIS",                    "web",      "CRITICAL", "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*")
        "DNS"                         = @("Windows DNS Server",     "network",  "CRITICAL", "cpe:2.3:a:microsoft:dns_server:*:*:*:*:*:*:*:*")
        "DHCP"                        = @("Windows DHCP Server",    "network",  "HIGH",     "")
        "SMTP-Server"                 = @("Windows SMTP Server",    "network",  "HIGH",     "")
        "ADCS-Cert-Authority"         = @("Active Directory CS",    "network",  "CRITICAL", "")
        "ADDS-Domain-Services"        = @("Active Directory DS",    "network",  "CRITICAL", "")
        "ADFS-Federation"             = @("ADFS",                   "network",  "CRITICAL", "cpe:2.3:a:microsoft:active_directory_federation_services:*:*:*:*:*:*:*:*")
        "Hyper-V"                     = @("Hyper-V",                "container","CRITICAL", "cpe:2.3:a:microsoft:hyper-v:*:*:*:*:*:*:*:*")
        "WinRM-Service"               = @("WinRM",                  "network",  "HIGH",     "")
        "RDS-RD-Server"               = @("Remote Desktop Services","network",  "CRITICAL", "")
        "Print-Services"              = @("Windows Print Spooler",  "tool",     "HIGH",     "")
        "File-Services"               = @("Windows File Services",  "network",  "HIGH",     "")
        "NFS-Service"                 = @("NFS",                    "network",  "HIGH",     "")
    }

    try {
        $features = Get-WindowsFeature -ErrorAction SilentlyContinue |
                    Where-Object { $_.Installed -eq $true }
        foreach ($f in $features) {
            if ($featureMap.ContainsKey($f.Name)) {
                $nvdName, $cat, $sev, $cpe = $featureMap[$f.Name]
                $items.Add((New-Software $nvdName "" $cat $sev $cpe "Windows Feature: $($f.Name)"))
            }
        }
    } catch { }

    return $items
}

# -- Dedup ---------------------------------------------------------------------

function Merge-Software {
    param([System.Collections.Generic.List[Software]]$Items)

    $best = [System.Collections.Generic.Dictionary[string, Software]]::new()
    foreach ($item in $Items) {
        $key = $item.Name.ToLower()
        if (-not $best.ContainsKey($key)) {
            $best[$key] = $item
        } elseif ($item.Version -and -not $best[$key].Version) {
            $best[$key] = $item   # prefer entries that carry a version
        } elseif ($item.Cpe -and -not $best[$key].Cpe) {
            $best[$key] = $item   # prefer entries that carry a CPE
        }
    }
    return [System.Collections.Generic.List[Software]]($best.Values)
}

# -- Keyword formatter ---------------------------------------------------------

function ConvertTo-Keywords {
    param([System.Collections.Generic.List[Software]]$Items)

    # Generic port-only names that produce useless NVD noise — skip entirely.
    $skipNames = [System.Collections.Generic.HashSet[string]]@(
        "http server","https server","smtp server","dns server","ftp server","telnet"
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($item in ($Items | Sort-Object Name)) {
        # Drop generic names
        if ($skipNames.Contains($item.Name.ToLower())) { continue }

        $sev = $item.Severity
        $kw  = $item.Name
        if ($item.Version) {
            # Trim to major.minor for broader NVD hits
            $parts = $item.Version -split '\.'
            if ($parts.Count -ge 2) {
                $kw = "$($item.Name) $($parts[0]).$($parts[1])"
            }
        }
        $lines.Add("${kw}::${sev}")
    }
    return $lines
}

# -- CPE builder for asset record ----------------------------------------------

function Build-AssetCpe {
    param([System.Collections.Generic.List[Software]]$Items)
    # Use the CPE of the primary OS entry as the asset CPE; if none, use the
    # first non-empty CPE from the list. The asset CPE drives CVE correlation.
    $osCpe = ($Items | Where-Object { $_.Category -eq "os" -and $_.Cpe } | Select-Object -First 1).Cpe
    if ($osCpe) { return $osCpe }
    $fallback = ($Items | Where-Object { $_.Cpe } | Select-Object -First 1).Cpe
    if ($fallback) { return $fallback } else { return "" }
}

function Build-AssetTags {
    param([System.Collections.Generic.List[Software]]$Items, [string]$ExtraTags)
    $cats = ($Items | Select-Object -ExpandProperty Category -Unique | Sort-Object) -join ","
    $all  = @($cats, $ExtraTags) | Where-Object { $_ } | ForEach-Object { $_.Trim(",") }
    return ($all -join ",")
}

# -- HTTP helper (no external deps) -------------------------------------------

function Get-CsrfToken {
    param([string]$BaseUrl)
    # Hits the dashboard root once to obtain the csrf_token cookie value.
    # Returns empty string if the dashboard is not running or CSRF is not required.
    try {
        $cookieJar = [System.Net.CookieContainer]::new()
        $pingReq   = [System.Net.HttpWebRequest]::Create($BaseUrl.TrimEnd("/") + "/")
        $pingReq.CookieContainer = $cookieJar
        $pingReq.Method = "GET"
        $resp = $pingReq.GetResponse()
        $resp.Close()
        $cookie = $cookieJar.GetCookies([Uri]($BaseUrl.TrimEnd("/") + "/")) |
                  Where-Object { $_.Name -eq "csrf_token" } |
                  Select-Object -First 1
        if ($cookie) { return $cookie.Value }
    } catch { }
    return ""
}

function Invoke-DashboardApi {
    param(
        [string]$Url,
        [string]$Token,
        [string]$CsrfToken = "",
        [string]$Method = "POST",
        [hashtable]$Body = @{}
    )
    $json    = $Body | ConvertTo-Json -Depth 10 -Compress
    $bytes   = [System.Text.Encoding]::UTF8.GetBytes($json)
    $req     = [System.Net.WebRequest]::Create($Url)
    $req.Method        = $Method
    $req.ContentType   = "application/json"
    $req.ContentLength = $bytes.Length
    if ($Token)     { $req.Headers.Add("Authorization", "Bearer $Token") }
    if ($CsrfToken -and ($Method -in "POST","PUT","PATCH","DELETE")) {
        $req.Headers.Add("X-CSRF-Token", $CsrfToken)
    }

    $stream = $req.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()

    $resp    = $req.GetResponse()
    $reader  = [System.IO.StreamReader]::new($resp.GetResponseStream())
    $content = $reader.ReadToEnd()
    $reader.Close()
    $resp.Close()
    return $content | ConvertFrom-Json
}

# -- Upload to dashboard -------------------------------------------------------

function Upload-ToDashboard {
    param(
        [string]$BaseUrl,
        [string]$Token,
        [string]$AssetName,
        [string]$Environment,
        [string]$Owner,
        [string]$AssetTags,
        [string]$AssetCpe,
        [System.Collections.Generic.List[string]]$Keywords,
        [switch]$Append,
        [switch]$DryRun
    )

    $base = $BaseUrl.TrimEnd("/")

    # Fetch CSRF token once; reuse for all write requests in this session.
    # Bearer-authenticated requests are exempt from CSRF, but we send it anyway
    # so the same code path works when Token is empty (same-origin browser case).
    $csrf = Get-CsrfToken -BaseUrl $base
    if ($csrf) {
        Write-Host "  CSRF token obtained." -ForegroundColor DarkGray
    }

    # -- 1. Check if asset already exists --------------------------------------
    Write-Host "  Checking existing assets..." -ForegroundColor Cyan
    $assetId = $null
    try {
        $req  = [System.Net.WebRequest]::Create("$base/api/assets")
        $resp = $req.GetResponse()
        $body = [System.IO.StreamReader]::new($resp.GetResponseStream()).ReadToEnd()
        $resp.Close()
        $assets = $body | ConvertFrom-Json
        $existing = $assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
        if ($existing) {
            $assetId = $existing.id
            Write-Host "  Found existing asset: $AssetName (id=$assetId)" -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "  Could not fetch assets: $_"
    }

    # -- 2. Create or update asset ---------------------------------------------
    $scanTime = [System.DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
    $assetBody = @{
        name            = $AssetName
        cpe             = $AssetCpe
        tags            = $AssetTags
        owner           = $Owner
        environment     = $Environment
        last_scanned_at = $scanTime
        scan_source     = "Scan-Environment.ps1"
    }
    if ($assetId) { $assetBody["id"] = $assetId }

    if ($DryRun) {
        Write-Host "  [DRY RUN] Would save asset:" -ForegroundColor DarkYellow
        Write-Host ($assetBody | ConvertTo-Json -Depth 3) -ForegroundColor DarkYellow
    } else {
        Write-Host "  Saving asset '$AssetName'..." -ForegroundColor Cyan
        try {
            $result = Invoke-DashboardApi -Url "$base/api/assets" -Token $Token -CsrfToken $csrf -Body $assetBody
            if ($result.ok) {
                $assetId = $result.id
                Write-Host "  Asset saved (id=$assetId)" -ForegroundColor Green
            } else {
                Write-Warning "  Asset save returned: $($result | ConvertTo-Json)"
            }
        } catch {
            Write-Warning "  Asset save failed: $_"
        }
    }

    # -- 3. Merge or replace keywords ------------------------------------------
    $finalKeywords = $Keywords

    if ($Append) {
        Write-Host "  Fetching existing keywords for merge..." -ForegroundColor Cyan
        try {
            $cfgReq  = [System.Net.WebRequest]::Create("$base/api/config")
            $cfgResp = $cfgReq.GetResponse()
            $cfgBody = [System.IO.StreamReader]::new($cfgResp.GetResponseStream()).ReadToEnd()
            $cfgResp.Close()
            $cfg = $cfgBody | ConvertFrom-Json
            $existingRaw = $cfg.'DEFAULT__keywords'.value
            $existingKws = $existingRaw -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() }

            # Update-in-place: if a matching name exists but the new entry has a
            # version and the existing one has a different (or no) version, replace it.
            $existingMap = [System.Collections.Generic.Dictionary[string,string]]::new()
            foreach ($kw in $existingKws) {
                $kname = ($kw -split "::")[0].Trim().ToLower()
                $existingMap[$kname] = $kw
            }
            foreach ($kw in $Keywords) {
                $kname = ($kw -split "::")[0].Trim().ToLower()
                $existingMap[$kname] = $kw   # always overwrite — scanner is authoritative for known products
            }
            $finalKeywords = [System.Collections.Generic.List[string]]($existingMap.Values)
            $newCount = ($Keywords | Where-Object { $existingMap.ContainsKey(($_ -split "::")[0].Trim().ToLower()) }).Count
            Write-Host "  Merged: $($existingKws.Count) existing + $($Keywords.Count - $newCount) net new keywords" -ForegroundColor Cyan
        } catch {
            Write-Warning "  Could not fetch existing keywords: $_"
        }
    }

    # -- 4. Upload keywords ----------------------------------------------------
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would upload $($finalKeywords.Count) keywords:" -ForegroundColor DarkYellow
        $finalKeywords | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    } else {
        Write-Host "  Uploading $($finalKeywords.Count) keywords..." -ForegroundColor Cyan
        try {
            $kwBody = @{ "DEFAULT__keywords" = ($finalKeywords -join "`n") }
            $result = Invoke-DashboardApi -Url "$base/api/config" -Token $Token -CsrfToken $csrf -Body $kwBody
            if ($result.ok) {
                Write-Host "  Keywords saved." -ForegroundColor Green
            } else {
                Write-Warning "  Keywords upload returned: $($result | ConvertTo-Json)"
            }
        } catch {
            Write-Warning "  Keywords upload failed: $_"
        }
    }

    Write-Host ""
    if ($DryRun) {
        Write-Host "  [DRY RUN] No changes were made." -ForegroundColor DarkYellow
    } else {
        Write-Host "  Done. Asset '$AssetName' created/updated (id=$assetId)." -ForegroundColor Green
        Write-Host "  Browse to $base/#assets to view it." -ForegroundColor Cyan
    }
}

# -- Main ----------------------------------------------------------------------

Write-Host ""
Write-Host "CVE Emailer -- Environment Scanner" -ForegroundColor White
Write-Host "Scanning $env:COMPUTERNAME ..." -ForegroundColor Cyan
Write-Host ""

$all = [System.Collections.Generic.List[Software]]::new()

$collectors = @(
    { Get-OsItems },
    { Get-RuntimeItems },
    { Get-WebServerItems },
    { Get-DatabaseItems },
    { Get-ContainerItems },
    { Get-NetworkItems },
    { Get-InstalledProgramItems },
    { Get-ListeningPortItems },
    { Get-WindowsFeatureItems }
)

foreach ($c in $collectors) {
    try {
        $results = & $c
        foreach ($r in $results) { $all.Add($r) }
    } catch { }
}

$all      = Merge-Software -Items $all
$keywords = ConvertTo-Keywords -Items $all
$assetCpe = Build-AssetCpe -Items $all
$assetTags = Build-AssetTags -Items $all -ExtraTags $Tags

Write-Host "Found $($all.Count) software items." -ForegroundColor Cyan
Write-Host ""

# -- Output --------------------------------------------------------------------

if ($Json) {
    $output = $all | ForEach-Object {
        [ordered]@{
            name     = $_.Name
            version  = $_.Version
            category = $_.Category
            severity = $_.Severity
            cpe      = $_.Cpe
            source   = $_.Source
        }
    } | ConvertTo-Json -Depth 5
} else {
    $output = $keywords -join "`n"
}

if ($OutFile) {
    $output | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Wrote output to $OutFile" -ForegroundColor Green
} else {
    if (-not $Json) {
        Write-Host "--- Keyword List -----------------------------------" -ForegroundColor DarkGray
    }
    Write-Host $output
    if (-not $Json) {
        Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# -- Upload --------------------------------------------------------------------

if ($DashboardUrl) {
    if (-not $Token) {
        Write-Warning "No -Token provided. Upload may fail if API_SECRET is set on the dashboard."
    }
    Write-Host "Uploading to $DashboardUrl ..." -ForegroundColor Cyan
    Upload-ToDashboard `
        -BaseUrl     $DashboardUrl `
        -Token       $Token `
        -AssetName   $AssetName `
        -Environment $Environment `
        -Owner       $Owner `
        -AssetTags   $assetTags `
        -AssetCpe    $assetCpe `
        -Keywords    $keywords `
        -Append:$Append `
        -DryRun:$DryRun
}
