#!/usr/bin/env python3
"""Collect locally as root, then send the snapshot to a configured Taildrop peer."""
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys


DIRECTORY = Path("/var/lib/sec-inventory")


def local_settings():
    path = Path(os.environ.get("SEC_INVENTORY_CONFIG", Path(__file__).resolve().parents[1] / "local-config.json"))
    config = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    settings = {"inventory_filename": "vps-inventory.json", "taildrop_target": ""}
    settings.update(config.get("vps", {}))
    name = settings["inventory_filename"]
    if not isinstance(name, str) or not re.fullmatch(r"[\w.-]+\.json", name):
        raise ValueError("inventory_filename must be a JSON basename")
    if not isinstance(settings["taildrop_target"], str) or not re.fullmatch(r"[\w.-]+:", settings["taildrop_target"]):
        raise ValueError("Configure vps.taildrop_target in local-config.json")
    return settings


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


def os_release(text):
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parts = shlex.split(value, comments=True)
        fields[key] = " ".join(parts)
    return fields


def paragraphs(text):
    for block in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if fields:
            yield fields


def dpkg_status(text):
    packages = []
    for fields in paragraphs(text):
        if fields.get("Status", "").split()[-1:] != ["installed"]:
            continue
        name, version = fields["Package"], fields["Version"]
        source = re.fullmatch(r"([^\s]+)(?:\s+\(([^)]+)\))?", fields.get("Source", name))
        if not source:
            raise ValueError(f"Invalid Source for {name}")
        packages.append({"name": name, "version": version, "source": source[1],
                         "source_version": source[2] or version})
    return packages


def apk_packages(text):
    return [{"name": fields["P"], "version": fields["V"], "origin": fields.get("o", fields["P"])}
            for fields in paragraphs(text) if "P" in fields and "V" in fields]


def host_packages():
    fmt = "${db:Status-Status}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"
    packages = []
    for line in command(["dpkg-query", "-W", "-f=" + fmt]).splitlines():
        status, name, version, source, source_version = line.split("\t")
        if status == "installed":
            packages.append({"name": name, "version": version, "source": source or name,
                             "source_version": source_version or version})
    return packages


def listening():
    listeners = []
    for line in command(["ss", "-Htlnp"]).splitlines():
        fields = line.split()
        address, port = fields[3].rsplit(":", 1)
        processes = re.findall(r'\("([^"\n]+)"', " ".join(fields[5:]))
        listeners.append({"address": address.strip("[]"), "port": int(port),
                          "name": ", ".join(dict.fromkeys(processes)) or "unknown"})
    return listeners


def containers():
    rows = []
    # Inspect only these fields: full docker inspect output can contain secrets in environment variables.
    fmt = ('{"id":{{json .Id}},"name":{{json .Name}},'
           '"image":{{json .Config.Image}},"image_id":{{json .Image}},"state":{{json .State.Status}}}')
    for container_id in command(["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}"]).splitlines():
        row = {"id": container_id, "name": container_id, "image": "", "image_id": "",
               "os": {}, "packages": [], "errors": []}
        rows.append(row)
        try:
            row.update(json.loads(command(["docker", "inspect", "--format", fmt, container_id])))
            row["name"] = row["name"].lstrip("/")
            if row["state"] != "running":
                row["errors"].append("停止中で中を読めない")
                continue
            row["os"] = os_release(command(["docker", "exec", container_id, "cat", "/etc/os-release"]))
            distro = row["os"].get("ID")
            if distro == "alpine":
                row["packages"] = apk_packages(command(
                    ["docker", "exec", container_id, "cat", "/lib/apk/db/installed"]))
            elif distro in ("debian", "ubuntu"):
                row["packages"] = dpkg_status(command(
                    ["docker", "exec", container_id, "cat", "/var/lib/dpkg/status"]))
            else:
                raise ValueError(f"Unsupported container OS: {distro}")
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            row["errors"].append(str(error))
    return rows


def security_facts(read_text, command):
    facts = {"errors": {}}
    try:
        lines = [line.split() for line in read_text("/proc/stat").splitlines()
                 if line.split()[:1] == ["btime"]]
        if len(lines) != 1 or len(lines[0]) != 2 or not re.fullmatch(r"[0-9]+", lines[0][1]):
            raise ValueError("Invalid or missing btime in /proc/stat")
        booted_at = dt.datetime.fromtimestamp(int(lines[0][1]), dt.timezone.utc)
        facts["boot"] = {"booted_at": booted_at.isoformat(timespec="seconds").replace("+00:00", "Z")}
    except (OSError, ValueError, OverflowError) as error:
        facts["errors"]["boot"] = str(error)
    if "boot" in facts:
        try:
            boot_id = read_text("/proc/sys/kernel/random/boot_id").strip()
            if not boot_id:
                raise ValueError("Empty boot_id")
            facts["boot"]["boot_id"] = boot_id
        except (OSError, ValueError) as error:
            facts["errors"]["boot"] = str(error)
    try:
        tables = []
        for line in command(["nft", "list", "tables"]).splitlines():
            if not line.strip():
                continue
            fields = shlex.split(line)
            if len(fields) != 3 or fields[0] != "table" or \
                    fields[1] not in ("ip", "ip6", "inet", "arp", "bridge", "netdev") or not fields[2].strip():
                raise ValueError("Invalid nft list tables output")
            tables.append({"family": fields[1], "name": fields[2]})
        facts["nft_tables"] = tables
    except (OSError, RuntimeError, ValueError) as error:
        facts["errors"]["nft_tables"] = str(error)
    return facts


def atomic_json(path, document):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main():
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    if os.geteuid() != 0:
        raise SystemExit("Run as root")
    settings = local_settings()
    inventory = DIRECTORY / settings["inventory_filename"]
    os.umask(0o077)
    document = {"schema": 1, "host": platform.node(), "generated": utc_now(),
                "os": {}, "kernel": platform.release(), "packages": [], "listening": [],
                "containers": [], "errors": []}
    collectors = {"os": lambda: os_release(Path("/etc/os-release").read_text(encoding="utf-8")),
                  "packages": host_packages, "listening": listening, "containers": containers,
                  "security_facts": lambda: security_facts(
                      lambda path: Path(path).read_text(encoding="utf-8"), command)}
    for key, collect in collectors.items():
        try:
            document[key] = collect()
        except (OSError, RuntimeError, ValueError, KeyError) as error:
            document["errors"].append(f"{key}: {error}")
    atomic_json(inventory, document)
    try:
        result = subprocess.run(["tailscale", "file", "cp", str(inventory), settings["taildrop_target"]],
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        code, error = result.returncode, result.stderr.strip() if result.returncode else ""
    except OSError as exc:
        code, error = 1, str(exc)
    atomic_json(DIRECTORY / "send-status.json", {"generated": utc_now(), "exit_code": code, "error": error})
    if code:
        print(f"Taildrop failed (exit {code}): {error}", file=sys.stderr)
    return 1 if code else 0


if __name__ == "__main__":
    raise SystemExit(main())
