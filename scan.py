"""Inventory software against OSV, release feeds and CISA KEV; watch Patch the Planet disclosures.

Usage: py -3.14 -I scan.py [--baseline] [--scan-id ID] [--selftest-impact] [--selftest] [--selftest-runtime] [--selftest-ptp] [--selftest-patchwait] [--selftest-scanmux] [--selftest-coverage] [--selftest-xwatch] [--selftest-vps] [--cve ID] [--config PATH]

Exit codes: 0 = no new findings, 10 = one or more new findings, 2 = failure (including an unverified PTP, patchwait or failed ScanMux check; unsupported dirty worktrees and partially verified projects are listed only, and are never reported as clean).
--cve: 10 = this PC is affected, 0 = not affected (unverified items are listed), 2 = the ID could not be fetched.
Results are split into three: hit / no hit / could not be checked. A fetch failure is never
treated as "no vulnerability"; it is counted under "unverified".
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import ipaddress
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from html.parser import HTMLParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC_FIXTURES = HERE / "fixtures" / "public"


def load_impact():
    spec = importlib.util.spec_from_file_location("security_loop_impact", HERE / "impact.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


impact = load_impact()
OUT = HERE / "out"
STATE = HERE / "state"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NODE_INDEX = "https://nodejs.org/dist/index.json"
FETCHED = "_fetched_at"  # added to each cached OSV detail
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def read_json(path: Path, default):
    if not path.exists():
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


EXAMPLE_FILES = {
    "scan-config.json": "scan-config.example.json",
    "coverage-map.json": "coverage-map.example.json",
    "assets-manual.json": "assets-manual.example.json",
    "x-watch-prompt.md": "watch-prompt.example.md",
}
_EXAMPLE_NOTICES = set()


def example_fallback(path: Path) -> Path:
    """Use a sibling example only when the requested real file is absent."""
    name = EXAMPLE_FILES.get(path.name)
    if name and not path.exists():
        example = path.with_name(name)
        if example.is_file():
            if example not in _EXAMPLE_NOTICES:
                print(f"Using example: {example.name} ({path.name} is absent)", file=sys.stderr)
                _EXAMPLE_NOTICES.add(example)
            return example
    return path


def load_config(path: Path, section: str) -> dict:
    """Overlay a sibling local-config.json section; arrays/scalars replace defaults."""
    def merge(base, override):
        if isinstance(base, dict) and isinstance(override, dict):
            result = dict(base)
            for key, value in override.items():
                result[key] = merge(result.get(key), value)
            return result
        return override

    path = example_fallback(path)
    config = read_json(path, None)
    local = read_json(path.parent / "local-config.json", {})
    if not isinstance(config, dict) or not isinstance(local, dict) or \
            not isinstance(local.get(section, {}), dict):
        raise ValueError(f"config と local-config.json の {section} は object が必要")
    return merge(config, local.get(section, {}))


def selftest_config() -> None:
    with tempfile.TemporaryDirectory(prefix=".config-selftest-", dir=HERE) as temporary:
        root = Path(temporary)
        path = root / "config.json"
        base = {"nested": {"keep": 1, "replace": [1]}, "enabled": True}
        write_json(path, base)
        assert load_config(path, "scan") == base
        write_json(root / "local-config.json", {"scan": {"nested": {"replace": [2]}, "enabled": False},
                                                "scanmux": {"schema": 1}})
        assert load_config(path, "scan") == {"nested": {"keep": 1, "replace": [2]}, "enabled": False}
        assert load_config(path, "scanmux") == {**base, "schema": 1}
        assert read_json(path, {}) == base
        write_json(root / "local-config.json", {"scan": []})
        try:
            load_config(path, "scan")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid local config accepted")


    # Exercise cutover and precedence without opening any operator configuration.
    from contextlib import redirect_stderr
    from io import StringIO
    with tempfile.TemporaryDirectory(prefix=".example-selftest-", dir=HERE) as temporary:
        root = Path(temporary)
        notice = StringIO()
        config = root / "scan-config.json"
        write_json(root / "scan-config.example.json", {"marker": "example"})
        with redirect_stderr(notice):
            assert load_config(config, "scan") == {"marker": "example"}
            assert load_config(config, "scan") == {"marker": "example"}
        assert notice.getvalue().count("Using example:") == 1
        write_json(config, {"marker": "real"})
        write_json(root / "local-config.json", {"scan": {"overlay": True}})
        assert load_config(config, "scan") == {"marker": "real", "overlay": True}
        config.write_text("broken JSON", encoding="utf-8", newline="\n")
        try:
            load_config(config, "scan")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid real configuration must not fall back")
        write_json(root / "coverage-map.example.json", [{"match": "^Example$", "kinds": ["apps"],
                    "routes": [{"type": "manual", "ref": "Example checklist"}]}])
        write_json(root / "assets-manual.example.json", [{"product": "Example", "where": "example.test", "note": "fixture"}])
        (root / "watch-prompt.example.md").write_text("Products: {{PRODUCTS}}", encoding="utf-8", newline="\n")
        errors = []
        with redirect_stderr(notice):
            assert check_coverage({"apps": [{"name": "Example"}]}, root / "coverage-map.json", errors)["covered"] == 1
            assert load_manual_assets(root / "assets-manual.json", errors)[0]["product"] == "Example"
            products = {"products": ["Example"]}
            write_xwatch_prompt(root / "x-watch-prompt.md", root / "prompt.md", products, errors)
        assert not errors and products["written"]
        assert (root / "prompt.md").read_text(encoding="utf-8") == "Products: Example"
        for real in ("coverage-map.json", "assets-manual.json", "x-watch-prompt.md"):
            (root / real).write_text("invalid", encoding="utf-8", newline="\n")
            assert example_fallback(root / real) == root / real
        assert example_fallback(root / "custom.json") == root / "custom.json"


STATS_LOCK = threading.Lock()
HTTP_STATS: dict = {}   # kind -> {"n": requests incl. retries, "sec": wall time incl. backoff, "fail": failed attempts}
PROC_STATS: dict = {}   # program -> {"n", "sec"}
DETAIL_STATS: dict = {"asked": 0, "cached": 0, "fetched": 0, "failed": 0}


def http_kind(url: str) -> str:
    if url.startswith(OSV_VULN.split("{")[0]):
        return "osv_vuln"
    return {OSV_BATCH: "osv_querybatch", OSV_QUERY: "osv_query", KEV_URL: "kev", NODE_INDEX: "node_index"}.get(url, urllib.parse.urlsplit(url).netloc)


def _add_stat(table: dict, key: str, sec: float, fail: bool = False) -> None:
    with STATS_LOCK:
        s = table.setdefault(key, {"n": 0, "sec": 0.0, "fail": 0})
        s["n"] += 1
        s["sec"] += sec
        s["fail"] += int(fail)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hostname: str | None = None):
        self.allowed_hostname = allowed_hostname

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise RuntimeError("HTTP redirect URL must use HTTPS")
        if self.allowed_hostname is not None and target.hostname != self.allowed_hostname:
            raise RuntimeError("HTTP redirect URL must use the allowed hostname")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Http:
    def __init__(self, ua: str, timeout: int):
        self.ua, self.timeout = ua, timeout

    def request(self, url: str, body=None, tries: int = 3, *, text: bool = False,
                allowed_hostname: str | None = None):
        t_start = time.time()
        try:
            return self._request(url, body, tries, text=text, allowed_hostname=allowed_hostname)
        finally:
            _add_stat(HTTP_STATS, http_kind(url), time.time() - t_start)

    def _request(self, url: str, body=None, tries: int = 3, *, text: bool = False,
                 allowed_hostname: str | None = None):
        if urllib.parse.urlsplit(url).scheme != "https":
            raise RuntimeError("HTTP request URL must use HTTPS")
        if allowed_hostname is not None and urllib.parse.urlsplit(url).hostname != allowed_hostname:
            raise RuntimeError("HTTP request URL must use the allowed hostname")
        opener = urllib.request.build_opener(SafeRedirectHandler(allowed_hostname))
        data = None if body is None else json.dumps(body).encode("utf-8")
        last = None
        for i in range(tries):
            if i:
                _add_stat(HTTP_STATS, http_kind(url) + "(retry)", 0.0, True)
            req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
            req.add_header("User-Agent", self.ua)
            req.add_header("Accept", "*/*" if text else "application/json")
            if data:
                req.add_header("Content-Type", "application/json")
            try:
                with opener.open(req, timeout=self.timeout) as r:
                    content = r.read().decode("utf-8")
                    return content if text else json.loads(content)
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code} {url}"
                if e.code in (400, 404):
                    break
            except Exception as e:  # network, timeout, JSON
                last = f"{type(e).__name__}: {e} ({url})"
            time.sleep(1.5 * (i + 1))
        raise RuntimeError(last)


def run(cmd: list[str], timeout: int = 120, *, env=None, encoding: str = "utf-8") -> tuple[int, str, str]:
    t_start = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, encoding=encoding, errors="replace", env=env)
    finally:
        _add_stat(PROC_STATS, Path(cmd[0]).name.lower(), time.time() - t_start)
    return p.returncode, (p.stdout or "").replace("\r", ""), (p.stderr or "").replace("\r", "")


# ---------- inventory ----------

PC_INVENTORY_KINDS = ("apps", "services", "listening", "containers_vms")
PACKAGE_KINDS = ("python_envs", "npm_global", "npm_locks")
COVERAGE_KINDS = (*PC_INVENTORY_KINDS, "vps_listening", "manual", "runtimes", *PACKAGE_KINDS, "vps_packages")
VPS_MAX_AGE = dt.timedelta(hours=13)


def inventory_failure(unverified: list, collector: str, reason: str) -> None:
    unverified.append({"kind": "inventory", "target": collector, "reason": reason})


def read_vps_inventory(path: Path, hosts: list[str]) -> dict:
    doc = read_json(path, None)
    if not isinstance(doc, dict) or type(doc.get("schema")) is not int or doc["schema"] != 1 or \
            doc.get("host") not in hosts:
        raise ValueError("schema 1 または host が許可リストにない")
    if not isinstance(doc.get("generated"), str):
        raise ValueError("generated が文字列ではない")
    generated = dt.datetime.fromisoformat(doc["generated"].replace("Z", "+00:00"))
    if generated.tzinfo is None:
        raise ValueError("generated にタイムゾーンが無い")
    if not isinstance(doc.get("containers"), list) or not isinstance(doc.get("listening"), list):
        raise ValueError("containers/listening は配列である必要がある")
    for env in [doc, *doc["containers"]]:
        if not isinstance(env, dict) or not isinstance(env.get("os"), dict) or \
                any(not isinstance(v, str) for v in env["os"].values()) or \
                not isinstance(env.get("packages"), list) or not isinstance(env.get("errors"), list) or \
                any(not isinstance(e, str) for e in env["errors"]):
            raise ValueError("OS・パッケージ・収集エラーの形式が不正")
        if env is not doc and (not isinstance(env.get("name"), str) or not env["name"].strip()):
            raise ValueError("コンテナ名が無い")
        for package in env["packages"]:
            fields = ("name", "version", "origin") if env["os"].get("ID") == "alpine" else \
                     ("name", "version", "source", "source_version")
            if not isinstance(package, dict) or any(not isinstance(package.get(k), str) or
                    not package[k].strip() for k in fields):
                raise ValueError("パッケージの名前・版・source/origin が不正")
    for listener in doc["listening"]:
        if not isinstance(listener, dict) or any(not isinstance(listener.get(k), str) or not listener[k]
                for k in ("address", "name")) or type(listener.get("port")) is not int or \
                not 0 <= listener["port"] <= 65535:
            raise ValueError("待受ポートの形式が不正")
    return doc


def load_vps_inventory(pattern: str, state_path: Path, unverified: list, hosts: list[str],
                       *, now: dt.datetime | None = None, inventory_filename: str = "vps-inventory.json",
                       impact_inventories: dict | None = None) -> dict | None:
    now = now or dt.datetime.now(dt.timezone.utc)

    def retain_snapshot(doc):
        # Impact uses collector time without the package matcher's age policy.
        if impact_inventories is not None:
            previous = impact_inventories.get(doc["host"])
            collected = dt.datetime.fromisoformat(doc["generated"].replace("Z", "+00:00"))
            if collected > now:
                return
            if previous is None or collected > dt.datetime.fromisoformat(previous["generated"].replace("Z", "+00:00")):
                impact_inventories[doc["host"]] = doc

    saved = None
    saved_time = None
    if state_path.exists():
        try:
            saved = read_vps_inventory(state_path, hosts)
            retain_snapshot(saved)
            saved_time = dt.datetime.fromisoformat(saved["generated"].replace("Z", "+00:00"))
            if saved_time > now or now - saved_time > VPS_MAX_AGE:
                raise ValueError("generated が未来または13時間超")
        except (OSError, ValueError) as e:
            saved, saved_time = None, None
            inventory_failure(unverified, "vps", f"保存済みの VPS 在庫が不正: {e}")
    # Validate all arrivals before selecting by content time, never filesystem arrival order.
    try:
        arrivals = [(p.stat().st_mtime_ns, p) for name in glob.glob(pattern)
                    if re.fullmatch(re.escape(Path(inventory_filename).stem) + r"(?: \([0-9]+\))?\.json", (p := Path(name)).name)
                    and p.is_file() and not p.is_symlink()]
        candidates = []
        for received_time, received in arrivals:
            try:
                doc = read_vps_inventory(received, hosts)
                if received.stat().st_mtime_ns != received_time:
                    raise ValueError("受信在庫が読み取り中に変更された")
                retain_snapshot(doc)
                generated = dt.datetime.fromisoformat(doc["generated"].replace("Z", "+00:00"))
                if generated > now or now - generated > VPS_MAX_AGE:
                    raise ValueError("generated が未来または13時間超")
                candidates.append((generated, received, received_time, doc))
            except (OSError, ValueError) as e:
                inventory_failure(unverified, "vps", f"受信在庫を取り込めない: {e}")
        if candidates:
            generated, newest, received_time, doc = max(candidates, key=lambda c: (c[0], c[1].name))
            if saved_time is None or generated > saved_time:
                if newest.stat().st_mtime_ns != received_time:
                    raise ValueError("受信在庫が読み取り中に変更された")
                write_json(state_path, doc)
                saved, saved_time = doc, generated
                if newest.stat().st_mtime_ns == received_time:
                    newest.unlink()
            for generated, received, received_time, doc in candidates:
                if generated < saved_time and doc["host"] == saved["host"] and received.exists() and \
                        received.stat().st_mtime_ns == received_time:
                    received.unlink()
    except (OSError, ValueError) as e:
        inventory_failure(unverified, "vps", f"受信在庫を取り込めない: {e}")
    if saved is None and not state_path.exists():
        inventory_failure(unverified, "vps", "保存済みの VPS 在庫が無い")
    return saved


def vps_ecosystem(release: dict) -> str | None:
    distro, version = release.get("ID"), release.get("VERSION_ID", "")
    if not re.fullmatch(r"\d+(?:\.\d+)*", version):
        return None
    if distro == "ubuntu":
        lts = "LTS" in (release.get("VERSION", "") + " " + release.get("PRETTY_NAME", ""))
        return f"Ubuntu:{version}" + (":LTS" if lts else "")
    if distro == "debian":
        return f"Debian:{version}"
    if distro == "alpine" and len(version.split(".")) >= 2:
        return "Alpine:v" + ".".join(version.split(".")[:2])
    return None


def vps_package_usage(doc: dict | None, unverified: list, inactive: list | None = None) -> list[tuple]:
    usage = set()
    if doc is None:
        return []
    for env, label in [(doc, "vps:host"), *((c, "vps:container:" + c["name"]) for c in doc["containers"])]:
        for error in env["errors"]:
            inventory_failure(unverified, "vps", f"{label}: {error}")
        eco = vps_ecosystem(env["os"])
        if not eco:
            inventory_failure(unverified, "vps", f"{label}: OSV 対応 OS・版を確認できない")
            continue
        # Source linux also builds ordinary tools/libraries. Only versioned kernel binaries
        # may be excluded, and containers never inherit the host's running-kernel filter.
        kernel = env.get("kernel")
        base = re.fullmatch(r"\d+\.\d+\.\d+(?:-\d+)?(?:[-+][a-zA-Z0-9.-]+)?", kernel) if isinstance(kernel, str) else None
        inactive_versions = set()
        kernel_unverified = False
        for package in env["packages"]:
            name = package["origin"] if eco.startswith("Alpine:") else package["source"]
            version = package["version"] if eco.startswith("Alpine:") else package["source_version"]
            binary_kernel = re.fullmatch(
                r"linux-(?:image-(?:unsigned-)?|modules-extra-|modules-|headers-|tools-|cloud-tools-|buildinfo-)"
                r"(\d+\.\d+\.\d+(?:-\d+)?(?:-[a-z][a-z0-9-]*)?)", package["name"])
            if label == "vps:host" and binary_kernel:
                embedded = binary_kernel[1]
                if base and kernel != embedded and not kernel.startswith(embedded + "-"):
                    inactive_versions.add(version)
                    continue
                if not base and not kernel_unverified:
                    inventory_failure(unverified, "vps", f"{label}: kernel が無いか形式不明のためカーネルの稼働版は未確認")
                    kernel_unverified = True
            usage.add((eco, name, version, label, name))
        if inactive_versions and inactive is not None:
            versions = sorted(inactive_versions)
            inactive.append({"env": label, "versions": versions,
                             "summary": "動いていないカーネルのパッケージ: " + ", ".join(versions)})
    return sorted(usage)


def vps_labels(doc: dict | None) -> list[str]:
    return ["vps:host", *("vps:container:" + c["name"] for c in doc["containers"])] if doc else []


def record_vps_packages(state: dict, doc: dict | None, usage: list[tuple], hits: dict) -> set[tuple]:
    # An empty environment entry records an attempted first scan, not successful packages.
    # Legacy environment-only history cannot prove any package was checked; do not rebaseline it.
    if doc is None:
        return set()
    previous = state.get("vps_packages_seen")
    if previous is None:
        previous = {label: [] for label in vps_labels(doc)} if "vps_labels_seen" in state or "last_run" in state else {}
    initial = set()
    for label in vps_labels(doc):
        checked = {(u[0], u[1]) for u in usage if u[3] == label and hits.get(u[:3]) is not None}
        if label not in previous:
            initial.update((label, eco, name) for eco, name in checked)
        previous[label] = sorted({tuple(p) for p in previous.get(label, [])} | checked)
    state["vps_packages_seen"] = previous
    state.pop("vps_labels_seen", None)
    return initial


def vps_osv_summary(findings: list[dict], labels: list[str]) -> str:
    parts = []
    for label in labels:
        rows = [f for f in findings if f["env"] == label]
        actionable = [f for f in rows if f["actionable"]]
        packages = len({f["package"] for f in actionable})
        fixed = f"{packages} パッケージ（{len(actionable)} 件）" if packages else "0 件 "
        parts.append(f"{label} 修正版あり {fixed}/ 修正なし {sum(f['unfixed'] for f in rows)} 件"
                     f" / 詳細未確認 {sum(not f['detail_ok'] for f in rows)} 件")
    return "VPS: " + "、".join(parts)


def vps_listening_assets(doc: dict | None, private_networks=("100.64.0.0/10",)) -> list[dict]:
    assets = []
    for listener in doc["listening"] if doc else []:
        address = listener["address"]
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0].strip("[]"))
            ip = (ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else ip
            private = ip.is_loopback or any(ip in ipaddress.ip_network(network) for network in private_networks)
        except ValueError:
            private = False  # Wildcards or unrecognized binds are conservatively exposed.
        assets.append({"kind": "vps_listening", "name": listener["name"], "version": "",
                       "address": address, "port": listener["port"], "exposed": not private})
    return assets


def selftest_vps_arrivals() -> None:
    now = dt.datetime(2026, 11, 6, 12, tzinfo=dt.timezone.utc)
    doc = {"schema": 1, "host": "fixture", "generated": now.isoformat(),
           "os": {}, "packages": [], "containers": [], "listening": [], "errors": []}
    with tempfile.TemporaryDirectory(prefix=".vps-arrivals-", dir=HERE) as temporary:
        root = Path(temporary)
        saved = root / "state" / "inventory.json"
        pattern = str(root / "vps-inventory*.json")
        backup = root / "vps-inventory-backup.json"
        write_json(backup, doc)
        assert load_vps_inventory(pattern, saved, [], ["fixture"], now=now) is None
        assert backup.exists() and not saved.exists(), "backup must never be ingested/deleted"
        write_json(saved, doc)
        for index, generated in enumerate((now - dt.timedelta(hours=1), now,
                                          now + dt.timedelta(seconds=1), now - dt.timedelta(hours=14),
                                          "invalid")):
            received = root / f"vps-inventory ({index}).json"
            candidate = {**doc, "generated": generated.isoformat() if isinstance(generated, dt.datetime) else generated}
            write_json(received, candidate)
            assert load_vps_inventory(pattern, saved, [], ["fixture"], now=now) == doc, "saved inventory regressed"
            assert read_json(saved, None) == doc
            assert received.exists() is (index != 0), "Only strictly older arrivals may be cleaned"
        # Content time, not filesystem arrival order, selects the replacement.
        newer = {**doc, "generated": (now + dt.timedelta(minutes=1)).isoformat()}
        received = root / "vps-inventory (99).json"
        write_json(received, newer)
        assert load_vps_inventory(pattern, saved, [], ["fixture"], now=now + dt.timedelta(minutes=1)) == newer
        assert not received.exists() and backup.exists()
        for invalid in ("invalid", (now + dt.timedelta(hours=1)).isoformat(),
                        (now - dt.timedelta(hours=14)).isoformat()):
            write_json(saved, {**doc, "generated": invalid})
            write_json(received, doc)
            errors, snapshots = [], {}
            assert load_vps_inventory(pattern, saved, errors, ["fixture"], now=now,
                                      impact_inventories=snapshots) == doc, \
                "invalid saved inventory must not suppress a valid arrival"
            assert read_json(saved, None) == doc and not received.exists() and errors
            assert snapshots == {"fixture": doc}
        custom = root / "custom.example.test (1).json"
        unrelated = root / "customXexampleXtest.json"
        write_json(custom, doc)
        write_json(unrelated, doc)
        custom_saved = root / "state" / "custom.json"
        assert load_vps_inventory(str(root / "custom*.json"), custom_saved, [], ["fixture"], now=now,
                                  inventory_filename="custom.example.test.json") == doc
        assert not custom.exists() and unrelated.exists()

    for with_genuine in (True, False):
        with tempfile.TemporaryDirectory(prefix=".vps-dates-", dir=HERE) as temporary:
            root = Path(temporary)
            saved = root / "saved.json"
            future = root / "vps-inventory (1).json"
            write_json(future, {**doc, "generated": (now + dt.timedelta(hours=1)).isoformat()})
            if with_genuine:
                write_json(root / "vps-inventory.json", doc)
            for _ in range(2):
                errors, snapshots = [], {}
                loaded = load_vps_inventory(str(root / "vps-inventory*.json"), saved, errors,
                                            ["fixture"], now=now, impact_inventories=snapshots)
                assert loaded == (doc if with_genuine else None)
                assert snapshots == ({"fixture": doc} if with_genuine else {})
                assert any("generated が未来または13時間超" in e["reason"] for e in errors)
                assert future.exists()
                assert read_json(saved, None) == (doc if with_genuine else None)

    for location in ("saved.json", "vps-inventory.json"):
        for hours in (-14, 1):
            with tempfile.TemporaryDirectory(prefix=".vps-impact-dates-", dir=HERE) as temporary:
                root = Path(temporary)
                saved = root / "saved.json"
                candidate = {**doc, "generated": (now + dt.timedelta(hours=hours)).isoformat()}
                write_json(root / location, candidate)
                for _ in range(2):
                    errors, snapshots = [], {}
                    assert load_vps_inventory(str(root / "vps-inventory*.json"), saved, errors,
                                              ["fixture"], now=now, impact_inventories=snapshots) is None
                    assert snapshots == ({"fixture": candidate} if hours < 0 else {}), \
                        "impact must retain old inventories but exclude future inventories"
                    assert any("generated が未来または13時間超" in e["reason"] for e in errors)
                    assert read_json(root / location, None) == candidate
                    assert saved.exists() is (location == "saved.json")


def selftest_vps_details() -> None:
    usage = [(eco, "fixture", "1", env, "fixture") for eco, env in
             [("Ubuntu:26.04:LTS", "vps:host"), ("PyPI", "pc")]]
    hits = {u[:3]: ["missing-" + u[0]] for u in usage}
    state = {"seen": {}, "sigs": {}, "vps_labels_seen": ["vps:host"]}
    first = build_osv_findings(usage, hits, {})
    mark_new_findings(first, state, set(), "first")
    assert all(not f["new"] and not f.get("unfixed") for f in first), "missing detail is unknown"
    remember_findings(first, state)
    assert not state["seen"] and not state["sigs"]
    state["seen"] = {f["key"]: "legacy-unknown" for f in first}
    remember_findings(first, state)
    assert not state["seen"]  # An old scan's unknown details must not suppress recovery either.
    cache = {ids[0]: {"id": ids[0], "affected": [{"package": {"ecosystem": eco, "name": name},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2"}]}]}]}
             for (eco, name, ver), ids in hits.items()}
    second = build_osv_findings(usage, hits, cache)
    mark_new_findings(second, state, set(), "second")
    assert all(f["new"] for f in second), "recovered detail must notify"
    remember_findings(second, state)
    assert len(state["seen"]) == 2


def selftest_vps_kernel() -> None:
    common = {"version": "6.8.0-40.40", "source": "linux", "source_version": "6.8.0-40.40"}
    ordinary = ["linux-libc-dev", "linux-tools-common", "bpftool", "linux-firmware", "linux-generic"]
    prefixes = ["linux-image-", "linux-modules-", "linux-modules-extra-", "linux-headers-",
                "linux-tools-", "linux-cloud-tools-", "linux-buildinfo-"]
    packages = [{**common, "name": n} for n in ordinary + [p + "6.8.0-40-generic" for p in prefixes]]
    doc = {"kernel": "6.8.0-42-generic", "os": {"ID": "ubuntu", "VERSION_ID": "24.04"},
           "packages": packages, "containers": [], "errors": []}
    inactive = []
    rows = vps_package_usage(doc, [], inactive)
    assert rows and rows[0][1:3] == ("linux", common["source_version"]), "non-kernel binaries lost"
    assert len(inactive) == 1
    for prefix in prefixes:
        for binary, excluded in [(prefix + "6.8.0-42-generic", False),
                                  (prefix + "6.8.0-420-generic", True),
                                  (prefix + "6.8.0-42-aws", True)]:
            doc["packages"] = [{**common, "name": binary}]
            assert bool(vps_package_usage(doc, [])) is not excluded, binary
    doc["containers"] = [{"name": "fixture", **{k: doc[k] for k in ("os", "packages", "errors")}}]
    assert any(u[3] == "vps:container:fixture" for u in vps_package_usage(doc, []))


def selftest_vps_partial_baseline() -> None:
    eco = "Ubuntu:26.04:LTS"
    doc = {"os": {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION": "26.04 LTS"},
           "containers": [], "errors": []}
    usage = [(eco, name, "1", "vps:host", name) for name in ("package-a", "package-b")]
    state = {"seen": {}, "sigs": {}}
    initial = record_vps_packages(state, doc, usage, {usage[0][:3]: [], usage[1][:3]: None})
    assert initial == {("vps:host", eco, "package-a")}
    assert state["vps_packages_seen"] == {"vps:host": [(eco, "package-a")]}
    state = json.loads(json.dumps(state))  # Exercise the persisted list representation.
    detail = {"id": "R7-fixed", "affected": [{"package": {"ecosystem": eco, "name": "package-b"},
              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2"}]}]}]}
    findings = build_osv_findings(usage, {usage[1][:3]: [detail["id"]]}, {detail["id"]: detail})
    first_a = {**findings[0], "package": "package-a"}
    mark_new_findings([first_a], {}, set(), "first", vps_baseline=initial)
    assert not first_a["new"], "successfully checked first-run packages still baseline"
    mark_new_findings(findings, state, set(), "second")
    assert findings[0]["new"], "package B recovering from a failed initial query must notify"
    remember_findings(findings, state)
    record_vps_packages(state, doc, usage, {usage[0][:3]: [], usage[1][:3]: [detail["id"]]})
    mark_new_findings(findings, state, set(), "third")
    assert not findings[0]["new"], "successful findings must not notify twice"
    for legacy in ({"vps_labels_seen": []}, {"vps_labels_seen": ["vps:host"]}, {"last_run": "earlier"}):
        baseline = record_vps_packages(legacy, doc, usage, {usage[1][:3]: [detail["id"]]})
        mark_new_findings(findings, legacy, set(), "recovered", vps_baseline=baseline)
        assert findings[0]["new"] and not baseline, "legacy environment history is not package evidence"
    failed = {}
    assert not record_vps_packages(failed, doc, usage, {})
    baseline = record_vps_packages(failed, doc, usage, {usage[1][:3]: [detail["id"]]})
    mark_new_findings(findings, failed, set(), "recovered", vps_baseline=baseline)
    assert findings[0]["new"] and not baseline


def selftest_vps_security_facts() -> None:
    import runpy
    from unittest.mock import patch

    collector = runpy.run_path(str(HERE / "vps" / "sec-inventory.py"))
    assert "security_facts" in collector, "security_facts collector is missing"
    collect = collector["security_facts"]
    boot = {"booted_at": "2026-11-04T00:00:00Z", "boot_id": "fixture-boot"}
    files = {"/proc/stat": "cpu 1 2 3 4\nbtime 1793750400\nprocesses 42\n",
             "/proc/sys/kernel/random/boot_id": "fixture-boot\n"}

    def fixture(text="table inet filter\ntable ip nat\ntable ip6 filter\n", *, source=None, error=None):
        source = files if source is None else source

        def read_text(path):
            if path not in source:
                raise FileNotFoundError("fixture file missing")
            return source[path]

        def command(args):
            assert args == ["nft", "list", "tables"]
            if error is not None:
                raise error
            return text

        return collect(read_text, command)

    observed = fixture()
    assert observed == {"boot": boot, "nft_tables": [
        {"family": "inet", "name": "filter"}, {"family": "ip", "name": "nat"},
        {"family": "ip6", "name": "filter"}], "errors": {}}
    assert fixture("table arp filter\ntable bridge filter\ntable netdev ingress\n")["nft_tables"] == [
        {"family": family, "name": name} for family, name in
        [("arp", "filter"), ("bridge", "filter"), ("netdev", "ingress")]]
    for output in ("", "\n \t\n"):
        assert fixture(output)["nft_tables"] == []
    for source in ({"/proc/stat": files["/proc/stat"]},
                   {**files, "/proc/sys/kernel/random/boot_id": " \n"}):
        partial = fixture(source=source)
        assert partial["boot"] == {"booted_at": boot["booted_at"]} and partial["errors"]["boot"]
        assert partial["nft_tables"] == observed["nft_tables"]
    for stat in (None, "cpu 1 2\n", "btime invalid\n", "btime -1\n", "btime 1.5\n",
                 "btime 0\nbtime 1\n", "btime " + "9" * 40 + "\n"):
        source = {**files}
        if stat is None:
            del source["/proc/stat"]
        else:
            source["/proc/stat"] = stat
        failed = fixture(source=source)
        assert "boot" not in failed and failed["errors"]["boot"]
        assert failed["nft_tables"] == observed["nft_tables"]
    assert fixture(source={**files, "/proc/stat": "btime 0\n"})["boot"]["booted_at"] == "1970-01-01T00:00:00Z"
    failures = [fixture(error=error) for error in
                (FileNotFoundError("nft missing"), RuntimeError("nft exited 1: fixture denied"))]
    failures.extend(fixture(output) for output in
                    ("table inet filter\ninvalid\n", "table unknown filter\n", "table inet\n",
                     "table inet filter extra\n", 'table inet "unterminated\n'))
    for failed in failures:
        assert failed["boot"] == boot and failed["errors"]["nft_tables"] and "nft_tables" not in failed
    both_failed = fixture(source={}, error=FileNotFoundError("nft missing"))
    assert set(both_failed) == {"errors"} and set(both_failed["errors"]) == {"boot", "nft_tables"}

    # Exercise the actual arrival importer and impact checker using only generated fixtures.
    at = "2026-11-06T12:00:00Z"
    now = dt.datetime.fromisoformat(at.replace("Z", "+00:00"))
    host = "host.example.test"
    claims = [{"id": "boot", "field": "our_exposure", "text": "fixture boot",
               "source_url": "https://example.test/observation", "source_type": "own_observation",
               "observed_at": at, "observed_by": "parent", "observation_scope": "inventory_only",
               "check": {"kind": "vps_fact", "host_alias": host, "fact": "boot", "expected": boot}},
              {"id": "table", "field": "mitigation", "text": "fixture table",
               "source_url": "https://example.test/observation", "source_type": "own_observation",
               "observed_at": at, "observed_by": "parent", "persistence": "lost_on_reboot",
               "check": {"kind": "vps_fact", "host_alias": host, "fact": "nft_table",
                         "family": "inet", "table": "filter",
                         "expected": {"family": "inet", "name": "filter", "present": True}}}]
    data = {"items": [{"id": "fixture-vps", "title": "fixture", "kind": "advisory",
                       "refs": ["https://example.test/observation"], "claims": claims}]}

    def forbidden_fetch(_):
        raise AssertionError("fixture must not fetch")

    with tempfile.TemporaryDirectory(prefix=".vps-facts-", dir=HERE) as temporary:
        root = Path(temporary)
        for facts, expected in ((observed, (impact.Confirmed, impact.Confirmed)),
                                (fixture(""), (impact.Confirmed, impact.Changed)),
                                (failures[0], (impact.Confirmed, impact.Unverified)),
                                (both_failed, (impact.Unverified, impact.Unverified))):
            document = {"schema": 1, "host": host, "generated": at, "os": {}, "kernel": "fixture",
                        "packages": [], "containers": [], "listening": [], "errors": [],
                        "security_facts": facts}
            received, saved = root / "vps-inventory.json", root / "saved.json"
            if saved.exists():
                saved.unlink()
            write_json(received, document)
            snapshots, errors = {}, []
            assert load_vps_inventory(str(received), saved, errors, [host], now=now,
                                      impact_inventories=snapshots) == document
            assert not errors and not received.exists() and read_json(saved, None) == document
            with patch.object(impact, "load_items", return_value=(data, [])):
                batch = impact.check_all(root, scan_id="fixture-collector", started_at=at,
                                         inventory=snapshots, fetch=forbidden_fetch)
            outcomes = [claim.outcome for claim in batch.assessment.items[0].claims]
            assert len(outcomes) == len(expected) and all(
                isinstance(outcome, kind) for outcome, kind in zip(outcomes, expected)), outcomes
            for outcome in outcomes:
                if isinstance(outcome, (impact.Confirmed, impact.Changed)):
                    assert outcome.evidence.observed_at == at and outcome.evidence.scope == "snapshot"
            if facts.get("nft_tables") == []:
                assert outcomes[1].evidence.value.present is False
    print("PASS VPS security_facts fixtures and importer/impact agreement")


def selftest_vps() -> int:
    selftest_vps_security_facts()
    selftest_vps_partial_baseline()
    selftest_vps_arrivals()
    selftest_vps_details()
    selftest_vps_kernel()
    import copy
    import runpy
    from unittest.mock import patch

    now = dt.datetime(2026, 11, 6, 12, tzinfo=dt.timezone.utc)
    host_package = {"name": "openssh-server", "version": "1:10.2p1-1ubuntu1",
                    "source": "openssh", "source_version": "1:10.2p1-1ubuntu1"}
    hosts = ["primary.example.test", "secondary.example.test"]
    fixture = {"schema": 1, "host": hosts[0], "generated": now.isoformat(),
               "os": {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION": "26.04 LTS"},
               "kernel": "fixture", "packages": [host_package, {**host_package, "name": "openssh-client"}],
               "listening": [{"address": address, "port": port, "name": name} for address, port, name in
                             [("0.0.0.0", 22, "sshd"), ("100.64.0.7", 8644, "hermes"),
                              ("127.0.0.1", 5432, "postgres")]],
               "containers": [{"id": "fixture", "name": "alpine-ssh", "image": "alpine:3.23", "image_id": "sha256:fixture",
                               "os": {"ID": "alpine", "VERSION_ID": "3.23.1"},
                               "packages": [{"name": "openssh-server", "version": "10.2_p1-r0", "origin": "openssh"}],
                               "errors": []}], "errors": []}
    expected = {("Ubuntu:26.04:LTS", "openssh", "1:10.2p1-1ubuntu1"),
                ("Alpine:v3.23", "openssh", "10.2_p1-r0")}
    unverified = []
    usage = vps_package_usage(fixture, unverified)
    assert {u[:3] for u in usage} == expected and len(usage) == 2 and not unverified
    assert {u[3] for u in usage} == {"vps:host", "vps:container:alpine-ssh"}

    class FixtureHttp:
        def request(self, url, body):
            assert url == OSV_BATCH
            actual = {(q["package"]["ecosystem"], q["package"]["name"], q["version"]) for q in body["queries"]}
            assert actual == expected
            return {"results": [{"vulns": [{"id": "fixture-vuln"}]} for _ in body["queries"]]}

    assert all(osv_query(FixtureHttp(), sorted(expected), 1000, unverified).values()) and not unverified
    # Kernel filtering happens before OSV; one source version can represent many binaries.
    kernels = copy.deepcopy(fixture)
    kernels["kernel"] = "7.0.0-42-generic"
    kernels["packages"] += [{"name": name, "version": version, "source": source, "source_version": version}
                            for name, source, version in [
                                ("linux-modules-7.0.0-38-generic", "linux", "7.0.0-38.38"),
                                ("linux-headers-7.0.0-38", "linux", "7.0.0-38.38"),
                                ("linux-image-7.0.0-38-generic", "linux-signed", "7.0.0-38.38"),
                                ("linux-modules-7.0.0-42-generic", "linux", "7.0.0-42.42")]]
    inactive = []
    kernel_usage = vps_package_usage(kernels, [], inactive)
    assert ("Ubuntu:26.04:LTS", "linux", "7.0.0-42.42", "vps:host", "linux") in kernel_usage
    assert not any(u[2] == "7.0.0-38.38" for u in kernel_usage)
    assert inactive == [{"env": "vps:host", "versions": ["7.0.0-38.38"],
                         "summary": "動いていないカーネルのパッケージ: 7.0.0-38.38"}]
    image_sources = ["linux", "linux-signed", "linux-meta"] + [
        f"linux-{prefix}{flavour}{suffix}" for prefix in ("", "signed-", "meta-")
        for flavour in ("hwe", "oem", "lowlatency", "aws", "azure", "gcp", "kvm", "generic")
        for suffix in ("", "-6.12", "-24.04a")]
    ordinary_sources = ["linux-base", "linux-firmware", "linux-atm", "linux-tools",
                        "linux-generic_extra", "linux-awsX", "linux-signed-other"]
    scope = copy.deepcopy(fixture)
    scope["kernel"] = "7.0.0-42-generic"
    scope["packages"] = [{"name": source, "source": source, "version": "4.15ubuntu5",
                          "source_version": "4.15ubuntu5"} for source in image_sources + ordinary_sources]
    container = {"name": "debian-headers", "os": {"ID": "debian", "VERSION_ID": "13"},
                 "packages": [{"name": "linux-libc-dev", "source": "linux", "version": "6.12.74-2",
                               "source_version": "6.12.74-2"}], "errors": []}
    scope["containers"] = [container]
    for own_kernel in (None, "7.0.0-42-generic", "invalid"):
        if own_kernel is not None:
            container["kernel"] = own_kernel
        inactive, unknown = [], []
        scoped_usage = vps_package_usage(scope, unknown, inactive)
        assert {u[1] for u in scoped_usage if u[3] == "vps:host"} == set(image_sources + ordinary_sources)
        assert ("Debian:13", "linux", "6.12.74-2", "vps:container:debian-headers", "linux") in scoped_usage
        assert not inactive and not unknown
    scope.pop("kernel")
    unknown = []
    assert len(vps_package_usage(scope, unknown, [])) == len(image_sources + ordinary_sources) + 1
    assert not unknown  # Unversioned names are evaluated even when their source is linux.
    kernels.pop("kernel")
    unknown = []
    assert any(u[2] == "7.0.0-38.38" for u in vps_package_usage(kernels, unknown, []))
    assert len(unknown) == 1 and "kernel" in unknown[0]["reason"]

    def detail(vid, eco, name, fixed=None):
        events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
        return {"id": vid, "modified": "2026-11-06T12:00:00Z", "affected": [
            {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}

    host_key, alpine_key = sorted(expected, reverse=True)
    deb_key = ("Debian:13", "openssl", "3.5.1-1")
    details = [detail("U-fixed", *host_key[:2], "2"), detail("U-unfixed", *host_key[:2]),
               detail("A-fixed", *alpine_key[:2], "2"), detail("D-fixed", *deb_key[:2], "4"),
               detail("D-unfixed", *deb_key[:2]), detail("P-unfixed", "PyPI", "fixture")]
    fixture_cache = {d["id"]: d for d in details}
    fixture_usage = usage + [(*deb_key, "vps:container:debian", "openssl"),
                             ("PyPI", "fixture", "1", "python", "fixture")]
    fixture_hits = {host_key: ["U-fixed", "U-unfixed"], alpine_key: ["A-fixed"],
                    deb_key: ["D-fixed", "D-unfixed"], ("PyPI", "fixture", "1"): ["P-unfixed"]}
    fs = build_osv_findings(fixture_usage, fixture_hits, fixture_cache)
    state = {"seen": {}, "sigs": {}}
    first_packages = {(u[3], u[0], u[1]) for u in fixture_usage if u[3].startswith("vps:")}
    mark_new_findings(fs, state, set(), "first", vps_baseline=first_packages)
    assert [f["id"] for f in fs if f["new"]] == ["P-unfixed"]
    assert all(f["unfixed"] == (not f["fixed"]) for f in fs if is_distro(f["ecosystem"]))
    labels = ["vps:host", "vps:container:alpine-ssh", "vps:container:debian"]
    summary = vps_osv_summary(fs, labels)
    assert summary == ("VPS: vps:host 修正版あり 1 パッケージ（1 件）/ 修正なし 1 件 / 詳細未確認 0 件、"
                       "vps:container:alpine-ssh 修正版あり 1 パッケージ（1 件）/ 修正なし 0 件 / 詳細未確認 0 件、"
                       "vps:container:debian 修正版あり 1 パッケージ（1 件）/ 修正なし 1 件 / 詳細未確認 0 件")
    assert vps_osv_summary([], ["vps:host"]) == "VPS: vps:host 修正版あり 0 件 / 修正なし 0 件 / 詳細未確認 0 件"
    state["seen"] = {f["key"]: "first" for f in fs}
    state["sigs"] = {f["key"]: f["sig"] for f in fs}
    record_vps_packages(state, fixture, usage, {k: [] for k in expected})
    assert set(state["vps_packages_seen"]) == set(labels[:2])
    mark_new_findings(fs, state, set(), "second")
    assert not any(f["new"] for f in fs)  # Previously observed findings remain known.
    # An unfixed advisory gaining a fix is actionable again; still-unfixed changes never notify.
    for f in fs:
        if f["id"] == "U-unfixed":
            f.update(fixed=["3"], actionable=True, unfixed=False, sig="fixed-now")
        elif f["id"] == "D-unfixed":
            f["sig"] = "changed-unfixed"
    mark_new_findings(fs, state, set(), "third")
    assert [f["id"] for f in fs if f["new"]] == ["U-unfixed"]
    fixture_cache["U-new"] = detail("U-new", *host_key[:2], "4")
    fixture_cache["U-new-unfixed"] = detail("U-new-unfixed", *host_key[:2])
    new_hits = build_osv_findings(usage, {host_key: ["U-new", "U-new-unfixed"]}, fixture_cache)
    mark_new_findings(new_hits, state, set(), "third")
    assert [f["id"] for f in new_hits if f["new"]] == ["U-new"]
    mark_new_findings(new_hits, state, set(), "third", baseline=True)
    assert not any(f["new"] for f in new_hits)
    failed_state = {}
    record_vps_packages(failed_state, fixture, usage, {k: None for k in expected})
    assert failed_state["vps_packages_seen"] == {label: [] for label in labels[:2]}
    record_vps_packages(failed_state, fixture, [], {})
    assert failed_state["vps_packages_seen"] == {label: [] for label in labels[:2]}

    # Three distro advisories in two pages need two package requests, never three /vulns calls.
    calls = []
    distro_details = [detail("D-1", *deb_key[:2], "4"), detail("D-2", *deb_key[:2]),
                      detail("D-3", *deb_key[:2], "5")]
    batch_rows = {deb_key: [{"id": d["id"], "modified": d["modified"]} for d in distro_details]}

    class DetailHttp:
        def request(self, url, body):
            calls.append((url, dict(body)))
            assert url == OSV_QUERY and body["package"] == {"ecosystem": deb_key[0], "name": deb_key[1]}
            assert body["version"] == deb_key[2]
            if "page_token" not in body:
                return {"vulns": distro_details[:2], "next_page_token": "page-2"}
            assert body["page_token"] == "page-2"
            return {"vulns": distro_details[2:]}

    detail_cache, errors = {}, []
    assert distro_vuln_details(DetailHttp(), batch_rows, detail_cache, errors) == set()
    assert len(calls) == 2 and not errors and set(detail_cache) == {"D-1", "D-2", "D-3"}
    for d in detail_cache.values():
        d[FETCHED] = "2000-01-01T00:00:00+00:00"
    assert distro_vuln_details(DetailHttp(), batch_rows, detail_cache, errors) == set()
    assert len(calls) == 2  # Unchanged modified dates reuse even TTL-expired details.
    distro_details[0] = detail("D-1", *deb_key[:2], "6")
    distro_details[0]["modified"] = "2026-11-07T12:00:00Z"
    batch_rows[deb_key][0]["modified"] = distro_details[0]["modified"]
    detail_cache["D-1"][FETCHED] = now_iso()
    assert distro_vuln_details(DetailHttp(), batch_rows, detail_cache, errors) == {"D-1"}
    assert len(calls) == 4 and not errors  # A changed advisory refreshes even within the TTL.
    calls.clear()
    inline_rows = {deb_key: distro_details}
    assert not distro_vuln_details(DetailHttp(), inline_rows, {}, errors) and not calls

    class BrokenDetailHttp:
        def request(self, url, body):
            return {"vulns": []}  # A partial/missing result must not claim successful detail acquisition.

    missing = {}
    distro_vuln_details(BrokenDetailHttp(), batch_rows, missing, errors)
    assert not missing and errors[-1]["kind"] == "osv_detail"
    # Ordinary ecosystems still get ID details and retain the original no-fix notification behavior.
    ordinary = [detail("P-1", "PyPI", "fixture"), detail("N-1", "npm", "fixture")]

    class OrdinaryHttp:
        def request(self, url):
            calls.append(url)
            return next(d.copy() for d in ordinary if url == OSV_VULN.format(d["id"]))

    ordinary_cache = {}
    assert not vuln_details(OrdinaryHttp(), {"P-1", "N-1"}, ordinary_cache, [])
    assert set(calls) == {OSV_VULN.format(d["id"]) for d in ordinary}
    ordinary_fs = build_osv_findings([("PyPI", "fixture", "1", "python", "fixture"),
                                      ("npm", "fixture", "1", "npm -g", "fixture")],
                                     {("PyPI", "fixture", "1"): ["P-1"], ("npm", "fixture", "1"): ["N-1"]},
                                     ordinary_cache)
    mark_new_findings(ordinary_fs, {}, set(), "first")
    assert all(f["new"] and "actionable" not in f and "unfixed" not in f for f in ordinary_fs)
    assert vps_ecosystem({"ID": "ubuntu", "VERSION_ID": "26.10"}) == "Ubuntu:26.10"
    assert vps_ecosystem({"ID": "debian", "VERSION_ID": "13"}) == "Debian:13"
    assets = vps_listening_assets(fixture)
    assert [(a["address"], a["port"]) for a in assets if a["exposed"]] == [("0.0.0.0", 22)]
    for address, exposed in [("::1", False), ("[::1]", False), ("2001:db8:1::7]%tailscale0", False),
                             ("2001:db8:1::1", False), ("0.0.0.0", True), ("::", True),
                             ("192.0.2.1", True), ("100.64.0.0", False), ("100.127.255.255", False),
                             ("203.0.113.1", True), ("2001:db8:2::1", True), ("::ffff:127.0.0.1", False)]:
        doc = {"listening": [{"address": address, "port": 22, "name": "fixture"}]}
        assert vps_listening_assets(doc, ["100.64.0.0/10", "2001:db8:1::/48"])[0]["exposed"] is exposed, address

    with tempfile.TemporaryDirectory(prefix=".vps-selftest-", dir=HERE) as temporary:
        root = Path(temporary)
        downloads = root / "Downloads"
        downloads.mkdir()
        state_path = root / "state" / "vps" / "vps-inventory.json"
        pattern = str(downloads / "vps-inventory*.json")

        def arrive(name, document, mtime):
            path = downloads / name
            write_json(path, document)
            os.utime(path, ns=(mtime, mtime))
            return path

        old = arrive("vps-inventory.json", {**fixture, "kernel": "old",
                     "generated": (now - dt.timedelta(hours=1)).isoformat()}, 1_000_000_000)
        other_host = arrive("vps-inventory-other.json", {**fixture, "host": hosts[1]}, 1_000_000_000)
        unrelated = arrive("vps-inventory-notes.json", {"notes": "not an inventory"}, 1_000_000_000)
        newest = arrive("vps-inventory (1).json", fixture, 2_000_000_000)
        tied = arrive("vps-inventory (0).json", fixture, 2_000_000_000)
        assert load_vps_inventory(pattern, state_path, unverified, hosts, now=now) == fixture and not unverified
        assert not newest.exists() and not old.exists()
        assert unrelated.exists() and other_host.exists() and tied.exists()
        # An invalid newest arrival is preserved and the last state is still usable.
        broken = arrive("vps-inventory (2).json", {}, 3_000_000_000)
        unverified = []
        assert load_vps_inventory(pattern, state_path, unverified, hosts, now=now) == fixture
        assert broken.exists() and unverified and "受信" in unverified[0]["reason"]
        no_arrivals = str(root / "absent" / "*.json")
        assert load_vps_inventory(no_arrivals, state_path, [], hosts, now=now) == fixture
        for age, accepted in [(13, True), (14, False)]:
            write_json(state_path, {**fixture, "generated": (now - dt.timedelta(hours=age)).isoformat()})
            unverified = []
            loaded = load_vps_inventory(no_arrivals, state_path, unverified, hosts, now=now)
            assert (loaded is not None) is accepted
            if not accepted:
                assert vps_package_usage(loaded, []) == [] and vps_listening_assets(loaded) == []
                assert unverified == [{"kind": "inventory", "target": "vps",
                                       "reason": "保存済みの VPS 在庫が不正: generated が未来または13時間超"}]
        for bad in [{}, {**fixture, "host": "unknown-host"}, {**fixture, "generated": "invalid"}, {**fixture, "packages": [{}]},
                    {**fixture, "schema": True}, {**fixture, "generated": now.replace(tzinfo=None).isoformat()}]:
            write_json(state_path, bad)
            unverified = []
            assert load_vps_inventory(no_arrivals, state_path, unverified, hosts, now=now) is None
            assert unverified[0]["target"] == "vps" and "不正" in unverified[0]["reason"]
        state_path.unlink()
        unverified = []
        assert load_vps_inventory(no_arrivals, state_path, unverified, hosts, now=now) is None
        assert "無い" in unverified[0]["reason"]
        map_path = root / "coverage-map.json"
        write_json(map_path, [])
        coverage = check_coverage({"vps_listening": assets, "vps_packages": usage,
                                   "listening": [{"name": "pc", "exposed": True}]}, map_path, [])
        assert coverage["covered"] == 2 and coverage["uncovered"][0]["kind"] == "vps_listening"
        write_json(map_path, [{"match": "sshd", "kinds": ["vps_listening"],
                               "routes": [{"type": "manual", "ref": "fixture"}]}])
        assert check_coverage({"vps_listening": assets}, map_path, [])["covered"] == 1
        partial = copy.deepcopy(fixture)
        partial["containers"][0]["errors"] = ["cat failed"]
        partial["containers"][0]["packages"] = []
        unverified = []
        assert len(vps_package_usage(partial, unverified)) == 1 and "cat failed" in unverified[0]["reason"]

    # Test the Linux parsers and argv without executing Linux commands on this PC.
    collector = runpy.run_path(str(HERE / "vps" / "sec-inventory.py"))
    with tempfile.TemporaryDirectory(prefix=".vps-config-", dir=HERE) as temporary:
        config_path = Path(temporary) / "local-config.json"
        settings = {"inventory_filename": "custom.example.test.json", "taildrop_target": "pc.example.test:"}
        write_json(config_path, {"vps": settings})
        with patch.dict(os.environ, SEC_INVENTORY_CONFIG=str(config_path)):
            assert collector["local_settings"]() == settings
            for invalid in ({"taildrop_target": ""}, {**settings, "inventory_filename": "../outside.json"}):
                write_json(config_path, {"vps": invalid})
                try:
                    collector["local_settings"]()
                except ValueError:
                    pass
                else:
                    raise AssertionError("Invalid VPS settings accepted")
    assert collector["os_release"]('ID=ubuntu\nVERSION="26.04 LTS"\n')["VERSION"] == "26.04 LTS"
    status = ("Package: openssh-server\nStatus: install ok installed\nVersion: 1:10.2p1-1ubuntu1\n"
              "Source: openssh (1:10.2p1-1ubuntu1)\n\n"
              "Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n")
    assert collector["dpkg_status"](status) == [host_package]
    assert collector["dpkg_status"]("Package: curl\nStatus: install ok installed\nVersion: 1\n") == [
        {"name": "curl", "version": "1", "source": "curl", "source_version": "1"}]
    apk = "P:openssh-server\nV:10.2_p1-r0\no:openssh\n\n"
    assert collector["apk_packages"](apk) == fixture["containers"][0]["packages"]
    namespace = collector["containers"].__globals__
    commands = []

    def fake_command(args):
        commands.append(args)
        if args[:2] == ["docker", "ps"]:
            assert "-a" in args, "stopped containers missing"
            return "id1\nid2\n"
        if args[:2] == ["docker", "inspect"]:
            return json.dumps({"id": args[-1], "name": "/" + args[-1], "image": "alpine", "image_id": "sha256:fixture",
                               "state": "running" if args[-1] == "id1" else "exited"})
        if args[2] == "id2":
            raise RuntimeError("container stopped")
        assert args[:4] == ["docker", "exec", "id1", "cat"] and len(args) == 5
        return "ID=alpine\nVERSION_ID=3.23.1\n" if args[-1] == "/etc/os-release" else apk

    with patch.dict(namespace, command=fake_command):
        rows = collector["containers"]()
    assert rows[0]["packages"] == fixture["containers"][0]["packages"]
    assert rows[1]["errors"] == ["停止中で中を読めない"] and rows[1]["state"] == "exited"
    assert not any(args[:3] == ["docker", "exec", "id2"] for args in commands)
    assert not any("sh" in args or "-c" in args for args in commands)
    with patch.dict(namespace, command=lambda args: "LISTEN 0 128 [::1]:22 [::]:* users:((\"sshd\",pid=1,fd=3))\n"):
        assert collector["listening"]() == [{"address": "::1", "port": 22, "name": "sshd"}]
    with patch.dict(namespace, command=lambda args: "installed\topenssh-server\t1\topenssh\t2\nconfig-files\told\t1\told\t1\n"):
        assert collector["host_packages"]() == [{"name": "openssh-server", "version": "1", "source": "openssh", "source_version": "2"}]
    print("VPS 自己テスト成功（OSV・カーネル除外・修正版判定・環境初回記録・集計・詳細一括取得・公開ポート・鮮度・受信選択・安全な整理・収集解析・コンテナ失敗）")
    return 0


def scan_apps(unverified: list) -> list[dict]:
    apps = []
    try:
        import winreg
    except ImportError as e:
        inventory_failure(unverified, "apps", str(e))
        return scan_appx(unverified)
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, "HKLM", uninstall, "machine"),
             (winreg.HKEY_LOCAL_MACHINE, "HKLM", uninstall.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\", 1), "machine"),
             (winreg.HKEY_CURRENT_USER, "HKCU", uninstall, "user")]

    def value(key, name, default=""):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except FileNotFoundError:
            return default

    for hive, label, path, scope in roots:
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except FileNotFoundError:
            continue  # An absent Uninstall key is valid (especially under HKCU).
        except OSError as e:
            inventory_failure(unverified, "apps", f"{label}\\{path}: {e}")
            continue
        with root:
            try:
                for i in range(winreg.QueryInfoKey(root)[0]):
                    sub = winreg.EnumKey(root, i)
                    try:
                        with winreg.OpenKey(root, sub) as key:
                            name = value(key, "DisplayName")
                            if not isinstance(name, str) or not name.strip() or value(key, "SystemComponent", 0) == 1:
                                continue
                            apps.append({"name": name.strip(), "version": str(value(key, "DisplayVersion")),
                                         "publisher": str(value(key, "Publisher")), "scope": scope, "source": "registry",
                                         "source_key": f"{label}\\{path}\\{sub}"})
                    except OSError as e:
                        inventory_failure(unverified, "apps", f"{label}\\{path}\\{sub}: {e}")
            except OSError as e:
                inventory_failure(unverified, "apps", f"{label}\\{path}: {e}")
    return apps + scan_appx(unverified)


def scan_appx(unverified: list) -> list[dict]:
    rows = powershell_inventory(
        "$rows = @(Get-AppxPackage | Select-Object @{n='name';e={$_.Name}}, "
        "@{n='version';e={$_.Version}}, @{n='publisher';e={$_.Publisher}}, "
        "@{n='framework';e={[bool]$_.IsFramework}}); ConvertTo-Json -InputObject $rows -Compress",
        "apps.appx", ("name", "version", "publisher", "framework"), unverified)
    apps = []
    for row in rows:
        if not isinstance(row["framework"], bool) or any(not isinstance(row[k], str)
                                                       for k in ("version", "publisher")):
            inventory_failure(unverified, "apps.appx", "Appx の版・発行者・framework の形が不正")
            continue
        user_app = re.fullmatch(r"Microsoft\.Windows\.(?:Photos|Camera|Calculator|SoundRecorder|Alarms|FeedbackHub|Notepad|Terminal)",
                                row["name"], re.I)
        if row["framework"] or (row["name"].casefold().startswith("microsoft.windows.") and not user_app):
            continue
        apps.append({"name": row["name"], "version": row["version"], "publisher": row["publisher"], "source": "appx"})
    return apps


def powershell_inventory(script: str, collector: str, fields: tuple, unverified: list) -> list[dict]:
    try:
        rc, out, err = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                          "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
                          "$ErrorActionPreference = 'Stop'; " + script])
        if rc:
            raise RuntimeError(f"PowerShell 終了コード {rc}: {err.strip()[:300]}")
        rows = json.loads(out)
        if not isinstance(rows, list) or any(not isinstance(row, dict) or
                                            any(f not in row for f in fields) for row in rows):
            raise ValueError("在庫 JSON の形が想定と違う")
        if any(not isinstance(row.get("name"), str) or not row["name"].strip() for row in rows):
            raise ValueError("在庫の名前を取得できない")
        return rows
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        inventory_failure(unverified, collector, str(e))
        return []


def scan_services(unverified: list) -> list[dict]:
    return powershell_inventory(
        "$rows = @(Get-CimInstance Win32_Service -Filter \"State='Running'\" | "
        "Select-Object @{n='name';e={$_.Name}}, @{n='display_name';e={$_.DisplayName}}, "
        "@{n='executable_path';e={$_.PathName}}, @{n='process_id';e={$_.ProcessId}}); "
        "ConvertTo-Json -InputObject $rows -Compress", "services",
        ("name", "display_name", "executable_path", "process_id"), unverified)


def scan_listening(unverified: list) -> list[dict]:
    rows = powershell_inventory(
        "$services = @{}; Get-CimInstance Win32_Service | Where-Object {$_.ProcessId -gt 0} | ForEach-Object { "
        "$id = [int]$_.ProcessId; $path = [string]$_.PathName; "
        r"if ($path -match '^\s*(?:[\x22]([^\x22]+\.exe)[\x22]|(.+?\.exe))') { "
        "$exe = if ($Matches[1]) {$Matches[1]} else {$Matches[2]}; "
        "$exe = [Environment]::ExpandEnvironmentVariables($exe); "
        r"if ($exe.StartsWith('\??\')) {$exe = $exe.Substring(4)}; "
        "if (-not $services.ContainsKey($id)) {$services[$id] = $exe} "
        "elseif ($services[$id] -ne $exe) {$services[$id] = ''} } }; "
        "$processes = @{}; Get-CimInstance Win32_Process | ForEach-Object {$processes[[int]$_.ProcessId] = $_}; "
        "$paths = @{}; $methods = @{}; "
        "$rows = @(Get-NetTCPConnection | ForEach-Object { "
        "$id = [int]$_.OwningProcess; $proc = $processes[$id]; "
        "if (-not $paths.ContainsKey($id)) { $path = $services[$id]; $method = 'Win32_Service'; "
        "if (-not $path) {$path = $proc.ExecutablePath; $method = 'Win32_Process'}; "
        "if (-not $path) {try {$path = (Get-Process -Id $id -ErrorAction Stop).Path} catch {$path = $null}; $method = 'Get-Process'}; "
        "if (-not $path) {$path = ''; $method = ''}; $paths[$id] = $path; $methods[$id] = $method }; "
        "[pscustomobject]@{name=if ($proc) {$proc.Name -replace '\\.exe$',''} else {'PID ' + $_.OwningProcess}; "
        "local_address=$_.LocalAddress; port=$_.LocalPort; process_id=$_.OwningProcess; "
        "state=[string]$_.State; remote_address=$_.RemoteAddress; remote_port=$_.RemotePort; "
        "executable_path=[string]$paths[$id]; path_method=if ($paths[$id]) {$methods[$id]} else {''}; process_readable=[bool]$proc} }); ConvertTo-Json -InputObject $rows -Compress",
        "listening", ("name", "local_address", "port", "process_id", "process_readable", "state", "remote_address", "remote_port", "executable_path", "path_method"), unverified)
    listen_states = ("listen", "listening", "2")
    valid = []
    for row in rows:
        if not isinstance(row["local_address"], str) or type(row["port"]) is not int or not 0 <= row["port"] <= 65535:
            inventory_failure(unverified, "listening", "待ち受けアドレス・ポートの形が想定と違う")
            continue
        if row["port"] == 0:
            continue
        if str(row["state"]).casefold() not in listen_states:
            if not (row["state"] in (None, "") and row["remote_port"] == 0 and
                    row["remote_address"] in ("0.0.0.0", "::")):
                continue
            peers = [other for other in rows if other is not row and
                     other["process_id"] == row["process_id"] and other["port"] == row["port"]]
            if peers:
                explicit_listener, remote_ports = False, []
                try:
                    bind = ipaddress.ip_address(row["local_address"].split("%", 1)[0])
                    for connected in peers:
                        local = ipaddress.ip_address(connected["local_address"].split("%", 1)[0])
                        if bind.version != local.version or not (bind.is_unspecified or local.is_unspecified or bind == local):
                            continue
                        if str(connected["state"]).casefold() in listen_states:
                            explicit_listener = True
                            continue
                        remote = ipaddress.ip_address(connected["remote_address"].split("%", 1)[0])
                        if (not local.is_unspecified and not remote.is_unspecified and
                                bind.version == remote.version and (bind.is_unspecified or bind == local) and
                                type(connected["remote_port"]) is int and 0 < connected["remote_port"] <= 65535):
                            remote_ports.append(connected["remote_port"])
                except (ValueError, AttributeError):
                    remote_ports = []
                complete = len(remote_ports) == len(peers)
                if not explicit_listener and complete and row["port"] >= 49152 and all(p < 49152 for p in remote_ports):
                    continue
                if not explicit_listener and not (complete and row["port"] < 49152 and all(p >= 49152 for p in remote_ports)):
                    row["listener_uncertain"] = True
                    inventory_failure(unverified, "listening", f"{row['name']}:{row['port']}: State が無いため待受か未確認")
        if not row.get("executable_path"):
            row["path_method"] = ""
        row["exposed"] = row["local_address"] not in ("127.0.0.1", "::1")
        if not row.pop("process_readable"):
            inventory_failure(unverified, "listening", f"{row['name']}: 持ち主のプロセス名を取得できない")
        # Preserve collector keys for existing consumers and expose the saved inventory names.
        row["address"] = row["local_address"]
        row["path"] = row.get("executable_path") or ""
        valid.append(row)
    return valid


def console_width(text: str) -> int:
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def console_columns(line: str, starts: list[int]) -> list[str]:
    fields = [""] * len(starts)
    position, column = 0, 0
    for char in line:
        while column + 1 < len(starts) and position >= starts[column + 1]:
            column += 1
        fields[column] += char
        position += console_width(char)
    return [field.strip() for field in fields]


def parse_winget_upgrade(output: str) -> dict:
    lines = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output).splitlines()
    updates, starts, tables = [], None, 0
    for index, line in enumerate(lines):
        if re.fullmatch(r"\s*-{5,}\s*", line):
            header = lines[index - 1] if index else ""
            labels = list(re.finditer(r"\S+", header))
            if len(labels) != 5 or labels[1][0].casefold() != "id":
                raise ValueError("winget の表見出しを解釈できない")
            starts = [console_width(header[:m.start()]) for m in labels]
            tables += 1
            continue
        if starts is None:
            continue
        if not line.strip() or re.match(r"\d+\s+(?:アップグレード|個の|upgrades?\b|packages?\b)", line.strip(), re.I):
            starts = None
            continue
        # A later table's header is followed by its own separator; do not parse it as a row.
        if index + 1 < len(lines) and re.fullmatch(r"\s*-{5,}\s*", lines[index + 1]):
            continue
        name, ident, version, available, source = console_columns(line, starts)
        if not all((name, ident, version, available, source)) or not re.fullmatch(r"[\w.+-]+", ident) or \
                not re.fullmatch(r"\S+", source):
            raise ValueError("winget の表の行を解釈できない")
        updates.append({"name": name, "id": ident, "version": version, "available": available, "source": source})
    no_updates = any(text in output for text in ("No available upgrade found", "No installed package found matching input criteria",
                                               "利用可能なアップグレードが見つかりません", "入力条件に一致するインストール済みパッケージが見つかりません"))
    if not tables and not no_updates:
        raise ValueError("winget の更新一覧を確認できない")
    if tables and not updates:
        raise ValueError("winget の更新表に解析できた行が無い")
    unknown = re.search(r"(\d+)\s+(?:個のパッケージのバージョン番号を判別できません|packages? have version numbers that cannot be determined)", output)
    return {"verified": True, "updates": updates, "unknown_versions": int(unknown[1]) if unknown else 0}


def scan_winget(unverified: list) -> dict:
    try:
        rc, out, err = run(["winget.exe", "upgrade", "--accept-source-agreements", "--disable-interactivity"], encoding="utf-8")
        parsed = parse_winget_upgrade(out)
        # APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE is a successful empty list.
        if rc and not (not parsed["updates"] and rc & 0xffffffff == 0x8a15002b):
            raise RuntimeError(f"winget 終了コード {rc}: {err.strip()[:200]}")
        if parsed["unknown_versions"]:
            unverified.append({"kind": "winget", "target": "versions", "reason": f"版を判別できないパッケージ {parsed['unknown_versions']} 件"})
        return parsed
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        unverified.append({"kind": "winget", "target": "upgrade", "reason": str(e)})
        return {"verified": False, "updates": [], "unknown_versions": None}


def check_winget(inventory: dict, coverage: dict, unverified: list) -> dict:
    snapshot = scan_winget(unverified)  # Exactly one subprocess per scan.
    checks, watched_ids = [], set()
    watched = {a["name"].casefold() for a in coverage.get("routed_assets", []) if a["kind"] == "apps"}
    for app in inventory.get("apps", []):
        name = normalize_product(app["name"], app.get("version", "")).casefold()
        candidates = [r for r in snapshot["updates"] if name in
                      (normalize_product(r["name"], r["version"]).casefold(), r["id"].casefold())]
        matches = []
        for row in candidates:
            installed = app.get("version", "").strip()
            if installed and installed == row["version"]:
                matches.append(row)
                continue
            try:
                ver = app_version(installed)
                if row["version"].startswith("<"):
                    same = numeric_app_range(row["version"]) and in_range(ver, row["version"]) is True
                else:
                    same = ver == app_version(row["version"])
                if same:
                    matches.append(row)
            except ValueError:
                pass
        if app["name"].casefold() in watched:
            watched_ids.update(r["id"] for r in matches)
        known = snapshot["verified"] and not snapshot["unknown_versions"] and not candidates and bool(app.get("version"))
        if candidates and not matches:
            unverified.append({"kind": "winget", "target": app["name"], "reason": "更新一覧と在庫の版が一致しない・比較できない"})
        checks.append({"name": app["name"], "version": app.get("version", ""),
                       "update_available": True if matches else False if known else None,
                       "updates": matches,
                       "result": "更新あり" if matches else "更新一覧に無し（winget 管理対象かは未確認）" if known else "確認できなかった"})
    return {**snapshot, "checks": checks, "watched_updates": len(watched_ids)}


def winget_summary(result: dict) -> str:
    if not result["verified"]:
        return "winget: 確認できなかった（更新一覧を取得・解析できない）"
    return f"winget: 更新あり {len(result['updates'])} 件（うち見張り対象 {result['watched_updates']} 件）"


def parse_wsl_inventory(output: bytes | str) -> list[dict]:
    text = output.decode("utf-16le") if isinstance(output, bytes) else output
    lines = [line.strip().lstrip("\ufeff").strip() for line in text.splitlines() if line.strip()]
    # Column headings and state labels are localized; parse rows from the numeric version at the end.
    rows = []
    for line in lines:
        match = re.fullmatch(r"\*?\s*(\S+)\s+(.+?)\s+([12])", line)
        if match:
            rows.append({"name": match[1], "state": match[2].strip(), "source": "wsl"})
        elif rows or not re.search(r"\bNAME\b|名前", line, re.I):
            raise ValueError("WSL 一覧の形が想定と違う（ディストリビューション無しを含め未確認）")
    if not lines:
        raise ValueError("WSL 一覧が空")
    return rows


def scan_containers_vms(unverified: list) -> list[dict]:
    rows = []
    try:
        rc, out, err = run(["wsl.exe", "-l", "-v"], encoding="utf-16le")
        if rc:
            raise RuntimeError(f"WSL 終了コード {rc}: {(err or out).strip()[:300]}")
        rows.extend(parse_wsl_inventory(out))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        inventory_failure(unverified, "containers_vms.wsl", str(e))
    vms = powershell_inventory(
        "$rows = @(Get-VM | Select-Object @{n='name';e={$_.Name}}, @{n='state';e={$_.State.ToString()}}); "
        "ConvertTo-Json -InputObject $rows -Compress", "containers_vms.hyperv", ("name", "state"), unverified)
    rows.extend({**vm, "source": "hyperv"} for vm in vms)
    try:
        # --host overrides DOCKER_HOST/context so inventory cannot contact a remote daemon.
        rc, out, _ = run(["docker", "--host", "npipe:////./pipe/docker_engine", "ps", "-a", "--format", "json"])
        if rc:
            raise RuntimeError("Docker が止まっている")
        containers = []
        for line in out.splitlines():
            doc = json.loads(line)
            if not isinstance(doc, dict) or not isinstance(doc.get("Names"), str) or not doc["Names"] or \
                    not isinstance(doc.get("State"), str) or not doc["State"]:
                raise ValueError("Docker 一覧の形が想定と違う")
            if not isinstance(doc.get("Image"), str) or not doc["Image"]:
                raise ValueError("Docker のイメージ名を取得できない")
            containers.append({"name": doc["Names"], "state": doc["State"], "source": "docker", "image": doc["Image"]})
        rows.extend(containers)
    except ValueError as e:
        inventory_failure(unverified, "containers_vms.docker", f"Docker の一覧を解析できない: {e}")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        inventory_failure(unverified, "containers_vms.docker", f"Docker が止まっている（確認できない: {type(e).__name__}）")
    return rows


def load_manual_assets(path: Path, unverified: list) -> list[dict]:
    try:
        path = example_fallback(path)
        items = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(items, list) or any(not isinstance(item, dict) or
                any(not isinstance(item.get(k), str) or not item[k].strip()
                    for k in ("product", "where", "note")) for item in items):
            raise ValueError("手動資産は product・where・note を持つ配列である必要がある")
        return items
    except (OSError, ValueError) as e:
        inventory_failure(unverified, "manual", str(e))
        return []


def coverage_assets(inventory: dict) -> list[dict]:
    listeners = inventory.get("listening", [])
    assets = []
    for kind in PC_INVENTORY_KINDS:
        for asset in inventory.get(kind, []):
            exposed = bool(asset.get("exposed"))
            if kind == "services":
                path = asset.get("executable_path") or ""
                executable = re.match(r'^"([^"]+)"|^(.+?\.exe)(?:\s|$)', path, re.I)
                process_name = Path((executable[1] or executable[2]) if executable else "").stem.casefold()
                exposed = any(l.get("exposed") and (
                    (asset.get("process_id") and asset["process_id"] == l.get("process_id")) or
                    l["name"].casefold() in (asset["name"].casefold(), process_name)) for l in listeners)
            assets.append({"kind": kind, "name": asset["name"], "version": asset.get("version") or "",
                           "exposed": exposed, "executable_path": asset.get("executable_path") or "",
                           "publisher": asset.get("publisher") or "", "source": asset.get("source") or "",
                           **({"address": asset.get("local_address") or asset.get("address") or "",
                               "path": asset.get("executable_path") or asset.get("path") or "",
                               "port": asset.get("port"), "process_id": asset.get("process_id"),
                               "path_method": asset.get("path_method") or ""} if kind == "listening" else {}),
                           **({"listener_uncertain": True} if asset.get("listener_uncertain") else {}),
                           **({"image_repository": asset.get("image", "").split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0],
                               "contents_inventoried": False, "source": asset.get("source")}
                              if kind == "containers_vms" else {})})
    assets.extend({"kind": "manual", "name": item["product"], "version": "", "exposed": False}
                  for item in inventory.get("manual", []))
    assets.extend(inventory.get("vps_listening", []))
    return assets


def package_runtime_assets(inventory: dict) -> list[dict]:
    assets = []
    assets.extend({"kind": "vps_packages", "name": package[1]} for package in inventory.get("vps_packages", []))
    for env in inventory.get("python_envs", {}).values():
        assets.extend({"kind": "python_envs", "name": name} for name in env["packages"])
    assets.extend({"kind": "npm_global", "name": name}
                  for name in inventory.get("npm_global", {}).get("packages", {}))
    for lock in inventory.get("npm_locks", {}).values():
        assets.extend({"kind": "npm_locks", "name": name} for name in lock["packages"])
    for name, version in inventory.get("runtimes", {}).items():
        present = (any(v.get("version") for v in version) if isinstance(version, list)
                   else bool(version and version != "なし"))
        if present:
            assets.append({"kind": "runtimes", "name": name})
    return assets


def appx_publisher_cn(publisher: str) -> str:
    # Commas inside quoted/escaped values belong to the value, not another DN component.
    component = re.compile(r'\s*([A-Za-z][A-Za-z0-9.-]*)\s*=\s*((?:[^,+"\\]|\\.|"(?:[^"\\]|\\.)*")*)([,+]|$)')
    offset, names = 0, []
    while offset < len(publisher):
        match = component.match(publisher, offset)
        if not match or (match[3] and match.end() == len(publisher)):
            return ""
        if match[1].casefold() == "cn":
            value = match[2].strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            value = re.sub(r'\\([0-9a-fA-F]{2}|.)',
                           lambda m: chr(int(m[1], 16)) if len(m[1]) == 2 else m[1], value)
            names.append(value)
        offset = match.end()
    return names[0] if len(names) == 1 else ""


def coverage_rule_matches(asset: dict, rule: tuple) -> bool:
    pattern, path_pattern, kinds, publisher_pattern = rule
    identity = (asset.get("image_repository", "") if asset.get("source") == "docker" else asset["name"]) if asset["kind"] == "containers_vms" else asset["name"]
    if publisher_pattern:
        return bool(asset["kind"] in kinds and asset["kind"] == "apps" and asset.get("source") == "appx" and
                    pattern.search(identity) and publisher_pattern.fullmatch(appx_publisher_cn(asset.get("publisher") or "")))
    return asset["kind"] in kinds and bool(pattern.search(identity) or
        (asset["kind"] in ("services", "listening") and path_pattern and asset.get("executable_path") and
         path_pattern.search(asset["executable_path"])))


def app_advisory_source(app: dict, entry: dict) -> bool:
    return app.get("source") in entry.get("advisory_sources", ["registry"])


def app_route_checked(app: dict, route: dict, advisory_checks: list, winget: dict) -> bool:
    if route["type"] == "winget":
        return bool(winget.get("verified") and any(
            c["name"] == app["name"] and c["version"] == app["version"] and
            type(c["update_available"]) is bool for c in winget.get("checks", [])))
    try:
        version = app_version(app["version"])
    except ValueError:
        return False
    checks = [c for c in advisory_checks if c["runtime"] == app["name"] and
              c["repo"] == route["ref"] and c["version"] == version]
    return bool(checks) and all(c["result"] in ("該当あり", "該当なし") for c in checks)


def check_coverage(inventory: dict, map_path: Path, unverified: list, *,
                   app_advisory_checks: list | None = None, winget: dict | None = None,
                   osv_hits: dict | None = None, extra_rules: list | None = None) -> dict:
    failed = sorted({u["target"].split(".")[0] for u in unverified if u["kind"] == "inventory"})
    result = {"covered": None, "uncovered": [], "unverified_kinds": failed, "matched_entries": [],
              "routed_assets": [], "winget_only": []}
    try:
        map_path = example_fallback(map_path)
        entries = json.loads(map_path.read_text(encoding="utf-8"))
        if not isinstance(entries, list):
            raise ValueError("対応表は配列である必要がある")
        entries = entries + (extra_rules or [])
        rules = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("match"), str) or not entry["match"] or \
                    ("path_match" in entry and (not isinstance(entry["path_match"], str) or not entry["path_match"])) or \
                    ("publisher_match" in entry and (not isinstance(entry["publisher_match"], str) or not entry["publisher_match"])) or \
                    ("product" in entry and (not isinstance(entry["product"], str) or not entry["product"].strip())) or \
                    ("advisory_package" in entry and (not isinstance(entry["advisory_package"], str) or
                     not re.search(r"[a-z0-9]", entry["advisory_package"], re.I))) or \
                    ("advisory_sources" in entry and (not isinstance(entry["advisory_sources"], list) or
                     not entry["advisory_sources"] or any(s not in ("registry", "appx") for s in entry["advisory_sources"]))) or \
                    not isinstance(entry.get("kinds"), list) or not entry["kinds"] or \
                    any(k not in COVERAGE_KINDS for k in entry["kinds"]) or \
                    not isinstance(entry.get("routes"), list) or not entry["routes"] or \
                    any(not isinstance(r, dict) or r.get("type") not in
                        ("osv", "runtime_advisory", "github_advisories", "winget", "release", "kev", "x_watch", "manual") or
                        not isinstance(r.get("ref"), str) or not r["ref"].strip() for r in entry["routes"]):
                raise ValueError("対応表の項目・経路の形が想定と違う")
            if any(r["type"] == "github_advisories" and not re.fullmatch(r"[\w.-]+/[\w.-]+", r["ref"])
                   for r in entry["routes"]):
                raise ValueError("github_advisories の ref は owner/repo が必要")
            rules.append((re.compile(entry["match"], re.I),
                          re.compile(entry["path_match"], re.I) if "path_match" in entry else None, entry["kinds"],
                          re.compile(entry["publisher_match"], re.I) if "publisher_match" in entry else None))
    except (OSError, ValueError, re.error) as e:
        unverified.append({"kind": "coverage", "target": str(map_path), "reason": f"対応表を確認できない: {e}"})
        result["unverified_kinds"] = sorted(set(failed) | {"coverage_map"})
        return result
    # Packages already have OSV coverage; map matches only add product display names.
    covered = sum(len(env["packages"]) for env in inventory.get("python_envs", {}).values())
    covered += len(inventory.get("npm_global", {}).get("packages", {}))
    covered += sum(len(versions) for lock in inventory.get("npm_locks", {}).values()
                   for versions in lock["packages"].values())
    covered += len(inventory.get("vps_packages", []))
    assets = coverage_assets(inventory)
    apps = [a for a in assets if a["kind"] == "apps"]
    matched = set()
    for asset in assets + package_runtime_assets(inventory):
        matches = {i for i, rule in enumerate(rules) if coverage_rule_matches(asset, rule)}
        if asset["kind"] == "containers_vms" and asset.get("source") == "hyperv":
            matches.update(i for i, rule in enumerate(rules) if asset["kind"] in rule[2] and
                           rule[0].search(asset["name"]) and all(r["type"] == "manual" for r in entries[i]["routes"]))
        matched.update(matches)
        if asset["kind"] in (*PACKAGE_KINDS, "vps_packages", "runtimes"):
            continue  # Existing package/runtime checks retain responsibility for their coverage.
        routes = [r for i in sorted(matches) for r in entries[i]["routes"]]
        if asset["kind"] == "apps":
            routes = [({**r, "advisory_package": entries[i].get("advisory_package") or
                        entries[i].get("product") or normalize_product(asset["name"], asset["version"])}
                       if r["type"] == "github_advisories" else r)
                      for i in sorted(matches) for r in entries[i]["routes"]
                      if r["type"] != "github_advisories" or app_advisory_source(asset, entries[i])]
            if matches and not routes:
                result["uncovered"].append({**asset, "unverified": True, "reason": "製品の版として使える収集元を確認できない"})
                continue
        if asset["kind"] in ("listening", "services"):
            registered_routes = routes
            routes = [r for i in sorted(matches) for r in entries[i]["routes"]
                      if r["type"] not in ("github_advisories", "winget") or any(
                          coverage_rule_matches(app, rules[i]) and
                          (r["type"] != "github_advisories" or app_advisory_source(app, entries[i])) and
                          app_route_checked(app, r, app_advisory_checks or [], winget or {}) for app in apps)]
            if matches and not routes:
                result["uncovered"].append({**asset, "unverified": True, "routes": registered_routes,
                                            "reason": "同じルールのアプリと今回の検査成功を確認できない"})
                continue
        if asset["kind"] == "vps_listening":
            registered_routes = routes
            vps = inventory.get("vps")
            routes = [r for r in routes if r["type"] != "osv" or (
                vps and "vps" not in failed and not vps.get("errors") and any(
                    p[3] == "vps:host" and p[1] == r["ref"] and (osv_hits or {}).get(p[:3]) is not None and
                    not any(u["kind"] in ("osv", "osv_detail") and u["target"] == f"{p[0]}:{p[1]}@{p[2]}"
                            for u in unverified)
                    for p in inventory.get("vps_packages", [])))]
            if matches and not routes:
                result["uncovered"].append({**asset, "unverified": True, "routes": registered_routes,
                                            "reason": "VPS ホストの対応パッケージと今回の OSV 照会成功を確認できない"})
                continue
        if asset.get("listener_uncertain"):
            result["uncovered"].append({**asset, "unverified": True, "routes": routes,
                                        "reason": "State が無いため待受か未確認"})
            continue
        if asset["kind"] == "containers_vms" and not asset["contents_inventoried"]:
            result["uncovered"].append({**asset, "unverified": True, "routes": routes,
                                        "reason": "中を確認していない（contents unverified）"})
            continue
        if asset["kind"] == "manual" and any(r["type"] == "osv" for r in routes):
            vps = inventory.get("vps")
            host_packages = [p for p in inventory.get("vps_packages", []) if p[3] == "vps:host"]
            verified = bool(vps and "vps" not in failed and not vps.get("errors") and host_packages)
            if asset["name"] == "Linux カーネル":
                verified = verified and bool(vps.get("kernel")) and any(p[1].startswith("linux") for p in host_packages)
            if not verified:
                reason = "VPS 在庫・対象パッケージを確認できない"
                result["uncovered"].append({**asset, "unverified": True, "routes": routes, "reason": reason})
                unverified.append({"kind": "coverage", "target": asset["name"], "reason": reason})
                result["unverified_kinds"] = sorted(set(result["unverified_kinds"]) | {"vps"})
                continue
        if matches:
            result["routed_assets"].append({**asset, "routes": routes})
            if asset["kind"] == "apps" and all(r["type"] == "winget" for r in routes):
                result["winget_only"].append(asset["name"])
            covered += 1
        else:
            result["uncovered"].append(asset)
    result["matched_entries"] = [entries[i] for i in sorted(matched)]
    result["covered"] = covered
    result["uncovered"].sort(key=lambda a: (not a["exposed"], a["kind"] != "vps_listening", a["kind"] != "services",
                                          a["kind"] != "listening", a["name"].casefold(), a["kind"]))
    return result


def coverage_keys(coverage: dict) -> set[str]:
    # Versions/ports changing are not newly installed unwatched products.
    return {f"{a['kind']}|{a['name'].casefold()}" for a in coverage["uncovered"]}


def coverage_changes(coverage: dict, state: dict, baseline: bool = False) -> int:
    if coverage["covered"] is None or "coverage_seen" not in state or baseline:
        return 0
    return len(coverage_keys(coverage) - set(state["coverage_seen"]))


def coverage_summary(coverage: dict) -> str:
    if coverage["covered"] is None:
        return "見張っていない: 確認できなかった（coverage-map.json を読めない・不正）"
    assets = coverage["uncovered"]
    names = list(dict.fromkeys(a["name"] for a in assets))[:10]
    return (f"見張っていない: {len(assets)} 件（外から届く {sum(a['exposed'] for a in assets)} 件）"
            + (": " + "、".join(names) if names else "")
            + (" / 在庫を確認できない種類: " + "、".join(coverage["unverified_kinds"])
               if coverage["unverified_kinds"] else "")
            + (" / 版の新旧だけ見ている: " + "、".join(coverage.get("winget_only", []))
               if coverage.get("winget_only") else ""))


def normalize_product(name: str, version: str = "") -> str:
    name = re.sub(r"\((?:user|(?:x64|x86|arm64|aarch64|32-bit|64-bit)(?:[ ,/]+(?:x64|x86|arm64|32-bit|64-bit))*)\)",
                  "", name, flags=re.I)
    name = re.sub(r"\b(?:x64|x86|arm64|aarch64|32-bit|64-bit)\b", "", name, flags=re.I)
    name = re.sub(r"\s*-\s*[a-z]{2}-[a-z]{2}\s*$", "", name, flags=re.I)
    if version:
        name = re.sub(r"(?<!\S)" + re.escape(version) + r"(?=\s|\)|$)", "", name, flags=re.I)
    name = re.sub(r"\b(?:version\s+|v)?\d+(?:\.\d+)+(?:[+_-][\w.]+)?\b", "", name, flags=re.I)
    name = re.sub(r"\(\s*\)", "", name)
    return re.sub(r"\s+", " ", name).strip(" -–,")


def readable_match(pattern: str) -> str:
    # A compatibility fallback for old maps; explicit product names avoid regex syntax in prompts.
    name = pattern.split("|")[0]
    name = re.sub(r"\(\?:[^)]*\)\??", "", name)
    name = re.sub(r"\\[bBsSdDwW]", " ", name)
    name = re.sub(r"\\(.)", r"\1", name)
    return normalize_product(re.sub(r"[\^$?*+()\[\]{}]", "", name))


def unique_products(names) -> list[str]:
    unique = {}
    for name in names:
        name = name.strip()
        if name:
            unique.setdefault(name.casefold(), name)
    return list(unique.values())


def xwatch_products(coverage: dict, manual: list[dict]) -> dict:
    missing = [entry["match"] for entry in coverage["matched_entries"] if "product" not in entry]
    manual_names = unique_products(item["product"] for item in manual)
    manual_keys = {name.casefold() for name in manual_names}
    inventory_names = unique_products(
        [entry.get("product") or readable_match(entry["match"]) for entry in coverage["matched_entries"]]
        + [normalize_product(asset["name"], asset["version"]) for asset in coverage["uncovered"] if asset["kind"] == "apps"])
    inventory_names = [name for name in inventory_names if name.casefold() not in manual_keys]
    return {"products": inventory_names + manual_names, "inventory_products": inventory_names,
            "manual_products": manual_names, "missing_product_entries": missing, "written": False}


def write_xwatch_prompt(template_path: Path, output_path: Path, products: dict, unverified: list,
                        *, inputs_ok: bool = True) -> None:
    products["written"] = False
    try:
        template_path = example_fallback(template_path)
        template = template_path.read_text(encoding="utf-8")
        if "{{PRODUCTS}}" not in template:
            raise ValueError("テンプレートに {{PRODUCTS}} が無い")
        if not inputs_ok:
            raise ValueError("対応表または手動資産を確認できない")
        if not products["products"]:
            raise ValueError("製品の一覧が空")
        text = template.replace("{{PRODUCTS}}", "、".join(products["products"]))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = output_path.with_suffix(output_path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, output_path)
        products["written"] = True
    except (OSError, ValueError) as e:
        unverified.append({"kind": "x_watch_prompt", "target": str(output_path), "reason": str(e)})


def selftest_coverage_contents() -> None:
    from unittest.mock import patch
    replies = [(0, "NAME STATE VERSION\n", ""), (0, "[]", ""),
               (0, '{"Names":"node","Image":"postgres:13","State":"running"}', "")]
    with patch.dict(scan_containers_vms.__globals__, run=lambda *a, **k: replies.pop(0)):
        rows = scan_containers_vms([])
    assert rows[0].get("image") == "postgres:13", "image identity lost"
    for asset in [rows[0], {"name": "node", "source": "hyperv", "state": "Running"},
                  {"name": "web", "image": "node:22", "source": "docker", "state": "running"}]:
        coverage = check_coverage({"containers_vms": [asset]}, PUBLIC_FIXTURES / "coverage-map.json", [])
        assert coverage["covered"] == 0 and len(coverage["uncovered"]) == 1
        assert "中を確認" in coverage["uncovered"][0]["reason"]
    asset = coverage_assets({"containers_vms": [rows[0]]})[0]
    assert not coverage_rule_matches(asset, (re.compile("^node$"), None, ["containers_vms"], None))
    assert coverage_rule_matches(asset, (re.compile("^postgres$"), None, ["containers_vms"], None))


def selftest_coverage_appx() -> None:
    from unittest.mock import patch
    guid = "1527c705-839a-4832-9118-54d4bd6a0c89"
    for name, source, publisher, covered in [
            (guid, "appx", "CN=Vendor", False), (guid, "appx", "", False),
            (guid, "appx", "CN=Microsoft Corporation, O=Microsoft Corporation", True),
            (guid, "registry", "CN=Microsoft Corporation", False),
            ("Vendor.App", "appx", "CN=Microsoft Corporation", False),
            ("Clipchamp.Clipchamp", "appx", "CN=Microsoft Windows", True)]:
        result = check_coverage({"apps": [{"name": name, "source": source, "publisher": publisher}]},
                                PUBLIC_FIXTURES / "coverage-map.json", [])
        assert result["covered"] == int(covered), "Appx name AND known publisher must match"
    for cn in ("Microsoft Windows", "Microsoft Corporation"):
        publisher = f"CN={cn}, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
        for name in (guid, "Microsoft.WindowsTerminal", "Clipchamp.Clipchamp"):
            for dn in (publisher, f'O="Vendor, Inc.", CN="{cn}", C=US',
                       rf'O=Vendor\, Inc., CN={cn}, C=US'):
                result = check_coverage({"apps": [{"name": name, "source": "appx", "publisher": dn}]},
                                        PUBLIC_FIXTURES / "coverage-map.json", [])
                assert result["covered"] == 1, ("match the publisher CN component", name, dn)
        for name, source, dn in (
                (guid, "registry", publisher), ("Vendor.App", "appx", publisher),
                ("Microsoft.VendorApp", "appx", "CN=Vendor, O=Microsoft Corporation"),
                (guid, "appx", f"CN={cn} Fake, O=Microsoft Corporation"),
                (guid, "appx", f'CN=Vendor, O="Vendor, CN={cn}"'),
                (guid, "appx", rf"CN=Vendor, O=Vendor\, CN={cn}"),
                (guid, "appx", f"CN={cn}, CN=Vendor"),
                (guid, "appx", f"CN={cn}, malformed")):
            result = check_coverage({"apps": [{"name": name, "source": source, "publisher": dn}]},
                                    PUBLIC_FIXTURES / "coverage-map.json", [])
            assert result["covered"] == 0, ("name AND Appx source AND publisher CN", name, dn)
    data = [{"name": "Vendor.StoreApp", "version": "1.2", "publisher": "Vendor", "framework": False},
            {"name": "Vendor.Framework", "version": "1", "publisher": "Vendor", "framework": True},
            {"name": "Microsoft.Windows.Shell", "version": "1", "publisher": "Microsoft", "framework": False},
            {"name": "Microsoft.WindowsTerminal", "version": "1.24", "publisher": "Microsoft", "framework": False},
            {"name": "Microsoft.Windows.Photos", "version": "1", "publisher": "Microsoft", "framework": False}]
    with patch.dict(scan_apps.__globals__, run=lambda *a, **k: (0, json.dumps(data), "")):
        unknown = []
        apps = scan_appx(unknown)
        assert not unknown and [a["name"] for a in apps] == ["Vendor.StoreApp", "Microsoft.WindowsTerminal", "Microsoft.Windows.Photos"]
        assert all(a["source"] == "appx" for a in apps)
    with patch.dict(scan_apps.__globals__, run=lambda *a, **k: (1, "", "fixture")):
        unknown = []
        assert scan_appx(unknown) == [] and unknown[0]["target"] == "apps.appx"


def selftest_listener_saved_rows() -> None:
    from unittest.mock import patch
    # Raw JSON uses the exact keys emitted by the PowerShell collector, not saved aliases.
    raw = r'''[{"name":"svchost","local_address":"0.0.0.0","port":135,"process_id":42,
        "state":"","remote_address":"0.0.0.0","remote_port":0,"process_readable":true,
        "executable_path":"C:\\Windows\\System32\\svchost.exe","path_method":"Win32_Service"},
        {"name":"lsass","local_address":"::","port":49664,"process_id":43,
        "state":"Listen","remote_address":"::","remote_port":0,"process_readable":true,
        "executable_path":"C:\\Windows\\System32\\lsass.exe","path_method":"Win32_Process"},
        {"name":"fixture","local_address":"127.0.0.1","port":80,"process_id":44,
        "state":"Listen","remote_address":"0.0.0.0","remote_port":0,"process_readable":true,
        "executable_path":"C:\\Vendor\\fallback.exe","path_method":"Get-Process"},
        {"name":"unknown","local_address":"::1","port":81,"process_id":45,
        "state":"Listen","remote_address":"::","remote_port":0,"process_readable":true,
        "executable_path":"","path_method":""}]'''
    # -InputObject $rows emits an array even with a single row.
    for output in (raw, json.dumps(json.loads(raw)[:1])):
        errors = []
        with patch.dict(scan_listening.__globals__, run=lambda *a, **k: (0, output, "")):
            inventory = {"listening": scan_listening(errors)}
        assert not errors, errors
        with tempfile.TemporaryDirectory(prefix=".listener-saved-", dir=HERE) as temp:
            path = Path(temp) / "inventory.json"
            # Match main(): coverage runs before inventory serialization.
            check_coverage(inventory, PUBLIC_FIXTURES / "coverage-map.json", errors)
            write_json(path, inventory)
            saved = read_json(path, None)
        assert saved == inventory and not errors
        checked = check_coverage(saved, PUBLIC_FIXTURES / "coverage-map.json", errors)
        assets = checked["routed_assets"] + checked["uncovered"]
        for expected, row in zip(json.loads(output), saved["listening"], strict=True):
            assert row.get("address") == expected["local_address"], ("saved address lost", row)
            assert row.get("path") == expected["executable_path"], ("saved path lost", row)
            assert row["local_address"] == row["address"] and row["executable_path"] == row["path"]
            assert row["path_method"] == expected["path_method"]
            assert row["exposed"] is (row["address"] not in ("127.0.0.1", "::1"))
            assert not row.get("listener_uncertain"), "lone PID/port is certain with real address"
            asset = next(a for a in assets if a["name"] == row["name"])
            for key in ("address", "port", "process_id", "path", "path_method", "exposed"):
                assert asset.get(key) == row[key], ("coverage field lost", key, asset)
        assert checked["covered"] == (2 if len(saved["listening"]) == 4 else 1)


def selftest_listener_paths() -> None:
    from unittest.mock import patch
    cases = [
        (r'C:\WINDOWS\system32\svchost.exe -k RPCSS -p', r'C:\WINDOWS\system32\svchost.exe'),
        (r'C:\WINDOWS\system32\lsass.exe', r'C:\WINDOWS\system32\lsass.exe'),
        (r'C:\WINDOWS\System32\OpenSSH\sshd.exe', r'C:\WINDOWS\System32\OpenSSH\sshd.exe'),
        (r'"C:\Program Files\Some Vendor\svc.exe" /arg', r'C:\Program Files\Some Vendor\svc.exe'),
        (r'\??\C:\Windows\System32\svc.EXE -p', r'C:\Windows\System32\svc.EXE'),
        (r'%SystemRoot%\System32\svc.exe -p', r'C:\Windows\System32\svc.exe'),
        (r'%windir%\System32\svc.exe', r'C:\Windows\System32\svc.exe'),
        (r'"\??\%SystemRoot%\System32\svc.EXE" /arg', r'C:\Windows\System32\svc.EXE'),
        (r'C:\Program Files\Some Vendor\svc.ExE/arg', r'C:\Program Files\Some Vendor\svc.ExE'),
        ('', ''), ('invalid command', ''),
    ]
    services = json.dumps([{"ProcessId": i + 10, "PathName": path} for i, (path, _) in enumerate(cases)])
    fixture = "$env:SystemRoot = 'C:\\Windows'; $env:windir = 'C:\\Windows'; " + r"""
$fixtureServices = ConvertFrom-Json @'
__SERVICES__
'@
function Get-CimInstance($ClassName) {
    if ($ClassName -eq 'Win32_Service') { $fixtureServices }
    else { $fixtureServices | ForEach-Object { [pscustomobject]@{ProcessId=$_.ProcessId; Name='svc.exe'; ExecutablePath=$null} } }
}
function Get-NetTCPConnection {
    $fixtureServices | ForEach-Object { [pscustomobject]@{OwningProcess=$_.ProcessId; LocalAddress='0.0.0.0'; LocalPort=80; State='Listen'; RemoteAddress='0.0.0.0'; RemotePort=0} }
}
function Get-Process($Id) { throw 'fixture: unavailable' }
""".replace("__SERVICES__", services)
    original_run = run
    def run_fixture(cmd, **kwargs):
        return original_run(cmd[:-1] + [fixture + cmd[-1]], **kwargs)
    with patch.dict(scan_listening.__globals__, run=run_fixture):
        errors = []
        found = scan_listening(errors)
    assert not errors and len(found) == len(cases), (errors, found)
    for row, (_, expected) in zip(found, cases):
        assert row["executable_path"] == expected, ("executable path", row, expected)
        assert row["path_method"] == ("Win32_Service" if expected else ""), ("path method", row)
    for path in (None, ""):
        rows = [{"name": "svc", "local_address": "0.0.0.0", "port": 80, "process_id": 42,
                 "state": "Listen", "remote_address": "0.0.0.0", "remote_port": 0,
                 "process_readable": True, "executable_path": path, "path_method": "Win32_Service"}]
        with patch.dict(scan_listening.__globals__, run=lambda *a, **k: (0, json.dumps(rows), "")):
            assert scan_listening([])[0]["path_method"] == "", "missing path must not claim a collection method"


def selftest_listener_classification() -> None:
    from unittest.mock import patch
    base = {"name": "svchost", "local_address": "0.0.0.0", "port": 135, "process_id": 42,
            "state": None, "remote_address": "0.0.0.0", "remote_port": 0,
            "process_readable": True, "executable_path": "", "path_method": ""}
    def collect(rows):
        errors = []
        with patch.dict(scan_listening.__globals__, run=lambda *a, **k: (0, json.dumps(rows), "")):
            found = scan_listening(errors)
        return found, errors
    for state in (None, ""):
        found, errors = collect([{**base, "state": state}])
        assert len(found) == 1 and not errors and not found[0].get("listener_uncertain"), "lone svchost:135 is a listener"
    for port in (3000, 49151, 49152, 49214, 65535):
        candidate = {**base, "port": port}
        for remote_port in (22, 49151, 49152, 55000, 65535):
            connected = {**candidate, "state": "Established", "local_address": "192.0.2.1",
                         "remote_address": "198.51.100.7", "remote_port": remote_port}
            found, errors = collect([candidate, connected])
            if port >= 49152 and remote_port < 49152:
                assert not found and not errors, "outbound client endpoint"
            elif port < 49152 and remote_port >= 49152:
                assert len(found) == 1 and not errors and not found[0].get("listener_uncertain"), "accepted server connection"
            else:
                assert len(found) == 1 and errors and found[0].get("listener_uncertain"), "mixed endpoint is uncertain"
        found, errors = collect([candidate, {**candidate, "process_id": 43, "state": "Established", "remote_port": 22}])
        assert len(found) == 1 and not errors and not found[0].get("listener_uncertain"), "other PID must not affect classification"


def selftest_listener_connections() -> None:
    from unittest.mock import patch
    base = {"name": "sshd", "local_address": "0.0.0.0", "port": 3000, "process_id": 42,
            "state": None, "remote_address": "0.0.0.0", "remote_port": 0,
            "process_readable": True, "executable_path": "", "path_method": ""}
    def collect(rows):
        errors = []
        with patch.dict(scan_listening.__globals__, run=lambda *a, **k: (0, json.dumps(rows), "")):
            found = scan_listening(errors)
        return found, errors
    for port in (3000, 49151, 49152, 49214, 65535):
        candidate = {**base, "port": port}
        connected = {**candidate, "state": "Established", "local_address": "192.0.2.1",
                     "remote_address": "198.51.100.2", "remote_port": 22}
        found, errors = collect([candidate, connected])
        if port < 49152:
            assert len(found) == 1 and found[0].get("listener_uncertain") and errors, \
                "accepted connections must not hide a server listener"
            coverage = check_coverage({"listening": found}, PUBLIC_FIXTURES / "coverage-map.json", [])
            assert coverage["covered"] == 0 and coverage["uncovered"][0]["unverified"]
        else:
            assert not found and not errors, "ephemeral client endpoint should be excluded"
        found, errors = collect([candidate, connected, {**candidate, "state": "LISTENING"}])
        assert len(found) == 2 and not errors and not any(r.get("listener_uncertain") for r in found)
    # A connected row on another address family is not evidence for excluding this bind.
    found, errors = collect([{**base, "port": 49214}, {**base, "port": 49214, "local_address": "2001:db8::1",
                             "state": "Established", "remote_address": "2001:db8::2", "remote_port": 22}])
    assert len(found) == 1 and found[0]["listener_uncertain"] and errors


def selftest_coverage_listening() -> None:
    from unittest.mock import patch
    sample = [
        {"LocalAddress": "::", "LocalPort": 22, "OwningProcess": 10, "State": None,
         "RemoteAddress": "::", "RemotePort": 0},
        {"LocalAddress": "0.0.0.0", "LocalPort": 445, "OwningProcess": 4, "State": "Listen",
         "RemoteAddress": "0.0.0.0", "RemotePort": 0},
        {"LocalAddress": "2001:db8::1", "LocalPort": 51000, "OwningProcess": 20, "State": "Established",
         "RemoteAddress": "2001:db8::2", "RemotePort": 443},
    ]
    rows = [{"name": "sshd" if r["LocalPort"] == 22 else "System" if r["OwningProcess"] == 4 else "fixture",
             "local_address": r["LocalAddress"], "port": r["LocalPort"], "process_id": r["OwningProcess"],
             "state": r["State"], "remote_address": r["RemoteAddress"], "remote_port": r["RemotePort"],
             "process_readable": True, "executable_path": "", "path_method": ""} for r in sample]
    # Exercise both address families without consulting the host inventory.
    ssh = next(r for r in rows if r["port"] == 22)
    rows.append({**ssh, "local_address": "0.0.0.0", "remote_address": "0.0.0.0"})
    rows += [{**rows[0], "port": 0, "process_id": 0, "state": "Listen"},
             {**rows[0], "port": 123, "state": "Established", "remote_port": 0},
             {**rows[0], "port": 124, "state": "", "remote_port": 0, "remote_address": "0.0.0.0"},
             {**rows[0], "port": 125, "state": None, "remote_port": 443},
             {**rows[0], "port": 126, "state": "Listen"}]
    rows += [{**rows[0], "name": "ssh", "process_id": 46500, "port": 49214,
              "local_address": "0.0.0.0", "state": "", "remote_address": "0.0.0.0", "remote_port": 0},
             {**rows[0], "name": "ssh", "process_id": 46500, "port": 49214,
              "local_address": "192.0.2.1", "state": "Established", "remote_address": "198.51.100.2", "remote_port": 22},
             {**rows[0], "process_id": 46501, "port": 49214, "state": None, "remote_address": "::", "remote_port": 0},
             {**rows[0], "process_id": 46500, "port": 49214, "state": "Listen", "remote_port": 0}]
    def fake_run(cmd, **kwargs):
        assert "-State Listen" not in cmd[-1], "B: null-State listeners filtered out by PowerShell"
        return 0, json.dumps(rows), ""
    with patch.dict(scan_listening.__globals__, run=fake_run):
        unknown = []
        found = scan_listening(unknown)
    assert unknown and all(u["target"] == "listening" for u in unknown)
    assert any(r["name"] == "sshd" and r["local_address"] == "::" and r["port"] == 22 and r["exposed"] for r in found)
    assert any(r["name"] == "sshd" and r["local_address"] == "0.0.0.0" and r["port"] == 22 and r["exposed"] for r in found)
    assert any(r["process_id"] == 4 and r["port"] == 445 for r in found)
    assert all(r["port"] not in (0, 123, 125) for r in found)
    assert {124, 126} <= {r["port"] for r in found}
    assert [(r["process_id"], r["state"]) for r in found if r["port"] == 49214] == [(46500, ""), (46501, None), (46500, "Listen")]
    assert not any(r.get("listener_uncertain") for r in found if r["process_id"] == 46501), "another PID's listener cannot make a lone endpoint uncertain"

    # Execute the actual PowerShell collector with fixture commands, including fallback failures.
    original_run = run
    fixture = r"""
function Get-FixtureInstance($ClassName) {
    if ($ClassName -eq 'Win32_Service') {
        [pscustomobject]@{ProcessId=10; PathName='"C:\Windows\System32\svchost.exe" -k test'}
    } else {
        [pscustomobject]@{ProcessId=10; Name='svchost.exe'; ExecutablePath=$null}
        [pscustomobject]@{ProcessId=11; Name='unknown.exe'; ExecutablePath=$null}
        [pscustomobject]@{ProcessId=12; Name='fixture.exe'; ExecutablePath='C:\Vendor\cim.exe'}
        [pscustomobject]@{ProcessId=13; Name='fixture.exe'; ExecutablePath=$null}
    }
}
function Get-NetTCPConnection {
    10..13 | ForEach-Object { [pscustomobject]@{OwningProcess=$_; LocalAddress='127.0.0.1'; LocalPort=80; State='Listen'; RemoteAddress='0.0.0.0'; RemotePort=0} }
}
function Get-Process($Id) { if ($Id -eq 13) { [pscustomobject]@{Path='C:\Vendor\fallback.exe'} } else { throw 'unreadable' } }
"""
    def run_fixture(cmd, **kwargs):
        return original_run(cmd[:-1] + [fixture + cmd[-1].replace("Get-CimInstance", "Get-FixtureInstance")], **kwargs)
    with patch.dict(scan_listening.__globals__, run=run_fixture):
        unknown = []
        found = scan_listening(unknown)
    assert not unknown and len(found) == 4
    by_pid = {row["process_id"]: row for row in found}
    assert by_pid[10]["executable_path"] == r"C:\Windows\System32\svchost.exe"
    assert [by_pid[i]["path_method"] for i in (10, 11, 12, 13)] == ["Win32_Service", "", "Win32_Process", "Get-Process"]
    checked = check_coverage({"listening": [by_pid[10], by_pid[11]]}, PUBLIC_FIXTURES / "coverage-map.json", [])
    assert checked["covered"] == 1 and [a["name"] for a in checked["uncovered"]] == ["unknown"]


def selftest_vps_listener_routes() -> None:
    path = PUBLIC_FIXTURES / "coverage-map.json"
    for process, package in (("sshd", "openssh"), ("systemd-resolve", "systemd"),
                             ("docker-proxy", "docker.io"), ("docker-proxy", "docker-ce")):
        listener = {"kind": "vps_listening", "name": process, "version": "", "exposed": True}
        inventory = {"vps": {"errors": []}, "vps_listening": [listener], "vps_packages": []}
        absent = check_coverage(inventory, path, [])
        assert absent["covered"] == 0 and absent["uncovered"][0]["unverified"], \
            "OSV route without a checked host package cannot cover VPS listener"
        for name, env, success in ((package, "vps:host", True), (package, "vps:host", False),
                                   (package, "vps:container:fixture", True), ("unrelated", "vps:host", True)):
            usage = [("Ubuntu:26.04:LTS", name, "1", env, name)]
            calls = []
            class FixtureHttp:
                def request(self, url, body):
                    calls.append((url, body))
                    if not success:
                        raise ValueError("fixture query failure")
                    return {"results": [{}]}
            hits = osv_query(FixtureHttp(), [usage[0][:3]], 1000, [])
            assert len(calls) == 1
            inv = {**inventory, "vps_packages": usage}
            cov = check_coverage(inv, path, [], osv_hits=hits)
            expected = success and name == package and env == "vps:host"
            assert cov["covered"] == 1 + int(expected)
            assert bool(cov["uncovered"]) is not expected
            pending = check_coverage(inv, path, [])
            assert pending["uncovered"][0]["unverified"], "package presence alone is not a query receipt"
            failed = check_coverage(inv, path, [{"kind": "inventory", "target": "vps", "reason": "fixture"}], osv_hits=hits)
            assert failed["uncovered"][0]["unverified"]
            failed = check_coverage({**inv, "vps": {"errors": ["package collection failed"]}}, path, [], osv_hits=hits)
            assert failed["uncovered"][0]["unverified"]
            for kind in ("osv", "osv_detail"):
                failed = check_coverage(inv, path, [{"kind": kind, "target": f"{usage[0][0]}:{name}@1",
                                                     "reason": "fixture"}], osv_hits=hits)
                assert failed["uncovered"][0]["unverified"]


def selftest_listener_routes() -> None:
    from unittest.mock import patch
    listener = {"name": "ollama", "executable_path": r"C:\tools\ollama.exe", "port": 11434, "exposed": True}
    portable = check_coverage({"listening": [listener]}, PUBLIC_FIXTURES / "coverage-map.json", [])
    assert portable["covered"] == 0 and portable["uncovered"][0]["unverified"], \
        "portable listener without checked app is uncovered"
    app = {"name": "Ollama", "version": "0.40.14", "source": "registry"}
    for route in ({"type": "github_advisories", "ref": "ollama/ollama"}, {"type": "winget", "ref": "Ollama"}):
        with tempfile.TemporaryDirectory(prefix=".listener-routes-", dir=HERE) as temp:
            path = Path(temp) / "map.json"
            write_json(path, [{"match": "^ollama$", "kinds": ["apps", "listening", "services"], "routes": [route]},
                              {"match": "^Other App$", "kinds": ["apps"], "routes": [route]}])
            for kind in ("listening", "services"):
                inventory = {kind: [listener], "apps": [app]}
                pending = check_coverage(inventory, path, [])
                assert pending["covered"] == 1 and pending["uncovered"][0]["unverified"]
                with patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda a: [], ADV_CACHE={}), \
                        patch.dict(scan_winget.__globals__, run=lambda *a, **k: (0, "No available upgrade found", "")):
                    _, checks = check_app_advisories(pending, [])
                    winget = check_winget(inventory, pending, [])
                evidence = {"app_advisory_checks": checks, "winget": winget}
                done = check_coverage(inventory, path, [], **evidence)
                assert done["covered"] == 2 and not done["uncovered"], "successful same-rule app check covers listener"
                for apps in ([], [{"name": "Other App", "version": app["version"], "source": "registry"}], [{**app, "version": "9"}]):
                    changed = check_coverage({**inventory, "apps": apps}, path, [], **evidence)
                    assert any(a["kind"] == kind and a["unverified"] for a in changed["uncovered"])
                with patch.dict(check_runtime_advisories.__globals__,
                                gh_pages=lambda a: (_ for _ in ()).throw(ValueError("fixture")), ADV_CACHE={}), \
                        patch.dict(scan_winget.__globals__, run=lambda *a, **k: (1, "", "fixture")):
                    _, checks = check_app_advisories(pending, [])
                    winget = check_winget(inventory, pending, [])
                failed = check_coverage(inventory, path, [], app_advisory_checks=checks, winget=winget)
                assert failed["covered"] == 1 and failed["uncovered"][0]["unverified"]


def selftest_advisory_packages() -> None:
    from unittest.mock import patch
    route = {"type": "github_advisories", "ref": "yt-dlp/yt-dlp"}
    entry = {"match": "^yt-dlp$", "product": "yt-dlp", "kinds": ["apps"], "routes": [route]}
    advisory = {"state": "published", "ghsa_id": "GHSA-v8mc-9377-rwjj", "vulnerabilities": [
        {"package": {"name": "yt-dlp"}, "vulnerable_version_range": "< 2023.07.06", "patched_versions": "2023.07.06"},
        {"package": {"name": "youtube-dl"}, "vulnerable_version_range": ">= 2015.01.25"},
        {"package": {"name": "youtube-dlc"}, "vulnerable_version_range": "All"}]}
    with tempfile.TemporaryDirectory(prefix=".advisory-packages-", dir=HERE) as temp:
        path = Path(temp) / "map.json"
        def check(version, configured=entry):
            write_json(path, [configured])
            coverage = check_coverage({"apps": [{"name": "yt-dlp", "source": "registry", "version": version}]}, path, [])
            errors = []
            with patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda a: [advisory], ADV_CACHE={}):
                findings, checks = check_app_advisories(coverage, errors)
            return findings, checks, errors
        findings, checks, errors = check("2026.07.04")
        assert not findings and not errors and checks[0]["result"] == "該当なし", "F3a: unrelated package ranges applied to yt-dlp"
        assert checks[0]["range"] == ["< 2023.07.06"]
        assert check("2023.07.05")[0] and not check("2023.07.06")[0]
        advisory["vulnerabilities"][0]["package"]["name"] = "YT_DLP"
        assert check("2023.07.05")[0], "F3a: normalized package identity"
        for vulnerabilities in ([advisory["vulnerabilities"][1]], [{}], []):
            with patch.dict(advisory, vulnerabilities=vulnerabilities):
                findings, checks, errors = check("2026.07.04")
                assert not findings and errors and checks[0]["result"] == "確認できなかった", "F3a: unmatched package must be unverified"
        advisory["vulnerabilities"][0]["package"]["name"] = "upstream-package"
        assert check("2023.07.05", {**entry, "advisory_package": "Upstream Package"})[0], "F3a: per-entry package override"


def selftest_advisory_repo_ranges() -> None:
    from unittest.mock import patch
    for name, repo in (("jq", "jqlang/jq"), ("Notepad++", "notepad-plus-plus/notepad-plus-plus")):
        def check(vulnerabilities, version="1.2"):
            coverage = check_coverage({"apps": [{"name": name, "source": "registry", "version": version}]},
                                      PUBLIC_FIXTURES / "coverage-map.json", [])
            advisory = {"state": "published", "ghsa_id": "GHSA-fixture", "vulnerabilities": vulnerabilities}
            errors = []
            with patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda a: [advisory], ADV_CACHE={}):
                findings, checks = check_app_advisories(coverage, errors)
            return findings, checks, errors
        for fields in ({}, {"package": None}, {"package": {}},
                       {"package": {"name": None, "ecosystem": None}}, {"package": {"name": ""}}):
            vuln = {**fields, "vulnerable_version_range": ">= 1.0", "patched_versions": "1.3"}
            findings, checks, errors = check([vuln])
            assert findings and not errors and checks[0]["result"] == "該当あり", "nameless advisory applies to repo product"
            assert checks[0]["range"] == [">= 1.0"] and checks[0]["patched"] == ["1.3"]
            for version in ("0.9", "1.3", "1.4"):
                findings, checks, errors = check([vuln], version)
                assert not findings and not errors and checks[0]["result"] == "該当なし", (name, version)
            for rng in (None, "All", "< 1.3-rc1", "not a range"):
                findings, checks, errors = check([{**vuln, "vulnerable_version_range": rng}])
                assert not findings and errors and checks[0]["result"] == "確認できなかった", "unparseable repo range is unverified"
        named = {"package": {"name": name}, "vulnerable_version_range": "< 1.3"}
        assert check([named])[0], "matching named package still applies"
        unrelated = {**named, "package": {"name": "other-package"}}
        findings, checks, errors = check([unrelated, {"vulnerable_version_range": "< 9"}])
        assert not findings and errors and checks[0]["result"] == "確認できなかった", "any named package keeps named-package filtering"
        findings, checks, errors = check([{**named, "vulnerable_version_range": "< 1"}, {"vulnerable_version_range": "< 9"}])
        assert not findings and not errors and checks[0]["result"] == "該当なし", "unnamed entries cannot bypass named matching"
        assert check([])[2], "no vulnerability entries is unverified"


def selftest_advisory_sources() -> None:
    from unittest.mock import patch
    appx = {"name": "NotepadPlusPlus", "version": "1.0.0.0", "source": "appx"}
    registry = {"name": "Notepad++ (64-bit x64)", "version": "8.9.1", "source": "registry"}
    coverage = check_coverage({"apps": [appx, registry]}, PUBLIC_FIXTURES / "coverage-map.json", [])
    routed = {a["name"]: a for a in coverage["routed_assets"]}
    assert coverage["covered"] == 2 and appx["name"] in coverage["winget_only"], "F3b: context-menu Appx needs winget coverage"
    assert [r["type"] for r in routed[appx["name"]]["routes"]] == ["winget"], "F3b: context-menu package version is not a product version"
    with patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda a: [], ADV_CACHE={}):
        _, checks = check_app_advisories(coverage, [])
    assert [c["runtime"] for c in checks] == [registry["name"]], "F3b: only registry product version may be checked"
    entry = {"match": ".*", "product": "Fixture", "kinds": ["apps"],
             "routes": [{"type": "github_advisories", "ref": "owner/repo"}, {"type": "winget", "ref": "Fixture"}]}
    with tempfile.TemporaryDirectory(prefix=".advisory-sources-", dir=HERE) as temp:
        path = Path(temp) / "map.json"
        for sources in (None, ["appx"], ["registry", "appx"]):
            configured = {**entry, **({"advisory_sources": sources} if sources is not None else {})}
            write_json(path, [configured])
            inventory = {"apps": [{"name": source or "unknown", "source": source, "version": "1"}
                                  for source in ("registry", "appx", "")]}
            coverage = check_coverage(inventory, path, [])
            with patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda a: [], ADV_CACHE={}):
                _, checks = check_app_advisories(coverage, [])
            assert {c["runtime"] for c in checks} == set(sources or ["registry"]), "F3b: explicit advisory source allowlist"


def selftest_coverage_app_routes() -> None:
    from unittest.mock import patch
    entries = [{"match": "^Fixture App$", "product": "Fixture", "kinds": ["apps"],
                "routes": [{"type": "github_advisories", "ref": "owner/repo"}, {"type": "winget", "ref": "Fixture"}]},
               {"match": "^Only Winget$", "product": "Only Winget", "kinds": ["apps"],
                "routes": [{"type": "winget", "ref": "Only Winget"}]}]
    with tempfile.TemporaryDirectory(prefix=".app-routes-", dir=HERE) as temporary:
        path = Path(temporary) / "coverage.json"
        write_json(path, entries)
        inventory = {"apps": [{"name": "Fixture App", "version": "v1.2.0.0", "source": "registry"},
                              {"name": "Only Winget", "version": "1"}]}
        unknown = []
        coverage = check_coverage(inventory, path, unknown)
        assert coverage["covered"] == 2 and not unknown, "routes rejected"
        assert "版の新旧だけ見ている" in coverage_summary(coverage)
        advisory = {"state": "published", "ghsa_id": "GHSA-fixture", "severity": "high",
                    "vulnerabilities": [{"package": {"name": "Fixture"}, "vulnerable_version_range": ">= 1.0, < 1.3", "patched_versions": "1.3"}]}
        calls = []
        def pages(args):
            calls.append(args)
            return [advisory]
        with patch.dict(check_runtime_advisories.__globals__, gh_pages=pages, ADV_CACHE={},
                        cmd_version=lambda c: (_ for _ in ()).throw(AssertionError("version_cmd forbidden"))):
            findings, checks = check_app_advisories(coverage, unknown)
            assert len(findings) == 1 and checks[0]["result"] == "該当あり" and not unknown
            assert calls == [["repos/owner/repo/security-advisories"]]
            for ver in ("garbage-99", "1.3-rc1", "", "unknown", "1.2 (preview)"):
                invalid = check_coverage({"apps": [{"name": "Fixture App", "version": ver, "source": "registry"}]}, path, [])
                unknown = []
                findings, checks = check_app_advisories(invalid, unknown)
                assert not findings and unknown and checks[0]["result"] == "確認できなかった", ver
            advisory["vulnerabilities"][0]["vulnerable_version_range"] = "< 1.3-rc1"
            unknown = []
            assert check_app_advisories(coverage, unknown)[1][0]["result"] == "確認できなかった" and unknown
        def table(rows):
            widths = (38, 32, 14, 14)
            def line(cells):
                return "".join(cell + " " * (width - console_width(cell))
                               for cell, width in zip(cells, widths)) + cells[-1]
            return "\n".join([line(("名前", "ID", "バージョン", "利用可能", "ソース")), "-" * 110,
                               *(line(row) for row in rows), f"{len(rows)} アップグレードを利用できます。", ""])
        winget_fixture = table([
            ("Blender", "BlenderFoundation.Blender", "5.2.2", "5.2.3", "winget"),
            ("Slack", "SlackTechnologies.Slack", "4.52.162", "4.53.280", "winget"),
            ("Linux 用 Windows サブシステム", "Microsoft.WSL", "2.6.1", "2.6.2", "winget"),
        ]) + table([("Python Launcher", "Python.Launcher", "< 3.14.7", "3.14.7", "winget")])
        winget_fixture += "1 個のパッケージのバージョン番号を判別できません。\n"
        winget = parse_winget_upgrade(winget_fixture)
        assert winget["verified"] and len(winget["updates"]) == 4
        by_id = {r["id"]: r for r in winget["updates"]}
        assert by_id["SlackTechnologies.Slack"]["available"] == "4.53.280"
        assert by_id["Microsoft.WSL"]["name"] == "Linux 用 Windows サブシステム"
        assert by_id["Python.Launcher"]["version"] == "< 3.14.7"
        assert winget["unknown_versions"] == 1
        counter = []
        def winget_run(cmd, **kwargs):
            counter.append(cmd)
            assert "upgrade" in cmd and "--disable-interactivity" in cmd and kwargs.get("encoding") == "utf-8"
            return 0, winget_fixture, ""
        inv = {"apps": [{"name": "Blender", "version": "5.2.2"}, {"name": "Slack", "version": "4.52.162"}]}
        cov = {"routed_assets": [{"kind": "apps", **a, "routes": [{"type": "winget", "ref": a["name"]}]} for a in inv["apps"]]}
        with patch.dict(scan_apps.__globals__, run=winget_run):
            result = check_winget(inv, cov, [])
        assert len(counter) == 1 and all(c["update_available"] is True for c in result["checks"])
        assert winget_summary(result) == "winget: 更新あり 4 件（うち見張り対象 2 件）"
        for raw in ("", "bad output", "Name Id Version Available Source\n------\nBroken row"):
            with patch.dict(scan_apps.__globals__, run=lambda *a, **k: (0, raw, "")):
                unknown = []
                result = check_winget(inv, cov, unknown)
            assert not result["verified"] and unknown
            assert all(c["update_available"] is None for c in result["checks"])
            assert "確認できなかった" in winget_summary(result)


def selftest_coverage_seeds() -> None:
    for route in ("runtime_advisory", "release", "kev", "x_watch", "manual", "winget", "github_advisories"):
        name = "Example " + route
        checked = check_coverage({"apps": [{"name": name, "version": "1", "source": "registry"}]},
                                 PUBLIC_FIXTURES / "coverage-map.json", [])
        assert checked["covered"] == 1 and not checked["uncovered"], route
        assert {r["type"] for a in checked["routed_assets"] for r in a["routes"]} == {route}
        assert all(e["product"] for e in checked["matched_entries"])
    for name in ("Linux カーネル", "Example OS"):
        errors = []
        inv = {"manual": [{"product": name}], "vps": None}
        missing = check_coverage(inv, PUBLIC_FIXTURES / "coverage-map.json", errors)
        assert missing["covered"] == 0 and missing["uncovered"][0]["unverified"] and errors
        inv.update(vps={"errors": [], "kernel": "6.8.0-example"},
                   vps_packages=[("Ubuntu:24.04", "linux", "6.8.0", "vps:host", "linux")])
        assert check_coverage(inv, PUBLIC_FIXTURES / "coverage-map.json", [])["covered"] == 2
        failed = [{"kind": "inventory", "target": "vps", "reason": "fixture"}]
        assert check_coverage(inv, PUBLIC_FIXTURES / "coverage-map.json", failed)["uncovered"][0]["unverified"]
    for source in ("hyperv", "wsl", "docker"):
        inv = {"containers_vms": [{"name": "lab.example.test", "source": source, "image": "example:1"}]}
        checked = check_coverage(inv, PUBLIC_FIXTURES / "coverage-map.json", [])
        assert checked["covered"] == 0 and checked["uncovered"][0]["unverified"]
    manual = check_coverage({"manual": [{"product": "Example Appliance"}]},
                            HERE / "coverage-map.example.json", [])
    assert manual["covered"] == 1



def selftest_coverage_fixture_independence() -> None:
    import builtins
    from unittest.mock import patch
    original_open = Path.open
    original_builtin_open = builtins.open
    def tracked_only(path, *args, **kwargs):
        assert "fixtures-new" not in path.parts, "selftest depends on untracked fixtures"
        return original_open(path, *args, **kwargs)
    def tracked_builtin(path, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)):
            assert "fixtures-new" not in Path(path).parts, "selftest depends on untracked fixtures"
        return original_builtin_open(path, *args, **kwargs)
    with patch.object(Path, "open", tracked_only), patch.object(builtins, "open", tracked_builtin):
        selftest_coverage_listening()
        selftest_coverage_app_routes()


def selftest_coverage() -> int:
    selftest_listener_saved_rows()
    selftest_listener_paths()
    selftest_listener_classification()
    selftest_advisory_packages()
    selftest_advisory_repo_ranges()
    selftest_advisory_sources()
    selftest_vps_listener_routes()
    selftest_listener_routes()
    selftest_listener_connections()
    selftest_coverage_contents()
    selftest_coverage_appx()
    selftest_coverage_fixture_independence()
    selftest_coverage_seeds()
    actual = PUBLIC_FIXTURES / "coverage-map.json"
    cases = [
        ("listening", "svchost", {"executable_path": r"C:\Windows\System32\svchost.exe"}, True),
        ("listening", "unknown", {"exposed": True}, False),
        ("listening", "System", {}, True),
        ("apps", "Example Unknown", {"source": "appx", "publisher": "CN=Vendor"}, False),
    ]
    for kind, name, extra, expected in cases:
        result = check_coverage({kind: [{"name": name, **extra}]}, actual, [])
        assert bool(result["covered"]) == expected, (kind, name, result)
    from types import SimpleNamespace
    from unittest.mock import patch

    inventory = {
        "apps": [{"name": "Microsoft Visual Studio Code", "version": "1.136.2"},
                 {"name": "Eclipse Temurin JDK with Hotspot 21.0.12+7 (x64)", "version": "21.0.12+7"},
                 {"name": "Unrelated App", "version": "1"}],
        "services": [{"name": "sshd", "display_name": "OpenSSH SSH Server"}],
        "listening": [{"name": "sshd", "local_address": "0.0.0.0", "port": 22, "exposed": True}],
        "containers_vms": [],
        "python_envs": {"fixture": {"packages": {"requests": "2.19.0"}}},
        "npm_global": {"packages": {"fixture": "1"}},
        "npm_locks": {"fixture": {"packages": {"fixture": {"1": False, "2": True}}}},
    }
    entries = [{"match": "visual studio code", "kinds": ["apps"],
                "routes": [{"type": "x_watch", "ref": "VS Code"}], "note": "fixture"},
               {"match": "temurin", "kinds": ["apps"],
                "routes": [{"type": "release", "ref": "adoptium/temurin21-binaries"}], "note": "fixture"}]
    module = sys.modules[__name__]
    # Both maps and command results are fixtures; no state or machine inventory is consulted.
    with tempfile.TemporaryDirectory(prefix=".coverage-selftest-", dir=HERE) as temp:
        map_path = Path(temp) / "coverage-map.json"
        map_path.write_text(json.dumps(entries), encoding="utf-8", newline="\n")
        unverified = []
        coverage = check_coverage(inventory, map_path, unverified)
        assert not unverified and coverage["covered"] == 6  # two apps + four OSV package versions
        assert [(a["kind"], a["name"]) for a in coverage["uncovered"]] == [
            ("services", "sshd"), ("listening", "sshd"), ("apps", "Unrelated App")]
        assert coverage["uncovered"][0]["exposed"] is True
        assert coverage_changes(coverage, {}) == 0
        state = {"coverage_seen": sorted(coverage_keys(coverage))}
        assert coverage_changes(coverage, state) == 0
        extra = {**inventory, "apps": inventory["apps"] + [{"name": "Added App", "version": "1"}]}
        changed = check_coverage(extra, map_path, [])
        assert coverage_changes(changed, state) == 1 and coverage_changes(changed, state, True) == 0
        assert scan_exit_code(coverage_changes(coverage, {}), False) == 0
        assert scan_exit_code(coverage_changes(changed, state), False) == 10
        updated = {**inventory, "apps": [{**a, "version": "2"} for a in inventory["apps"]]}
        assert coverage_changes(check_coverage(updated, map_path, []), state) == 0
        loopback = {**inventory, "listening": [{**inventory["listening"][0], "exposed": False}]}
        assert not any(a["exposed"] for a in check_coverage(loopback, map_path, [])["uncovered"])
        for service in ({"name": "SSH service", "process_id": 42},
                        {"name": "SSH service", "executable_path": '"C:\\OpenSSH\\sshd.exe" -D'}):
            linked = {**inventory, "services": [service],
                      "listening": [{**inventory["listening"][0], "process_id": 42}]}
            assert check_coverage(linked, map_path, [])["uncovered"][0]["exposed"] is True
        assert "外から届く 2 件" in coverage_summary(coverage)
        windows_rule = {"match": "(?!)", "path_match": r'^"?C:\\Windows\\', "kinds": ["services", "listening"],
                        "routes": [{"type": "kev", "ref": "Microsoft Windows"},
                                   {"type": "manual", "ref": "Windows Update checklist"}]}
        service_rules = [windows_rule, {"match": "^sshd$", "kinds": ["services"],
                                       "routes": [{"type": "manual", "ref": "fixture"}]}]
        map_path.write_text(json.dumps(service_rules), encoding="utf-8", newline="\n")
        service_cases = [
            ({"name": "Appinfo", "executable_path": r"C:\Windows\system32\svchost.exe -k netsvcs"}, True),
            ({"name": "Quoted", "executable_path": r'"C:\Windows\System32\svchost.exe" -k netsvcs'}, True),
            ({"name": "Mixed Case", "executable_path": r"c:\WINDOWS\SysWOW64\service.exe"}, True),
            ({"name": "Unknown Vendor", "executable_path": r'"C:\Program Files\Vendor\service.exe"'}, False),
            ({"name": "SSHD", "executable_path": r'"C:\Program Files\OpenSSH\sshd.exe"'}, True),
            ({"name": "Lookalike", "executable_path": r"C:\WindowsOld\service.exe"}, False),
            ({"name": "Argument", "executable_path": r'C:\Vendor\service.exe "C:\Windows\file"'}, False),
            ({"name": "No Path"}, False),
            ({"name": "Null Path", "executable_path": None}, False),
            ({"name": "Empty Path", "executable_path": ""}, False),
        ]
        for service, expected_covered in service_cases:
            unverified = []
            checked = check_coverage({"services": [service]}, map_path, unverified)
            assert not unverified and checked["covered"] == int(expected_covered), service
            assert bool(checked["uncovered"]) is not expected_covered, service
        checked = check_coverage({"apps": [service_cases[0][0]]}, map_path, [])
        assert checked["covered"] == 0 and len(checked["uncovered"]) == 1
        actual_map = json.loads((PUBLIC_FIXTURES / "coverage-map.json").read_text(encoding="utf-8"))
        assert windows_rule in [{k: v for k, v in entry.items() if k not in ("note", "product")} for entry in actual_map]
        for service, expected_covered in service_cases:
            checked = check_coverage({"services": [service]}, PUBLIC_FIXTURES / "coverage-map.json", [])
            assert checked["covered"] == int(expected_covered), service
        partial = [{"kind": "inventory", "target": "containers_vms.hyperv", "reason": "fixture"}]
        assert check_coverage(inventory, map_path, partial)["unverified_kinds"] == ["containers_vms"]
        for raw in (None, "{", '[{"match":"[","kinds":["apps"],"routes":[{"type":"manual","ref":"fixture"}]}]',
                    '[{"match":".*","kinds":["apps"],"routes":[]}]',
                    *(json.dumps([{**windows_rule, field: bad}]) for field in ("path_match", "publisher_match") for bad in ("[", "", None, 1, []))):
            if raw is None:
                path = Path(temp) / "missing.json"
            else:
                path = map_path
                path.write_text(raw, encoding="utf-8", newline="\n")
            unverified = []
            missing = check_coverage(inventory, path, unverified)
            assert missing["covered"] is None and missing["uncovered"] == [] and unverified
            assert "coverage_map" in missing["unverified_kinds"]
            assert coverage_changes(missing, state) == 0 and "確認できなかった" in coverage_summary(missing)
        with patch.object(Path, "read_text", side_effect=PermissionError("fixture")):
            unverified = []
            assert check_coverage(inventory, map_path, unverified)["covered"] is None and unverified

    wsl = "\ufeff  NAME             STATE           VERSION\r\n* Ubuntu-24.04     Running         2\r\n  日本語Linux       Stopped         1\r\n"
    assert parse_wsl_inventory(wsl.encode("utf-16le")) == [
        {"name": "Ubuntu-24.04", "state": "Running", "source": "wsl"},
        {"name": "日本語Linux", "state": "Stopped", "source": "wsl"}]
    assert parse_wsl_inventory("  名前     状態     バージョン\n* Ubuntu   実行中   2\n")[0]["state"] == "実行中"
    for text in ("", "WSL failed", "NAME STATE VERSION\nUbuntu Running invalid"):
        try:
            parse_wsl_inventory(text)
        except ValueError:
            pass
        else:
            raise AssertionError("不正な WSL 一覧を受理した")
    with patch.object(module, "run", side_effect=FileNotFoundError("fixture")):
        unverified = []
        assert scan_services(unverified) == [] and scan_listening(unverified) == []
        assert scan_containers_vms(unverified) == []
        assert {u["target"] for u in unverified} == {
            "services", "listening", "containers_vms.wsl", "containers_vms.hyperv", "containers_vms.docker"}
        assert all(u["kind"] == "inventory" for u in unverified)
    for address, exposed in (("127.0.0.1", False), ("::1", False), ("0.0.0.0", True), ("::", True)):
        doc = [{"name": "sshd", "local_address": address, "port": 22, "process_id": 42, "process_readable": True,
                "state": "Listen", "remote_address": "0.0.0.0", "remote_port": 0, "executable_path": "", "path_method": ""}]
        with patch.object(module, "run", return_value=(0, json.dumps(doc), "")):
            assert scan_listening([])[0]["exposed"] is exposed
    for output in ("", "null", "{}", '[{"name":"broken"}]'):
        with patch.object(module, "run", return_value=(0, output, "")):
            unverified = []
            assert scan_services(unverified) == [] and unverified
    with patch.object(module, "run", return_value=(0, "[]", "")):
        unverified = []
        assert scan_services(unverified) == [] and not unverified
    replies = [(0, wsl, ""), (0, '[{"name":"VM","state":"Off"}]', ""),
               (0, '{"Names":"web","Image":"nginx:1","State":"exited"}\n{"Names":"db","Image":"postgres:13","State":"running"}', "")]
    with patch.object(module, "run", side_effect=replies):
        unverified = []
        containers = scan_containers_vms(unverified)
        assert len(containers) == 5 and not unverified
        assert containers[-1] == {"name": "db", "state": "running", "source": "docker", "image": "postgres:13"}

    class RegistryKey:
        def __init__(self, data):
            self.data = data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    records = {"machine": [{"DisplayName": "Fixture App", "DisplayVersion": "1", "Publisher": "Vendor"},
                           {"DisplayName": "Hidden", "SystemComponent": 1}, {"DisplayVersion": "2"}],
               "wow": [{"DisplayName": "Legacy App"}], "user": [{"DisplayName": "User App"}]}
    denied = False

    def open_key(hive, path, *access):
        if isinstance(hive, RegistryKey):
            if denied and hive.data[int(path)].get("DisplayName") == "Fixture App":
                raise PermissionError("fixture")
            return RegistryKey(hive.data[int(path)])
        assert access == (0, 0x20119 | 0x100)
        return RegistryKey(records["user" if hive == 2 else "wow" if "WOW6432Node" in path else "machine"])

    def query_value(key, name):
        if name not in key.data:
            raise FileNotFoundError(name)
        return key.data[name], 1

    registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, HKEY_CURRENT_USER=2, KEY_READ=0x20119,
                               KEY_WOW64_64KEY=0x100, OpenKey=open_key, QueryValueEx=query_value,
                               QueryInfoKey=lambda key: (len(key.data), 0, 0), EnumKey=lambda key, i: str(i))
    with patch.dict(sys.modules, {"winreg": registry}), patch.object(module, "scan_appx", return_value=[]):
        unverified = []
        apps = scan_apps(unverified)
        assert len(apps) == 3 and not unverified
        assert all(a["source"] == "registry" for a in apps), "F3b: registry collector must identify its version source"
        assert apps[0]["version"] == "1" and apps[0]["publisher"] == "Vendor"
        assert apps[2]["scope"] == "user" and "WOW6432Node" in apps[1]["source_key"]
        denied = True
        assert len(scan_apps(unverified)) == 2 and unverified[0]["target"] == "apps"
    print("selftest-coverage: 成功（未監視・サービスのパス照合・外向け sshd・空State待受fixture・コンテナ画像/内部未確認・レジストリ/Appx・GitHub勧告/版不明・winget日本語2表/解析失敗・対応表全追加経路・VPS未確認・UTF-16LE WSL）")
    return 0


def read_metadata(path: Path) -> tuple[str | None, str | None]:
    name = ver = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                break
            if line.startswith("Name:") and name is None:
                name = line[5:].strip()
            elif line.startswith("Version:") and ver is None:
                ver = line[8:].strip()
    return name, ver


def local_source_url(dist_info: Path) -> str | None:
    """PEP 610 direct_url.json: the URL when installed editable or from a file:// source (its version
    is not a PyPI release, so OSV matching is meaningless). None = ordinary install or unreadable."""
    try:
        d = json.loads(Path(dist_info, "direct_url.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    url = d.get("url") if isinstance(d.get("url"), str) else ""
    dir_info = d.get("dir_info")
    # A file:// archive (.whl / .tar.gz, archive_info) is a real release and stays in OSV matching.
    if (isinstance(dir_info, dict) and dir_info.get("editable") is True) or \
            (url.startswith("file://") and isinstance(dir_info, dict)):
        return url or "(url なし)"
    return None


def scan_python(roots: list[str], excludes: list[str], unverified: list) -> dict:
    envs: dict[str, dict] = {}
    excl = [e.lower() for e in excludes]

    def excluded(p: str) -> bool:
        lp = p.lower() + "\\"
        return any(e in lp for e in excl)

    for root in roots:
        if not os.path.isdir(root):
            unverified.append({"kind": "python_root", "target": root, "reason": "フォルダが無い"})
            continue
        for dirpath, dirnames, _ in os.walk(root, onerror=None):
            if excluded(dirpath):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d != ".git" and not excluded(os.path.join(dirpath, d))]
            base = os.path.basename(dirpath).lower()
            parent = os.path.basename(os.path.dirname(dirpath)).lower()
            if base != "site-packages" or parent != "lib":
                continue
            dirnames[:] = []  # do not descend into site-packages
            env = os.path.normcase(os.path.dirname(os.path.dirname(dirpath)))
            if env in envs:
                continue
            pkgs, local = {}, {}
            try:
                entries = os.listdir(dirpath)
            except OSError as e:
                unverified.append({"kind": "site-packages", "target": dirpath, "reason": str(e)})
                continue
            for d in entries:
                if not d.endswith(".dist-info"):
                    continue
                meta = Path(dirpath, d, "METADATA")
                if not meta.is_file():
                    continue
                try:
                    name, ver = read_metadata(meta)
                except OSError as e:
                    unverified.append({"kind": "metadata", "target": str(meta), "reason": str(e)})
                    continue
                if name and ver:
                    url = local_source_url(Path(dirpath, d))
                    if url:
                        local[name] = {"version": ver, "url": url}
                    else:
                        pkgs[name] = ver
                else:
                    unverified.append({"kind": "metadata", "target": str(meta), "reason": "Name/Version が読めない"})
            envs[env] = {"path": os.path.dirname(os.path.dirname(dirpath)), "packages": dict(sorted(pkgs.items(), key=lambda kv: kv[0].lower())),
                         "local_source": dict(sorted(local.items(), key=lambda kv: kv[0].lower()))}
    return dict(sorted(envs.items()))


def scan_npm(unverified: list) -> dict:
    if not shutil.which("npm"):
        return {"status": "なし", "packages": {}}
    try:
        rc, out, err = run(["cmd", "/c", "npm", "ls", "-g", "--json", "--depth=0"], timeout=180)
        data = json.loads(out)
    except Exception as e:
        unverified.append({"kind": "npm", "target": "npm ls -g", "reason": f"{type(e).__name__}: {e}"})
        return {"status": "失敗", "packages": {}}
    pkgs = {k: v.get("version") for k, v in (data.get("dependencies") or {}).items() if isinstance(v, dict)}
    missing = [k for k, v in pkgs.items() if not v]
    for k in missing:
        unverified.append({"kind": "npm", "target": k, "reason": "版が取れない"})
    return {"status": "ok", "packages": {k: v for k, v in sorted(pkgs.items()) if v}}


LOCK_SUPPORTED = ("package-lock.json", "pnpm-lock.yaml")
LOCK_UNSUPPORTED = ("yarn.lock", "bun.lock", "bun.lockb")
LOCK_SKIP_DIRS = {"node_modules", ".git", ".next", "dist", ".worktrees"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]*)?$")


def parse_package_lock(path: str) -> tuple[dict, int, int]:
    """package-lock.json v1-v3. Returns ({name: {ver: dev}}, skipped, lockfileVersion)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    lv = int(data.get("lockfileVersion") or 1)
    pkgs: dict = {}
    skipped = 0

    def add(name, ver, dev, link=False):
        nonlocal skipped
        if link or not name or not isinstance(ver, str) or not SEMVER_RE.match(ver):
            skipped += 1
            return
        d = pkgs.setdefault(name, {})
        d[ver] = bool(d.get(ver, True) and dev)  # dev only if every occurrence is dev

    if isinstance(data.get("packages"), dict):
        for key, ent in data["packages"].items():
            if not key or not isinstance(ent, dict):
                continue  # "" is the root project
            if "node_modules/" not in key:
                skipped += 1  # workspace folder (local source)
                continue
            name = ent.get("name") or key.rsplit("node_modules/", 1)[1]
            add(name, ent.get("version"), ent.get("dev") is True, ent.get("link") is True)
    elif isinstance(data.get("dependencies"), dict):
        stack = [data["dependencies"]]
        while stack:
            for name, ent in stack.pop().items():
                if not isinstance(ent, dict):
                    continue
                add(name, ent.get("version"), ent.get("dev") is True)
                if isinstance(ent.get("dependencies"), dict):
                    stack.append(ent["dependencies"])
    return pkgs, skipped, lv


def parse_pnpm_lock(path: str) -> tuple[dict, int, str]:
    """pnpm-lock.yaml (v5 '/name/1.0.0', v6 '/name@1.0.0', v9 'name@1.0.0') by regex, `packages:` only."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().replace("\r", "").split("\n")
    lv = ""
    pkgs: dict = {}
    skipped = 0
    in_pk = False
    cur = None  # (name, ver) of the current entry, for 'dev: true'
    for ln in lines:
        if ln.startswith("lockfileVersion:"):
            lv = ln.split(":", 1)[1].strip().strip("'\"")
            continue
        if ln and not ln.startswith(" "):
            in_pk = ln.rstrip() == "packages:"
            cur = None
            continue
        if not in_pk:
            continue
        m = re.match(r"^  (\S.*?):\s*$", ln) or re.match(r"^  (\S.*?):\s+\{.*$", ln)
        if m:
            key = m.group(1).strip("'\"").lstrip("/")
            key = key.split("(", 1)[0]
            name, ver = key.rsplit("@", 1) if "@" in key[1:] else (key, "")
            if not SEMVER_RE.match(ver) and "/" in key[1:]:
                m5 = re.match(r"^(.+)/(\d+\.\d+\.\d+[^_/]*)(?:_.*)?$", key)  # v5: /name/1.0.0_peer@x
                if m5:
                    name, ver = m5.group(1), m5.group(2)
            if not SEMVER_RE.match(ver):
                skipped += 1
                cur = None
                continue
            pkgs.setdefault(name, {}).setdefault(ver, False)
            cur = (name, ver)
            continue
        if cur and re.match(r"^    dev:\s*true\s*$", ln):
            pkgs[cur[0]][cur[1]] = True
    return pkgs, skipped, lv


def scan_npm_locks(roots: list[str], excludes: list[str], unverified: list, max_depth: int = 6) -> dict:
    """package-lock.json / pnpm-lock.yaml under roots (read only). yarn/bun lockfiles are listed as unsupported."""
    excl = [e.lower() for e in excludes] + ["\\.claude\\worktrees\\"]
    locks, unsupported = {}, []
    skipped = 0
    t0 = time.time()

    def excluded(p: str) -> bool:
        lp = p.lower() + "\\"
        return any(e in lp for e in excl)

    for root in roots:
        if not os.path.isdir(root):
            unverified.append({"kind": "npm_lock_root", "target": root, "reason": "フォルダが無い"})
            continue
        base_depth = os.path.normpath(root).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            if excluded(dirpath):
                dirnames[:] = []
                continue
            depth = os.path.normpath(dirpath).count(os.sep) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d.lower() not in LOCK_SKIP_DIRS and not excluded(os.path.join(dirpath, d))]
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if fn in LOCK_UNSUPPORTED:
                    unsupported.append({"kind": "npm_lock_unsupported", "target": p, "reason": f"{fn} は読まない（未対応）"})
                    continue
                if fn not in LOCK_SUPPORTED:
                    continue
                try:
                    if fn == "package-lock.json":
                        pkgs, sk, lv = parse_package_lock(p)
                    else:
                        pkgs, sk, lv = parse_pnpm_lock(p)
                except Exception as e:
                    unverified.append({"kind": "npm_lock", "target": p, "reason": f"{type(e).__name__}: {e}"})
                    continue
                skipped += sk
                locks[p] = {"type": fn, "lockfileVersion": lv, "skipped": sk,
                            "packages": {n: dict(sorted(vs.items())) for n, vs in sorted(pkgs.items())}}
    return {"locks": dict(sorted(locks.items())), "unsupported": unsupported, "skipped": skipped,
            "elapsed_sec": round(time.time() - t0, 1)}


def first_version(text: str) -> str | None:
    m = re.search(r"\d+\.\d+(?:\.\d+)?(?:[.\-+][0-9A-Za-z.]+)?", text)
    return m.group(0) if m else None


def scan_runtimes(unverified: list) -> dict:
    res = {}
    for name, cmd in [("node", ["node", "--version"]), ("bun", ["bun", "--version"]), ("deno", ["deno", "--version"]),
                      ("uv", ["uv", "--version"]), ("git", ["git", "--version"]), ("java", ["java", "--version"])]:
        exe = shutil.which(cmd[0])
        if not exe:
            res[name] = "なし"
            continue
        try:
            rc, out, err = run([exe] + cmd[1:], timeout=60)
            text = (out or err).strip().splitlines()
            res[name] = first_version(text[0]) if text else None
            if not res[name]:
                raise RuntimeError(f"rc={rc} 出力から版が読めない")
        except Exception as e:
            res[name] = None
            unverified.append({"kind": "runtime", "target": name, "reason": str(e)})
    pys = []
    if shutil.which("py"):
        try:
            rc, out, _ = run(["py", "-0p"], timeout=60)
            for line in out.splitlines():
                m = re.match(r"\s*(-V:\S+)\s+\*?\s*(.+?)\s*$", line)
                if not m:
                    continue
                path = m.group(2)
                try:
                    _, vout, verr = run([path, "--version"], timeout=60)
                    pys.append({"tag": m.group(1), "path": path, "version": first_version(vout or verr)})
                except Exception as e:
                    pys.append({"tag": m.group(1), "path": path, "version": None})
                    unverified.append({"kind": "runtime", "target": path, "reason": str(e)})
        except Exception as e:
            unverified.append({"kind": "runtime", "target": "py -0p", "reason": str(e)})
        res["python"] = pys
    else:
        res["python"] = "なし"
    return res


# ---------- OSV ----------

def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def cvss3_score(vector: str) -> float | None:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
             "UI": {"N": .85, "R": .62}, "C": {"H": .56, "L": .22, "N": 0}}
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - W["C"][m["C"]]) * (1 - W["C"][m["I"]]) * (1 - W["C"][m["A"]])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * pr * W["UI"][m["UI"]]
        if imp <= 0:
            return 0.0
        raw = min(1.08 * (imp + expl), 10) if changed else min(imp + expl, 10)
        return __import__("math").ceil(raw * 10 - 1e-9) / 10
    except Exception:
        return None


def summarize_vuln(v: dict, eco: str, name: str) -> dict:
    sev_label, score = None, None
    ds = v.get("database_specific") or {}
    if isinstance(ds.get("severity"), str):
        sev_label = ds["severity"].upper()
    for s in v.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_score(s.get("score", ""))
    if sev_label is None and score is not None:
        sev_label = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MODERATE" if score >= 4 else "LOW"
    fixed = []
    for a in v.get("affected") or []:
        pk = a.get("package") or {}
        if pk.get("ecosystem") != eco:
            continue
        pn = pk.get("name", "")
        if (pep503(pn) if eco == "PyPI" else pn) != (pep503(name) if eco == "PyPI" else name):
            continue
        for r in a.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev and ev["fixed"] not in fixed:
                    fixed.append(ev["fixed"])
    aliases = v.get("aliases") or []
    return {"id": v.get("id"), "summary": v.get("summary") or (v.get("details") or "")[:200],
            "severity": sev_label or "UNKNOWN", "cvss3": score, "fixed": fixed,
            "published": v.get("published"), "aliases": aliases,
            "cve": [a for a in aliases + [v.get("id", "")] if a.startswith("CVE-")]}


def is_distro(eco: str) -> bool:
    return eco.startswith(("Ubuntu:", "Debian:", "Alpine:"))


def osv_query(http: Http, pkgs: list[tuple[str, str, str]], batch: int, unverified: list,
              *, distro_rows: dict | None = None) -> dict:
    """pkgs: (ecosystem, name, version). Returns {(eco,name,ver): [ids] or None (unverified)}."""
    result = {}
    chunks = [pkgs[i:i + batch] for i in range(0, len(pkgs), batch)]

    def ask(chunk):
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        try:
            resp = http.request(OSV_BATCH, body)
            rows = resp.get("results")
            if not isinstance(rows, list) or len(rows) != len(chunk):
                raise RuntimeError("querybatch の応答件数が問い合わせと合わない")
            return rows, None
        except Exception as e:
            return None, e

    # The batches are independent (sequential they took ~2 s each, 8 batches with the lockfiles);
    # ex.map keeps chunk order, so results and unverified entries come out as before.
    with ThreadPoolExecutor(max_workers=4) as ex:
        answers = list(ex.map(ask, chunks))
    for chunk, (rows, e) in zip(chunks, answers):
        if rows is None:
            for k in chunk:
                result[k] = None
                unverified.append({"kind": "osv", "target": f"{k[0]}:{k[1]}@{k[2]}", "reason": str(e)})
            continue
        for k, row in zip(chunk, rows):
            ids = [v["id"] for v in (row.get("vulns") or [])]
            if distro_rows is not None and is_distro(k[0]):
                distro_rows[k] = row.get("vulns") or []
            if row.get("next_page_token"):
                unverified.append({"kind": "osv", "target": f"{k[0]}:{k[1]}@{k[2]}", "reason": "一覧が複数ページ（残りは未取得）"})
            result[k] = ids
    return result


def affected_sig(v: dict | None) -> str | None:
    """Fingerprint of who is affected and where it is fixed (enumerated `versions` are left out:
    they grow with every upstream release even when nothing about the advisory changed)."""
    if not v:
        return None
    rows = []
    for a in v.get("affected") or []:
        pk = a.get("package") or {}
        rngs = [[r.get("type"), r.get("repo"), r.get("events")] for r in a.get("ranges") or []]
        rows.append([pk.get("ecosystem"), pk.get("name"), rngs])
    rows.sort(key=lambda r: json.dumps(r, sort_keys=True))
    return json.dumps(rows, sort_keys=True)


def is_stale(entry: dict | None, ttl_h: float) -> bool:
    if not entry or not entry.get(FETCHED):
        return True
    try:
        t = dt.datetime.fromisoformat(entry[FETCHED])
    except ValueError:
        return True
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() > ttl_h * 3600


def vuln_details(http: Http, ids: set[str], cache: dict, unverified: list, ttl_h: float = 24) -> set[str]:
    """Fetch details that are missing or older than ttl_h. Returns IDs whose affected ranges / fixed
    versions changed on refetch. A failed refetch keeps the old detail and is reported as unverified."""
    todo = sorted(v for v in ids if is_stale(cache.get(v), ttl_h))
    DETAIL_STATS["asked"] += len(ids)
    DETAIL_STATS["cached"] += len(ids) - len(todo)

    def one(vid):
        try:
            return vid, http.request(OSV_VULN.format(urllib.parse.quote(vid))), None
        except Exception as e:
            return vid, None, str(e)

    changed = set()
    with ThreadPoolExecutor(max_workers=8) as ex:
        for vid, data, err in ex.map(one, todo):
            old = cache.get(vid)
            DETAIL_STATS["failed" if data is None else "fetched"] += 1
            if data is None:
                reason = err if old is None else f"取り直せなかった（{old.get(FETCHED) or '取得時刻なし'} の詳細を使用）: {err}"
                unverified.append({"kind": "osv_detail", "target": vid, "reason": reason})
                continue
            data[FETCHED] = now_iso()
            if old is not None and affected_sig(old) != affected_sig(data):
                changed.add(vid)
            cache[vid] = data
    return changed


def distro_vuln_details(http: Http, rows: dict, cache: dict, unverified: list,
                        ttl_h: float = 24) -> set[str]:
    """querybatch normally supplies only id/modified. Fetch full distro records by package,
    via /query (including all pages), rather than one /vulns request per advisory ID."""
    def complete(v, key):
        return isinstance(v, dict) and any(
            (a.get("package") or {}).get("ecosystem") == key[0] and
            (a.get("package") or {}).get("name") == key[1] for a in v.get("affected") or [])

    fresh = {}
    pending = []
    ids = {v["id"] for vs in rows.values() for v in vs}
    for key, vulns in rows.items():
        missing = False
        for v in vulns:
            old = cache.get(v["id"])
            if complete(v, key):
                fresh[v["id"]] = v
            elif not (complete(old, key) and
                      (old.get("modified") == v["modified"] if v.get("modified") else not is_stale(old, ttl_h))):
                missing = True
        if missing:
            pending.append(key)

    def ask(key):
        body = {"package": {"ecosystem": key[0], "name": key[1]}, "version": key[2]}
        fetched, tokens = {}, set()
        try:
            while True:
                page = http.request(OSV_QUERY, body)
                for v in page.get("vulns") or []:
                    if not v.get("id") or not complete(v, key):
                        raise RuntimeError("OSV の詳細に対象パッケージの affected が無い")
                    fetched[v["id"]] = v
                token = page.get("next_page_token")
                if not token:
                    break
                if token in tokens:
                    raise RuntimeError("OSV の詳細ページが循環している")
                tokens.add(token)
                body["page_token"] = token
            if not {v["id"] for v in rows[key]} <= fetched.keys():
                raise RuntimeError("OSV の詳細に querybatch の ID が揃っていない")
            return fetched, None
        except Exception as e:
            return {}, str(e)

    with ThreadPoolExecutor(max_workers=4) as ex:
        for key, (fetched, err) in zip(pending, ex.map(ask, pending)):
            if err:
                unverified.append({"kind": "osv_detail", "target": f"{key[0]}:{key[1]}@{key[2]}", "reason": err})
            fresh.update(fetched)
    changed = set()
    for vid, data in fresh.items():
        old = cache.get(vid)
        if old is not None and affected_sig(old) != affected_sig(data):
            changed.add(vid)
        cache[vid] = {**data, FETCHED: now_iso()}
    DETAIL_STATS["asked"] += len(ids)
    DETAIL_STATS["fetched"] += len(ids & fresh.keys())
    DETAIL_STATS["cached"] += len((ids - fresh.keys()) & cache.keys())
    DETAIL_STATS["failed"] += len(ids - fresh.keys() - cache.keys())
    return changed


def build_osv_findings(usage: list[tuple], hits: dict, cache: dict, dev_of: dict | None = None) -> list[dict]:
    findings = []
    for eco, n, v, envp, disp in usage:
        ids = hits.get((eco, n, v))
        if not ids:
            continue
        for vid in dedupe_ids(ids, cache):
            s = summarize_vuln(cache.get(vid) or {"id": vid}, eco, n)
            k = f"osv|{envp}|{eco}|{n}|{v}|{vid}"
            f = {"key": k, "env": envp, "ecosystem": eco, "package": disp, "version": v,
                 "id": vid, "cve": s["cve"], "severity": s["severity"], "cvss3": s["cvss3"],
                 "fixed": s["fixed"], "published": s["published"], "summary": s["summary"],
                 "detail_ok": vid in cache, "sig": affected_sig(cache.get(vid))}
            if is_distro(eco):
                f.update(actionable=f["detail_ok"] and bool(s["fixed"]),
                         unfixed=f["detail_ok"] and not bool(s["fixed"]))
            if dev_of is not None and (envp, n, v) in dev_of:
                f.update(source="npm_lock", dev=dev_of[(envp, n, v)])
            findings.append(f)
    return findings


def mark_new_findings(findings: list[dict], state: dict, changed_ids: set[str], stamp: str,
                      baseline: bool = False, *, vps_baseline: set[tuple] | None = None) -> None:
    seen, sigs = state.get("seen", {}), state.get("sigs", {})
    for f in findings:
        f["changed"] = False
        if f.get("detail_ok") is False or baseline or (is_distro(f.get("ecosystem", "")) and not f["actionable"]) or \
                ((f.get("env"), f.get("ecosystem"), f.get("package")) in (vps_baseline or set())):
            f["new"] = False
        elif f["key"].startswith("ptp|"):
            pass  # ptp_findings handles the first observation and CVEs outside disclosure titles.
        elif f["key"] not in seen:
            f["new"] = True
        elif f.get("sig") is not None and ((f["key"] in sigs and sigs[f["key"]] != f["sig"]) or
                                           (f["key"] not in sigs and f.get("id") in changed_ids)):
            f["new"] = f["changed"] = True
        else:
            f["new"] = False
        f["first_seen"] = seen.get(f["key"], stamp)


def remember_findings(findings: list[dict], state: dict) -> None:
    seen, sigs = state.setdefault("seen", {}), state.setdefault("sigs", {})
    for f in findings:
        if f.get("detail_ok") is False:
            # Discard legacy observations saved by older scans without advisory details.
            seen.pop(f["key"], None)
            sigs.pop(f["key"], None)
            continue
        seen.setdefault(f["key"], f["first_seen"])
        if f.get("sig") is not None:
            sigs[f["key"]] = f["sig"]


def dedupe_ids(ids: list[str], cache: dict) -> list[str]:
    """Same advisory often appears as GHSA + PYSEC; keep one (GHSA first, it carries severity)."""
    order = sorted(ids, key=lambda x: (0 if x.startswith("GHSA") else 1, x))
    covered, keep = set(), []
    for vid in order:
        al = set((cache.get(vid) or {}).get("aliases") or [])
        if vid in covered:
            continue
        keep.append(vid)
        covered |= {vid} | al
    return keep


# ---------- releases / KEV ----------

def gh_exe() -> str | None:
    return shutil.which("gh.exe") or shutil.which("gh")


def fetch_releases(repos: list[str], tag_repos: list[str], unverified: list) -> dict:
    gh = gh_exe()
    res = {}
    for repo in repos:
        if not gh:
            unverified.append({"kind": "release", "target": repo, "reason": "gh が無い"})
            continue
        try:
            if repo in tag_repos:
                rc, out, err = run([gh, "api", f"repos/{repo}/tags", "--jq", ".[0:5]"], timeout=60)
                data = json.loads(out) if rc == 0 else None
                if not isinstance(data, list) or not data or "name" not in data[0]:
                    raise RuntimeError(f"rc={rc} {err.strip()[:120] or out.strip()[:120]}")
                res[repo] = {"tag": data[0]["name"], "tags": [t["name"] for t in data], "published": None, "url": f"https://github.com/{repo}/tags"}
            else:
                rc, out, err = run([gh, "api", f"repos/{repo}/releases/latest"], timeout=60)
                data = json.loads(out) if rc == 0 else None
                if not isinstance(data, dict) or not data.get("tag_name"):
                    raise RuntimeError(f"rc={rc} {err.strip()[:120] or out.strip()[:120]}")
                res[repo] = {"tag": data["tag_name"], "published": data.get("published_at"), "url": data.get("html_url")}
        except Exception as e:
            unverified.append({"kind": "release", "target": repo, "reason": str(e)})
    return res


def kev_match(item: dict, kws: dict[str, str]) -> str | None:
    vendor = item.get('vendorProject', '')
    product = item.get('product', '')
    text = f"{vendor} {product}"
    for kw, source in kws.items():
        if source == "derived":
            keyword = kw.casefold()
            if keyword not in KEV_DERIVED_STOPLIST and (product.casefold() == keyword or product.casefold().startswith(keyword + " ")):
                return kw
        elif re.search(r"(?<![A-Za-z0-9])" + re.escape(kw) + r"(?![A-Za-z0-9])", text, re.I):
            return kw
    return None


KEV_DERIVED_STOPLIST = {"microsoft", "windows", "update", "runtime", "driver", "service", "tools", ".net",
                        "intel", "nvidia", "google", "apple", "lenovo", "logitech", "realtek"}


def inventory_kev_keywords(hand: list[str], products: list[str]) -> tuple[dict[str, str], list[str]]:
    keywords = {kw: "hand" for kw in unique_products(hand)}
    known = {kw.casefold() for kw in keywords}
    skipped = []
    for product in unique_products(products):
        if len(product) < 4 or product.casefold() in KEV_DERIVED_STOPLIST:
            skipped.append(product)
        elif product.casefold() not in known:
            keywords[product] = "derived"
            known.add(product.casefold())
    return keywords, skipped


def selftest_kev_derived() -> None:
    vendors = ["Intel", "Microsoft", "NVIDIA", "Google", "Apple", "Lenovo", "Logitech", "Realtek"]
    keywords, skipped = inventory_kev_keywords([], vendors + [".NET", "Notepad++", "Brotli"])
    assert set(vendors) <= set(skipped), "vendor names must not become derived KEV keywords"
    assert kev_match({"vendorProject": "Intel", "product": "AMT"}, keywords) is None, "vendor-only Intel match"
    assert kev_match({"vendorProject": "Microsoft", "product": ".NET Framework"}, keywords) is None, "modern .NET must not imply .NET Framework"
    assert kev_match({"vendorProject": "Brotli", "product": "Unrelated"}, {"Brotli": "derived"}) is None
    assert kev_match({"vendorProject": "Intel", "product": "Intel AMT"}, {"Intel": "derived"}) is None
    assert kev_match({"product": "Notepad++"}, keywords) == "Notepad++"
    assert kev_match({"product": "Notepad++ Updater"}, keywords) == "Notepad++"
    assert kev_match({"product": "Brotli"}, keywords) == "Brotli"
    assert kev_match({"product": "xNotepad++x"}, keywords) is None
    assert kev_match({"vendorProject": "Intel", "product": "AMT"}, {"Intel": "hand"}) == "Intel"


def selftest_xwatch() -> int:
    selftest_kev_derived()
    from unittest.mock import patch
    for name, product in [("Microsoft OneNote", "Microsoft OneNote"), ("Microsoft 365 - ja-jp", "Microsoft 365"),
                          ("Visual Studio Community", "Visual Studio"), ("Microsoft .NET SDK", ".NET"),
                          ("Microsoft Windows Desktop Runtime", ".NET"), ("Microsoft ASP.NET Core", ".NET")]:
        coverage = check_coverage({"apps": [{"name": name}]}, PUBLIC_FIXTURES / "coverage-map.json", [])
        products = xwatch_products(coverage, [])
        assert product in products["products"], "preserve each Microsoft product for KEV/X"
        assert any(r["type"] == "manual" and "Windows Update" in r["ref"]
                   for e in coverage["matched_entries"] for r in e["routes"])
        if product == "Microsoft OneNote":
            keywords, _ = inventory_kev_keywords([], products["products"])
            assert kev_match({"vendorProject": "Microsoft", "product": "Microsoft OneNote"}, keywords) == product
            with tempfile.TemporaryDirectory(prefix=".microsoft-xwatch-", dir=HERE) as temp:
                output = Path(temp) / "prompt.md"
                write_xwatch_prompt(HERE / "watch-prompt.example.md", output, products, [])
                assert products["written"] and product in output.read_text(encoding="utf-8")

    inventory = {
        "apps": [{"name": "Notepad++ (64-bit x64)"}, {"name": "notepad++ (x86)"},
                 {"name": "Microsoft 365 - ja-jp"}, {"name": "Fixture App 2.3.4 (User)"},
                 {"name": "Windows"}, {"name": "Tools"}, {"name": "Runtime"}],
        "services": [{"name": "OS Service", "executable_path": r"C:\Windows\system32\fixture.exe"}],
        "python_envs": {"fixture": {"packages": {"certifi": "1", "mcp": "1"}}},
        "npm_global": {"packages": {"typescript": "1"}},
        "npm_locks": {"fixture": {"packages": {"next": {"1": False}}}},
        "runtimes": {"bun": "1.0", "deno": "なし", "uv": None},
    }
    route = [{"type": "x_watch", "ref": "fixture"}]
    entries = [{"match": "^certifi$", "product": "certifi", "kinds": ["python_envs"], "routes": route},
               {"match": "^mcp$", "product": "mcp", "kinds": ["python_envs"], "routes": route},
               {"match": "^typescript$", "product": "typescript", "kinds": ["npm_global", "npm_locks"], "routes": route},
               {"match": "^next$", "product": "next", "kinds": ["npm_global", "npm_locks"], "routes": route},
               {"match": "^absent$", "product": "Absent", "kinds": ["apps"], "routes": route},
               {"match": "^bun$", "product": "Bun", "kinds": ["runtimes"], "routes": route},
               {"match": "^Fixture App\\b", "kinds": ["apps"], "routes": route},
               {"match": "(?!)", "path_match": r"^C:\\Windows\\", "product": "Microsoft Windows",
                "kinds": ["services"], "routes": route}]
    with tempfile.TemporaryDirectory(prefix=".xwatch-selftest-", dir=HERE) as temp:
        root = Path(temp)
        map_path, manual_path = root / "map.json", root / "manual.json"
        template, output = root / "template.md", root / "out" / "x-watch-prompt.md"
        map_path.write_text(json.dumps(entries), encoding="utf-8", newline="\n")
        manual_path.write_text(json.dumps([
            {"product": "Ubuntu", "where": "VPS", "note": "fixture"},
            {"product": "ubuntu", "where": "VPS", "note": "duplicate"}]), encoding="utf-8", newline="\n")
        unverified = []
        inventory["manual"] = load_manual_assets(manual_path, unverified)
        coverage = check_coverage(inventory, map_path, unverified)
        products = xwatch_products(coverage, inventory["manual"])
        assert not unverified and coverage["covered"] == 6  # four OSV + app + service
        assert sum(a["kind"] == "manual" for a in coverage["uncovered"]) == 2
        names = products["products"]
        assert {"Notepad++", "Microsoft 365", "Fixture App", "Ubuntu", "certifi", "mcp", "next",
                "typescript", "Bun", "Microsoft Windows"} <= set(names), names
        assert "Absent" not in names and len(names) == len({n.casefold() for n in names})
        assert products["missing_product_entries"] == [r"^Fixture App\b"]
        assert normalize_product("Example 2.3.4 (x64) - ja-jp") == "Example"
        assert normalize_product("7-Zip (x86)") == "7-Zip"
        assert normalize_product("Intel(R) Wireless Bluetooth(R)") == "Intel(R) Wireless Bluetooth(R)"
        assert normalize_product("Example 2 (User)", "2") == "Example"
        template.write_text("製品:\n{{PRODUCTS}}\n末尾\n", encoding="utf-8", newline="\n")
        write_xwatch_prompt(template, output, products, unverified)
        assert products["written"] and not unverified
        assert output.read_text(encoding="utf-8") == "製品:\n" + "、".join(names) + "\n末尾\n"
        original = output.read_bytes()
        template.write_text("placeholder 無し\n", encoding="utf-8", newline="\n")
        for target in (output, root / "not-written.md"):
            errors = []
            write_xwatch_prompt(template, target, products, errors)
            assert errors[0]["kind"] == "x_watch_prompt"
        assert output.read_bytes() == original and not (root / "not-written.md").exists()
        template.write_text("{{PRODUCTS}}", encoding="utf-8", newline="\n")
        for items, inputs_ok in (([], True), (names, False)):
            errors = []
            write_xwatch_prompt(template, output, {"products": items}, errors, inputs_ok=inputs_ok)
            assert errors[0]["kind"] == "x_watch_prompt" and output.read_bytes() == original
        with patch.object(Path, "write_text", side_effect=OSError("fixture")):
            errors = []
            write_xwatch_prompt(template, output, products, errors)
            assert errors and output.read_bytes() == original
        entries.append({"match": "^Ubuntu$", "product": "Ubuntu", "kinds": ["manual"], "routes": route})
        map_path.write_text(json.dumps(entries), encoding="utf-8", newline="\n")
        assert check_coverage(inventory, map_path, [])["covered"] == coverage["covered"] + 2
        manual_path.write_text("{}", encoding="utf-8", newline="\n")
        errors = []
        assert load_manual_assets(manual_path, errors) == [] and errors[0]["target"] == "manual"
    keywords, skipped = inventory_kev_keywords(["Hand Product", "PHP"], names + ["Microsoft", "Update", "Driver", "Service"])
    assert keywords["Hand Product"] == "hand" and keywords["Notepad++"] == "derived"
    assert {"Windows", "Tools", "Runtime", "Bun", "mcp", "Microsoft", "Update", "Driver", "Service"} <= set(skipped)
    assert kev_match({"vendorProject": "Notepad++", "product": "Notepad++"}, keywords) == "Notepad++"
    assert kev_match({"vendorProject": "Tools", "product": "Windows Runtime"}, keywords) is None
    assert kev_match({"product": "notepad++"}, keywords) == "Notepad++"
    assert kev_match({"product": "xNotepad++x"}, keywords) is None
    assert kev_match({"product": "PHP"}, keywords) == "PHP"  # Hand base is not filtered.
    assert kev_match({"vendorProject": "Jenkins", "product": "Jenkins Command Line Interface (CLI)"}, {"LINE": "derived"}) is None
    assert kev_match({"product": "Notepad++ Updater"}, {"Notepad++": "derived"}) == "Notepad++"
    assert kev_match({"product": "Brotli"}, {"brotli": "derived"}) == "brotli"
    assert kev_match({"product": "Git for Windows"}, {"Git": "hand"}) == "Git"
    assert kev_match({"product": "GitHub"}, {"Git": "hand"}) is None
    print("𝕏 自己テスト: 成功（在庫・正規化・手動資産・重複排除・未生成時の保全・KEV 派生照合と除外）")
    return 0


# ---------- Patch the Planet ----------

def extract_ptp(html: str, fetcher, url: str = "https://patchtheplanet.org/") -> tuple[list, set[str]]:
    class Scripts(HTMLParser):
        def __init__(self):
            super().__init__()
            self.urls = []

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "script" and attrs.get("type") == "module" and attrs.get("src"):
                self.urls.append(attrs["src"])

    scripts = Scripts()
    scripts.feed(html)
    if not scripts.urls:
        raise RuntimeError("module script URL が見つからない")
    script_url = urllib.parse.urljoin(url, scripts.urls[0])
    script = urllib.parse.urlsplit(script_url)
    if script.scheme != "https" or script.hostname != urllib.parse.urlsplit(url).hostname:
        raise RuntimeError("module script URL must use HTTPS and the page hostname")
    bundle = fetcher(script_url)
    cve_re = r"\bCVE-\d{4}-\d{4,}\b"
    disclosures = {}
    for literal in re.findall(r'\btitle\s*[:=]\s*("(?:[^"\\]|\\.)*")', bundle):
        title = json.loads(literal)
        suffix = " — Patch the Planet"
        if not title.endswith(suffix):
            continue
        title = title[:-len(suffix)].strip()
        if not title:
            continue
        cves = sorted(set(re.findall(cve_re, title)))
        key = "ptp|" + (",".join(cves) if cves else title)
        disclosures[key] = {"key": key, "title": title, "cve": cves}
    if not disclosures:
        raise RuntimeError("disclosure titles が 0 件（サイトの形が変わった可能性）")
    return list(disclosures.values()), set(re.findall(cve_re, bundle))


def ptp_findings(disclosures: list, cves: set[str], state: dict) -> list:
    initialized = "ptp_seen" in state
    seen = set(state.get("ptp_seen") or [])
    seen_cves = set(state.get("ptp_cves_seen") or [])
    findings = []
    covered = {c for d in disclosures for c in d["cve"]}
    entries = disclosures + [{"key": f"ptp|{c}", "title": c, "cve": [c]} for c in sorted(cves - covered)]
    for d in entries:
        findings.append({**d, "new": initialized and (d["key"] not in seen or bool(set(d["cve"]) - seen_cves))})
    return findings


def selftest_ptp() -> int:
    import io
    from email.message import Message
    from unittest.mock import patch

    html = (PUBLIC_FIXTURES / "index.html").read_text(encoding="utf-8")
    bundle = (PUBLIC_FIXTURES / "app.js").read_text(encoding="utf-8")
    fetched = []

    def fetcher(url):
        fetched.append(url)
        return bundle

    disclosures, cves = extract_ptp(html, fetcher, "https://example.test/")
    assert len(fetched) == 1 and fetched[0].startswith("https://example.test/assets/index-")
    assert any("Example Codec" in d["title"] and d["cve"] == ["CVE-2026-900001"] for d in disclosures)
    assert {"CVE-2026-900002", "CVE-2026-900003", "CVE-2026-900001"} <= cves
    assert not any(d["title"].startswith("Patch the Planet") for d in disclosures)
    assert any(d["title"] == "XYZ: remote code execution" for d in disclosures)
    first = ptp_findings(disclosures, cves, {})
    assert not any(f["new"] for f in first)
    state = {"ptp_seen": [f["key"] for f in first], "ptp_cves_seen": sorted(cves)}
    assert not any(f["new"] for f in ptp_findings(disclosures, cves, state))
    extra = ';title:"Foo flaw (CVE-2026-999999) — Patch the Planet"'
    updated, ids = extract_ptp(html, lambda url: bundle + extra)
    assert len({d["key"] for d in updated} - {d["key"] for d in disclosures}) == 1
    assert sum(f["new"] for f in ptp_findings(updated, ids, state)) == 1
    updated, ids = extract_ptp(html, lambda url: bundle + ';"CVE-2026-999998"')
    assert sum(f["new"] for f in ptp_findings(updated, ids, state)) == 1
    for page, js, reason in [(html, 'title:"Upgrade commands";"CVE-2026-900001"', "disclosure titles が 0 件"),
                             ("<html></html>", bundle, "module script URL")]:
        try:
            extract_ptp(page, lambda url: js)
        except RuntimeError as e:
            assert reason in str(e)
        else:
            raise AssertionError(reason)
    for src in ("file:///etc/passwd", "http://127.0.0.1/x.js", "https://evil.example/x.js"):
        fetched.clear()
        try:
            extract_ptp(f'<script type="module" src="{src}"></script>', fetcher)
        except RuntimeError:
            pass  # The scan records extraction errors as unverified.
        else:
            raise AssertionError("unsafe script URL must be unverified")
        assert not fetched, "unsafe script URL reached the fetcher"
    with patch.object(urllib.request.OpenerDirector, "open") as opening:
        opening.return_value.__enter__.return_value.read.return_value = b"{}"
        http = Http("selftest", 1)
        for url in ("file:///etc/passwd", "http://127.0.0.1/x.js", "ftp://example.test/x.js"):
            try:
                http._request(url)
            except RuntimeError:
                pass
            else:
                raise AssertionError("non-HTTPS URL accepted by Http")
        opening.assert_not_called()
        assert http._request("https://example.test/x.js") == {}
        assert opening.call_count == 1
    requested = []
    start = "https://patchtheplanet.org/redirect.js"

    def serve(req):
        requested.append(req.full_url)
        headers = Message()
        code, content = 200, bundle.encode("utf-8")
        if req.full_url == start:
            code, content = status, b""
            headers["Location"] = "/intermediate.js" if chained else target
        elif req.full_url == "https://patchtheplanet.org/intermediate.js":
            code, content = status, b""
            headers["Location"] = target
        response = urllib.response.addinfourl(io.BytesIO(content), headers, req.full_url, code)
        response.msg = "fixture"
        return response

    with patch.object(urllib.request, "getproxies", return_value={}), \
            patch.object(urllib.request.HTTPSHandler, "https_open", side_effect=serve), \
            patch.object(urllib.request.HTTPHandler, "http_open", side_effect=serve), \
            patch.object(time, "sleep"):
        # Exercise the real opener and redirect handler, without any socket connection.
        for status in (301, 302, 303, 307, 308):
            for chained in (False, True):
                for target in ("http://127.0.0.1/x.js", "https://evil.example/x.js",
                               "/final.js", "https://patchtheplanet.org/final.js"):
                    requested.clear()
                    blocked = target.startswith(("http:", "https://evil.example/"))
                    try:
                        actual = extract_ptp('<script type="module" src="/redirect.js"></script>',
                                             lambda url: http.request(url, text=True, tries=1,
                                                                      allowed_hostname="patchtheplanet.org"))
                    except RuntimeError as exc:
                        assert blocked and "HTTP redirect URL must use" in str(exc)
                    else:
                        assert not blocked, "unsafe redirect must be unverified"
                        assert actual == (disclosures, cves)
                    prefix = [start] + (["https://patchtheplanet.org/intermediate.js"] if chained else [])
                    assert requested == prefix + ([] if blocked else [urllib.parse.urljoin(start, target)]), \
                        "unsafe redirect target was requested, or safe redirect was not followed"
        # Other feeds may redirect to another HTTPS hostname, but never downgrade to HTTP.
        status, chained = 302, False
        for target in ("http://127.0.0.1/x.js", "https://evil.example/x.js"):
            requested.clear()
            try:
                actual = http.request(start, text=True, tries=1)
            except RuntimeError as exc:
                assert target.startswith("http:") and "must use HTTPS" in str(exc)
            else:
                assert target.startswith("https:") and actual == bundle
            assert requested == ([start] if target.startswith("http:") else [start, target])
    print("selftest-ptp: 成功（fixture 抽出・初回・既知・新規タイトル/CVE・形変更・script 欠落・URL 制限・リダイレクト制限）")
    return 0


# ---------- patchwait (executable only; no package import) ----------

def patchwait_version(exe: str, timeout: int) -> str:
    try:
        rc, out, _ = run([exe, "--version"], timeout=timeout)
        if rc == 0 and (version := first_version(out)):
            return version
    except (OSError, subprocess.TimeoutExpired):
        pass
    # patchwait 0.2.0's uv receipt contains the install path but not the package version.
    # Read distribution metadata only from the tool whose receipt owns this executable.
    tool_dirs = []
    if os.environ.get("UV_TOOL_DIR"):
        tool_dirs.append(Path(os.environ["UV_TOOL_DIR"]) / "patchwait")
    if os.environ.get("APPDATA"):
        tool_dirs.append(Path(os.environ["APPDATA"]) / "uv/tools/patchwait")
    for tool_dir in tool_dirs:
        try:
            receipt = tomllib.loads((tool_dir / "uv-receipt.toml").read_text(encoding="utf-8"))
            entries = receipt.get("tool", {}).get("entrypoints", [])
            if not any(os.path.normcase(os.path.abspath(e.get("install-path", ""))) ==
                       os.path.normcase(os.path.abspath(exe)) for e in entries):
                continue
            for meta in sorted((tool_dir / "Lib/site-packages").glob("patchwait-*.dist-info/METADATA")):
                name, version = read_metadata(meta)
                if name == "patchwait" and version:
                    return version
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return "unknown"


def parse_patchwait(document: dict, kind: str) -> dict:
    """Validate the verdict/count boundary before reducing a raw patchwait document."""
    if not isinstance(document, dict) or document.get("tool") != "patchwait" or document.get("schema") != 1:
        raise ValueError("patchwait JSON の tool/schema が想定と違う")
    if document.get("kind" if kind == "node" else "check") != kind:
        raise ValueError(f"patchwait JSON は {kind} の結果ではない")
    counts, items = document.get("counts"), document.get("items")
    if not isinstance(counts, dict) or not isinstance(items, list):
        raise ValueError("patchwait JSON に counts/items が無い")
    results = ("found", "not_found", "undetermined")
    roles = ("node",) if kind == "node" else ("trust", "distrust")
    tallies = {role: dict.fromkeys(results, 0) for role in roles}
    found, undetermined = [], []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("verdict"), dict):
            raise ValueError("patchwait JSON の item/verdict が想定と違う")
        verdict = item["verdict"]
        result = verdict.get("result")
        role = "node" if kind == "node" else item.get("role")
        location = item.get("path" if kind == "node" else "location")
        if (role not in roles or result not in results or
                not isinstance(location, str) or not location.strip()):
            raise ValueError("patchwait JSON の場所・role・result が想定と違う")
        tallies[role][result] += 1
        if result == "undetermined":
            reason = verdict.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("patchwait JSON の判定不能に reason が無い")
            if kind == "node":
                undetermined.append({"path": location, "reason": reason})
        elif result == "found":
            if kind == "node":
                version = item.get("product_version")
                if not isinstance(version, str) or not version.strip():
                    raise ValueError("patchwait JSON の found に product_version が無い")
                found.append({"path": location, "product_version": version})
            elif role == "trust":
                if any(not isinstance(item.get(k), str) or not item[k].strip()
                       for k in ("location_kind", "distrust")):
                    raise ValueError("patchwait JSON の信頼側に location_kind/distrust が無い")
                found.append({k: item[k] for k in ("location", "location_kind", "role", "distrust", "verdict")})
    for role in roles:
        bucket = counts if kind == "node" else counts.get(role)
        if (not isinstance(bucket, dict) or
                any(type(bucket.get(r)) is not int or bucket[r] < 0 or bucket[r] != tallies[role][r]
                    for r in results)):
            raise ValueError(f"patchwait JSON の {role} 件数と items が一致しない")
    if kind == "node":
        if type(counts.get("targets")) is not int or counts["targets"] != len(items):
            raise ValueError("patchwait JSON の targets と items が一致しない")
        return {"counts": {k: counts[k] for k in ("targets", *results)},
                "found": found, "undetermined": undetermined}
    return {"counts": {r: {k: counts[r][k] for k in results} for r in roles}, "trust_found": found}


def patchwait_changes(current: dict, previous: dict | None, baseline: bool = False) -> dict:
    """Compare this run with the previous findings.json, never alert on disappearances."""
    changes = {"node": 0, "roots": 0, "undetermined": 0, "total": 0}
    if baseline or not current["enabled"]:
        return changes
    previous = previous or {}
    for kind, field, keys in (("node", "found", ("path", "product_version")),
                              ("roots", "trust_found", ("location_kind", "location", "distrust"))):
        now = current.get(kind)
        if now is None:
            continue  # Failure is recorded separately; absent results are never clean counts.
        before = previous.get(kind) or {}
        old_keys = {tuple(i[k] for k in keys) for i in before.get(field, [])}
        new_keys = {tuple(i[k] for k in keys) for i in now[field]}
        changes[kind] = len(new_keys - old_keys)
        buckets = (None,) if kind == "node" else ("trust", "distrust")
        for role in buckets:
            now_counts, old_counts = now["counts"], before.get("counts", {})
            if role:
                now_counts, old_counts = now_counts[role], old_counts.get(role, {})
            changes["undetermined"] += max(0, now_counts["undetermined"] - old_counts.get("undetermined", 0))
    changes["total"] = changes["node"] + changes["roots"] + changes["undetermined"]
    return changes


def run_patchwait(cfg: dict, minimums, unverified: list, *, output_dir: Path = OUT) -> dict:
    summary = {"enabled": cfg.get("enabled", True), "version": "unknown",
               "node": None, "roots": None, "notes": [], "errors": []}
    if not summary["enabled"]:
        return summary

    def failed(target: str, reason: str) -> None:
        summary["errors"].append(f"{target}: {reason}")
        unverified.append({"kind": "patchwait", "target": target, "reason": reason})

    exe = shutil.which("patchwait")
    if not exe:
        failed("patchwait", "実行ファイルが PATH に見つからない")
        return summary
    timeout = cfg.get("timeout_sec", 600)
    if type(timeout) is not int or timeout <= 0:
        failed("設定", "timeout_sec は正の整数が必要")
        return summary
    summary["version"] = patchwait_version(exe, timeout)
    versions = list(minimums.values()) if isinstance(minimums, dict) else list(minimums or [])
    node_cmd = [exe, "scan", "--kind", "node", "--min", "node=" + ",".join(versions),
                "--source", "node=https://nodejs.org/en/blog/vulnerability"]
    for root in cfg.get("node_roots", []):
        node_cmd += ["--root", root]
    for exclude in cfg.get("node_excludes", []):
        node_cmd += ["--exclude", exclude]
    roots_cmd = [exe, "roots", "--distrust-pem", str(HERE / "g3.pem"), "--windows"]
    keystore = cfg.get("roots_keystore")
    if keystore:
        if Path(keystore).exists():
            roots_cmd += ["--keystore", keystore]
        else:
            summary["notes"].append(f"Java キーストアが無いため --keystore を省略: {keystore}")
    for kind, cmd in (("node", node_cmd), ("roots", roots_cmd)):
        path = output_dir / f"patchwait-{kind}.json"
        try:
            if kind == "node" and not versions:
                raise ValueError("Node のセキュリティ修正版が取得できなかった")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)  # A successful command must produce fresh JSON.
            rc, _, err = run(cmd + ["--out", str(path)], timeout=timeout)
            if rc not in (0, 10):
                raise RuntimeError(f"終了コード {rc}: {err.strip()[:200]}")
            summary[kind] = parse_patchwait(json.loads(path.read_text(encoding="utf-8")), kind)
        except subprocess.TimeoutExpired:
            failed(kind, f"{timeout} 秒で時間切れ")
        except (OSError, ValueError, RuntimeError) as e:
            failed(kind, f"{type(e).__name__}: {e}")
    return summary


def patchwait_summary(summary: dict) -> str:
    if not summary["enabled"]:
        return "patchwait: 設定により無効"
    if summary["errors"]:
        return f"patchwait: 確認できなかった（{' / '.join(summary['errors'])}）"
    node, roots, new = summary["node"], summary["roots"], summary["new"]
    unknown = node["counts"]["undetermined"] + sum(roots["counts"][r]["undetermined"] for r in ("trust", "distrust"))
    return (f"patchwait: 同梱 Node 修正前 {node['counts']['found']}（新規 {new['node']}）"
            f"/ 判定不能 {unknown} / G3 信頼側 {roots['counts']['trust']['found']}（新規 {new['roots']}）"
            f"（版 {summary['version']}）" + (" / " + " / ".join(summary["notes"]) if summary["notes"] else ""))


def scan_exit_code(new_count: int, incomplete: bool) -> int:
    return 10 if new_count else 2 if incomplete else 0


def selftest_patchwait() -> int:
    import copy
    import tempfile
    from unittest.mock import patch

    fixtures = HERE / "fixtures/patchwait"
    node_doc = read_json(fixtures / "node.json", None)
    roots_doc = read_json(fixtures / "roots.json", None)
    cases = read_json(fixtures / "cases.json", None)
    previous = {"enabled": True, "node": parse_patchwait(node_doc, "node"),
                "roots": parse_patchwait(roots_doc, "roots")}
    assert previous["node"]["found"] == [{"path": r"C:\Apps\Alpha\node.exe", "product_version": "26.11.0"}]
    assert previous["node"]["undetermined"] == [{"path": r"C:\Apps\Unreadable", "reason": "file_unreadable"}]
    assert len(previous["roots"]["trust_found"]) == 1

    for case in cases["changes"]:
        docs = {"node": copy.deepcopy(node_doc), "roots": copy.deepcopy(roots_doc)}
        for kind in ("node", "roots"):
            if item := case.get("append_" + kind):
                docs[kind]["items"].append(item)
            if result := case.get("remove_" + kind):
                docs[kind]["items"] = [i for i in docs[kind]["items"] if i["verdict"]["result"] != result]
        if version := case.get("node_version"):
            docs["node"]["items"][0]["product_version"] = version
            docs["node"]["items"][0]["verdict"]["value"] = version
        for kind, doc in docs.items():
            counts = doc["counts"]
            buckets = (None,) if kind == "node" else ("trust", "distrust")
            for role in buckets:
                bucket = counts[role] if role else counts
                for result in ("found", "not_found", "undetermined"):
                    bucket[result] = sum(i["verdict"]["result"] == result and
                                         (role is None or i["role"] == role) for i in doc["items"])
            counts["targets" if kind == "node" else "items"] = len(doc["items"])
        current = {"enabled": True, **{k: parse_patchwait(d, k) for k, d in docs.items()}}
        changes = patchwait_changes(current, previous if case.get("previous", True) else None,
                                    case.get("baseline", False))
        assert changes == case["expected"], (case["name"], changes)

    module = sys.modules[__name__]
    with tempfile.TemporaryDirectory(prefix=".patchwait-selftest-", dir=HERE) as temp:
        output_dir = Path(temp)
        cfg = {"enabled": True, "node_roots": [r"C:\Program Files", r"C:\Apps"],
               "node_excludes": [r"\AppData\Local\Temp"],
               "roots_keystore": str(output_dir / "cacerts"), "timeout_sec": 7}
        calls = []
        failure = {}

        def fake_run(cmd, timeout):
            assert timeout == 7
            if cmd[1] == "--version":
                return 0, "patchwait 0.2.0\n", ""
            calls.append(cmd)
            kind = "node" if cmd[1] == "scan" else "roots"
            document = copy.deepcopy(node_doc if kind == "node" else roots_doc)
            path = Path(cmd[cmd.index("--out") + 1])
            if cmd[1] == failure.get("command"):
                if failure.get("timeout"):
                    raise subprocess.TimeoutExpired(cmd, timeout)
                if failure.get("launch_error"):
                    raise FileNotFoundError("fixture missing executable")
                if failure.get("no_output"):
                    return 0, "", ""
                if failure.get("wrong_counts"):
                    document["counts"]["found"] = 0
                path.write_text(failure.get("raw", json.dumps(document)), encoding="utf-8", newline="\n")
                return failure.get("returncode", 10), "", "fixture failure"
            path.write_bytes((fixtures / f"{kind}.json").read_bytes())
            return 10, "", ""

        with patch.object(shutil, "which", return_value="fixture-patchwait"), patch.object(module, "run", fake_run):
            unverified = []
            summary = run_patchwait(cfg, {"26": "26.12.1", "25": "25.8.2"}, unverified, output_dir=output_dir)
            assert not unverified and not summary["errors"] and summary["version"] == "0.2.0"
            assert summary["notes"] and "--keystore" not in calls[1] and "--windows" in calls[1]
            assert calls[0][calls[0].index("--min") + 1] == "node=26.12.1,25.8.2"
            assert calls[0][calls[0].index("--source") + 1] == "node=https://nodejs.org/en/blog/vulnerability"
            assert calls[0].count("--root") == 2 and cfg["node_excludes"][0] in calls[0]
            assert calls[1][calls[1].index("--distrust-pem") + 1] == str(HERE / "g3.pem")
            assert (output_dir / "patchwait-node.json").read_bytes() == (fixtures / "node.json").read_bytes()
            summary["new"] = patchwait_changes(summary, previous)
            line = patchwait_summary(summary)
            assert "同梱 Node 修正前 1（新規 0）" in line and "判定不能 2" in line and "版 0.2.0" in line
            (output_dir / "cacerts").write_text("fixture", encoding="utf-8", newline="\n")
            calls.clear()
            summary = run_patchwait(cfg, ["26.12.1"], [], output_dir=output_dir)
            assert "--keystore" in calls[1] and not summary["notes"]
            for failure in cases["failures"]:
                unverified, calls = [], []
                with patch.object(shutil, "which", return_value=None if failure.get("missing") else "fixture-patchwait"):
                    summary = run_patchwait(cfg, ["26.12.1"], unverified, output_dir=output_dir)
                assert summary["errors"] and unverified, failure["name"]
                assert all(u["kind"] == "patchwait" for u in unverified)
                assert "patchwait: 確認できなかった（" in patchwait_summary(summary)
                assert scan_exit_code(0, bool(summary["errors"])) == 2
                assert scan_exit_code(1, bool(summary["errors"])) == 10
                if not failure.get("missing"):
                    assert {c[1] for c in calls} == {"scan", "roots"}, failure["name"]
                    assert summary["node" if failure["command"] == "scan" else "roots"] is None
            failure = {}
            calls.clear()
            unverified = []
            summary = run_patchwait(cfg, {}, unverified, output_dir=output_dir)
            assert summary["node"] is None and summary["roots"] is not None and unverified
            calls.clear()
            assert not run_patchwait({"enabled": False}, {}, [], output_dir=output_dir)["enabled"]
            assert not calls

        # Test the pip-free version fallback without consulting the real tool environment.
        tool_dir = output_dir / "patchwait"
        metadata_dir = tool_dir / "Lib/site-packages/patchwait-0.2.0.dist-info"
        metadata_dir.mkdir(parents=True)
        (tool_dir / "uv-receipt.toml").write_text(
            '[tool]\nentrypoints = [{ name = "patchwait", install-path = "fixture-patchwait" }]\n',
            encoding="utf-8", newline="\n")
        (metadata_dir / "METADATA").write_text("Name: patchwait\nVersion: 0.2.0\n\n", encoding="utf-8", newline="\n")
        with patch.dict(os.environ, {"UV_TOOL_DIR": temp, "APPDATA": temp}), \
                patch.object(module, "run", return_value=(2, "", "unsupported --version")):
            assert patchwait_version("fixture-patchwait", 7) == "0.2.0"
            assert patchwait_version("unrelated-executable", 7) == "unknown"
    assert scan_exit_code(0, False) == 0 and scan_exit_code(1, False) == 10
    print("selftest-patchwait: 成功（fixture 解析・初回・既知・新規・判定不能増加・消失・失敗・コマンド・版取得）")
    return 0


# ---------- ScanMux (executable only; no package import) ----------

def parse_scanmux(document: dict) -> dict:
    """Keep advisories separate from coverage; exit 0 is not a security verdict."""
    if not isinstance(document, dict) or type(document.get("exitCode")) is not int or document["exitCode"] not in (0, 10, 2):
        raise ValueError("ScanMux JSON の exitCode が想定と違う")
    if document["exitCode"] != 2 and any(k not in document for k in
            ("advisories", "advisoryCounts", "projects", "osv", "missing")):
        raise ValueError("ScanMux JSON に結果・検証範囲が無い")
    advisories, projects, missing = (document.get(k, []) for k in ("advisories", "projects", "missing"))
    counts, osv = document.get("advisoryCounts", {}), document.get("osv", {})
    if (any(not isinstance(x, list) for x in (advisories, projects, missing)) or
            not isinstance(counts, dict) or not isinstance(osv, dict) or
            not isinstance(osv.get("errors", []), list) or not isinstance(osv.get("database", []), list)):
        raise ValueError("ScanMux JSON の結果・OSV が想定と違う")
    if document["exitCode"] != 2 and any(k not in osv for k in ("state", "errors", "database")):
        raise ValueError("ScanMux JSON に OSV の検証範囲が無い")
    for item in advisories:
        if (not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not item[k].strip()
                for k in ("lockfile", "ecosystem", "package", "id")) or "headVersion" not in item or
                (item["headVersion"] is not None and not isinstance(item["headVersion"], str))):
            raise ValueError("ScanMux JSON の advisory 識別子が想定と違う")
    for item in projects:
        if (not isinstance(item, dict) or item.get("status") not in ("complete", "undetermined") or
                any(not isinstance(item.get(k), str) or not item[k].strip() for k in ("lockfile", "ecosystem")) or
                (item["status"] == "undetermined" and not item.get("reason"))):
            raise ValueError("ScanMux JSON の project/status/reason が想定と違う")
    for item in missing:
        if not isinstance(item, dict) or not item.get("kind") or not (item.get("code") or item.get("reason")):
            raise ValueError("ScanMux JSON の missing に kind/code/reason が無い")
    for item in osv.get("database", []):
        if not isinstance(item, dict) or not item.get("ecosystem") or "modifiedAt" not in item:
            raise ValueError("ScanMux JSON の database に ecosystem/modifiedAt が無い")
    return {"advisories": advisories, "advisoryCounts": counts, "projects": projects,
            "osv": osv, "missing": missing, "exitCode": document["exitCode"]}


def scanmux_changes(current: dict, previous: dict | None, baseline: bool = False) -> dict:
    """Compare advisories transactionally; partial coverage cannot erase history."""
    changes = {"advisories": 0, "total": 0}
    last_good = dict(current.get("last_good", {}))
    current["last_good"] = last_good
    previous = previous or {}
    last_good.update(previous.get("last_good", {}))
    before = dict(previous.get("last_good", {}))
    for repo, result in previous.get("repos", {}).items():
        if "last_good" not in previous and result is not None and repo not in before:
            before[repo] = result["advisories"]  # Migrate only older findings.json.
            last_good[repo] = before[repo]
    keys = ("lockfile", "ecosystem", "package", "headVersion", "id")
    updates = {}
    for repo, now in current["repos"].items():
        if now is None:
            continue  # An unreadable repo is never a successful zero-finding result.
        old = {tuple(i[k] for k in keys): i for i in before.get(repo, [])}
        new = {tuple(i[k] for k in keys): i for i in now["advisories"]}
        partial = bool(now["missing"]) or any(p["status"] == "undetermined" for p in now["projects"])
        updates[repo] = list((old | new).values()) if partial else now["advisories"]
        if not baseline and current["enabled"]:
            changes["advisories"] += len(new.keys() - old.keys())
    # Commit only after every repo has compared successfully. On failure the
    # caller persists carried history without acknowledging this run's findings.
    last_good.update(updates)
    changes["total"] = changes["advisories"]
    return changes


def compare_scanmux_findings(scanmux: dict, path: Path, unverified: list, baseline: bool = False) -> None:
    """Missing findings start fresh; invalid history is an error, never a baseline."""
    try:
        previous = read_json(path, {}) if scanmux["enabled"] else {}
        scanmux["new"] = scanmux_changes(scanmux, previous.get("scanmux"), baseline)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
        reason = f"前回の ScanMux 結果を比較できない: {type(e).__name__}: {e}"
        scanmux["errors"].append(reason)
        unverified.append({"kind": "scanmux", "target": "out/findings.json", "reason": reason})
        scanmux.setdefault("last_good", {})
        scanmux["new"] = {"advisories": 0, "total": 0}


def run_scanmux(cfg: dict, unverified: list) -> dict:
    summary = {"enabled": cfg.get("enabled", True), "repos": {}, "databases": [], "notes": [], "errors": []}
    if not summary["enabled"]:
        return summary

    def failed(target: str, reason: str, *, fatal: bool = True) -> None:
        if fatal:
            summary["errors"].append(f"{target}: {reason}")
        else:
            summary["notes"].append(f"{target}: 確認できなかった（{reason}）")
        unverified.append({"kind": "scanmux", "target": target, "reason": reason})

    timeout = cfg.get("timeout_sec", 600)
    repos = cfg.get("repos", [])
    if (type(timeout) is not int or timeout <= 0 or not isinstance(repos, list) or not repos or
            any(not isinstance(p, str) or not Path(p).is_absolute() for p in repos) or
            any(not isinstance(cfg.get(k), str) or not Path(cfg[k]).is_absolute() for k in ("node", "entry", "config"))):
        failed("設定", "絶対パスの node/entry/config/repos と正の整数 timeout_sec が必要")
        return summary
    for repo in repos:
        summary["repos"][repo] = None
        work_dir = None
        try:
            if not Path(cfg["entry"]).is_file():
                raise FileNotFoundError(f"entry が無い: {cfg['entry']}")
            work_dir = tempfile.mkdtemp(prefix="scanpy-scanmux-", dir=HERE)
            config_path = Path(work_dir) / "config.json"
            write_json(config_path, load_config(Path(cfg["config"]), "scanmux"))
            cmd = [cfg["node"], cfg["entry"], "deps", repo, "--config", str(config_path), "--json"]
            env = os.environ.copy()
            env.update(TEMP=work_dir, TMP=work_dir)
            rc, out, err = run(cmd, timeout=timeout, env=env)
            if rc not in (0, 10, 2):
                raise RuntimeError(f"終了コード {rc}: {err.strip()[:200]}")
            result = parse_scanmux(json.loads(out))  # Exit 2 may still explain the failure in JSON.
            summary["databases"] += [{"repo": repo, **d} for d in result["osv"].get("database", [])]
            if rc != result["exitCode"]:
                raise ValueError(f"終了コード {rc} と JSON exitCode {result['exitCode']} が一致しない")
            missing, errors = result["missing"], result["osv"].get("errors", [])
            reasons = [str(m.get("code") or m["reason"]) for m in missing]
            reasons += [json.dumps(e, ensure_ascii=False) for e in errors]
            if rc == 2 or errors:
                dirty_blocker = {"kind": "plan_blocker", "side": "head", "code": "dirty_worktree_unsupported"}
                blocked_osv = {"kind": "osv", "side": "head", "state": "not_started", "reason": "plan_blocked"}
                dirty = (rc == 2 and all(e == "plan_blocked" for e in errors) and missing.count(dirty_blocker) == 1 and
                         all(m == dirty_blocker or m == blocked_osv for m in missing))
                failed(repo, f"終了コード {rc}: " + (" / ".join(reasons) or err.strip()[:200] or "理由なし"), fatal=not dirty)
                continue
            summary["repos"][repo] = result
            for item in missing:
                reason = f"部分検証 {item['kind']}: {item.get('code') or item['reason']}"
                summary["notes"].append(f"{repo}: {reason}")
                unverified.append({"kind": "scanmux", "target": repo, "reason": reason})
            for project in result["projects"]:
                if project["status"] == "undetermined":
                    reason = f"部分検証 {project['lockfile']} ({project['ecosystem']}): {project['reason']}"
                    summary["notes"].append(f"{repo}: {reason}")
                    unverified.append({"kind": "scanmux", "target": repo, "reason": reason})
        except subprocess.TimeoutExpired:
            failed(repo, f"{timeout} 秒で時間切れ")
        except (OSError, ValueError, RuntimeError) as e:
            failed(repo, f"{type(e).__name__}: {e}")
        finally:
            if work_dir is not None:
                try:
                    shutil.rmtree(work_dir)
                except Exception as e:
                    summary["notes"].append(f"{work_dir}: 一時ディレクトリを削除できない: {type(e).__name__}: {e}")
    return summary


def scanmux_summary(summary: dict) -> str:
    if not summary["enabled"]:
        return "ScanMux: 設定により無効"
    results = [r for r in summary["repos"].values() if r is not None]
    complete = sum(not r["missing"] and all(p["status"] == "complete" for p in r["projects"]) for r in results)
    line = (f"ScanMux: advisory {sum(len(r['advisories']) for r in results)}（新規 {summary['new']['total']}）"
            f" / 検証完了 {complete} / 部分検証 {len(results) - complete}"
            f" / 確認できなかった {sum(r is None for r in summary['repos'].values())} repo"
            "（終了0は追加 advisory なしを示す。安全判定ではない）")
    details = [f"確認できなかった（{e}）" for e in summary["errors"]] + summary["notes"]
    details += [f"DB {ecosystem} modifiedAt={modified_at or '不明'}"
                for ecosystem, modified_at in dict.fromkeys(
                    (d["ecosystem"], d["modifiedAt"]) for d in summary["databases"])]
    return line + (" / " + " / ".join(details) if details else "")


def selftest_scanmux() -> int:
    selftest_config()
    import copy
    from unittest.mock import patch

    repo, other = str(HERE / "fixture-repo"), str(HERE / "other-repo")
    cfg = {"enabled": True, "node": str(HERE / "node.exe"), "entry": str(HERE / "scanmux.mjs"),
           "config": str(PUBLIC_FIXTURES / "scanmux-config.json"), "repos": [repo], "timeout_sec": 7}
    clean = {"exitCode": 0, "advisories": [], "advisoryCounts": {}, "missing": [],
             "projects": [{"lockfile": "package-lock.json", "ecosystem": "npm", "status": "complete"}],
             "osv": {"state": "complete", "errors": [], "database": [
                 {"ecosystem": "npm", "modifiedAt": "2026-10-01T00:00:00Z", "provenance": {"state": "verified"}}]}}
    advisory = {"lockfile": "package-lock.json", "ecosystem": "npm", "package": "fixture", "baseVersion": "1.0.0",
                "headVersion": "1.1.0", "id": "GHSA-fixture-known", "aliases": [], "severity": "HIGH",
                "fixedVersions": ["1.2.0"], "dev": False, "status": "added"}
    known = copy.deepcopy(clean)
    known.update(exitCode=10, advisories=[advisory], advisoryCounts={"added": 1})
    added = copy.deepcopy(known)
    added["advisories"].append({**advisory, "id": "GHSA-fixture-new"})
    added["advisoryCounts"]["added"] = 2
    previous = {"enabled": True, "repos": {repo: parse_scanmux(known)}}
    module = sys.modules[__name__]
    calls = []
    work_dirs = []
    make_temp_dir = tempfile.mkdtemp
    parent_env = os.environ.copy()
    response = (0, json.dumps(clean), "")

    def make_work_dir(*, prefix, dir):
        assert prefix == "scanpy-scanmux-"
        assert dir == HERE
        return make_temp_dir(prefix=prefix, dir=fixture_root)

    def fake_run(cmd, timeout, *, env=None):
        assert cmd == [cfg["node"], cfg["entry"], "deps", cmd[3], "--config", str(Path(env["TEMP"]) / "config.json"), "--json"]
        assert read_json(Path(cmd[5]), {}) == load_config(Path(cfg["config"]), "scanmux")
        assert cmd[3] in cfg["repos"] and timeout == 7
        work_dir = Path(env["TEMP"])
        assert env == {**parent_env, "TEMP": str(work_dir), "TMP": str(work_dir)}
        assert work_dir.is_dir() and work_dir.parent == Path(fixture_root)
        assert work_dir.name.startswith("scanpy-scanmux-") and work_dir not in work_dirs
        work_dirs.append(work_dir)
        private = work_dir / "scanmux-private" / "objects"
        private.mkdir(parents=True)
        (private / "object").write_bytes(b"inline git object fixture")
        calls.append(cmd)
        if isinstance(response, Exception):
            raise response
        return response

    def check(document, rc, *, expected_new=0, failed=False, incomplete=False):
        nonlocal response
        response = (rc, json.dumps(document), "") if isinstance(document, dict) else document
        unverified = []
        count = len(work_dirs)
        summary = run_scanmux(cfg, unverified)
        assert all(not path.exists() for path in work_dirs[count:])
        assert dict(os.environ) == parent_env
        summary["new"] = scanmux_changes(summary, previous)
        assert summary["new"]["total"] == expected_new
        assert bool(summary["errors"]) == incomplete
        assert (summary["repos"][repo] is None) == failed
        partial = isinstance(document, dict) and (bool(document.get("missing")) or any(
            p["status"] == "undetermined" for p in document.get("projects", [])))
        assert bool(unverified) == (failed or incomplete or partial)
        if failed:
            assert "検証完了 0" in scanmux_summary(summary)
            assert "確認できなかった 1 repo" in scanmux_summary(summary)
            assert unverified[0]["target"] == repo
        assert scan_exit_code(expected_new, bool(summary["errors"])) == (10 if expected_new else 2 if incomplete else 0)
        return summary, unverified

    def comparison(document, prior=None, *, read_error=None, raw=None, exists=True):
        summary = {"enabled": True, "repos": {repo: parse_scanmux(document)}, "errors": []}
        unverified = []
        # Use the real read_json path, with only filesystem I/O replaced.
        with patch.object(Path, "exists", return_value=exists), patch("builtins.open") as opened:
            if read_error:
                opened.side_effect = read_error
            else:
                opened.return_value.__enter__.return_value.read.return_value = json.dumps(prior) if raw is None else raw
            compare_scanmux_findings(summary, HERE / "fixture-findings.json", unverified)
            if not exists:
                opened.assert_not_called()
        return summary, unverified

    first, unverified = comparison(known, exists=False)
    assert first["new"]["total"] == 1 and not first["errors"] and not unverified
    for kwargs in ({"read_error": PermissionError("fixture unreadable")}, {"raw": "{"}, {"prior": None}):
        failed_comparison, unverified = comparison(added, **kwargs)
        assert failed_comparison["errors"] and unverified
        assert scan_exit_code(failed_comparison["new"]["total"], True) == 2
        assert not failed_comparison.get("last_good", {})
        recovered, _ = comparison(added, {"scanmux": failed_comparison})
        assert recovered["new"]["total"] == 2
    malformed = {"scanmux": {"repos": {repo: parse_scanmux(known), other: {"invalid": True}}}}
    failed_comparison, _ = comparison(added, malformed)
    assert failed_comparison["errors"]
    assert failed_comparison["last_good"][repo] == known["advisories"]
    recovered, _ = comparison(added, {"scanmux": failed_comparison})
    assert recovered["new"]["total"] == 1
    for coverage in ("missing", "undetermined"):
        partial = copy.deepcopy(clean)
        partial["advisories"] = [added["advisories"][1], added["advisories"][1]]
        if coverage == "missing":
            partial["missing"] = [{"kind": "project", "reason": "unsupported_lockfile"}]
        else:
            partial["projects"][0].update(status="undetermined", reason="unsupported_lockfile")
        summary, _ = comparison(partial, {"scanmux": previous})
        assert summary["new"]["total"] == 1
        assert summary["last_good"][repo] == added["advisories"]
        recovered, _ = comparison(added, {"scanmux": summary})
        assert recovered["new"]["total"] == 0
        verified, _ = comparison(clean, {"scanmux": summary})
        assert verified["last_good"][repo] == []
    assert "unsupported dirty worktrees and partially verified projects are listed only, and are never reported as clean" in module.__doc__

    with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(["fixture"], 0, "ok", "")) as child:
        assert run(["fixture"], env=parent_env) == (0, "ok", "")
        assert child.call_args.kwargs["env"] is parent_env
        run(["fixture"])
        assert child.call_args.kwargs["env"] is None

    with tempfile.TemporaryDirectory(prefix="scanpy-selftest-", dir=HERE) as fixture_root, \
            patch.object(tempfile, "mkdtemp", make_work_dir), \
            patch.object(Path, "is_file", return_value=True), patch.object(module, "run", fake_run):
        sentinel = Path(fixture_root) / "outside-work-dir"
        sentinel.write_bytes(b"must remain untouched")
        summary, _ = check(clean, 0)
        assert "2026-10-01T00:00:00Z" in scanmux_summary(summary)
        database = summary["databases"][0]
        summary["databases"].extend([
            {**database, "repo": other},
            {**database, "modifiedAt": "2026-10-02T00:00:00Z"},
            {**database, "ecosystem": "PyPI"},
        ])
        text = scanmux_summary(summary)
        assert text.count("DB npm modifiedAt=2026-10-01T00:00:00Z") == 1
        assert text.count("DB npm modifiedAt=2026-10-02T00:00:00Z") == 1
        assert text.count("DB PyPI modifiedAt=2026-10-01T00:00:00Z") == 1
        summary, _ = check(added, 10, expected_new=1)
        assert scanmux_changes(summary, None)["total"] == 2  # Like patchwait: no automatic first-run baseline.
        assert scanmux_changes(summary, None, baseline=True)["total"] == 0
        assert scanmux_changes(summary, summary)["total"] == 0
        for field in ("lockfile", "ecosystem", "package", "headVersion", "id"):
            changed = copy.deepcopy(known)
            changed["advisories"][0][field] += "-changed"
            check(changed, 10, expected_new=1)
        cfg["repos"] = [other]
        response = (10, json.dumps(known), "")
        assert scanmux_changes(run_scanmux(cfg, []), previous)["total"] == 1
        cfg["repos"] = [repo]
        dirty = {"exitCode": 2, "osv": {"state": "not_started", "findings": 0, "errors": ["plan_blocked"], "database": []}, "missing": [
            {"kind": "plan_blocker", "side": "head", "code": "dirty_worktree_unsupported"},
            {"kind": "osv", "side": "head", "state": "not_started", "reason": "plan_blocked"}]}
        summary, unverified = check(dirty, 2, failed=True)
        assert "dirty_worktree_unsupported" in unverified[0]["reason"]
        # Persist through JSON just as findings.json does between runs.
        assert summary["last_good"][repo] == known["advisories"]
        response = (10, json.dumps(known), "")
        first = run_scanmux(cfg, [])
        assert scanmux_changes(first, None)["total"] == 1
        response = (2, json.dumps(dirty), "")
        unreadable = run_scanmux(cfg, [])
        assert scanmux_changes(unreadable, json.loads(json.dumps(first)))["total"] == 0
        dirty_previous = json.loads(json.dumps(unreadable))
        assert dirty_previous["repos"][repo] is None
        assert dirty_previous["last_good"][repo] == known["advisories"]
        assert scanmux_changes(unreadable, dirty_previous, baseline=True)["total"] == 0
        assert unreadable["last_good"][repo] == known["advisories"]
        for document, expected in ((known, 0), (added, 1)):
            response = (10, json.dumps(document), "")
            recovered = run_scanmux(cfg, [])
            assert scanmux_changes(recovered, dirty_previous)["total"] == expected
            assert recovered["last_good"][repo] == document["advisories"]
        baseline = run_scanmux(cfg, [])
        assert scanmux_changes(baseline, dirty_previous, baseline=True)["total"] == 0
        assert baseline["last_good"][repo] == added["advisories"]
        # A later repo's comparison failure cannot acknowledge earlier repos.
        invalid_previous = copy.deepcopy(dirty_previous)
        invalid_previous["last_good"][other] = [{"id": "incomplete"}]
        response = (10, json.dumps(added), "")
        recovered = run_scanmux(cfg, [])
        recovered["repos"][other] = parse_scanmux(known)
        with patch.object(module, "read_json", return_value={"scanmux": invalid_previous}):
            compare_scanmux_findings(recovered, HERE / "fixture-findings.json", [])
        assert recovered["errors"] and recovered["new"]["total"] == 0
        assert recovered["last_good"][repo] == known["advisories"]
        # Seed history before a malformed legacy repo interrupts comparison.
        invalid_previous = {"repos": {repo: parse_scanmux(known), other: {"invalid": True}}}
        response = (2, json.dumps(dirty), "")
        recovered = run_scanmux(cfg, [])
        with patch.object(module, "read_json", return_value={"scanmux": invalid_previous}):
            compare_scanmux_findings(recovered, HERE / "fixture-findings.json", [])
        assert recovered["errors"] and recovered["new"]["total"] == 0
        assert recovered["last_good"][repo] == known["advisories"]
        next_run = run_scanmux(cfg, [])
        scanmux_changes(next_run, json.loads(json.dumps(recovered)))
        assert next_run["last_good"][repo] == known["advisories"]
        check((0, "not JSON", ""), 0, failed=True, incomplete=True)
        check(subprocess.TimeoutExpired(["fixture"], 7), 0, failed=True, incomplete=True)
        check(OSError("fixture child exception"), 0, failed=True, incomplete=True)
        for document, rc, expected_new in ((clean, 0, 0), (added, 10, 1), (dirty, 2, 0)):
            response = (rc, json.dumps(document), "")
            expected_unverified = []
            expected = run_scanmux(cfg, expected_unverified)
            unverified = []
            with patch.object(shutil, "rmtree", side_effect=PermissionError("fixture cleanup denied")) as removal:
                summary = run_scanmux(cfg, unverified)
            leftover = work_dirs[-1]
            try:
                removal.assert_called_once()
                assert removal.call_args.args == (str(leftover),)
                assert leftover.is_dir()
                assert summary["repos"] == expected["repos"] and summary["errors"] == expected["errors"]
                assert unverified == expected_unverified
                assert summary["notes"][:-1] == expected["notes"]
                note = summary["notes"][-1]
                assert str(leftover) in note and "PermissionError: fixture cleanup denied" in note
                assert scanmux_changes(summary, previous)["total"] == expected_new
            finally:
                shutil.rmtree(leftover)
        response = (0, json.dumps(clean), "")
        expected = run_scanmux(cfg, [])
        sentinel.chmod(0o444)
        def readonly_run(cmd, timeout, *, env=None):
            result = fake_run(cmd, timeout, env=env)
            os.link(sentinel, Path(env["TEMP"]) / "readonly-link")
            return result
        try:
            with patch.object(module, "run", readonly_run):
                summary = run_scanmux(cfg, [])
            leftover = work_dirs[-1]
            assert summary["repos"] == expected["repos"] and summary["errors"] == expected["errors"]
            assert any(str(leftover) in note for note in summary["notes"])
            assert sentinel.read_bytes() == b"must remain untouched" and not sentinel.stat().st_mode & 0o200
        finally:
            sentinel.chmod(0o666)
            if work_dirs[-1].exists():
                shutil.rmtree(work_dirs[-1])
        with patch.object(tempfile, "mkdtemp", side_effect=PermissionError("fixture mkdtemp denied")):
            count = len(calls)
            summary, unverified = check(clean, 0, failed=True, incomplete=True)
            assert len(calls) == count and "fixture mkdtemp denied" in unverified[0]["reason"]
        partial = copy.deepcopy(added)
        partial["projects"][0].update(status="undetermined", reason="unsupported_lockfile")
        summary, unverified = check(partial, 10, expected_new=1)
        assert "部分検証 1" in scanmux_summary(summary) and "unsupported_lockfile" in unverified[0]["reason"]
        partial["missing"] = [{"kind": "project", "reason": "unsupported_lockfile"}]
        check(partial, 10, expected_new=1)
        partial_known = copy.deepcopy(known)
        partial_known["projects"][0].update(lockfile="uv.lock", status="undetermined", reason="unsupported_lockfile")
        summary, _ = check(partial_known, 10)
        assert scan_exit_code(summary["new"]["total"], bool(summary["errors"])) == 0
        assert "部分検証 1" in scanmux_summary(summary) and "検証完了 0" in scanmux_summary(summary)
        for extra in (dirty["missing"][0], {"kind": "osv", "side": "base", "state": "not_started", "reason": "plan_blocked"}):
            broken = copy.deepcopy(dirty)
            broken["missing"].append(extra)
            check(broken, 2, failed=True, incomplete=True)
        broken = copy.deepcopy(dirty)
        broken["missing"] = broken["missing"][1:]
        check(broken, 2, failed=True, incomplete=True)
        broken = copy.deepcopy(dirty)
        broken["osv"]["errors"].append("database_unreadable")
        check(broken, 2, failed=True, incomplete=True)
        broken = copy.deepcopy(dirty)
        broken["missing"][1]["reason"] = "other_reason"
        check(broken, 2, failed=True, incomplete=True)
        broken = copy.deepcopy(clean)
        broken["osv"]["errors"] = [{"code": "database_unreadable"}]
        check(broken, 0, failed=True, incomplete=True)
        broken = copy.deepcopy(dirty)
        broken["missing"].append({"kind": "plan_blocker", "reason": "repo_unreadable"})
        check(broken, 2, failed=True, incomplete=True)
        check((2, "not JSON", ""), 2, failed=True, incomplete=True)
        broken = copy.deepcopy(clean)
        del broken["projects"]
        check(broken, 0, failed=True, incomplete=True)
        with patch.object(Path, "is_file", return_value=False):
            count = len(calls)
            check(clean, 0, failed=True, incomplete=True)
            assert len(calls) == count
        cfg["repos"] = [repo, other]
        response = (2, json.dumps(dirty), "")
        summary = run_scanmux(cfg, [])
        assert set(summary["repos"]) == {repo, other} and all(r is None for r in summary["repos"].values())
        assert calls[-2][3] == repo and calls[-1][3] == other and work_dirs[-2] != work_dirs[-1]
        response = (0, json.dumps(clean), "")
        summary = run_scanmux(cfg, [])
        assert all(result is not None for result in summary["repos"].values())
        assert all(not path.exists() for path in work_dirs)
        assert sentinel.read_bytes() == b"must remain untouched" and dict(os.environ) == parent_env
        count = len(calls)
        assert not run_scanmux({"enabled": False}, [])["enabled"] and len(calls) == count
    print("selftest-scanmux: 成功（初回・既知・新規・終了0/10/2・dirty・JSON不正・時間切れ・部分検証・OSV失敗・entry欠落・TEMP分離・読取専用削除・削除失敗注記・一時ディレクトリ作成失敗）")
    return 0


# ---------- runtimes ----------

def num_parts(v: str) -> tuple[int, ...] | None:
    """Numeric parts only: '2.54.0.windows.1' -> (2, 54, 0, 1), 'v24.22.1' -> (24, 22, 1)."""
    p = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in p) if p else None


def vcmp(a: str, b: str) -> int:
    x, y = num_parts(a), num_parts(b)
    if x is None or y is None:
        raise ValueError(f"版を比べられない: {a!r} / {b!r}")
    n = max(len(x), len(y))
    x, y = x + (0,) * (n - len(x)), y + (0,) * (n - len(y))
    return (x > y) - (x < y)


VER = r"v?(\d[0-9A-Za-z.\-+()]*)"  # '2.54.0.windows.1', '2.53.0(3)' (Git for Windows style)
RANGE_SPAN = re.compile(r"(?:>=\s*)?" + VER + r"\s+(?:-|through|to)\s+" + VER)
RANGE_ONE = re.compile(r"\s*(<=|>=|==|=|<|>)?\s*" + VER + r"\s*,?")


def in_range(ver: str, rng) -> bool | None:
    """GitHub advisory range such as '<= 1.4.3', '< 1.4.4', '>= 1.0.0, < 1.2.1', '> 1.46.0 <= 2.1.6',
    '1.5.0 - 1.10.1', '>= v2.44.0.windows.1 through v2.54.0.windows.1'. None = cannot parse."""
    if not isinstance(rng, str) or not rng.strip() or "||" in rng:
        return None
    s = rng.strip()
    m = RANGE_SPAN.fullmatch(s)
    if m:
        return vcmp(ver, m.group(1)) >= 0 and vcmp(ver, m.group(2)) <= 0
    pos, ok, n = 0, True, 0
    while pos < len(s):
        m = RANGE_ONE.match(s, pos)
        if not m or m.end() == pos:
            return None
        op, c = m.group(1) or "=", vcmp(ver, m.group(2))
        ok &= {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0, "==": c == 0}[op]
        pos, n = m.end(), n + 1
    return ok if n else None


def is_patched(ver: str, patched: str | None) -> bool | None:
    """patched_versions such as '1.4.4', '>= 2.2.5', '2.1.13, 2.2.13, >=2.3.3'. True when the installed
    version is at or above the newest listed fix, or at or above a fix of the same major.minor line.
    None = empty or cannot parse (then the vulnerable range alone decides)."""
    if not isinstance(patched, str) or not patched.strip():
        return None
    fixes = []
    for tok in patched.split(","):
        m = re.fullmatch(r"\s*(?:>=\s*)?" + VER + r"\s*", tok)
        if not m:
            return None
        fixes.append(m.group(1))
    fixes.sort(key=num_parts)
    if vcmp(ver, fixes[-1]) >= 0:
        return True
    vp = num_parts(ver)[:2]
    return any(num_parts(f)[:2] == vp and vcmp(ver, f) >= 0 for f in fixes)


def osv_events_affected(ver: str, events: list) -> bool | None:
    """OSV SEMVER/ECOSYSTEM events evaluated in order (introduced / fixed / last_affected)."""
    if not events:
        return None
    affected = False
    for ev in events:
        if "introduced" in ev:
            if ev["introduced"] == "0" or vcmp(ver, ev["introduced"]) >= 0:
                affected = True
        elif "fixed" in ev:
            if vcmp(ver, ev["fixed"]) >= 0:
                affected = False
        elif "last_affected" in ev:
            if vcmp(ver, ev["last_affected"]) > 0:
                affected = False
        elif "limit" in ev:
            continue
        else:
            return None
    return affected


def gh_pages(args: list[str]) -> list:
    """`gh api --paginate` prints one JSON array per page back to back; join them."""
    gh = gh_exe()
    if not gh:
        raise RuntimeError("gh が無い")
    rc, out, err = run([gh, "api"] + args + ["--paginate"], timeout=120)
    if rc != 0:
        raise RuntimeError(f"rc={rc} {err.strip()[:160] or out.strip()[:160]}")
    dec, i, items = json.JSONDecoder(), 0, []
    while True:
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            break
        page, i = dec.raw_decode(out, i)
        if not isinstance(page, list):
            raise RuntimeError("一覧の形が想定と違う")
        items += page
    return items


def cmd_version(cmd: list[str]) -> str | None:
    """'なし' if the program is not installed, the version string, or raises."""
    exe = shutil.which(cmd[0])
    if not exe:
        return "なし"
    rc, out, err = run([exe] + cmd[1:], timeout=60)
    lines = (out or err).strip().splitlines()
    v = first_version(lines[0]) if lines else None
    if not v:
        raise RuntimeError(f"rc={rc} 出力から版が読めない")
    return v


def check_node(http: Http, installed, unverified: list) -> tuple[list, list, dict]:
    """Node.js release index: a newer `security: true` release in the installed major = hit."""
    findings, checks, minimums = [], [], {}
    try:
        idx = http.request(NODE_INDEX)
        if not isinstance(idx, list) or not idx:
            raise RuntimeError("index.json の形が想定と違う")
    except Exception as e:
        unverified.append({"kind": "runtime", "target": "node index.json", "reason": str(e)})
        checks.append({"runtime": "node", "version": installed, "id": "node-security-releases", "result": "確認できなかった"})
        return findings, checks, minimums
    by_major: dict[int, list[str]] = {}
    for r in idx:
        if r.get("security") and isinstance(r.get("version"), str):
            v = r["version"].lstrip("v")
            by_major.setdefault(num_parts(v)[0], []).append(v)
    for major, vs in by_major.items():
        vs.sort(key=num_parts)
        minimums[str(major)] = vs[-1]
    minimums = dict(sorted(minimums.items(), key=lambda kv: -int(kv[0])))
    if installed == "なし":
        return findings, checks, minimums
    if not installed:
        unverified.append({"kind": "runtime", "target": "node", "reason": "インストール済みの版が取れない"})
        checks.append({"runtime": "node", "version": None, "id": "node-security-releases", "result": "確認できなかった"})
        return findings, checks, minimums
    newer = [v for v in by_major.get(num_parts(installed)[0], []) if vcmp(v, installed) > 0]
    latest = newer[-1] if newer else None
    checks.append({"runtime": "node", "version": installed, "id": "node-security-releases",
                   "result": "該当あり" if newer else "該当なし", "newer_security": newer, "fixed": latest})
    if newer:
        findings.append({"key": f"runtime|node|{installed}|node-security-v{latest}", "env": "nodejs/node", "ecosystem": "runtime",
                         "package": "node", "version": installed, "id": f"node-security-v{latest}", "cve": [],
                         "severity": "UNKNOWN", "cvss3": None, "fixed": [latest], "published": None,
                         "summary": f"同じメジャーに新しいセキュリティリリースあり: {', '.join(newer)}",
                         "sig": json.dumps(newer)})
    return findings, checks, minimums


ADV_CACHE: dict = {}  # repo -> repository security advisories (one fetch per run)


def app_version(version: str) -> str:
    if not isinstance(version, str) or not re.fullmatch(r"v?\d+(?:\.\d+)*", version.strip(), re.I):
        raise ValueError("在庫の版を安全に比較できない")
    parts = [str(int(p)) for p in version.strip().lstrip("vV").split(".")]
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def numeric_app_range(text) -> bool:
    if not isinstance(text, str):
        return False
    rest = re.sub(r"v?\d+(?:\.\d+)*", "", text, flags=re.I)
    rest = re.sub(r"\b(?:through|to)\b", "", rest)
    return bool(text.strip()) and bool(re.fullmatch(r"[\s,<>=-]*", rest))


def check_app_advisories(coverage: dict, unverified: list) -> tuple[list, list]:
    entries = [{"name": asset["name"], "repo": route["ref"], "installed_version": asset["version"],
                "advisory_package": route.get("advisory_package") or normalize_product(asset["name"], asset["version"])}
               for asset in coverage.get("routed_assets", []) if asset["kind"] == "apps"
               for route in asset["routes"] if route["type"] == "github_advisories"]
    return check_runtime_advisories(entries, unverified)


def check_runtime_advisories(entries: list[dict], unverified: list, override: dict | None = None,
                             fixed_overrides: dict | None = None) -> tuple[list, list]:
    """Repository security advisories (gh api repos/<repo>/security-advisories) vs installed version.
    fixed_overrides: {GHSA: {"fixed": [...]}} from scan-config, used only when a range cannot be parsed."""
    findings, checks = [], []
    for ent in entries:
        repo = ent.get("repo")
        name = ent.get("name") or (repo or "?").split("/")[-1]
        try:
            ver = app_version(ent["installed_version"]) if "installed_version" in ent else \
                  (override or {}).get(repo) or cmd_version(ent["version_cmd"])
        except Exception as e:
            unverified.append({"kind": "runtime", "target": repo, "reason": f"版が取れない: {e}"})
            checks.append({"runtime": name, "repo": repo, "version": None, "id": None, "result": "確認できなかった"})
            continue
        if ver == "なし":
            checks.append({"runtime": name, "repo": repo, "version": "なし", "id": None, "result": "未インストール"})
            continue
        try:
            if repo not in ADV_CACHE:  # the running-process check asks again for the same repo
                ADV_CACHE[repo] = gh_pages([f"repos/{repo}/security-advisories"])
            advs = ADV_CACHE[repo]
        except Exception as e:
            unverified.append({"kind": "runtime_advisory", "target": repo, "reason": str(e)})
            checks.append({"runtime": name, "repo": repo, "version": ver, "id": None, "result": "確認できなかった"})
            continue
        if not any(a.get("state") == "published" for a in advs):
            checks.append({"runtime": name, "repo": repo, "version": ver, "id": None, "result": "該当なし"})
        for a in advs:
            if a.get("state") != "published":
                continue
            ghsa = a.get("ghsa_id")
            vulns = a.get("vulnerabilities") or []
            if "installed_version" in ent or "advisory_package" in ent:
                package = re.sub(r"[^a-z0-9]", "", (ent.get("advisory_package") or name).lower())
                # Nameless repository entries describe the repo product. If any
                # entry names a package, retain F3's product-only matching.
                if any(str((v.get("package") or {}).get("name") or "").strip() for v in vulns):
                    vulns = [v for v in vulns if package and
                             re.sub(r"[^a-z0-9]", "", str((v.get("package") or {}).get("name") or "").lower()) == package]
                if not vulns:
                    unverified.append({"kind": "runtime_advisory", "target": f"{repo} {ghsa}",
                                       "reason": f"製品に一致する package を確認できない: {ent.get('advisory_package') or name}"})
                    checks.append({"runtime": name, "repo": repo, "version": ver, "id": ghsa,
                                   "cve": a.get("cve_id"), "result": "確認できなかった", "range": [], "patched": []})
                    continue
            res, ranges, patched = [], [], []
            ov = (fixed_overrides or {}).get(ghsa) or {}
            ov_fixed = ", ".join(ov.get("fixed") or [])
            used_override = False
            for v in vulns:
                rng = v.get("vulnerable_version_range")
                try:
                    comparable = "installed_version" not in ent or (numeric_app_range(rng) and
                                  (not v.get("patched_versions") or numeric_app_range(v["patched_versions"])))
                    r = in_range(ver, rng) if comparable else None
                    # Many repository advisories give only a lower bound ('>= 2.7.0') and put the
                    # upper bound in patched_versions ('2.7.2'); an installed fix clears the hit.
                    if r is True and is_patched(ver, v.get("patched_versions")):
                        r = False
                    # Prose range (no parseable bound): fixed versions confirmed by hand in scan-config.
                    if r is None and ov_fixed:
                        p = is_patched(ver, ov_fixed)
                        if p is not None:
                            r, used_override = not p, True
                except ValueError:
                    r = None
                res.append(r)
                ranges.append(rng)
                if v.get("patched_versions"):
                    patched.append(v["patched_versions"])
            if any(r is True for r in res):
                result = "該当あり"
            elif not res or any(r is None for r in res):
                result = "確認できなかった"
                unverified.append({"kind": "runtime_advisory", "target": f"{repo} {ghsa}",
                                   "reason": f"範囲を解釈できない: {ranges!r}"})
            else:
                result = "該当なし"
            checks.append({"runtime": name, "repo": repo, "version": ver, "id": ghsa, "cve": a.get("cve_id"),
                           "result": result, "range": ranges, "patched": patched})
            if used_override:
                checks[-1].update({"fixed_source": "override", "override_fixed": ov.get("fixed"),
                                   "override_source": ov.get("source")})
            if result == "該当あり":
                sev = str(a.get("severity") or "unknown").upper()
                findings.append({"key": f"runtime|{repo}|{ver}|{ghsa}", "env": repo, "ecosystem": "runtime",
                                 "package": name, "version": ver, "id": ghsa,
                                 "cve": [a["cve_id"]] if a.get("cve_id") else [], "severity": sev,
                                 "cvss3": (a.get("cvss") or {}).get("score"), "fixed": patched,
                                 "published": a.get("published_at"), "summary": a.get("summary") or "",
                                 "sig": json.dumps([ranges, patched])})
    return findings, checks


# ---------- running processes ----------

RUNNING_BASE = ("node.exe", "bun.exe", "deno.exe", "python.exe", "git.exe", "msedge.exe", "chrome.exe")
# One PowerShell call: target processes grouped by image path, with the file's version and write time.
RUNNING_PS = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$names = @(__NAMES__)
$rows = foreach ($p in Get-CimInstance Win32_Process) {
  if ($names -notcontains $p.Name.ToLower()) { continue }
  $start = $null
  if ($p.CreationDate) { $start = $p.CreationDate.ToUniversalTime().ToString('o') }
  [pscustomobject]@{ name = $p.Name.ToLower(); pid = [int]$p.ProcessId; path = $p.ExecutablePath; start = $start }
}
$files = @{}
foreach ($r in $rows) {
  if (-not $r.path -or $files.ContainsKey($r.path)) { continue }
  try {
    $i = Get-Item -LiteralPath $r.path -ErrorAction Stop
    $files[$r.path] = [pscustomobject]@{ product = $i.VersionInfo.ProductVersion; file = $i.VersionInfo.FileVersion;
      mtime = $i.LastWriteTimeUtc.ToString('o'); error = $null }
  } catch {
    $files[$r.path] = [pscustomobject]@{ product = $null; file = $null; mtime = $null; error = $_.Exception.Message }
  }
}
[pscustomobject]@{ processes = @($rows); files = $files } | ConvertTo-Json -Depth 4 -Compress
"""


def list_running(names: list[str]) -> dict:
    """{'processes': [{name, pid, path|None, start|None}], 'files': {path: {product, file, mtime, error}}}. Raises on failure."""
    import base64
    script = RUNNING_PS.replace("__NAMES__", ", ".join("'" + n.replace("'", "") + "'" for n in names))
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    rc, out, err = run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], timeout=120)
    if rc != 0 or not out.strip():
        raise RuntimeError(f"rc={rc} {err.strip()[:160]}")
    data = json.loads(out.lstrip("﻿"))
    procs = data.get("processes") or []
    if isinstance(procs, dict):
        procs = [procs]
    files = data.get("files") or {}
    if not isinstance(procs, list) or not isinstance(files, dict):
        raise RuntimeError("プロセス一覧の形が想定と違う")
    return {"processes": procs, "files": files}


def parse_utc(s) -> dt.datetime | None:
    try:
        t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def check_running(cfg: dict, node_min: dict, node_ok: bool, unverified: list, listing: dict | None = None) -> list:
    """Running executables vs the same criteria as the installed runtimes (read only; nothing is stopped).
    Result per image path: 該当あり / 該当なし / 判定不能. The version is read from the file at the image
    path, and only trusted when the file was not rewritten after the oldest process started."""
    adv = {}  # exe name -> runtime_advisories entry
    for ent in cfg.get("runtime_advisories", []):
        cmd = ent.get("version_cmd") or []
        if cmd:
            adv[Path(cmd[0]).name.lower().removesuffix(".exe") + ".exe"] = ent
    names = sorted(set(RUNNING_BASE) | set(adv))
    if listing is None:
        try:
            listing = list_running(names)
        except Exception as e:
            unverified.append({"kind": "running", "target": "プロセス一覧", "reason": f"{type(e).__name__}: {e}"})
            return [{"path": None, "name": "(全体)", "version": None, "pids": 0, "first_start": None,
                     "result": "判定不能", "reason": f"プロセス一覧が取れない: {e}"}]
    groups: dict = {}
    for p in listing["processes"]:
        key = p.get("path") or f"(パス読めず) {p.get('name')}"
        g = groups.setdefault(key, {"path": p.get("path"), "name": p.get("name"), "pids": [], "starts": []})
        g["pids"].append(p.get("pid"))
        if parse_utc(p.get("start")):
            g["starts"].append(parse_utc(p.get("start")))
    rows = []
    for key, g in sorted(groups.items(), key=lambda kv: kv[0].lower()):
        name, path = g["name"], g["path"]
        first = min(g["starts"]) if g["starts"] else None
        row = {"path": path, "name": name, "version": None, "disk_version": None, "pids": len(g["pids"]),
               "first_start": first.astimezone().isoformat(timespec="seconds") if first else None,
               "result": "判定不能", "reason": "", "disk": None}
        rows.append(row)
        if not path:
            row["reason"] = "実行ファイルのパスが読めない（アクセス拒否の可能性）"
            continue
        fi = listing["files"].get(path) or {}
        ver = fi.get("product") or fi.get("file")
        if not ver and (name == "node.exe" or name in adv):
            try:  # bun / uv carry no version resource
                rc, out, err = run([path, "--version"], timeout=60)
                ver = first_version(((out or err).strip().splitlines() or [""])[0])
            except Exception as e:
                row["reason"] = f"--version が動かない: {e}"
        ver = first_version(ver) if ver and name != "git.exe" else (ver.strip() if ver else None)
        row["disk_version"] = ver
        if fi.get("error") or not ver:
            row["reason"] = row["reason"] or f"版が読めない: {fi.get('error') or '版情報なし'}"
            continue
        mtime = parse_utc(fi.get("mtime"))
        if first is None or mtime is None:
            row["reason"] = "起動時刻かファイルの更新時刻が読めない（動いている版がディスクと同じか分からない）"
            continue
        rewritten = mtime > first
        # Criterion for this executable
        verdict, why, fixed = None, "", None
        try:
            if name == "node.exe":
                if not node_ok:
                    why = "Node のリリース一覧が取れなかった"
                else:
                    m = node_min.get(str(num_parts(ver)[0]))
                    verdict = bool(m and vcmp(ver, m) < 0)
                    fixed = m
                    why = f"同じメジャーの最新セキュリティリリース {m}" if m else "このメジャーにセキュリティリリースなし"
            elif name in adv:
                ent = adv[name]
                unv: list = []
                f_rt, checks = check_runtime_advisories([ent], unv, override={ent.get("repo"): ver},
                                                        fixed_overrides=cfg.get("advisory_fixed_overrides"))
                if any(c["result"] == "該当あり" for c in checks):
                    verdict = True
                    why = "該当: " + ", ".join(f["id"] for f in f_rt)
                    fixed = ", ".join(x for f in f_rt for x in f["fixed"]) or None
                elif checks and all(c["result"] == "該当なし" for c in checks):
                    verdict, why = False, f"{ent.get('repo')} のアドバイザリ {len(checks)} 件に該当なし"
                else:
                    why = f"{ent.get('repo')} のアドバイザリを判定できない（{'; '.join(u['reason'][:80] for u in unv[:2])}）"
            else:
                why = "判定の基準がない（照合の対象外の製品）"
        except ValueError as e:
            verdict, why = None, f"版を比べられない: {e}"
        if rewritten:
            # The loaded image may differ from the file now on disk: its version cannot be read.
            row["reason"] = (f"起動後にファイルが更新された（ディスク上は {ver}。動いている版は読めない）"
                             + ("。ディスク上は修正済みなので、再起動すれば直る見込み" if verdict is False else
                                "。ディスク上も修正前" if verdict else ""))
            row["disk"] = "新しい（再起動で直る見込み）" if verdict is False else "古い" if verdict else None
            continue
        row["version"] = ver
        if verdict is None:
            row["reason"] = why
            continue
        row["result"] = "該当あり" if verdict else "該当なし"
        row["reason"] = why
        row["fixed"] = fixed
        if verdict:
            row["disk"] = "古い（ディスク上の同じパスも修正前。更新が要る）"
    for r in rows:
        if r["result"] == "判定不能" and not r["reason"].startswith("判定の基準がない"):
            unverified.append({"kind": "running", "target": r["path"] or r["name"], "reason": r["reason"]})
    return rows


# ---------- --cve ----------

RUNTIME_PKG = {"node": "node", "node-min": "node", "nodejs": "node", "bun": "bun", "deno": "deno", "uv": "uv", "git": "git"}


def env_label(path: str) -> str:
    p = Path(path)
    return p.parent.name if p.name.startswith(".") or p.name.lower() in ("venv", "env") else p.name


def lock_label(path: str, cfg: dict) -> str:
    for r in cfg.get("npm_lock_roots", []):
        if path.lower().startswith(r.lower().rstrip("\\") + "\\"):
            return path[len(r.rstrip("\\")) + 1:]
    return path


GH_ECO = {"pip": "PyPI", "npm": "npm"}  # GitHub advisory ecosystem -> inventory ecosystem


def gh_global_advisories(vid: str) -> tuple[list | None, str]:
    """GitHub Global Security Advisories for one GHSA / CVE ID. ([], '') = no record,
    (None, reason) = could not be fetched."""
    gh = gh_exe()
    if not gh:
        return None, "gh が無い"
    path = f"advisories/{vid}" if vid.upper().startswith("GHSA-") else f"advisories?cve_id={urllib.parse.quote(vid)}"
    try:
        rc, out, err = run([gh, "api", path], timeout=60)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"
    if rc != 0:
        if "HTTP 404" in err:
            return [], ""
        return None, f"rc={rc} {err.strip()[:120] or out.strip()[:120]}"
    try:
        data = json.loads(out)
    except ValueError as e:
        return None, f"JSON: {e}"
    advs = [data] if isinstance(data, dict) else data
    if not isinstance(advs, list) or not all(isinstance(a, dict) for a in advs):
        return None, "応答の形が想定と違う"
    return advs, ""


def gh_range_affected(ver: str, rng, first_patched) -> bool | None:
    """One GitHub advisory vulnerability entry vs an installed version (existing in_range / is_patched)."""
    if isinstance(first_patched, dict):
        first_patched = first_patched.get("identifier")
    try:
        r = in_range(ver, rng)
        if r is True and is_patched(ver, first_patched):
            r = False
        return r
    except ValueError:
        return None


def cve_lookup(http: Http, cfg: dict, cache: dict, vid: str, t0: float) -> int:
    unv: list = []
    ttl = float(cfg.get("osv_detail_ttl_hours", 24))
    vuln_details(http, {vid}, cache, unv, ttl)
    root = cache.get(vid)
    if root is None:
        reason = unv[-1]["reason"] if unv else "?"
        if "HTTP 404" not in reason:
            print(f"{vid}: 確認できなかった（OSV から取れない: {reason}）")
            return 2
        root = {}  # not in OSV (e.g. a repository-only GHSA): still matched against runtime advisories
        unv.pop()
    ids = {vid} | set(root.get("aliases") or []) | set(root.get("related") or [])
    known = {vid} if not root else set()  # do not ask OSV again for an ID it just answered 404 to
    vuln_details(http, ids - known, cache, unv, ttl)
    for i in list(ids):  # one more hop: aliases listed only on the alias records
        ids |= set((cache.get(i) or {}).get("aliases") or [])
    vuln_details(http, ids - known, cache, unv, ttl)
    write_json(STATE / "osv-cache.json", cache)
    affected = []  # (eco, name, ranges)
    for i in sorted(ids):
        for a in (cache.get(i) or {}).get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("ecosystem") and pk.get("name"):
                affected.append((pk["ecosystem"], pk["name"], a.get("ranges") or []))
    pkgs = sorted({(e, n) for e, n, _ in affected})
    # No affected packages in OSV: fall back to the GitHub Global Security Advisories' ranges.
    gh_advs, gh_note, gh_other = None, "", set()
    if not affected:
        gh_advs, why = gh_global_advisories(vid)
        if gh_advs is None:
            gh_note = f"（OSV に記録なし・GitHub のアドバイザリは引けなかった: {why}）"
        elif not gh_advs:
            gh_note = "（OSV に記録なし・GitHub のアドバイザリにも記録なし）"
        else:
            gh_note = "（OSV に記録なし・GitHub のアドバイザリで照合）"
            for a in gh_advs:
                ids |= {x for x in (a.get("ghsa_id"), a.get("cve_id")) if x}
                for v in a.get("vulnerabilities") or []:
                    e = ((v.get("package") or {}).get("ecosystem") or "?")
                    if e not in GH_ECO:
                        gh_other.add(e)
    gh_summary = next((a.get("summary") for a in gh_advs or [] if a.get("summary")), None)
    print(f"{vid}: {(root.get('summary') or root.get('details') or gh_summary or '（OSV に記録なし。ランタイムのアドバイザリだけで照合）')[:90]}")
    gh_pkgs = sorted({((v.get("package") or {}).get("ecosystem") or "?", (v.get("package") or {}).get("name") or "?")
                      for a in gh_advs or [] for v in a.get("vulnerabilities") or []})
    print(f"  関連ID {len(ids)} 件 / 影響パッケージ: " + (", ".join(f"{e}:{n}" for e, n in pkgs) or
          (", ".join(f"{e}:{n}" for e, n in gh_pkgs) + "（GitHub のアドバイザリ）" if gh_pkgs else "（OSV に記載なし）")))
    lines, verdicts = [], []
    inv = read_json(OUT / "inventory.json", None)
    if inv is None:
        print("  確認できなかった: out/inventory.json が無い（先に通常の実行をする）")
        return 0
    # PyPI / npm: ask OSV for the exact installed versions, then look for any of the related IDs
    usage = {}
    for env in inv.get("python_envs", {}).values():
        for n, v in env["packages"].items():
            usage.setdefault(("PyPI", pep503(n)), []).append((env_label(env["path"]), v))
    for n, v in (inv.get("npm_global") or {}).get("packages", {}).items():
        usage.setdefault(("npm", n), []).append(("npm -g", v))
    lock_usage = {}  # npm name -> [(lockfile, version, dev)]
    for lp, lk in (inv.get("npm_locks") or {}).items():
        for n, vs in (lk.get("packages") or {}).items():
            for v, dev in vs.items():
                lock_usage.setdefault(n, []).append((lp, v, dev))
    lib_pkgs = [(e, pep503(n) if e == "PyPI" else n) for e, n in pkgs if e in ("PyPI", "npm")]
    queries = sorted({(e, n, v) for e, n in lib_pkgs for _, v in usage.get((e, n), [])} |
                     {("npm", n, v) for e, n in lib_pkgs if e == "npm" for _, v, _ in lock_usage.get(n, [])})
    hits = osv_query(http, queries, int(cfg.get("osv_batch_size", 1000)), unv) if queries else {}
    for e, n in sorted(set(lib_pkgs)):
        found = usage.get((e, n), [])
        if not found and not (e == "npm" and lock_usage.get(n)):
            lines.append(f"  {e} {n}: 対象のパッケージなし")
            continue
        for label, v in sorted(found):
            r = hits.get((e, n, v))
            res = "確認できなかった" if r is None else "該当あり" if ids & set(r) else "該当なし"
            verdicts.append(res)
            lines.append(f"  {e} {n} {v} ({label}): {res}")
    lock_lines = []  # repository lockfiles; hits first so they survive the 15-line cut
    for e, n in sorted(set(lib_pkgs)):
        if e != "npm":
            continue
        for lp, v, dev in sorted(lock_usage.get(n, [])):
            r = hits.get(("npm", n, v))
            res = "確認できなかった" if r is None else "該当あり" if ids & set(r) else "該当なし"
            verdicts.append(res)
            lock_lines.append((res != "該当あり", f"  npm {n} {v} ({lock_label(lp, cfg)}{', dev' if dev else ''}): {res}"))
    lines += [ln for _, ln in sorted(lock_lines, key=lambda x: x[0])]
    # GitHub advisory ranges (only when OSV listed no affected package)
    gh_ranges = {}  # (eco, name) -> [(range, first_patched)]
    for a in gh_advs or []:
        for v in a.get("vulnerabilities") or []:
            pk = v.get("package") or {}
            e = GH_ECO.get(pk.get("ecosystem"))
            if e and pk.get("name"):
                n = pep503(pk["name"]) if e == "PyPI" else pk["name"]
                gh_ranges.setdefault((e, n), []).append((v.get("vulnerable_version_range"), v.get("first_patched_version")))
    gh_lock_lines = []
    for (e, n), rl in sorted(gh_ranges.items()):
        found = [(label, v, "") for label, v in usage.get((e, n), [])]
        if e == "npm":
            found += [(lock_label(lp, cfg), v, ", dev" if dev else "") for lp, v, dev in lock_usage.get(n, [])]
        if not found:
            lines.append(f"  {e} {n}: 対象のパッケージなし")
            continue
        for label, v, dev in sorted(found):
            rs = [gh_range_affected(v, rng, fp) for rng, fp in rl]
            res = "該当あり" if True in rs else "確認できなかった" if None in rs else "該当なし"
            verdicts.append(res)
            if res == "確認できなかった":
                unv.append({"kind": "gh_advisory", "target": f"{e}:{n} {v}",
                            "reason": f"範囲を解釈できない: {[rng for rng, _ in rl]!r}"})
            gh_lock_lines.append((res != "該当あり", f"  {e} {n} {v} ({label}{dev}, GitHub の範囲): {res}"))
    lines += [ln for _, ln in sorted(gh_lock_lines, key=lambda x: x[0])]
    if gh_other:
        lines.append(f"  照合の範囲外のエコシステム: {', '.join(sorted(gh_other))}")
    # runtimes: OSV ranges on runtime-named packages (e.g. Bitnami node) + repository advisories
    rts = inv.get("runtimes") or {}
    for e, n, rngs in affected:
        rt = RUNTIME_PKG.get(n.lower())
        if not rt or e in ("PyPI", "npm"):
            continue
        ver = rts.get(rt)
        if ver == "なし":
            lines.append(f"  {rt}: 未インストール（{e}:{n}）")
            continue
        res = None
        for r in rngs:
            if r.get("type") in ("SEMVER", "ECOSYSTEM") and ver:
                try:
                    res = osv_events_affected(ver, r.get("events") or [])
                except ValueError:
                    res = None
        word = "確認できなかった" if res is None else "該当あり" if res else "該当なし"
        verdicts.append(word)
        lines.append(f"  {rt} {ver} ({e}:{n} の範囲): {word}")
    # Everything unverified so far came from looking up this ID (a 404 only means OSV has no record).
    related_unv = [u for u in unv if "HTTP 404" not in u.get("reason", "")]
    unrelated_unv: list = []
    n0 = len(unv)
    _, checks = check_runtime_advisories(cfg.get("runtime_advisories", []), unv,
                                         fixed_overrides=cfg.get("advisory_fixed_overrides"))
    # Advisory-step failures count only when tied to a related ID, or when the repo's list/version
    # could not be read at all (then it is unknown whether the ID applies).
    for u in unv[n0:]:
        parts = u.get("target", "").split()
        (related_unv if len(parts) < 2 or parts[-1] in ids else unrelated_unv).append(u)
    for c in checks:
        if c.get("id") is None and c["result"] == "確認できなかった":
            verdicts.append("確認できなかった")
            lines.append(f"  {c['runtime']}: アドバイザリを確認できなかった")
        elif c.get("id") in ids or (c.get("cve") and c["cve"] in ids):
            verdicts.append(c["result"])
            lines.append(f"  {c['runtime']} {c['version']} ({c['id']} 範囲 {', '.join(c['range'])}): {c['result']}")
    for ln in lines[:15]:
        print(ln)
    if len(lines) > 15:
        print(f"  ...ほか {len(lines) - 15} 行（省略）")
    if "該当あり" in verdicts:
        final = "該当あり"
    elif "確認できなかった" in verdicts or related_unv:
        final = "確認できなかった"
    elif not verdicts:
        final = "対象外（この PC の照合の範囲に該当する製品なし）"
    else:
        final = "該当なし"
    note = f"（この ID に関係して確認できなかったもの {len(related_unv)} 件）" if related_unv else ""
    if gh_other and gh_advs:
        gh_note = gh_note[:-1] + f"・pip/npm 以外のエコシステム: {', '.join(sorted(gh_other))}）"
    print(f"結論: この PC は {final}{gh_note}{note}  所要 {time.time() - t0:.1f} 秒")
    if unrelated_unv:
        print(f"参考: 通常の照合で確認できなかったもの {len(unrelated_unv)} 件（この ID とは無関係。内訳は通常実行の out/findings.json）")
    return 10 if final == "該当あり" else 0


# ---------- main ----------

def print_timing(laps: list, total: float) -> None:
    """--timing: stage seconds, HTTP / subprocess counts and OSV detail cache use, to stderr."""
    err = sys.stderr
    print("[timing] 段階ごとの秒数", file=err)
    for name, sec in laps:
        print(f"[timing]   {sec:7.2f}  {name}", file=err)
    print(f"[timing]   {total:7.2f}  合計（起動から）", file=err)
    d = DETAIL_STATS
    print(f"[timing] OSV 詳細: 対象 {d['asked']} 件 / キャッシュ {d['cached']} / 新しく取得 {d['fetched']} / 失敗 {d['failed']}", file=err)
    for k, v in sorted(HTTP_STATS.items()):
        print(f"[timing] HTTP {k}: {v['n']} 回 / 待ち延べ {v['sec']:.1f} 秒" + (f" / 失敗 {v['fail']}" if v["fail"] else ""), file=err)
    for k, v in sorted(PROC_STATS.items()):
        print(f"[timing] 子プロセス {k}: {v['n']} 回 / 延べ {v['sec']:.1f} 秒", file=err)


def selftest_osv() -> int:
    """Exercise OSV matching/detail handling using fixed responses, without state writes."""
    from unittest.mock import patch

    http = Http("selftest", 1)
    key = ("PyPI", "requests", "2.19.0")
    vid = "GHSA-fixture-requests"
    detail = {"id": vid, "aliases": ["CVE-2000-0001"], "affected": [
        {"package": {"ecosystem": "PyPI", "name": "requests"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}
    unverified, cache = [], {}
    with patch.object(Http, "request", side_effect=[{"results": [{"vulns": [{"id": vid}]}]}, detail]):
        hits = osv_query(http, [key], 1, unverified)
        assert hits[key] == [vid] and not unverified
        assert vuln_details(http, set(hits[key]), cache, unverified) == set()
    assert not unverified and dedupe_ids(hits[key], cache) == [vid]
    assert summarize_vuln(cache[vid], "PyPI", "requests")["fixed"] == ["2.20.0"]
    with patch.object(Http, "request", return_value={"results": [{}]}):
        assert osv_query(http, [key], 1, []) == {key: []}
    with patch.object(Http, "request", side_effect=OSError("fixture failure")):
        unverified = []
        assert osv_query(http, [key], 1, unverified) == {key: None} and unverified
        unverified = []
        before = dict(cache[vid])
        vuln_details(http, {vid}, cache, unverified, ttl_h=-1)
        assert cache[vid] == before and unverified
    print("selftest: 成功（固定 OSV 応答で該当・非該当・取得失敗・詳細保持を検証、通信なし）")
    return 0


def selftest_runtime() -> int:
    from unittest.mock import patch

    repo = "oven-sh/bun"
    advisory = {"state": "published", "ghsa_id": "GHSA-fixture-runtime", "vulnerabilities": [
        {"vulnerable_version_range": "< 1.3.15", "patched_versions": "1.3.15"}]}
    entries = [{"repo": repo, "version_cmd": ["bun", "--version"]}]
    with patch.dict(check_runtime_advisories.__globals__, ADV_CACHE={}), \
            patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda _: [advisory]):
        for version, expected in (("1.3.14", True), ("1.3.15", False)):
            unverified = []
            findings, checks = check_runtime_advisories(entries, unverified, override={repo: version})
            assert bool(findings) is expected and checks and not unverified
    with patch.dict(check_runtime_advisories.__globals__, ADV_CACHE={}), \
            patch.dict(check_runtime_advisories.__globals__, gh_pages=lambda _: (_ for _ in ()).throw(OSError("fixture"))):
        unverified = []
        findings, checks = check_runtime_advisories(entries, unverified, override={repo: "1.3.14"})
        assert not findings and unverified and checks[0]["result"] == "確認できなかった"
    print("selftest-runtime: 成功（固定勧告で該当・修正済み・取得失敗を検証、通信なし）")
    return 0


def selftest_impact() -> int:
    result = impact.selftest(scan_exit_code)
    # Exercise the real counting and final writes as well as the pure impact core.
    import contextlib
    import io
    from unittest.mock import patch

    module = sys.modules[__name__]
    inventory_loader = load_vps_inventory
    integration_failures = []

    def case(name, test):
        try:
            with io.TextIOWrapper(io.BytesIO(), encoding="utf-8") as output, contextlib.redirect_stdout(output):
                test()
        except Exception as exc:
            integration_failures.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print("PASS " + name)

    try:
        with tempfile.TemporaryDirectory(prefix="impact-scan-selftest-", dir=HERE) as temporary:
            root = Path(temporary)
            example = read_json(HERE / "impact-items.example.json", {})
            write_json(root / "impact-items.json", example)
            coverage = {"covered": 0, "uncovered": [], "matched_entries": [], "unverified_kinds": []}
            xwatch = {"products": [], "inventory_products": [], "manual_products": [], "missing_product_entries": []}
            fixture_values = {
                "load_config": {"python_roots": [], "exclude_path_parts": [],
                                "patchwait": {"enabled": False}, "scanmux": {"enabled": False}},
                "load_vps_inventory": None, "scan_python": {}, "scan_npm": {"packages": {}},
                "scan_runtimes": {}, "scan_npm_locks": {"locks": {}, "unsupported": [], "skipped": 0, "elapsed_sec": 0},
                "scan_apps": [], "scan_services": [], "scan_listening": [], "scan_containers_vms": [],
                "check_winget": {"verified": True, "updates": [], "watched_updates": 0},
                "load_manual_assets": [], "check_coverage": coverage, "xwatch_products": xwatch,
                "write_xwatch_prompt": None, "check_node": ([], [], {}),
                "check_runtime_advisories": ([], []), "check_app_advisories": ([], []),
                "check_running": [], "fetch_releases": {}, "coverage_summary": "合成の監視範囲",
                "coverage_changes": 0, "coverage_keys": set(),
            }
            ubuntu = {"id": "CVE-2099-10001", "packages": [{"name": "linux", "statuses": [{"release_codename": "resolute",
                       "status": "released", "description": "example-fixed-version"}]}]}
            cvss = example["items"][0]["claims"][1]["check"]["expected"]
            record = {"cveMetadata": {"cveId": "CVE-2099-10001"},
                      "containers": {"cna": {"providerMetadata": {"shortName": cvss["scorer"]},
                      "metrics": [{"cvssV3_1": {"version": cvss["version"], "baseScore": cvss["score"],
                                              "vectorString": cvss["vector"]}}]}}}
            write_order = []
            original_write = write_json

            def save(path, data):
                write_order.append(path.name)
                original_write(path, data)

            def integration():
                with patch.object(impact, "check_all", wraps=impact.check_all) as called:
                    code = main()
                    assert called.call_count == 1
                findings = read_json(root / "out" / "findings.json", {})
                saved = read_json(root / "state" / "state.json", {})
                assert code == 10 and findings["counts"]["new"] == 1
                assert findings["scan_id"] == findings["impact_checks"]["scan_id"] == "fixture-main"
                assert findings["impact_checks"]["changed_count"] == 1 and saved["impact"]["entries"]
                assert write_order.index("findings.json") < write_order.index("state.json")
                write_order.clear()
                code = main()
                findings = read_json(root / "out" / "findings.json", {})
                assert code == 2 and findings["counts"]["new"] == 0
                assert any(u["kind"] == "impact" for u in findings["unverified"])

            def stale_inventory():
                now = dt.datetime(2026, 11, 7, 12, tzinfo=dt.timezone.utc)
                collected = (now - dt.timedelta(hours=24)).isoformat()
                boot = {"booted_at": "2026-11-04T00:00:00Z", "boot_id": "fixture-old"}
                data = {"items": [{"id": "fixture-vps", "title": "合成VPS在庫", "kind": "advisory",
                        "refs": ["https://observations.example.test/vps"], "claims": [{
                        "id": "boot", "field": "our_exposure", "text": "在庫の起動事実を確認する。",
                        "source_url": "https://observations.example.test/vps", "source_type": "own_observation",
                        "observed_at": collected, "observed_by": "parent", "observation_scope": "inventory_only",
                        "check": {"kind": "vps_fact", "host_alias": "host.example.test", "fact": "boot",
                                  "expected": boot}}]}]}
                doc = {"schema": 1, "host": "host.example.test", "generated": collected,
                       "os": {"ID": "ubuntu", "VERSION_ID": "26.04"}, "packages": [], "errors": [],
                       "containers": [], "listening": [], "security_facts": {"boot": boot}}
                original_write(root / "impact-items.json", data)
                first = impact.check_all(root, scan_id="fixture-history", started_at=collected, inventory=doc)
                assert isinstance(first.assessment.items[0].claims[0].outcome, impact.Confirmed)
                original_write(root / "state" / "state.json", {"impact": asdict(first.next_state)})
                # An older saved snapshot and two arrivals prove selection by collector time.
                original_write(root / "state" / "vps" / "vps-inventory.json", doc)
                newer = json.loads(json.dumps(doc))
                newer["security_facts"]["boot"] = {**boot, "boot_id": "fixture-new"}
                newer["generated"] = (now - dt.timedelta(hours=23)).isoformat()
                original_write(root / "inbox" / "vps-inventory.json", newer)
                doc["security_facts"]["boot"] = {**boot, "boot_id": "fixture-middle"}
                original_write(root / "inbox" / "vps-inventory (1).json", doc)

                def load(*args, **kwargs):
                    return inventory_loader(*args, **kwargs, now=now)

                config = {**fixture_values["load_config"], "vps_hosts": ["host.example.test"]}
                with patch.object(module, "load_config", return_value=config), \
                        patch.object(module, "load_vps_inventory", side_effect=load):
                    code = main()
                findings = read_json(root / "out" / "findings.json", {})
                check = findings["impact_checks"]["items"][0]["claims"][0]
                assert code == 10 and findings["impact_checks"]["changed_count"] == 1
                assert check["outcome"]["status"] == "changed" and newer["generated"] in check["display"]
                assert findings["vps_summary"] is None  # Package matching still rejects >13 hours.
                # With no arrivals left, impact must still use the saved 24-hour snapshot.
                for path in (root / "inbox").glob("*.json"):
                    path.unlink()
                with patch.object(module, "load_config", return_value=config), \
                        patch.object(module, "load_vps_inventory", side_effect=load):
                    assert main() == 10
                check = read_json(root / "out" / "findings.json", {})["impact_checks"]["items"][0]["claims"][0]
                assert check["outcome"]["evidence"]["observed_at"] == collected

            def held_lock():
                with impact.workspace_lock(root), patch.object(module, "run_scan") as scan:
                    stream = io.StringIO()
                    # main configures stdout; keep its real stream and capture print calls instead.
                    with patch("builtins.print", side_effect=lambda *a, **k: stream.write(" ".join(map(str, a)) + "\n")):
                        assert main() == 2
                    assert not scan.called
                    lines = stream.getvalue().splitlines()
                    assert len(lines) == 1 and "別の走査" in lines[0]
                    assert "Traceback" not in lines[0]

            with contextlib.ExitStack() as stack:
                for name, value in fixture_values.items():
                    stack.enter_context(patch.object(module, name, return_value=value))
                for name, value in (("HERE", root), ("STATE", root / "state"), ("OUT", root / "out")):
                    stack.enter_context(patch.object(module, name, value))
                stack.enter_context(patch.object(module, "write_json", side_effect=save))
                child = stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("実機の子プロセスは禁止")))
                stack.enter_context(patch.object(Http, "request", return_value={"vulnerabilities": [{"cveID": "CVE-2099-10001"}]}))
                stack.enter_context(patch.object(impact, "real_fetch", side_effect=lambda u: ubuntu if "ubuntu.com" in u else record))
                stack.enter_context(patch.object(sys, "argv", ["scan.py", "--baseline", "--scan-id", "fixture-main"]))
                # Capture each result outside redirected stdout without reconfiguring a StringIO.
                for name, test in (
                    ("scan.mainの単一呼出・baseline終了10・履歴保存順・継続矛盾終了2", integration),
                    ("24時間前のVPS在庫もimpactで比較・収集日時表示・終了10", stale_inventory),
                    ("ロック競合は日本語1行・終了2・走査未開始", held_lock),
                ):
                    case(name, test)
                assert not child.called, "統合ケースで子プロセスが起動された"
        print("PASS impact統合ケースは実機の子プロセス起動なし")
    except Exception as exc:
        print(f"FAIL scan.mainのimpact統合: {type(exc).__name__}: {exc}")
        return 1
    result = max(result, bool(integration_failures))
    spec = importlib.util.spec_from_file_location("security_loop_report_build", Path(__file__).resolve().with_name("report_build.py"))
    report_build = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = report_build
    spec.loader.exec_module(report_build)
    result = max(result, report_build.selftest(show_sample=False))
    print("selftest-impact: " + ("失敗" if result else "成功（合成fixture・通信・実機収集なし）"))
    return int(result)


def main() -> int:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", newline="\n")
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true", help="既存の検出を既知扱いにする。impactの欠けた履歴は初期化できるが、観測した変化は抑制せず新規・終了10にする")
    ap.add_argument("--selftest-impact", action="store_true", help="合成データで影響の主張・照合・履歴・承認を検査（通信・実機収集なし）")
    ap.add_argument("--scan-id", help="親が割り当てた照合ID（省略時は自動生成）")
    ap.add_argument("--selftest", action="store_true", help="既知の脆弱な版 requests 2.19.0 を足して照合が効くか確かめる")
    ap.add_argument("--selftest-runtime", action="store_true", help="Bun を 1.3.14 と仮定してランタイム照合が効くか確かめる（state は変えない）")
    ap.add_argument("--selftest-ptp", action="store_true", help="fixture で Patch the Planet の抽出と新規判定を確かめる（通信・state 更新なし）")
    ap.add_argument("--selftest-patchwait", action="store_true", help="fixture で patchwait の解析・新規判定・失敗処理を確かめる（通信・実走査なし）")
    ap.add_argument("--selftest-scanmux", action="store_true", help="inline fixture で ScanMux の解析・新規判定・失敗処理を確かめる（通信・実走査なし）")
    ap.add_argument("--selftest-coverage", action="store_true", help="fixture で在庫の未監視・新規判定を確かめる（通信・state 更新・実機収集なし）")
    ap.add_argument("--selftest-xwatch", action="store_true", help="fixture で製品一覧・手動資産・KEV を確かめる（通信・state 更新なし）")
    ap.add_argument("--selftest-vps", action="store_true", help="fixture で VPS 在庫・受信・OSV・鮮度を確かめる（通信・state 更新なし）")
    ap.add_argument("--cve", metavar="ID", help="CVE / GHSA ID 1つについて、この PC で該当する環境・版を答える")
    ap.add_argument("--config", default=str(HERE / "scan-config.json"))
    ap.add_argument("--timing", action="store_true", help="各段階の所要秒数と HTTP / 子プロセスの回数を標準エラーに出す")
    args = ap.parse_args()
    selftests = [(args.selftest, selftest_osv), (args.selftest_coverage, selftest_coverage),
                 (args.selftest_patchwait, selftest_patchwait), (args.selftest_ptp, selftest_ptp),
                 (args.selftest_runtime, selftest_runtime), (args.selftest_scanmux, selftest_scanmux),
                 (args.selftest_vps, selftest_vps), (args.selftest_xwatch, selftest_xwatch),
                 (args.selftest_impact, selftest_impact)]
    if any(selected for selected, _ in selftests):
        from unittest.mock import patch
        with patch.object(urllib.request, "urlopen", side_effect=AssertionError("network forbidden in selftests")), \
                patch.object(urllib.request.HTTPHandler, "http_open", side_effect=AssertionError("network forbidden in selftests")), \
                patch.object(urllib.request.HTTPSHandler, "https_open", side_effect=AssertionError("network forbidden in selftests")):
            results = [test() for selected, test in selftests if selected]
        return max(results)
    try:
        with impact.workspace_lock(HERE):
            return run_scan(args)
    except impact.WorkspaceLockError as exc:
        print(str(exc))
        return 2


def run_scan(args) -> int:
    t0 = time.time()
    scan_id = args.scan_id or uuid.uuid4().hex
    cfg = load_config(Path(args.config), "scan")
    http = Http(cfg.get("user_agent", "security-loop-scan/1.0"), int(cfg.get("http_timeout_sec", 60)))
    batch = int(cfg.get("osv_batch_size", 1000))
    cache_path = STATE / "osv-cache.json"
    cache = read_json(cache_path, {})
    ttl_h = float(cfg.get("osv_detail_ttl_hours", 24))

    if args.cve:
        return cve_lookup(http, cfg, cache, args.cve.strip(), t0)

    state_path = STATE / "state.json"
    state = read_json(state_path, {"seen": {}, "releases": {}, "kev_seen": [], "kev_last_run": None})
    seen: dict = state.setdefault("seen", {})
    unverified: list = []
    stamp = now_iso()
    laps: list = []
    t_lap = [t0]

    def lap(name: str) -> None:
        now = time.time()
        laps.append((name, now - t_lap[0]))
        t_lap[0] = now

    # 1. inventory
    lap("起動・config/state 読み込み")
    impact_inventories = {}
    vps = load_vps_inventory(str(HERE / cfg.get("vps_inventory_glob", "inbox/vps-inventory*.json")),
                             STATE / "vps" / cfg.get("vps_inventory_filename", "vps-inventory.json"),
                             unverified, cfg.get("vps_hosts", []),
                             inventory_filename=cfg.get("vps_inventory_filename", "vps-inventory.json"),
                             impact_inventories=impact_inventories)
    inactive_kernels = []
    vps_usage = vps_package_usage(vps, unverified, inactive_kernels)
    py_envs = scan_python(cfg["python_roots"], cfg.get("exclude_path_parts", []), unverified)
    lap("Python 環境の走査")
    npm = scan_npm(unverified)
    lap("npm グローバル")
    runtimes = scan_runtimes(unverified)
    lap("ランタイムの版（scan_runtimes）")
    npm_locks = scan_npm_locks(cfg.get("npm_lock_roots", []), cfg.get("exclude_path_parts", []), unverified)
    lap("lockfile の探索と解析")
    inventory = {"generated": stamp, "python_envs": py_envs, "npm_global": npm, "runtimes": runtimes,
                 "npm_locks": npm_locks["locks"], "npm_lock_unsupported": [u["target"] for u in npm_locks["unsupported"]]}
    inventory.update(apps=scan_apps(unverified), services=scan_services(unverified),
                     listening=scan_listening(unverified), containers_vms=scan_containers_vms(unverified))
    inventory["manual"] = load_manual_assets(HERE / "assets-manual.json", unverified)
    inventory.update(vps=vps, vps_packages=vps_usage,
                     vps_listening=vps_listening_assets(vps, cfg.get("vps_private_networks", ["100.64.0.0/10"])))
    inventory["unverified"] = [u for u in unverified if u["kind"] == "inventory"]
    coverage = check_coverage(inventory, HERE / cfg.get("coverage_map", "coverage-map.json"), unverified,
                              extra_rules=cfg.get("coverage_extra_rules"))
    winget = check_winget(inventory, coverage, unverified)
    inventory["winget"] = winget
    xwatch = xwatch_products(coverage, inventory["manual"])
    write_xwatch_prompt(HERE / "x-watch-prompt.md", OUT / "x-watch-prompt.md", xwatch, unverified,
                        inputs_ok=coverage["covered"] is not None and "manual" not in coverage["unverified_kinds"])
    kev_keywords, kev_skipped = inventory_kev_keywords(cfg.get("kev_keywords", []), xwatch["products"])
    lap("PC 在庫・未監視の突き合わせ")
    write_json(OUT / "inventory.json", inventory)

    # 2. OSV
    keys = set()
    for env in py_envs.values():
        for n, v in env["packages"].items():
            keys.add(("PyPI", pep503(n), v))
    for n, v in npm["packages"].items():
        keys.add(("npm", n, v))
    keys.update(item[:3] for item in vps_usage)
    keys = sorted(keys)
    lock_keys = sorted({("npm", n, v) for lk in npm_locks["locks"].values() for n, vs in lk["packages"].items() for v in vs})
    lap("inventory 書き出し・キー作成")
    distro_rows = {}
    batch_requests_before = HTTP_STATS.get("osv_querybatch", {}).get("n", 0)
    batch_start = time.perf_counter()
    hits = osv_query(http, sorted(set(keys) | set(lock_keys)), batch, unverified, distro_rows=distro_rows)
    vps_batch_sec = time.perf_counter() - batch_start
    vps_batch_requests = HTTP_STATS.get("osv_querybatch", {}).get("n", 0) - batch_requests_before
    lap("OSV querybatch")
    all_ids = {i for key, ids in hits.items() if not is_distro(key[0]) and ids for i in ids}
    changed_ids = vuln_details(http, all_ids, cache, unverified, ttl_h)
    query_before = dict(HTTP_STATS.get("osv_query", {}))
    details_before = DETAIL_STATS["fetched"]
    detail_start = time.perf_counter()
    changed_ids |= distro_vuln_details(http, distro_rows, cache, unverified, ttl_h)
    vps_detail_sec = time.perf_counter() - detail_start
    vps_detail_count = DETAIL_STATS["fetched"] - details_before
    query_after = HTTP_STATS.get("osv_query", {})
    vps_query_requests = query_after.get("n", 0) - query_before.get("n", 0)
    vps_query_sec = query_after.get("sec", 0.0) - query_before.get("sec", 0.0)
    lap("OSV 詳細取得（vuln_details）")
    write_json(cache_path, cache)
    lap("osv-cache 書き出し")

    usage = []  # (eco, name, ver, env)
    for env in py_envs.values():
        for n, v in env["packages"].items():
            usage.append(("PyPI", pep503(n), v, env["path"], n))
    for n, v in npm["packages"].items():
        usage.append(("npm", n, v, "npm -g", n))
    usage.extend(vps_usage)
    dev_of = {}
    for lp, lk in npm_locks["locks"].items():
        for n, vs in lk["packages"].items():
            for v, dev in vs.items():
                usage.append(("npm", n, v, lp, n))
                dev_of[(lp, n, v)] = dev
    findings_osv = build_osv_findings(usage, hits, cache, dev_of)
    checked = sum(1 for k in keys if hits.get(k) is not None)
    hit_pkgs = sum(1 for k in keys if hits.get(k))
    lock_checked = sum(1 for k in lock_keys if hits.get(k) is not None)
    lock_hit = sum(1 for k in lock_keys if hits.get(k))

    lap("OSV findings 組み立て")
    # 2b. runtimes (Node release index + repository security advisories)
    findings_rt, node_checks, node_min = check_node(http, runtimes.get("node"), unverified)
    lap("Node のリリース一覧")
    patchwait = run_patchwait(cfg.get("patchwait", {}), node_min, unverified)
    lap("patchwait（同梱 Node・G3 信頼側）")
    scanmux = run_scanmux(cfg.get("scanmux", {}), unverified)
    lap("ScanMux（依存 advisory）")
    f_adv, adv_checks = check_runtime_advisories(cfg.get("runtime_advisories", []), unverified,
                                                  fixed_overrides=cfg.get("advisory_fixed_overrides"))
    f_apps, app_adv_checks = check_app_advisories(coverage, unverified)
    coverage = check_coverage(inventory, HERE / cfg.get("coverage_map", "coverage-map.json"), unverified,
                              app_advisory_checks=app_adv_checks, winget=winget, osv_hits=hits,
                              extra_rules=cfg.get("coverage_extra_rules"))
    n_coverage = coverage_changes(coverage, state, args.baseline)
    lap("ランタイムのアドバイザリ")
    findings_rt += f_adv + f_apps
    running = check_running(cfg, node_min, bool(node_min), unverified)
    # A pre-fix version still running: tracked like other findings, keyed by path and version.
    findings_run = [r for r in running if r["result"] == "該当あり"]
    for r in findings_run:
        r["key"] = f"running|{r['path']}|{r['version']}"
    lap("動いているプロセス")
    rt_checks = node_checks + adv_checks + app_adv_checks

    # 3. releases
    release_repos = sorted(set(cfg.get("watch_releases", [])) | {
        r["ref"] for e in coverage["matched_entries"] for r in e["routes"] if r["type"] == "release"})
    rel = fetch_releases(release_repos, cfg.get("tag_repos", []), unverified)
    lap("リリース")
    prev_rel = state.setdefault("releases", {})
    findings_rel = []
    for repo, r in rel.items():
        findings_rel.append({"key": f"release|{repo}|{r['tag']}", "repo": repo, "tag": r["tag"],
                             "previous": (prev_rel.get(repo) or {}).get("tag"), "published": r["published"], "url": r["url"]})

    # 4. KEV
    findings_kev = []
    kev_ok = False
    kev_ids_now: list = []
    try:
        kev = http.request(KEV_URL)
        vulns = kev.get("vulnerabilities")
        if not isinstance(vulns, list) or not vulns:
            raise RuntimeError("KEV の形が想定と違う")
        kev_ok = True
        for it in vulns:
            cid = it.get("cveID")
            kev_ids_now.append(cid)
            # Re-match the whole catalog: newly inventoried products can match old KEV entries.
            # The existing findings key in state['seen'] handles new/known detection below.
            kw = kev_match(it, kev_keywords)
            if kw:
                findings_kev.append({"key": f"kev|{cid}", "cve": cid, "vendor": it.get("vendorProject"),
                                     "product": it.get("product"), "name": it.get("vulnerabilityName"),
                                     "dateAdded": it.get("dateAdded"), "dueDate": it.get("dueDate"),
                                     "ransomware": it.get("knownRansomwareCampaignUse"), "keyword": kw,
                                     "keyword_source": kev_keywords[kw]})
    except Exception as e:
        unverified.append({"kind": "kev", "target": KEV_URL, "reason": str(e)})

    lap("KEV")
    # 4b. Patch the Planet
    ptp_url = cfg.get("patchtheplanet_url")
    findings_ptp = []
    ptp_cves = None
    if ptp_url:
        try:
            disclosures, ptp_cves = extract_ptp(http.request(ptp_url, text=True),
                                                lambda url: http.request(url, text=True,
                                                                         allowed_hostname=urllib.parse.urlsplit(ptp_url).hostname), ptp_url)
            findings_ptp = ptp_findings(disclosures, ptp_cves, state)
            for f in findings_ptp:
                f["url"] = ptp_url
        except Exception as e:
            ptp_cves = None
            unverified.append({"kind": "ptp", "target": ptp_url, "reason": f"patchtheplanet: {e}"})
        lap("Patch the Planet")

    # The only impact acquisition path; reuse the inventory already imported above.
    impact_batch = impact.check_all(HERE, scan_id=scan_id, started_at=stamp, fetch=impact.real_fetch,
                                   previous_state=state.get("impact", impact.MISSING), inventory=impact_inventories,
                                   release_codenames=cfg.get("impact_release_codenames"))
    unverified.extend(impact_batch.assessment.diagnostics)

    # 5. new / seen
    # A seen OSV / runtime finding becomes new again when its advisory's affected ranges or fixed
    # versions changed: compared with the fingerprint recorded at the last successful run, or (first
    # run with fingerprints) with the cached detail it replaced.
    sigs: dict = state.setdefault("sigs", {})
    all_f = findings_osv + findings_rt + findings_run + findings_rel + findings_kev + findings_ptp
    vps_baseline = record_vps_packages(state, vps, vps_usage, hits)
    mark_new_findings(all_f, state, changed_ids, stamp, args.baseline, vps_baseline=vps_baseline)
    new_osv = [f for f in findings_osv if f["new"]]
    new_rt = [f for f in findings_rt if f["new"]]
    new_rel = [f for f in findings_rel if f["new"]]
    new_kev = [f for f in findings_kev if f["new"]]
    new_run = [f for f in findings_run if f["new"]]
    new_ptp = [f for f in findings_ptp if f["new"]]
    try:
        previous = read_json(OUT / "findings.json", {}) if patchwait["enabled"] else {}
        patchwait["new"] = patchwait_changes(patchwait, previous.get("patchwait"), args.baseline)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as e:
        reason = f"前回の patchwait 結果を比較できない: {type(e).__name__}: {e}"
        patchwait["errors"].append(reason)
        unverified.append({"kind": "patchwait", "target": "out/findings.json", "reason": reason})
        patchwait["new"] = patchwait_changes(patchwait, None, baseline=True)
    n_patchwait = patchwait["new"]["total"]
    compare_scanmux_findings(scanmux, OUT / "findings.json", unverified, args.baseline)
    n_scanmux = scanmux["new"]["total"]
    n_new = len(new_osv) + len(new_rt) + len(new_run) + len(new_rel) + len(new_kev) + len(new_ptp) + n_patchwait + n_scanmux + n_coverage + impact_batch.assessment.changed_count
    exit_code = scan_exit_code(n_new, bool(ptp_url and ptp_cves is None) or bool(patchwait["errors"]) or bool(scanmux["errors"]) or impact_batch.assessment.required_failure)
    run_count = {w: sum(1 for r in running if r["result"] == w) for w in ("該当あり", "該当なし", "判定不能")}
    rt_count = {w: sum(1 for c in rt_checks if c["result"] == w) for w in ("該当あり", "該当なし", "確認できなかった", "未インストール")}
    local_source = [{"env": e["path"], "package": n, "version": x["version"], "url": x["url"]}
                    for e in py_envs.values() for n, x in e.get("local_source", {}).items()]

    findings = {"generated": stamp, "baseline": args.baseline,
                "scan_id": scan_id, "impact_checks": asdict(impact_batch.assessment),
                "counts": {"python_envs": len(py_envs), "pypi_packages": sum(len(e["packages"]) for e in py_envs.values()),
                           **{kind: len(inventory[kind]) if inventory[kind] or kind not in coverage["unverified_kinds"] else None
                              for kind in PC_INVENTORY_KINDS},
                           "manual": len(inventory["manual"]) if "manual" not in coverage["unverified_kinds"] else None,
                           "vps_package_versions": len(vps_usage) if vps is not None else None,
                           "vps_listening": len(inventory["vps_listening"]) if vps is not None else None,
                           "npm_packages": len(npm["packages"]), "osv_queried": len(keys), "osv_checked": checked,
                           "osv_hit_packages": hit_pkgs, "osv_no_hit_packages": checked - hit_pkgs,
                           "osv_unverified_packages": len(keys) - checked,
                           "osv_findings": len(findings_osv), "osv_changed": sum(1 for f in findings_osv if f["changed"]),
                           "runtime_checks": len(rt_checks), "runtime_hit": rt_count["該当あり"],
                           "runtime_no_hit": rt_count["該当なし"], "runtime_unverified": rt_count["確認できなかった"],
                           "runtime_findings": len(findings_rt), "releases": len(findings_rel), "kev": len(findings_kev),
                           "ptp": len(findings_ptp) if ptp_cves is not None else None,
                           "new": n_new, "unverified": len(unverified), "local_source": len(local_source), "npm_lockfiles": len(npm_locks["locks"]), "npm_lock_versions": len(lock_keys), "npm_lock_osv_checked": lock_checked, "npm_lock_hit_versions": lock_hit, "npm_lock_unverified_versions": len(lock_keys) - lock_checked, "npm_lock_skipped": npm_locks["skipped"], "npm_lock_unsupported": len(npm_locks["unsupported"]),
                           "running_hit": run_count["該当あり"], "running_no_hit": run_count["該当なし"],
                           "running_unverified": run_count["判定不能"], "running_new": len(new_run), "patchwait_new": n_patchwait,
                           "scanmux_new": n_scanmux, "coverage_new": n_coverage,
                           "coverage_covered": coverage["covered"],
                           "coverage_uncovered": len(coverage["uncovered"]) if coverage["covered"] is not None else None,
                           "coverage_exposed": sum(a["exposed"] for a in coverage["uncovered"]) if coverage["covered"] is not None else None,
                           "coverage_unverified_kinds": len(coverage["unverified_kinds"])},
                "local_source": local_source, "osv": findings_osv, "runtime": findings_rt, "runtime_checks": rt_checks,
                "vps_inactive_kernels": inactive_kernels,
                "vps_summary": vps_osv_summary(findings_osv, vps_labels(vps)) if vps else None,
                "running": running,
                "node_security_minimums": node_min,
                "patchwait": patchwait,
                "scanmux": scanmux,
                "coverage": coverage,
                "winget": winget, "app_advisory_checks": app_adv_checks,
                "x_watch_prompt": xwatch, "kev_skipped_keywords": kev_skipped,
                "releases": findings_rel, "kev": findings_kev, "ptp": findings_ptp,
                "unverified": unverified, "npm_lock_unsupported": npm_locks["unsupported"]}
    write_json(OUT / "findings.json", findings)

    # state: only reached on success
    remember_findings(all_f, state)
    for repo, r in rel.items():
        prev_rel[repo] = {"tag": r["tag"], "checked": stamp}
    if kev_ok:
        state["kev_seen"] = sorted(set(state.get("kev_seen") or []) | {c for c in kev_ids_now if c})
        state["kev_last_run"] = stamp
    if ptp_cves is not None:
        state["ptp_seen"] = sorted(set(state.get("ptp_seen") or []) | {f["key"] for f in findings_ptp})
        state["ptp_cves_seen"] = sorted(set(state.get("ptp_cves_seen") or []) | ptp_cves)
        state["ptp_last_run"] = stamp
    if coverage["covered"] is not None:
        state["coverage_seen"] = sorted(set(state.get("coverage_seen") or []) | coverage_keys(coverage))
    state["last_run"] = stamp
    state["impact"] = asdict(impact_batch.next_state)
    write_json(state_path, state)
    lap("findings / state の書き出し")
    if args.timing:
        print_timing(laps, time.time() - t0)

    # stdout summary (<= 20 lines)
    c = findings["counts"]
    print(f"走査: Python環境 {c['python_envs']} / PyPIパッケージ {c['pypi_packages']} / npm -g {c['npm_packages']}  (OSV照合 {c['osv_queried']} 版)")
    print(f"OSV: 該当あり {c['osv_hit_packages']} 版 / 該当なし {c['osv_no_hit_packages']} 版 / 確認できなかった {c['osv_unverified_packages']} 版 / 該当ID延べ {c['osv_findings']}")
    if findings["vps_summary"]:
        print(findings["vps_summary"])
    if vps is not None:
        # Request counts include failed calls; request seconds include retries/backoff.
        # Details count distinct records acquired (including inline querybatch records).
        print(f"VPS OSV 計測: querybatch（PC共通）{vps_batch_requests} 回 / {vps_batch_sec:.1f} 秒、"
              f"/query {vps_query_requests} 回 / 待ち延べ {vps_query_sec:.1f} 秒、"
              f"詳細取得 {vps_detail_count} 件 / {vps_detail_sec:.1f} 秒（通信再試行の待ち時間を含む）")
    if inactive_kernels:
        print("動いていないカーネルのパッケージ: " + "、".join(
            f"{item['env']} {', '.join(item['versions'])}" for item in inactive_kernels))
    print(f"npm lockfile: {c['npm_lockfiles']} 件・パッケージ {c['npm_lock_versions']} 版（OSV 照合 {c['npm_lock_osv_checked']} 版）・該当あり {c['npm_lock_hit_versions']} 版・未対応の lockfile {c['npm_lock_unsupported']} 件（照合しない版 {c['npm_lock_skipped']} 件・探索 {npm_locks['elapsed_sec']} 秒）")
    print(f"ローカルのソース（editable / file://）{c['local_source']} 件は OSV の対象外（一覧は out/findings.json の local_source）")
    rv = {c["runtime"]: c["version"] for c in rt_checks}
    print(f"ランタイム: 該当あり {c['runtime_hit']} / 該当なし {c['runtime_no_hit']} / 確認できなかった {c['runtime_unverified']} 件"
          f"（{' '.join(f'{k} {v}' for k, v in rv.items())}）  Node security 最新: "
          + ", ".join(f"{m}={v}" for m, v in list(node_min.items())[:4]))
    print(f"動いているプロセス: 該当あり {c['running_hit']} / 該当なし {c['running_no_hit']} / 判定不能 {c['running_unverified']}")
    print(patchwait_summary(patchwait))
    print(scanmux_summary(scanmux))
    print(coverage_summary(coverage))
    print(winget_summary(winget))
    print(f"𝕏 の製品の一覧: {len(xwatch['products'])} 件（在庫 {len(xwatch['inventory_products'])}・手で持つ物 {len(xwatch['manual_products'])}）")
    if xwatch["missing_product_entries"]:
        print("製品名 product の無い対応表の項目: " + "、".join(xwatch["missing_product_entries"]))
    if kev_skipped:
        print("KEV の派生キーワードから除外（短名・一般名）: " + "、".join(kev_skipped))
    print(f"新規: OSV {len(new_osv)}（うち範囲変更 {sum(1 for f in new_osv if f['changed'])}） / ランタイム {len(new_rt)} / プロセス {len(new_run)} / リリース {len(new_rel)} / KEV {len(new_kev)}"
          + ((f" / Patch the Planet {len(new_ptp)}" if ptp_cves is not None else " / Patch the Planet 確認できなかった") if ptp_url else "")
          + f" / patchwait {n_patchwait}"
          + f" / ScanMux {n_scanmux}"
          + f" / 未監視 {n_coverage}"
          + f" / 影響の変化 {impact_batch.assessment.changed_count}"
          + ("  (--baseline: impactの変化を除き既知扱い)" if args.baseline else ""))
    ranked = sorted(new_rt + new_osv, key=lambda f: (f["ecosystem"] != "runtime", -SEV_RANK.get(f["severity"], 0), -(f["cvss3"] or 0)))
    top = [f"{'RUN' if f['ecosystem'] == 'runtime' else 'OSV'} {f['severity']:<8} {f['package']} {f['version']} {f['id']}"
           f"{' (範囲変更)' if f['changed'] else ''} 修正版={','.join(f['fixed'][-2:]) or '-'}"
           + (f" [{lock_label(f['env'], cfg)}{' dev' if f.get('dev') else ''}]" if f.get("source") == "npm_lock" else "")
           for f in ranked]
    top = [f"KEV {f['cve']} {f['vendor']} {f['product']}" for f in new_kev] + top
    top = [f"Patch the Planet {f['title']}" for f in new_ptp] + top
    top = [f"PROC {f['name']} {f['version']} 修正版={f.get('fixed') or '-'} {f['path']}" for f in new_run] + top
    top += [f"REL {f['repo']} {f['previous'] or '(初回)'} -> {f['tag']}" for f in new_rel]
    for line in top[:10]:
        print("  " + line)
    print(f"確認できなかった: {c['unverified']} 件（内訳は out/findings.json の unverified）")
    print(f"所要 {time.time() - t0:.1f} 秒  終了コード {exit_code}")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        print("scan.py: 失敗（state は更新していない）", file=sys.stderr)
        sys.exit(2)
