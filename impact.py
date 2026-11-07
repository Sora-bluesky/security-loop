"""Authored impact claims, observations and two-lane approval stay separate.

JSON input is {"items": [...]} (a bare item list is also accepted). Claims use
the flat source_* fields; checks carry a kind and a structured expected value.
check_all receives previous_state and the already imported inventory from scan.
It never reads an inventory or writes history. The caller holds workspace_lock
from before reading state until after writing findings and then state.

Collector handoff: inventory has host, generated and security_facts containing
boot: {booted_at, boot_id?}, nft_tables: [{family, name}], and optional errors:
{boot: message, nft_tables: message}. Missing/failed fields are not empty facts.
read_for_report(items_path, findings_path, scan_id=...) returns an Assessment,
revalidates authored input and approval, and never acquires new evidence.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import math
import os
import re
import tempfile
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable, Literal


@dataclass(frozen=True)
class Source:
    url: str
    type: Literal["vendor", "distro", "cna", "nvd", "researcher", "own_observation"]
    observed_at: str
    observed_by: Literal["parent", "sora", "hermes", "scan"]
    quote: str | None = None
    demo_env: str | None = None


@dataclass(frozen=True)
class UbuntuStatus:
    release: str
    package: str
    status: str
    fixed_version: str | None = None


@dataclass(frozen=True)
class Cvss:
    version: str
    score: str
    vector: str
    scorer: str
    role: Literal["cna", "adp"]


@dataclass(frozen=True)
class BootFact:
    booted_at: str
    boot_id: str | None = None


@dataclass(frozen=True)
class TableFact:
    family: str
    name: str
    present: bool


@dataclass(frozen=True)
class UbuntuCve:
    cve: str
    release: str
    package: str
    expected: UbuntuStatus
    kind: str = field(default="ubuntu_cve", init=False)


@dataclass(frozen=True)
class CveRecord:
    cve: str
    provider: str
    cvss_version: str
    expected: Cvss
    kind: str = field(default="cve_record", init=False)


@dataclass(frozen=True)
class VpsFact:
    host_alias: str
    fact: str
    expected: BootFact | TableFact
    family: str | None = None
    table: str | None = None
    kind: str = field(default="vps_fact", init=False)


CheckSpec = UbuntuCve | CveRecord | VpsFact


@dataclass(frozen=True)
class Claim:
    id: str
    field: str
    text: str
    source: Source
    product: str | None = None
    issue_ref: str | None = None
    persistence: str | None = None
    check: CheckSpec | None = None
    # Explicit scope for exposure; upstream source is always separately authored.
    observation_scope: str | None = None
    release: str | None = None
    package: str | None = None
    cvss_version: str | None = None
    score: str | None = None
    vector: str | None = None
    scorer: str | None = None


@dataclass(frozen=True)
class LaneReview:
    lane: str
    model: str
    effort: str
    run_id: str
    hash: str
    at: str
    verdict: str


@dataclass(frozen=True)
class Review:
    claims_hash: str
    lanes: tuple[LaneReview, ...]


@dataclass(frozen=True)
class ImpactItem:
    id: str
    title: str
    kind: str
    refs: tuple[str, ...]
    claims: tuple[Claim, ...]
    review: Review | None = None
    summary: str = ""
    status: Literal["open", "watching"] = "open"


@dataclass(frozen=True)
class Evidence:
    value: UbuntuStatus | Cvss | BootFact | TableFact
    source: str
    observed_at: str
    observed_by: str
    retrieved_at: str
    scope: Literal["fetched", "snapshot"]
    snapshot_id: str | None = None


@dataclass(frozen=True)
class Confirmed:
    evidence: Evidence
    status: str = field(default="confirmed", init=False)


@dataclass(frozen=True)
class Changed:
    before: UbuntuStatus | Cvss | BootFact | TableFact
    evidence: Evidence
    status: str = field(default="changed", init=False)


@dataclass(frozen=True)
class Unverified:
    reason: str
    last_known: Evidence | None = None
    status: str = field(default="unverified", init=False)


Outcome = Confirmed | Changed | Unverified


@dataclass(frozen=True)
class ClaimAssessment:
    claim: dict  # Flat input boundary, including authored text (never used as evidence).
    outcome: Outcome
    display: str
    blocked: bool = False


@dataclass(frozen=True)
class ItemAssessment:
    id: str
    title: str
    kind: str
    refs: tuple[str, ...]
    claims: tuple[ClaimAssessment, ...]
    blocked: bool
    claims_hash: str
    review_status: str
    summary: str = ""
    status: Literal["open", "watching"] = "open"


@dataclass(frozen=True)
class Assessment:
    scan_id: str
    started_at: str
    items: tuple[ItemAssessment, ...]
    diagnostics: tuple[dict, ...]
    required_failure: bool
    changed_count: int = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "changed_count", sum(
            isinstance(c.outcome, Changed) for i in self.items for c in i.claims))


@dataclass(frozen=True)
class ImpactState:
    version: int
    entries: dict


@dataclass(frozen=True)
class Batch:
    assessment: Assessment
    next_state: ImpactState


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("日時はタイムゾーン付きISO形式が必要")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("日時にタイムゾーンが無い")
    return value


def nonempty(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("空でない文字列が必要")
    return value


def url(value):
    parsed = urllib.parse.urlsplit(nonempty(value))
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("出所のURLが不正")
    return value


def cvss_vector(version, vector):
    if version == "2.0":
        vector = vector.removeprefix("CVSS2#").removeprefix("CVSS:2.0/")
        required = {"AV", "AC", "Au", "C", "I", "A"}
    else:
        prefix = f"CVSS:{version}/"
        if not vector.startswith(prefix):
            raise ValueError("CVSSの版とvectorが一致しない")
        vector = vector[len(prefix):]
        required = ({"AV", "AC", "PR", "UI", "S", "C", "I", "A"} if version in ("3.0", "3.1")
                    else {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"})
    metrics = []
    for part in vector.split("/"):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*:[A-Za-z0-9.]+", part):
            raise ValueError("CVSS vectorにはmetric:valueの組が必要")
        metrics.append(part.split(":", 1)[0])
    if len(metrics) != len(set(metrics)) or not required.issubset(metrics):
        raise ValueError("CVSS vectorの必須metricが欠落または重複")
    return vector if version == "2.0" else f"CVSS:{version}/" + vector


def value_from(kind, raw, fact=None):
    if not isinstance(raw, dict):
        raise ValueError("expected/value はobjectが必要")
    if kind == "ubuntu_cve":
        value = UbuntuStatus(**raw)
        for part in (value.release, value.package, value.status):
            nonempty(part)
        if value.fixed_version is not None:
            nonempty(value.fixed_version)
    elif kind == "cve_record":
        value = Cvss(**raw)
        for part in (value.version, value.score, value.vector, value.scorer):
            nonempty(part)
        score = Decimal(value.score)
        if not score.is_finite() or not 0 <= score <= 10 or value.role not in ("cna", "adp") or \
                value.version not in ("2.0", "3.0", "3.1", "4.0"):
            raise ValueError("CVSSの版・点数・主体が不正")
        value = Cvss(value.version, value.score, cvss_vector(value.version, value.vector), value.scorer, value.role)
    elif fact == "boot":
        value = BootFact(**raw)
        timestamp(value.booted_at)
        value = BootFact(dt.datetime.fromisoformat(value.booted_at.replace("Z", "+00:00")).astimezone(
                         dt.timezone.utc).isoformat(), value.boot_id)
        if value.boot_id is not None:
            nonempty(value.boot_id)
    elif fact == "nft_table":
        value = TableFact(**raw)
        nonempty(value.family)
        nonempty(value.name)
        if type(value.present) is not bool:
            raise ValueError("present はbooleanが必要")
    else:
        raise ValueError("未知の事実の種類")
    return value


def check_from(raw):
    if not isinstance(raw, dict) or raw.get("kind") not in CHECK_RULES:
        raise ValueError("未知のcheck kind")
    kind = raw["kind"]
    args = {k: v for k, v in raw.items() if k != "kind"}
    args["expected"] = value_from(kind, args.get("expected"), args.get("fact"))
    spec = CHECK_RULES[kind].spec_type(**args)
    CHECK_RULES[kind].validate(spec)
    return spec


def cve_selector(spec):
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", spec.cve):
        raise ValueError("CVEの形式が不正")


def ubuntu_selector(spec):
    cve_selector(spec)
    nonempty(spec.release)
    nonempty(spec.package)
    if (spec.release, spec.package) != (spec.expected.release, spec.expected.package):
        raise ValueError("Ubuntuのselectorとexpectedが不一致")


def cve_record_selector(spec):
    cve_selector(spec)
    nonempty(spec.provider)
    if spec.cvss_version != spec.expected.version or \
            (spec.provider == "cna") != (spec.expected.role == "cna"):
        raise ValueError("CVSSのselectorとexpectedが不一致")


def vps_selector(spec):
    nonempty(spec.host_alias)
    if spec.fact == "boot":
        if spec.family is not None or spec.table is not None:
            raise ValueError("bootに表のselectorは使えない")
    elif spec.fact == "nft_table":
        nonempty(spec.family)
        nonempty(spec.table)
        if (spec.family, spec.table) != (spec.expected.family, spec.expected.name):
            raise ValueError("nftのselectorとexpectedが不一致")
    else:
        raise ValueError("未知のVPS fact")


def project_value(value):
    if isinstance(value, UbuntuStatus):
        return f"Ubuntu {value.release} / {value.package}: {value.status}" + (
            f" / 修正版 {value.fixed_version}" if value.fixed_version else "")
    if isinstance(value, Cvss):
        return f"CVSS {value.version}: {value.score} / {value.vector} / {value.scorer} ({value.role})"
    if isinstance(value, BootFact):
        return f"起動日時 {value.booted_at}" + (f" / boot ID {value.boot_id}" if value.boot_id else "")
    return f"nft {value.family} {value.name}: {'表あり' if value.present else '表なし'}（表の存在だけを確認）"


@dataclass(frozen=True)
class FieldRule:
    required: tuple[str, ...]
    checks: tuple[str, ...]
    project: Callable = project_value


FIELD_RULES = {
    "severity": FieldRule(("cvss_version", "score", "vector", "scorer"), ("cve_record",)),
    "upstream_fix": FieldRule((), ()),
    "distro_fix": FieldRule(("release", "package"), ("ubuntu_cve",)),
    "product_status": FieldRule(("product", "issue_ref", "quote"), ()),
    "our_exposure": FieldRule(("observation_scope",), ("vps_fact",)),
    "mitigation": FieldRule(("persistence",), ("vps_fact",)),
}


def flat_claim(claim):
    result = asdict(claim)
    source = result.pop("source")
    result.update(source_url=source.pop("url"), source_type=source.pop("type"), **source)
    return result


def claim_from(raw):
    if not isinstance(raw, dict):
        raise ValueError("claimはobjectが必要")
    args = dict(raw)
    source = Source(*(args.pop(k, None) for k in
                      ("source_url", "source_type", "observed_at", "observed_by", "quote", "demo_env")))
    url(source.url)
    timestamp(source.observed_at)
    if source.type not in ("vendor", "distro", "cna", "nvd", "researcher", "own_observation") or \
            source.observed_by not in ("parent", "sora", "hermes", "scan"):
        raise ValueError("出所の種類または観測者が不正")
    if args.get("check") is not None:
        args["check"] = check_from(args["check"])
    claim = Claim(source=source, **args)
    for value in (claim.id, claim.text):
        nonempty(value)
    if claim.field not in FIELD_RULES:
        raise ValueError("未知のfield")
    flat = flat_claim(claim)
    for attr in FIELD_RULES[claim.field].required:
        nonempty(flat.get(attr))
    if source.type == "researcher":
        for value in (source.quote, source.demo_env, claim.product):
            nonempty(value)
    if claim.persistence is not None and claim.persistence not in (
            "survives_reboot", "lost_on_reboot", "unknown"):
        raise ValueError("persistenceが不正")
    if claim.field == "upstream_fix" and source.type not in ("vendor", "cna"):
        raise ValueError("上流の修正には上流自身の出所が必要")
    if claim.check:
        if claim.check.kind not in FIELD_RULES[claim.field].checks:
            raise ValueError("fieldに使えないcheck")
        expected = claim.check.expected
        if isinstance(expected, UbuntuStatus) and (claim.release, claim.package) != (expected.release, expected.package):
            raise ValueError("主張と照合のrelease/packageが不一致")
        if isinstance(expected, Cvss) and (claim.cvss_version, claim.score, claim.vector, claim.scorer) != (
                expected.version, expected.score, expected.vector, expected.scorer):
            raise ValueError("主張と照合のCVSSが不一致")
        if claim.field == "our_exposure" and claim.observation_scope != "inventory_only":
            raise ValueError("VPSの事実はinventory_onlyの範囲だけ（外部到達性は証明しない）")
    elif claim.field == "severity":
        value_from("cve_record", dict(version=claim.cvss_version, score=claim.score,
                   vector=claim.vector, scorer=claim.scorer, role="cna"))
    return claim


def diagnostic(target, reason):
    return {"kind": "impact", "target": target, "reason": reason}


def validate_json_values(value):
    """Validate even optional/unknown attributes before hashing or retaining them."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("UTF-8で表現できない文字列") from None
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("数値は有限である必要がある")
    elif isinstance(value, dict):
        for key, part in value.items():
            validate_json_values(key)
            validate_json_values(part)
    elif isinstance(value, list):
        for part in value:
            validate_json_values(part)


def invalid_item(index, original=None):
    # Never retain invalid Unicode/nonfinite numbers in the report's JSON boundary.
    item = {"id": f"item[{index}]", "title": "書き方の不備", "kind": "advisory", "refs": [],
            "claims": [{"invalid": "書き方の不備"}]}
    if isinstance(original, dict):
        for key in ("id", "title", "kind"):
            value = original.get(key)
            if isinstance(value, str) and value.strip():
                try:
                    validate_json_values(value)
                except ValueError:
                    continue
                item[key] = value
        if isinstance(original.get("claims"), list):
            item["claims"] = [{"invalid": "書き方の不備"} for _ in original["claims"]]
    return item


def item_display_fields(raw):
    summary, status = raw.get("summary", ""), raw.get("status", "open")
    if not isinstance(summary, str) or len(summary) > 150:
        raise ValueError("summaryは150文字以内の日本語の表示用文字列が必要")
    if not isinstance(status, str) or status not in ("open", "watching"):
        raise ValueError("statusはopenまたはwatchingが必要")
    return summary, status


def validate(raw):
    """Return (raw item, valid claims, blocked) rows plus visible diagnostics."""
    items = raw.get("items") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return [], [diagnostic("impact-items.json", "書き方の不備: itemsは配列が必要")]
    rows, errors = [], []
    ids = [i.get("id") for i in items if isinstance(i, dict)]
    for index, original in enumerate(items):
        try:
            validate_json_values(original)
        except (ValueError, RecursionError) as exc:
            item = invalid_item(index, original)
            errors.append(diagnostic(item["id"], "書き方の不備: " + (
                str(exc) if type(exc) is ValueError else "属性の入れ子が不正")))
            rows.append((item, [], True))
            continue
        item = copy.deepcopy(original) if isinstance(original, dict) else {}
        target = item.get("id") if isinstance(item.get("id"), str) else f"item[{index}]"
        start = len(errors)
        try:
            nonempty(item.get("id"))
            nonempty(item.get("title"))
            if ids.count(item["id"]) != 1 or item.get("kind") not in ("cve", "advisory"):
                raise ValueError("id重複またはkindが不正")
            if not isinstance(item.get("refs"), list) or not item["refs"]:
                raise ValueError("refsに出所のURLが必要")
            for ref in item["refs"]:
                url(ref)
        except (ValueError, TypeError):
            errors.append(diagnostic(target, "書き方の不備: id/title/kind/refsが不正または重複"))
        try:
            item_display_fields(item)
        except ValueError as exc:
            errors.append(diagnostic(target, "書き方の不備: " + str(exc)))
        raw_claims = item.get("claims")
        if not isinstance(raw_claims, list) or not raw_claims:
            errors.append(diagnostic(target, "書き方の不備: claimsは空でない配列が必要"))
            raw_claims = []
        claim_ids = [c.get("id") for c in raw_claims if isinstance(c, dict)]
        claims, products = [], set()
        for ci, raw_claim in enumerate(raw_claims):
            try:
                claim = claim_from(raw_claim)
                if claim_ids.count(claim.id) != 1:
                    raise ValueError("claim idが重複")
                if claim.field == "product_status":
                    key = (claim.product, claim.issue_ref)
                    if key in products:
                        raise ValueError("同じ製品・問題の主張が重複")
                    products.add(key)
                claims.append(claim)
            except (ValueError, TypeError, KeyError, InvalidOperation) as exc:
                # Do not echo malformed values or raw parser exceptions containing input.
                reason = str(exc) if type(exc) is ValueError else "属性または値の形が不正"
                errors.append(diagnostic(f"{target}/claim[{ci}]", "書き方の不備: " + reason))
        item.setdefault("id", target)
        rows.append((item, claims, len(errors) != start))
    return rows, errors


# Small configuration table; the scan config can override/extend it explicitly.
DEFAULT_RELEASE_CODENAMES = {"24.04": "noble", "26.04": "resolute"}


def fetched_evidence(value, source, raw, at):
    observed = raw.get("updated_at") or raw.get("cveMetadata", {}).get("dateUpdated") or at
    # CVE services sometimes omit the UTC suffix on their UTC dateUpdated field.
    if observed != at and isinstance(observed, str) and dt.datetime.fromisoformat(observed.replace("Z", "+00:00")).tzinfo is None:
        observed += "+00:00"
    timestamp(observed)
    return Evidence(value, source, observed, "scan", at, "fetched")


def ubuntu_acquire(spec, fetch, inventory, releases, at):
    codename = releases.get(spec.release)
    if not isinstance(codename, str) or not codename:
        raise ValueError("Ubuntuリリースのcodenameが未設定")
    source = f"https://ubuntu.com/security/cves/{spec.cve}.json"
    raw = fetch(source)
    if nonempty(raw.get("id")).casefold() != spec.cve.casefold():
        raise ValueError("Ubuntu応答のCVE識別子が要求と不一致")
    matches = [s for p in raw["packages"] if p["name"] == spec.package
               for s in p["statuses"] if s["release_codename"] == codename]
    if len(matches) != 1:
        raise ValueError("Ubuntuのrelease/packageが欠落または曖昧")
    status = nonempty(matches[0]["status"])
    # Pending descriptions can name a planned version; that is not a released fix.
    fixed = nonempty(matches[0]["description"]) if status == "released" else None
    value = UbuntuStatus(spec.release, spec.package, status, fixed)
    return fetched_evidence(value, source, raw, at)


def cve_acquire(spec, fetch, inventory, releases, at):
    source = f"https://cveawg.mitre.org/api/cve/{spec.cve}"
    raw = fetch(source)
    if nonempty(raw.get("cveMetadata", {}).get("cveId")).casefold() != spec.cve.casefold():
        raise ValueError("CVE応答の識別子が要求と不一致")
    containers = raw["containers"]
    if spec.provider == "cna":
        selected, role = [containers["cna"]], "cna"
    else:
        selected, role = [c for c in containers.get("adp", [])
                          if c["providerMetadata"]["shortName"] == spec.provider], "adp"
    if len(selected) != 1:
        raise ValueError("CVEのproviderが欠落または曖昧")
    container = selected[0]
    scorer = nonempty(container["providerMetadata"]["shortName"])
    metric_key = {"2.0": "cvssV2_0", "3.0": "cvssV3_0", "3.1": "cvssV3_1", "4.0": "cvssV4_0"}[spec.cvss_version]
    metrics = [m[metric_key] for m in container["metrics"] if metric_key in m]
    if len(metrics) != 1:
        raise ValueError("指定CVSSの値が欠落または曖昧")
    metric = metrics[0]
    vector = metric["vectorString"]
    value = value_from("cve_record", dict(version=metric["version"], score=str(metric["baseScore"]),
                      vector=vector, scorer=scorer, role=role))
    if value.version != spec.cvss_version:
        raise ValueError("CVSSの版が不一致")
    return fetched_evidence(value, source, raw, at)


def vps_acquire(spec, fetch, inventory, releases, at):
    if isinstance(inventory, dict) and "host" not in inventory:
        inventory = inventory.get(spec.host_alias)
    if not isinstance(inventory, dict) or inventory.get("host") != spec.host_alias:
        raise ValueError("今回取り込んだVPS在庫に指定ホストが無い")
    observed = timestamp(inventory["generated"])
    facts = inventory["security_facts"]
    errors = facts.get("errors", {})
    key = "boot" if spec.fact == "boot" else "nft_tables"
    if not isinstance(errors, dict) or errors.get(key):
        raise ValueError("VPSの事実の収集に失敗")
    if spec.fact == "boot":
        value = value_from("vps_fact", facts["boot"], "boot")
    else:
        tables = facts["nft_tables"]
        if not isinstance(tables, list):
            raise ValueError("nftの表一覧が不正")
        for table in tables:
            nonempty(table["family"])
            nonempty(table["name"])
        value = TableFact(spec.family, spec.table, any(
            (t["family"], t["name"]) == (spec.family, spec.table) for t in tables))
    return Evidence(value, "inventory:" + spec.host_alias, observed, "scan", at, "snapshot",
                    hashlib.sha256(canonical(inventory).encode("utf-8")).hexdigest())


@dataclass(frozen=True)
class CheckRule:
    spec_type: type
    validate: Callable
    acquire: Callable  # Acquisition includes strict parse and normalization.


CHECK_RULES = {
    "ubuntu_cve": CheckRule(UbuntuCve, ubuntu_selector, ubuntu_acquire),
    "cve_record": CheckRule(CveRecord, cve_record_selector, cve_acquire),
    "vps_fact": CheckRule(VpsFact, vps_selector, vps_acquire),
}


def real_fetch(source):
    """Only the two contracted HTTPS endpoints; redirects cannot expand access."""
    if not re.fullmatch(r"https://(?:ubuntu\.com/security/cves/CVE-[0-9]{4}-[0-9]{4,}\.json|"
                        r"cveawg\.mitre\.org/api/cve/CVE-[0-9]{4}-[0-9]{4,})", source):
        raise ValueError("許可されていない取得先")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("照合先の転送は許可しない")

    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(source, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"), parse_float=Decimal)


def state_key(item_id, claim):
    return canonical([item_id, claim.id, asdict(claim.check)])


def evidence_from(raw, spec):
    args = dict(raw)
    args["value"] = value_from(spec.kind, args["value"], getattr(spec, "fact", None))
    result = Evidence(**args)
    timestamp(result.observed_at)
    timestamp(result.retrieved_at)
    nonempty(result.source)
    if result.observed_by != "scan" or result.scope != ("snapshot" if isinstance(spec, VpsFact) else "fetched"):
        raise ValueError("証拠の観測者・範囲が不正")
    if isinstance(spec, UbuntuCve):
        if (result.value.release, result.value.package, result.source) != (
                spec.release, spec.package, f"https://ubuntu.com/security/cves/{spec.cve}.json"):
            raise ValueError("証拠のselectorが不一致")
    elif isinstance(spec, CveRecord):
        if result.value.version != spec.cvss_version or result.value.role != spec.expected.role or \
                result.source != f"https://cveawg.mitre.org/api/cve/{spec.cve}" or \
                (spec.provider != "cna" and result.value.scorer != spec.provider):
            raise ValueError("証拠のselectorが不一致")
    elif result.source != "inventory:" + spec.host_alias or not result.snapshot_id or \
            (isinstance(result.value, TableFact) and (result.value.family, result.value.name) != (spec.family, spec.table)):
        raise ValueError("在庫の証拠のselectorが不一致")
    return result


MISSING = object()


def history_from(raw):
    if raw is MISSING:
        return ImpactState(1, {})
    if not isinstance(raw, dict) or type(raw.get("version")) is not int or raw["version"] != 1 or \
            not isinstance(raw.get("entries"), dict):
        raise ValueError("履歴の形式が不正")
    for key, evidence in raw["entries"].items():
        parts = json.loads(key)
        if not isinstance(parts, list) or len(parts) != 3:
            raise ValueError("履歴キーが不正")
        nonempty(parts[0])
        nonempty(parts[1])
        spec = check_from(parts[2])
        if key != canonical([parts[0], parts[1], asdict(spec)]):
            raise ValueError("履歴キーが正規形でない")
        evidence_from(evidence, spec)
    return ImpactState(1, copy.deepcopy(raw["entries"]))


def _hash_claims(claims, outcomes, *, authored, version):
    semantic = []
    for claim, outcome in zip(claims, outcomes):
        evidence = outcome.last_known if isinstance(outcome, Unverified) else outcome.evidence
        fact = None
        if evidence:
            fact = {"value": asdict(evidence.value), "source": evidence.source,
                    "scope": evidence.scope, "observed_by": evidence.observed_by}
            # Only migration reproduces the legacy snapshot collection timestamp.
            if version == 1 and evidence.scope == "snapshot":
                fact["observed_at"] = evidence.observed_at
        semantic.append({"claim": flat_claim(claim), "fact": fact})
    payload = {"version": version, "claims": sorted(semantic, key=lambda row: row["claim"]["id"])}
    # Preserve legacy hashes when these optional authored fields are absent.
    if authored:
        payload["authored"] = authored
    return f"v{version}:" + hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def claims_hash(claims, outcomes, *, authored=None):
    return _hash_claims(claims, outcomes, authored=authored, version=2)


def _claims_hash_v1(claims, outcomes, *, authored=None):
    """Legacy computation, exclusively for validating review migration."""
    return _hash_claims(claims, outcomes, authored=authored, version=1)


def review_status(raw, digest):
    try:
        if not isinstance(raw, dict) or raw["claims_hash"] != digest or len(raw["lanes"]) != 2:
            return "確認待ち"
        lanes = [LaneReview(**lane) for lane in raw["lanes"]]
        for lane in lanes:
            for value in (lane.lane, lane.model, lane.effort, lane.run_id):
                nonempty(value)
            timestamp(lane.at)
            if lane.hash != digest or lane.verdict != "approve":
                return "確認待ち"
        return "確認済み" if len({l.lane for l in lanes}) == len({l.run_id for l in lanes}) == 2 else "確認待ち"
    except (TypeError, ValueError, KeyError):
        return "確認待ち"


def display(claim, outcome):
    if not claim.check:
        return f"{claim.source.observed_at} に {claim.source.observed_by} が観測（過去の記録・手動確認）: {claim.text}"
    if isinstance(outcome, Unverified):
        text = "確認できなかった: " + outcome.reason
        if outcome.last_known:
            e = outcome.last_known
            text += f" / 最後の成功 {e.observed_at}: " + FIELD_RULES[claim.field].project(e.value)
        return text
    e = outcome.evidence
    label = (f"{e.observed_at} に収集した在庫（今回の照合で再読）" if e.scope == "snapshot"
             else "今回の照合で確認")
    if isinstance(outcome, Changed):
        label += "・変化あり"
    return label + ": " + FIELD_RULES[claim.field].project(e.value)


def load_items(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return {"items": []}, []
    except (OSError, ValueError):
        return {"items": []}, [diagnostic("impact-items.json", "書き方の不備: JSONを読み取れない")]


def assess(rows, errors, scan_id, started_at, evaluate):
    results = []
    for index, (raw, claims, blocked) in enumerate(rows):
        try:
            results.append(assess_item(raw, claims, blocked, evaluate))
        except (ValueError, TypeError, KeyError, AttributeError, InvalidOperation, RecursionError, OverflowError):
            # Final item boundary: malformed authored data must not abort the scan.
            raw = invalid_item(index, raw)
            errors.append(diagnostic(raw["id"], "書き方の不備: 項目を処理できない"))
            results.append(assess_item(raw, [], True, evaluate))
    return Assessment(scan_id, started_at, tuple(results), tuple(errors), bool(errors))


def assess_item(raw, claims, blocked, evaluate):
    outcomes = [Unverified("書き方の不備のため項目全体を保留") if blocked else evaluate(raw["id"], c)
                for c in claims]
    rendered = [ClaimAssessment(flat_claim(c), o, display(c, o), blocked) for c, o in zip(claims, outcomes)]
    # Retain malformed claims too, so nothing disappears from a blocked item.
    if blocked:
        rendered = [ClaimAssessment(c if isinstance(c, dict) else {"invalid": c},
                    Unverified("書き方の不備"), "書き方の不備", True)
                    for c in (raw.get("claims") if isinstance(raw.get("claims"), list) else [])]
    digest = claims_hash(claims, outcomes, authored={key: raw[key] for key in ("summary", "status") if key in raw})
    try:
        summary, status = item_display_fields(raw)
    except ValueError:
        summary, status = "", "open"
    return ItemAssessment(str(raw.get("id", "")), str(raw.get("title", "")),
                   str(raw.get("kind", "")), tuple(raw.get("refs", [])) if isinstance(raw.get("refs"), list) else (),
                   tuple(rendered), blocked, digest,
                   "確認待ち" if blocked else review_status(raw.get("review"), digest), summary, status)


def check_all(here, *, scan_id, started_at, fetch=real_fetch, previous_state=MISSING,
              inventory=None, release_codenames=None):
    timestamp(started_at)
    nonempty(scan_id)
    raw, errors = load_items(Path(here) / "impact-items.json")
    rows, validation_errors = validate(raw)
    errors.extend(validation_errors)
    try:
        history = history_from(previous_state)
        history_error = False
    except (ValueError, TypeError, KeyError, InvalidOperation):
        # Preserve corrupt bytes structurally instead of quietly resetting history.
        history = (ImpactState(0, copy.deepcopy(previous_state["entries"]))
                   if isinstance(previous_state, dict) and previous_state.get("version") == 0 and
                   isinstance(previous_state.get("entries"), dict) and "unreadable" in previous_state["entries"]
                   else ImpactState(0, {"unreadable": copy.deepcopy(previous_state)}))
        history_error = True
        errors.append(diagnostic("state.impact", "履歴の比較失敗: 保存された履歴が不正"))
    entries = copy.deepcopy(history.entries)
    releases = DEFAULT_RELEASE_CODENAMES if release_codenames is None else release_codenames
    cache = {}

    def once(source):
        if source not in cache:
            try:
                cache[source] = (fetch(source), None)
            except Exception as exc:
                cache[source] = (None, type(exc).__name__)
        value, error = cache[source]
        if error:
            raise ValueError("取得失敗: " + error)
        return value

    def evaluate(item_id, claim):
        if not claim.check:
            return Unverified("手動の過去の観測（今回の機械確認なし）")
        if history_error:
            return Unverified("履歴の比較失敗")
        key, spec = state_key(item_id, claim), claim.check
        last = evidence_from(entries[key], spec) if key in entries else None
        try:
            retrieved_at = dt.datetime.now(dt.timezone.utc).isoformat()
            evidence = CHECK_RULES[spec.kind].acquire(spec, once, inventory, releases, retrieved_at)
            # Validate acquired evidence exactly as persisted/report evidence.
            evidence = evidence_from(asdict(evidence), spec)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, InvalidOperation):
            reason = "取得または解析に失敗（出所・selector・収集項目を確認）"
            errors.append(diagnostic(f"{item_id}/{claim.id}", reason))
            return Unverified(reason, last)
        entries[key] = asdict(evidence)
        before = last.value if last else spec.expected
        if evidence.value != before:
            return Changed(before, evidence)
        if evidence.value != spec.expected:
            reason = "主張と証拠が矛盾（claim contradicts evidence）"
            errors.append(diagnostic(f"{item_id}/{claim.id}", reason))
            return Unverified(reason, evidence)
        return Confirmed(evidence)

    assessment = assess(rows, errors, scan_id, started_at, evaluate)
    return Batch(assessment, ImpactState(history.version, entries))


def read_for_report(items_path, findings_path, *, scan_id):
    """Reject foreign scans; callers must retain their previous last_scan_at on error."""
    try:
        findings = json.loads(Path(findings_path).read_text(encoding="utf-8"))
        stored = findings["impact_checks"]
        required = {"scan_id": str, "started_at": str, "items": list, "diagnostics": list,
                    "changed_count": int, "required_failure": bool}
        if not isinstance(stored, dict) or any(type(stored.get(key)) is not kind for key, kind in required.items()):
            raise ValueError("Assessmentの必須項目が欠落または型が不正")
        nonempty(stored["scan_id"])
        if stored["changed_count"] < 0 or any(
                not isinstance(d, dict) or any(not isinstance(d.get(key), str) for key in ("kind", "target", "reason"))
                for d in stored["diagnostics"]):
            raise ValueError("Assessmentの件数または診断が不正")
        if findings["scan_id"] != scan_id or stored["scan_id"] != scan_id:
            raise ValueError("照合IDが一致しないためレポートを更新できない")
        timestamp(stored["started_at"])
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("照合結果を読み取れない、または照合IDが一致しない") from exc
    raw, errors = load_items(items_path)
    rows, validation_errors = validate(raw)
    errors.extend(validation_errors)
    stored_items = stored["items"]

    def evaluate(item_id, claim):
        if not claim.check:
            return Unverified("手動の過去の観測（今回の機械確認なし）")
        try:
            items = [i for i in stored_items if i["id"] == item_id]
            if len(items) != 1 or items[0]["blocked"]:
                raise ValueError("項目の照合結果が無い")
            matches = [c for c in items[0]["claims"] if c["claim"] == flat_claim(claim)]
            if len(matches) != 1:
                raise ValueError("主張が照合後に変更された")
            result = matches[0]["outcome"]
            if result["status"] == "unverified":
                return Unverified(nonempty(result["reason"]), evidence_from(result["last_known"], claim.check)
                                  if result.get("last_known") else None)
            evidence = evidence_from(result["evidence"], claim.check)
            if result["status"] == "changed":
                before = value_from(claim.check.kind, result["before"], getattr(claim.check, "fact", None))
                if before == evidence.value:
                    raise ValueError("変化の値が同じ")
                return Changed(before, evidence)
            if result["status"] != "confirmed" or evidence.value != claim.check.expected:
                raise ValueError("確認済みの事実と主張が不一致")
            return Confirmed(evidence)
        except (KeyError, TypeError, ValueError, InvalidOperation):
            reason = "照合結果が欠落・不正、または主張が照合後に変更された"
            errors.append(diagnostic(f"{item_id}/{claim.id}", reason))
            return Unverified(reason)

    # Preserve scan failures even when a later edit made the items syntactically valid.
    errors.extend(stored["diagnostics"])
    return assess(rows, errors, scan_id, stored["started_at"], evaluate)


def migrate_review_hashes(items_path, findings_path):
    """Upgrade only reviews whose legacy hash is proven by the stored assessment."""
    items_path = Path(items_path)
    original = items_path.read_text(encoding="utf-8")
    raw = json.loads(original)
    rows, _ = validate(raw)
    findings = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    assessment = read_for_report(items_path, findings_path, scan_id=findings["scan_id"])
    items = raw.get("items") if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise ValueError("itemsは配列が必要")
    saved_items = findings["impact_checks"]["items"]
    migrated = []
    for item, (_, claims, blocked), result in zip(items, rows, assessment.items):
        if not isinstance(item, dict):
            print("item: skipped: invalid item")
            continue
        item_id, review = item.get("id", "item"), item.get("review")
        if not isinstance(review, dict) or not isinstance(review.get("claims_hash"), str) or \
                not review["claims_hash"].startswith("v1:"):
            print(f"{item_id}: skipped: no v1 review")
            continue
        reason = None
        saved = [i for i in saved_items if isinstance(i, dict) and i.get("id") == item_id]
        if blocked or result.blocked:
            reason = "invalid current item"
        elif len(saved) != 1 or saved[0].get("blocked") is not False:
            reason = "stored assessment missing, ambiguous or blocked"
        else:
            saved_claims = saved[0].get("claims")
            if not isinstance(saved_claims, list):
                reason = "invalid stored claims"
            else:
                for current in result.claims:
                    matches = [c for c in saved_claims if isinstance(c, dict) and c.get("claim") == current.claim]
                    if len(matches) != 1 or matches[0].get("outcome") != asdict(current.outcome):
                        reason = "stored assessment no longer matches current claims or evidence"
                        break
        if reason is None:
            authored = {key: item[key] for key in ("summary", "status") if key in item}
            legacy = _claims_hash_v1(claims, [c.outcome for c in result.claims], authored=authored)
            lanes = review.get("lanes")
            if legacy != review["claims_hash"]:
                reason = "v1 hash mismatch: content changed"
            elif not isinstance(lanes, list) or len(lanes) != 2 or any(
                    not isinstance(lane, dict) or lane.get("hash") != legacy for lane in lanes):
                reason = "both lanes must carry the same v1 hash"
        if reason:
            print(f"{item_id}: skipped: {reason}")
            continue
        review["claims_hash"] = result.claims_hash
        for lane in lanes:
            lane["hash"] = result.claims_hash
        migrated.append(item_id)

    if migrated:
        def replace_text(path, text):
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                                 dir=path.parent, prefix=path.name + ".", suffix=".tmp",
                                                 delete=False) as stream:
                    temporary = Path(stream.name)
                    stream.write(text)
                os.replace(temporary, path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)

        updated = json.dumps(raw, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        replace_text(items_path.with_suffix(items_path.suffix + ".bak"), original)
        replace_text(items_path, updated)
        for item_id in migrated:
            print(f"{item_id}: migrated")
    return migrated


class WorkspaceLockError(ValueError):
    """The workspace is already held by another scan."""


@contextmanager
def workspace_lock(here):
    """Process-held lock; no clock, stale-file deletion or age-based expiry."""
    path = Path(here) / ".impact.lock"
    with path.open("a+b") as stream:
        if not path.stat().st_size:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise WorkspaceLockError("別の走査が実行中のため開始できない") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def selftest(exit_code):
    """Core fixtures only; scan's dispatcher also runs report_build.selftest."""
    example = json.loads(Path(__file__).with_name("impact-items.example.json").read_text(encoding="utf-8"))
    at = "2026-11-07T12:00:00+09:00"
    ubuntu = {"id": "CVE-2099-10001", "updated_at": at, "packages": [{"name": "linux", "statuses": [
        {"release_codename": "resolute", "status": "pending", "description": "example-planned-version"}]}]}
    metric = {"version": "3.1", "baseScore": "9.8",
              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    record = {"cveMetadata": {"cveId": "CVE-2099-10001", "dateUpdated": at}, "containers": {"cna": {
        "providerMetadata": {"shortName": "ExampleCNA"}, "metrics": [{"cvssV3_1": metric}]}}}
    failed = []

    def run(name, case):
        try:
            case()
        except Exception as exc:
            failed.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print("PASS " + name)

    def require(condition, message="fixtureの期待結果と不一致"):
        if not condition:
            raise AssertionError(message)

    def fetch(source):
        return copy.deepcopy(ubuntu if source.startswith("https://ubuntu.com/") else record)

    with tempfile.TemporaryDirectory(prefix="impact-selftest-", dir=Path(__file__).resolve().parent) as temp:
        here = Path(temp)
        items_path, findings_path = here / "impact-items.json", here / "findings.json"

        def put(data):
            items_path.write_text(json.dumps(data, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

        def check(data=example, previous=MISSING, fetcher=fetch, inventory=None):
            put(data)
            return check_all(here, scan_id="fixture-scan", started_at=at, fetch=fetcher,
                             previous_state=previous, inventory=inventory)

        def outcome(batch, item=0, claim=0):
            return batch.assessment.items[item].claims[claim].outcome

        def same_claim_history(first, later, claim_id):
            keys = [k for k in first.next_state.entries if json.loads(k)[:2] == ["example-kernel", claim_id]]
            require(len(keys) == 1)
            require(later.next_state.entries[keys[0]] == first.next_state.entries[keys[0]])

        def invalid_source():
            for attr in ("source_url", "source_type", "observed_at", "observed_by"):
                data = copy.deepcopy(example)
                del data["items"][0]["claims"][0][attr]
                b = check(data)
                require(b.assessment.items[0].blocked and b.assessment.diagnostics)
                require("書き方の不備" in b.assessment.diagnostics[0]["reason"])
                require(len(b.assessment.items[0].claims) == 3)
                require(not b.next_state.entries)
        run("出所の必須属性欠落を可視化し項目を保持", invalid_source)

        def researcher_missing():
            for attr in ("quote", "demo_env", "product"):
                data = copy.deepcopy(example)
                # our_exposure isolates researcher requirements from product_status's rules.
                c = data["items"][1]["claims"][0]
                c.update(field="our_exposure", observation_scope="research_demo")
                del c[attr]
                b = check(data)
                require(b.assessment.items[1].blocked)
        run("研究者の引用・実証環境・製品欠落", researcher_missing)

        def missing_product():
            data = copy.deepcopy(example)
            del data["items"][1]["claims"][1]["product"]
            require(check(data).assessment.items[1].blocked)
        run("product_statusの製品欠落", missing_product)

        def separate_products():
            data = copy.deepcopy(example)
            claims = data["items"][1]["claims"]
            claims[0]["product"], claims[1]["product"] = "Cursor", "Codex"
            b = check(data)
            require(not b.assessment.items[1].blocked)
            require([c.claim["product"] for c in b.assessment.items[1].claims[:2]] == ["Cursor", "Codex"])
        run("CursorとCodexを別の製品・問題として保持", separate_products)

        def past_observation():
            b = check()
            c = b.assessment.items[1].claims[3]
            require("2026-11-04" in c.display and "parent" in c.display and "過去" in c.display)
            require("今回の照合で確認" not in c.display and isinstance(c.outcome, Unverified))
        run("過去の合成観測は日付付き履歴で表示", past_observation)

        def ubuntu_change():
            first = check()
            require(isinstance(outcome(first), Confirmed))
            require(outcome(first).evidence.value.fixed_version is None)
            changed = copy.deepcopy(ubuntu)
            changed["packages"][0]["statuses"][0].update(status="released", description="example-fixed-version")
            b = check(previous=asdict(first.next_state), fetcher=lambda u: changed if "ubuntu.com" in u else record)
            require(isinstance(outcome(b), Changed) and b.assessment.changed_count == 1)
            require(exit_code(b.assessment.changed_count, b.assessment.required_failure) == 10)
            # Missing history (including --baseline) still compares against authored expected.
            initial = check(fetcher=lambda u: changed if "ubuntu.com" in u else record)
            require(initial.assessment.changed_count == 1)
        run("Ubuntuの変化は新規・終了10（baselineでも抑制なし）", ubuntu_change)

        def failed_fetch():
            first = check()

            def fail(_):
                raise OSError("fixture fetch failure")

            b = check(previous=asdict(first.next_state), fetcher=fail)
            require(isinstance(outcome(b), Unverified) and outcome(b).last_known is not None)
            require(b.next_state == first.next_state and b.assessment.required_failure)
            require(exit_code(b.assessment.changed_count, b.assessment.required_failure) == 2)
        run("取得失敗は最後の成功を保持して未確認・終了2", failed_fetch)

        def response_identity():
            first = check()
            for service, claim_index in (("ubuntu", 0), ("cve", 1)):
                for identity in ("CVE-2099-99999", None):
                    doc = copy.deepcopy(ubuntu if service == "ubuntu" else record)
                    container = doc if service == "ubuntu" else doc.setdefault("cveMetadata", {})
                    key = "id" if service == "ubuntu" else "cveId"
                    container[key] = identity
                    b = check(previous=asdict(first.next_state), fetcher=lambda u:
                              doc if ("ubuntu.com" in u) == (service == "ubuntu") else fetch(u))
                    require(isinstance(outcome(b, claim=claim_index), Unverified))
                    require(outcome(b, claim=claim_index).last_known is not None)
                    require(b.assessment.required_failure and b.assessment.diagnostics)
                    same_claim_history(first, b, "distro" if claim_index == 0 else "severity")
                    require(b.assessment.changed_count == 0)
            lower_ubuntu, lower_record = copy.deepcopy(ubuntu), copy.deepcopy(record)
            lower_ubuntu["id"] = "cve-2099-10001"
            lower_record.setdefault("cveMetadata", {})["cveId"] = "cve-2099-10001"
            b = check(fetcher=lambda u: lower_ubuntu if "ubuntu.com" in u else lower_record)
            require(isinstance(outcome(b), Confirmed) and isinstance(outcome(b, claim=1), Confirmed))
        run("応答CVE識別子の不一致・欠落を拒否し履歴保持（大小文字は同一視）", response_identity)

        def cvss_vectors():
            vectors = {
                "2.0": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "3.0": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "3.1": metric["vectorString"],
                "4.0": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            }
            for version, vector in vectors.items():
                data = copy.deepcopy(example)
                c = data["items"][0]["claims"][1]
                c.update(cvss_version=version, vector=vector)
                c["check"]["cvss_version"] = version
                c["check"]["expected"].update(version=version, vector=vector)
                doc = copy.deepcopy(record)
                key = {"2.0": "cvssV2_0", "3.0": "cvssV3_0", "3.1": "cvssV3_1", "4.0": "cvssV4_0"}[version]
                m = dict(metric, version=version, vectorString=vector)
                doc["containers"]["cna"]["metrics"] = [{key: m}]
                fetcher = lambda u: ubuntu if "ubuntu.com" in u else doc
                first = check(data, fetcher=fetcher)
                require(isinstance(outcome(first, claim=1), Confirmed))
                prefix = "CVSS2#" if version == "2.0" else f"CVSS:{version}/"
                for bad in (prefix, vector.rsplit("/", 1)[0], vector + "/AV:N",
                            vector + "/broken", vector + "/E:", vector + "/"):
                    m["vectorString"] = bad
                    b = check(data, previous=asdict(first.next_state), fetcher=fetcher)
                    require(isinstance(outcome(b, claim=1), Unverified))
                    require(b.assessment.required_failure and b.assessment.changed_count == 0)
                    same_claim_history(first, b, "severity")
                    authored = copy.deepcopy(data)
                    authored["items"][0]["claims"][1]["vector"] = bad
                    authored["items"][0]["claims"][1]["check"]["expected"]["vector"] = bad
                    b = check(authored, previous=asdict(first.next_state), fetcher=fetcher)
                    require(b.assessment.items[0].blocked and b.assessment.required_failure)
                    require(any("書き方の不備" in d["reason"] for d in b.assessment.diagnostics))
                    require(b.next_state == first.next_state)
                m["vectorString"] = vector
            for prefix in ("", "CVSS2#", "CVSS:2.0/"):
                require(value_from("cve_record", dict(version="2.0", score="10", vector=prefix + vectors["2.0"],
                                                     scorer="ExampleCNA", role="cna")).vector == vectors["2.0"])
        run("CVSS全4版の必須metric・重複・構文を取得値とexpectedで検証", cvss_vectors)

        def malformed_values():
            first = check()
            for mutate in (
                lambda d: d["items"][0]["claims"][0].update(text="bad\ud800"),
                lambda d: d["items"][0]["claims"][0].update(product=float("inf")),
                lambda d: d["items"][0]["claims"][0].update(product=float("-inf")),
                lambda d: d["items"][0]["claims"][0].update(product=float("nan")),
                lambda d: d["items"][0].update(id="bad\udfff"),
                lambda d: d["items"][0].update(title={"nested": ["bad\ud800"]}),
                lambda d: d["items"][0]["claims"][0].update(field=[]),
            ):
                data = copy.deepcopy(example)
                mutate(data)
                # Escaped JSON allows malformed Unicode to reach the real input reader.
                items_path.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8", newline="\n")
                b = check_all(here, scan_id="bad-item", started_at=at, fetch=fetch,
                              previous_state=asdict(first.next_state))
                require(b.assessment.items[0].blocked and b.assessment.required_failure)
                require(any("書き方の不備" in d["reason"] for d in b.assessment.diagnostics))
                require(b.next_state == first.next_state)
                canonical(asdict(b.assessment)).encode("utf-8")
        run("不正Unicode・非有限数・不正属性は例外にせず書き方の不備", malformed_values)

        def contradiction():
            changed = copy.deepcopy(ubuntu)
            changed["packages"][0]["statuses"][0].update(status="released", description="example-fixed-version")
            fetcher = lambda u: changed if "ubuntu.com" in u else record
            first = check(fetcher=fetcher)
            second = check(previous=asdict(first.next_state), fetcher=fetcher)
            require(isinstance(outcome(first), Changed))
            require(isinstance(outcome(second), Unverified) and "矛盾" in outcome(second).reason)
            require(second.assessment.changed_count == 0 and second.assessment.required_failure)
            require(outcome(second).last_known.value.status == "released")
        run("expectedとの継続した矛盾は確認済みにしない", contradiction)

        vps_item = {"items": [{"id": "vps-example", "title": "合成在庫", "kind": "advisory",
            "refs": ["https://observations.example.test/vps"], "claims": [{
                "id": "boot", "field": "our_exposure", "text": "在庫で起動時刻を確認する。",
                "source_url": "https://observations.example.test/vps", "source_type": "own_observation",
                "observed_at": at, "observed_by": "parent", "observation_scope": "inventory_only",
                "check": {"kind": "vps_fact", "host_alias": "host.example.test", "fact": "boot",
                          "expected": {"booted_at": "2026-11-04T00:00:00Z", "boot_id": "fixture-boot"}}}]}]}
        inv = {"host": "host.example.test", "generated": "2026-11-04T01:00:00Z", "security_facts": {
            "boot": {"booted_at": "2026-11-04T00:00:00Z", "boot_id": "fixture-boot"},
            "nft_tables": [], "errors": {}}}

        def old_vps():
            b = check(vps_item, inventory={"host": "host.example.test", "generated": at})
            require(isinstance(outcome(b), Unverified) and b.assessment.required_failure)
        run("旧VPS在庫の項目欠落は未確認", old_vps)

        def snapshot():
            def forbidden(_):
                raise AssertionError("snapshot must not fetch")

            first = check(vps_item, fetcher=forbidden, inventory=inv)
            second = check(vps_item, previous=asdict(first.next_state), fetcher=forbidden, inventory=inv)
            require(isinstance(outcome(second), Confirmed))
            require(outcome(second).evidence.observed_at == inv["generated"])
            require(inv["generated"] in second.assessment.items[0].claims[0].display)
            require(first.assessment.items[0].claims_hash == second.assessment.items[0].claims_hash)
            data = copy.deepcopy(vps_item)
            c = data["items"][0]["claims"][0]
            c.update(field="mitigation", persistence="lost_on_reboot")
            c["check"] = {"kind": "vps_fact", "host_alias": "host.example.test", "fact": "nft_table",
                          "family": "inet", "table": "example", "expected": {
                              "family": "inet", "name": "example", "present": False}}
            require(isinstance(outcome(check(data, inventory=inv)), Confirmed))
            broken = copy.deepcopy(inv)
            broken["security_facts"]["errors"]["nft_tables"] = "fixture collection failed"
            require(isinstance(outcome(check(data, inventory=broken)), Unverified))
            del broken["security_facts"]["nft_tables"]
            broken["security_facts"]["errors"] = {}
            require(isinstance(outcome(check(data, inventory=broken)), Unverified))
            data = copy.deepcopy(vps_item)
            data["items"][0]["claims"][0]["observation_scope"] = "external_reachability"
            require(check(data, inventory=inv).assessment.items[0].blocked)
        run("VPSは収集日時を維持・空表と収集失敗を区別・外部到達性を証明しない", snapshot)

        def approved(data, digest):
            data = copy.deepcopy(data)
            data["items"][0]["review"] = {"claims_hash": digest, "lanes": [
                {"lane": str(i), "model": "example-model", "effort": "high", "run_id": f"fixture-{i}",
                 "hash": digest, "at": at, "verdict": "approve"} for i in (1, 2)]}
            return data

        def snapshot_refresh():
            first = check(vps_item, inventory=inv)
            digest = first.assessment.items[0].claims_hash
            data = approved(vps_item, digest)
            require(check(data, inventory=inv).assessment.items[0].review_status == "確認済み")
            fresh = copy.deepcopy(inv)
            fresh["generated"] = "2026-11-04T07:00:00Z"
            later = check(data, previous=asdict(first.next_state), inventory=fresh)
            item = later.assessment.items[0]
            require(item.claims_hash == digest and item.review_status == "確認済み")
            require(digest.startswith("v2:"))
            require(outcome(first).evidence.snapshot_id != outcome(later).evidence.snapshot_id)
            require(fresh["generated"] in item.claims[0].display)
        run("snapshot生成時刻だけの更新はv2ハッシュと確認済みを維持", snapshot_refresh)

        def snapshot_fact_change(fact):
            data = copy.deepcopy(vps_item)
            if fact == "nft_table":
                data["items"][0]["claims"][0]["check"] = {
                    "kind": "vps_fact", "host_alias": "host.example.test", "fact": "nft_table",
                    "family": "inet", "table": "example", "expected": {
                        "family": "inet", "name": "example", "present": False}}
            first = check(data, inventory=inv)
            digest = first.assessment.items[0].claims_hash
            data = approved(data, digest)
            require(check(data, inventory=inv).assessment.items[0].review_status == "確認済み")
            changed = copy.deepcopy(inv)
            if fact == "boot":
                changed["security_facts"]["boot"]["booted_at"] = "2026-11-04T02:00:00Z"
            else:
                changed["security_facts"]["nft_tables"] = [{"family": "inet", "name": "example"}]
            later = check(data, previous=asdict(first.next_state), inventory=changed)
            require(isinstance(outcome(later), Changed))
            require(later.assessment.items[0].claims_hash != digest)
            require(later.assessment.items[0].review_status == "確認待ち")
        run("起動時刻の変更はハッシュ変更・確認待ち", lambda: snapshot_fact_change("boot"))
        run("表の存在の変更はハッシュ変更・確認待ち", lambda: snapshot_fact_change("nft_table"))

        def approval():
            first = check()
            digest = first.assessment.items[0].claims_hash
            data = copy.deepcopy(example)
            review = {"claims_hash": digest, "lanes": [
                {"lane": str(i), "model": "example-model", "effort": "high", "run_id": f"fixture-{i}",
                 "hash": digest, "at": at, "verdict": "approve"} for i in (1, 2)]}
            data["items"][0]["review"] = review
            require(check(data).assessment.items[0].review_status == "確認済み")
            review["lanes"][1]["run_id"] = "fixture-1"
            require(check(data).assessment.items[0].review_status == "確認待ち")
            review["lanes"][1]["run_id"] = "fixture-2"
            review["lanes"][1]["hash"] = "wrong"
            require(check(data).assessment.items[0].review_status == "確認待ち")
            review["lanes"][1]["hash"] = digest
            data["items"][0]["claims"][0]["text"] += "追記。"
            require(check(data).assessment.items[0].review_status == "確認待ち")
            data = copy.deepcopy(example)
            data["items"][0]["claims"].reverse()
            require(check(data).assessment.items[0].claims_hash == digest)
            later = check_all(here, scan_id="later", started_at="2026-11-08T12:00:00+09:00", fetch=fetch)
            require(later.assessment.items[0].claims_hash == digest)
            changed = copy.deepcopy(ubuntu)
            changed["packages"][0]["statuses"][0]["status"] = "needed"
            b = check(fetcher=lambda u: changed if "ubuntu.com" in u else record)
            require(b.assessment.items[0].claims_hash != digest)
        run("二系統承認・hash不一致は確認待ち・取得日時だけではhash不変", approval)

        def legacy_fixture(source):
            # Independent reproduction of the old serialized v1 payload.
            data = copy.deepcopy(source)
            data["items"][0].update(summary="合成の要約", status="watching")
            batch = check(data, inventory=inv)
            semantic = []
            for current in batch.assessment.items[0].claims:
                o = current.outcome
                e = o.last_known if isinstance(o, Unverified) else o.evidence
                fact = None if e is None else {
                    "value": asdict(e.value), "source": e.source, "scope": e.scope,
                    "observed_by": e.observed_by}
                if e is not None and e.scope == "snapshot":
                    fact["observed_at"] = e.observed_at
                semantic.append({"claim": current.claim, "fact": fact})
            payload = {"version": 1, "claims": sorted(semantic, key=lambda row: row["claim"]["id"]),
                       "authored": {k: data["items"][0][k] for k in ("summary", "status")}}
            legacy = "v1:" + hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()
            return approved(data, legacy), batch.assessment

        def migration_files(name, data, assessment):
            path, stored = here / (name + ".json"), here / (name + "-findings.json")
            original = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
            path.write_text(original, encoding="utf-8", newline="\n")
            stored.write_text(json.dumps({"scan_id": assessment.scan_id, "impact_checks": asdict(assessment)},
                                         ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
            return path, stored, original.encode("utf-8")

        def migrate_quiet(path, stored):
            import contextlib
            import io

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                migrated = migrate_review_hashes(path, stored)
            return migrated, output.getvalue()

        def migration_match():
            for index, source in enumerate((vps_item, example)):
                data, assessment = legacy_fixture(source)
                # Exercise both accepted top-level JSON shapes.
                raw = data if index == 0 else data["items"]
                path, stored, original = migration_files(f"matching-{index}", raw, assessment)
                stored_bytes = stored.read_bytes()
                migrated, output = migrate_quiet(path, stored)
                require(migrated == [data["items"][0]["id"]] and migrated[0] + ": migrated" in output)
                backup = path.with_suffix(".json.bak")
                require(backup.read_bytes() == original and stored.read_bytes() == stored_bytes)
                digest = assessment.items[0].claims_hash
                expected = copy.deepcopy(raw)
                target = expected["items"][0] if isinstance(expected, dict) else expected[0]
                target["review"]["claims_hash"] = digest
                for lane in target["review"]["lanes"]:
                    lane["hash"] = digest
                require(digest.startswith("v2:") and json.loads(path.read_text(encoding="utf-8")) == expected)
                require(read_for_report(path, stored, scan_id=assessment.scan_id).items[0].review_status == "確認済み")
                before, modified = path.read_bytes(), path.stat().st_mtime_ns
                require(migrate_quiet(path, stored)[0] == [])
                require(path.read_bytes() == before and path.stat().st_mtime_ns == modified)
                require(backup.read_bytes() == original)
        run("一致するv1承認をv2へ移行・バックアップ・再実行は書換なし", migration_match)

        def migration_refusal():
            for index, change in enumerate(("claim", "authored", "fact", "lane", "missing", "invalid")):
                data, assessment = legacy_fixture(vps_item)
                if change == "claim":
                    data["items"][0]["claims"][0]["text"] += "変更。"
                elif change == "authored":
                    data["items"][0]["summary"] += "変更。"
                elif change == "lane":
                    data["items"][0]["review"]["lanes"][1]["hash"] = "v1:wrong"
                path, stored, original = migration_files(f"refused-{index}", data, assessment)
                if change in ("fact", "missing", "invalid"):
                    doc = json.loads(stored.read_text(encoding="utf-8"))
                    if change == "missing":
                        doc["impact_checks"]["items"] = []
                    else:
                        evidence = doc["impact_checks"]["items"][0]["claims"][0]["outcome"]["evidence"]
                        if change == "fact":
                            evidence["value"]["boot_id"] = "changed-boot"
                            c = doc["impact_checks"]["items"][0]["claims"][0]
                            c["outcome"].update(status="changed", before=asdict(assessment.items[0].claims[0].outcome.evidence.value))
                        else:
                            evidence["source"] = "inventory:other.example.test"
                    stored.write_text(json.dumps(doc, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
                modified = path.stat().st_mtime_ns
                migrated, output = migrate_quiet(path, stored)
                require(not migrated and data["items"][0]["id"] + ": skipped:" in output)
                require(path.read_bytes() == original and path.stat().st_mtime_ns == modified)
                require(not path.with_suffix(".json.bak").exists())
        run("内容・事実変更とレーン不一致・保存証拠欠落不正のv1移行を拒否", migration_refusal)

        def migration_cli():
            import subprocess
            import sys

            data, assessment = legacy_fixture(vps_item)
            path, stored, original = migration_files("cli-migration", data, assessment)
            result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                     "--migrate-review-hashes", "--items", str(path), "--findings", str(stored)],
                                    capture_output=True, text=True, encoding="utf-8", timeout=30)
            require(result.returncode == 0 and "vps-example: migrated" in result.stdout, result.stderr)
            updated = json.loads(path.read_text(encoding="utf-8"))
            require(updated["items"][0]["review"]["claims_hash"] == assessment.items[0].claims_hash)
            require(path.with_suffix(".json.bak").read_bytes() == original)
        run("移行CLIは合成ファイルだけをv2へ更新", migration_cli)

        def invalid_shapes():
            for mutate in (
                lambda d: d["items"][0].update(claims=[]),
                lambda d: d["items"].append(copy.deepcopy(d["items"][0])),
                lambda d: d["items"][0]["claims"].append(copy.deepcopy(d["items"][0]["claims"][0])),
                lambda d: d["items"][0]["claims"][0].update(field="unknown"),
                lambda d: d["items"][0]["claims"][0]["check"].update(kind="unknown"),
                lambda d: d["items"][0]["claims"][0].update(field="upstream_fix"),
                lambda d: d["items"][0]["claims"][0].update(observed_at="2026-11-07T12:00:00"),
            ):
                data = copy.deepcopy(example)
                mutate(data)
                b = check(data)
                require(b.assessment.required_failure and b.assessment.items[0].blocked)
        run("空claims・重複・未知field/check・上流混同・日時不備を拒否", invalid_shapes)

        def history_corrupt():
            first = check()
            corrupt = asdict(first.next_state)
            next(iter(corrupt["entries"].values()))["value"] = {"bad": True}
            b = check(previous=corrupt)
            require(isinstance(outcome(b), Unverified) and b.assessment.required_failure)
            require(b.assessment.changed_count == 0 and b.next_state.version == 0)
            again = check(previous=asdict(b.next_state))
            require(again.next_state == b.next_state)
            require(check(previous=None).assessment.required_failure)
        run("破損履歴は空baselineにせず比較失敗として保存", history_corrupt)

        def selectors():
            for doc in ({}, {"id": "CVE-2099-10001", "packages": []},
                        {"id": "CVE-2099-10001", "packages": ubuntu["packages"] * 2}):
                b = check(fetcher=lambda u: doc if "ubuntu.com" in u else record)
                require(isinstance(outcome(b), Unverified))
            adp = copy.deepcopy(example)
            c = adp["items"][0]["claims"][1]
            c["scorer"] = "ExampleADP"
            c["check"].update(provider="ExampleADP")
            c["check"]["expected"].update(scorer="ExampleADP", role="adp")
            doc = copy.deepcopy(record)
            doc["containers"]["adp"] = [{"providerMetadata": {"shortName": "ExampleADP"},
                                           "metrics": [{"cvssV3_1": metric}]}]
            b = check(adp, fetcher=lambda u: ubuntu if "ubuntu.com" in u else doc)
            require(isinstance(outcome(b, claim=1), Confirmed))
            require(outcome(b, claim=1).evidence.value.scorer == "ExampleADP")
            doc["containers"]["adp"] *= 2
            require(isinstance(outcome(check(adp, fetcher=lambda u: ubuntu if "ubuntu.com" in u else doc), claim=1), Unverified))
            doc = copy.deepcopy(record)
            doc["containers"]["cna"]["metrics"] *= 2
            require(isinstance(outcome(check(fetcher=lambda u: ubuntu if "ubuntu.com" in u else doc), claim=1), Unverified))
        run("UbuntuとCVEのselector欠落・曖昧さ・ADP主体を検査", selectors)

        def missing_malformed():
            items_path.unlink(missing_ok=True)
            b = check_all(here, scan_id="empty", started_at=at, fetch=fetch)
            require(not b.assessment.items and not b.assessment.required_failure)
            items_path.write_text("{\n", encoding="utf-8", newline="\n")
            b = check_all(here, scan_id="bad", started_at=at, fetch=fetch)
            require(b.assessment.required_failure and "書き方の不備" in b.assessment.diagnostics[0]["reason"])
        run("items欠落は0件・不正JSONは可視診断", missing_malformed)

        def report_read():
            b = check()
            findings_path.write_text(json.dumps({"scan_id": "fixture-scan", "impact_checks": asdict(b.assessment)},
                                     ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
            require(read_for_report(items_path, findings_path, scan_id="fixture-scan") == b.assessment)
            data = copy.deepcopy(example)
            data["items"][0]["claims"][0]["text"] += "変更。"
            put(data)
            reread = read_for_report(items_path, findings_path, scan_id="fixture-scan")
            require(isinstance(reread.items[0].claims[0].outcome, Unverified))
            try:
                read_for_report(items_path, findings_path, scan_id="foreign")
            except ValueError:
                pass
            else:
                raise AssertionError("foreign scan accepted")
        run("read_for_reportは保存結果だけを使用し再検証", report_read)

        def locking():
            with workspace_lock(here):
                try:
                    with workspace_lock(here):
                        raise AssertionError("同時取得できた")
                except ValueError:
                    pass
            with workspace_lock(here):
                pass
        run("workspaceロックの排他と解放", locking)

    print(f"selftest-impact-core: {'失敗 ' + str(len(failed)) + ' 件' if failed else '成功（合成fixture・通信なし）'}")
    return 1 if failed else 0


def main():
    import argparse
    import sys

    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", newline="\n")
    parser = argparse.ArgumentParser(description="Migrate matching impact review hashes from v1 to v2")
    parser.add_argument("--migrate-review-hashes", action="store_true", required=True)
    parser.add_argument("--items", type=Path, required=True)
    parser.add_argument("--findings", type=Path, required=True)
    args = parser.parse_args()
    try:
        migrate_review_hashes(args.items, args.findings)
    except (OSError, ValueError, KeyError, TypeError):
        print("承認ハッシュを移行できない: 入力または保存先を確認してください", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
