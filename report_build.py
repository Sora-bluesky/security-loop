"""Build a daily Artifact report from saved impact assessments, without network I/O."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import importlib.util
import json
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
JST = dt.timezone(dt.timedelta(hours=9))


def load_impact():
    name = "security_loop_report_impact"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / "impact.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


impact = load_impact()


def build(assessment, base, *, now):
    """Pure projection: saved evidence supplies facts; the parent owns narrative."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("更新日時はタイムゾーン付きで指定")
    updated_at = now.astimezone(JST).isoformat()
    document = copy.deepcopy(base) if base is not None else empty_report(report_date(assessment.started_at))
    entries = []
    for index, item in enumerate(assessment.items):
        targets = (item.id, f"item[{index}]")
        entries.append({
            "title": item.title, "ref": next((ref for ref in item.refs if isinstance(ref, str)), ""),
            "detail": item.summary, "status": item.status,
            "claims": [render_claim(c) for c in item.claims],
            "review": "承認済み" if item.review_status == "確認済み" else "確認待ち",
            "blocked": item.blocked,
            "diagnostics": [copy.deepcopy(d) for d in assessment.diagnostics
                            if any(d["target"] == target or d["target"].startswith(target + "/")
                                   for target in targets)],
        })
    document["impact"] = entries
    document["counts"]["impact"] = len(entries)
    document["counts"]["sora_items"] = len(document["sora_items"])
    document["last_scan_at"] = assessment.started_at
    document["updated_at"] = updated_at
    return document


def report_date(started_at):
    impact.timestamp(started_at)
    return dt.datetime.fromisoformat(started_at.replace("Z", "+00:00")).astimezone(JST).replace(
        hour=9, minute=0, second=0, microsecond=0).isoformat()


def empty_report(at):
    return {"date": at, "label": "", "title": "", "updated_at": at, "conclusion": "",
            "counts": {"impact": 0, "compromise": 0, "sora_items": 0}, "impact": [],
            "sora_items": [], "done": [], "no_impact": [], "unverified": [], "last_scan_at": None}


def render_claim(checked):
    claim, outcome = checked.claim, checked.outcome
    required = ("text", "field", "source_url", "source_type", "observed_at", "observed_by")
    optional = ("id", "product", "issue_ref", "quote", "demo_env", "persistence", "observation_scope")
    rendered = {key: copy.deepcopy(claim.get(key, "")) for key in required}
    rule = impact.FIELD_RULES.get(claim.get("field")) if isinstance(claim.get("field"), str) else None
    attributes = set(optional) | set(rule.required if rule else ())
    rendered.update({key: copy.deepcopy(claim[key]) for key in sorted(attributes) if claim.get(key) is not None})
    if isinstance(outcome, impact.Unverified):
        rendered.update(result="確認できなかった", reason=outcome.reason, display=outcome.reason)
        if not claim.get("check"):
            rendered["display"] = (f"{claim.get('observed_at', '日時不明')} に "
                                   f"{claim.get('observed_by', '観測者不明')} が観測"
                                   f"（過去の記録）: {outcome.reason}")
        if outcome.last_known:
            rendered["last_known"] = asdict(outcome.last_known)
            rendered["display"] += " / 最後の成功: " + render_evidence(outcome.last_known, historical=True)
    else:
        rendered["result"] = "変化あり" if isinstance(outcome, impact.Changed) else "確認済み"
        rendered["evidence"] = asdict(outcome.evidence)
        rendered["display"] = render_evidence(outcome.evidence)
        if isinstance(outcome, impact.Changed):
            rendered["before"] = asdict(outcome.before)
            rendered["display"] = impact.project_value(outcome.before) + " → " + rendered["display"]
    return rendered


def render_evidence(evidence, *, historical=False):
    if historical:
        return (f"過去の観測（観測日時 {evidence.observed_at}・取得日時 {evidence.retrieved_at}・"
                f"観測者 {evidence.observed_by}）: " + impact.project_value(evidence.value))
    timing = (f"{evidence.observed_at} に {evidence.observed_by} が収集した在庫"
              if evidence.scope == "snapshot" else f"今回の照合で確認（{evidence.observed_at}・{evidence.observed_by}）")
    return timing + ": " + impact.project_value(evidence.value)


def read_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(label + "を読み取れない（ファイルまたはJSONを確認）") from exc


def read_base(path):
    if path == "none":
        return None
    base = read_json(path, "前回レポート")
    shape = empty_report("")
    if not isinstance(base, dict) or any(k not in base or type(base[k]) is not type(v)
                                         for k, v in shape.items() if k != "last_scan_at"):
        raise ValueError("前回レポートを読み取れない（既存キーと型を確認）")
    if any(type(base["counts"].get(k)) is not int for k in ("impact", "compromise", "sora_items")):
        raise ValueError("前回レポートを読み取れない（countsの型を確認）")
    impact.validate_json_values(base)
    return base


def write_report(path, document):
    """Serialize before replacing, so an error cannot leave a partial daily report."""
    payload = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".report-build-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="保存済みの照合結果から日次レポートを作成（通信なし）")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--items", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--base", required=True, help="前回の日次JSON、または none")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        base = read_base(args.base)
        # impact.load_items deliberately tolerates missing files for scan, not for reports.
        raw = read_json(args.items, "影響項目")
        items = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            raise ValueError("影響項目を読み取れない（itemsは配列が必要）")
        findings = read_json(args.findings, "照合結果")
        if not isinstance(findings, dict) or not isinstance(findings.get("impact_checks"), dict):
            raise ValueError("照合結果を読み取れない（impact_checksが必要）")
        stored = findings["impact_checks"]
        if not all(isinstance(value, str) and value for value in (findings.get("scan_id"), stored.get("scan_id"))):
            raise ValueError("照合結果を読み取れない（照合IDが必要）")
        mismatch = findings["scan_id"] != args.scan_id or stored["scan_id"] != args.scan_id
        now = dt.datetime.now(JST)
        try:
            assessment = impact.read_for_report(args.items, args.findings, scan_id=args.scan_id)
        except ValueError:
            if not mismatch:
                raise
            document = copy.deepcopy(base) if base is not None else empty_report(report_date(stored["started_at"]))
            document["updated_at"] = now.isoformat()
            write_report(args.output, document)
            print("照合IDが一致しないため更新を拒否しました。前回の内容と最終照合日時を保持しました。", file=sys.stderr)
            return 2
        write_report(args.output, build(assessment, base, now=now))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        # Paths and raw OS exceptions can disclose local account information.
        reason = str(exc) if isinstance(exc, ValueError) else "ファイルまたは照合結果の形式を確認"
        print("レポートを作成できません: " + reason, file=sys.stderr)
        return 2


def selftest(*, show_sample=True):
    """Saved-report regressions and file boundaries; synthetic only."""
    import contextlib
    import io
    import subprocess
    from unittest.mock import patch

    failed = []
    total = 0
    at = "2026-11-07T12:00:00+09:00"
    now = dt.datetime.fromisoformat("2026-11-07T13:00:00+09:00")

    def require(condition):
        if not condition:
            raise AssertionError("合成レポートの期待結果と不一致")

    def run(name, case):
        nonlocal total
        total += 1
        try:
            case()
        except Exception as exc:
            failed.append(name)
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print("PASS " + name)

    def write(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n",
                        encoding="utf-8", newline="\n")

    with patch.object(impact.urllib.request, "urlopen", side_effect=AssertionError("selftestで通信は禁止")), \
            tempfile.TemporaryDirectory(prefix="report-selftest-", dir=HERE) as temporary:
        root = Path(temporary)
        items_path, findings_path = root / "items.json", root / "findings.json"
        base_path, output_path = root / "base.json", root / "daily.json"
        item = {"id": "example", "title": "合成の起動確認", "kind": "advisory",
                "refs": ["https://observations.example.test/boot"], "claims": [{
                    "id": "boot", "field": "our_exposure", "text": "記述文は証拠値に使わない。",
                    "source_url": "https://observations.example.test/boot", "source_type": "own_observation",
                    "observed_at": "2026-11-04T12:00:00+09:00", "observed_by": "parent",
                    "observation_scope": "inventory_only", "check": {
                        "kind": "vps_fact", "host_alias": "host.example.test", "fact": "boot",
                        "expected": {"booted_at": "2026-11-04T00:00:00Z", "boot_id": "example-boot"}}}]}
        manual = copy.deepcopy(item)
        manual.update(id="manual", title="過去の手動観測")
        del manual["claims"][0]["check"]
        blocked = copy.deepcopy(item)
        blocked.update(id="blocked", title="書き方の不備を残す例")
        del blocked["claims"][0]["source_url"]
        raw = {"items": [item, manual, blocked]}
        rows, errors = impact.validate(raw)
        evidence = impact.Evidence(impact.BootFact("2026-11-06T00:00:00+00:00", "example-new-boot"),
                                   "inventory:host.example.test", at, "scan", at, "snapshot", "example-snapshot")
        assessment = impact.assess(rows, errors, "example-scan", at,
                                   lambda _, claim: impact.Changed(claim.check.expected, evidence)
                                   if claim.check else impact.Unverified("今回の機械確認なし"))
        # Both approval lanes cover the semantic evidence used by read_for_report.
        digest = assessment.items[0].claims_hash
        raw["items"][0]["review"] = {"claims_hash": digest, "lanes": [
            {"lane": str(i), "model": "example-model", "effort": "high", "run_id": f"example-{i}",
             "hash": digest, "at": at, "verdict": "approve"} for i in (1, 2)]}
        write(items_path, raw)
        findings = {"scan_id": "example-scan", "impact_checks": asdict(assessment)}
        write(findings_path, findings)
        base = {
            "date": "2026-11-07T09:00:00+09:00", "label": "合成日報", "title": "合成の点検レポート",
            "updated_at": "2026-11-07T09:00:00+09:00", "conclusion": "親が記入した結論。",
            "counts": {"impact": 1, "compromise": 2, "sora_items": 1},
            "impact": [{"title": "旧項目", "ref": "https://example.test/old", "detail": "旧記録", "status": "watching"}],
            "sora_items": [{"title": "合成の確認作業", "status": "todo", "urgency": "中",
                            "ref": "https://example.test/task", "when": "本日", "detail": "親が記入。"}],
            "done": [{"title": "合成の完了作業", "ref": "https://example.test/done", "detail": "確認した。"}],
            "no_impact": [{"title": "合成の対象外", "reason": "対象製品がない。", "confidence": "高"}],
            "unverified": [{"title": "親の未確認事項", "reason": "次回確認。"}],
            "last_scan_at": "2026-11-07T06:00:00+09:00"}
        write(base_path, base)
        argv = ["--scan-id", "example-scan", "--items", str(items_path), "--findings", str(findings_path),
                "--base", str(base_path), "--output", str(output_path)]

        def invoke(arguments):
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream):
                code = main(arguments)
            return code, stream.getvalue()

        def mismatch():
            for outer, inner in (("foreign", "example-scan"), ("example-scan", "foreign")):
                foreign = copy.deepcopy(findings)
                foreign["scan_id"] = outer
                foreign["impact_checks"]["scan_id"] = inner
                write(findings_path, foreign)
                code, error = invoke(argv)
                require(code != 0 and "照合ID" in error)
                actual = json.loads(output_path.read_text(encoding="utf-8"))
                require(dt.datetime.fromisoformat(actual["updated_at"]) > dt.datetime.fromisoformat(base["updated_at"]))
                actual["updated_at"] = base["updated_at"]
                require(actual == base)
            write(findings_path, findings)

        run("report_buildは外側・内側の照合ID不一致を拒否し旧文書を保持", mismatch)

        def golden():
            require(invoke(argv)[0] == 0)
            actual = json.loads(output_path.read_text(encoding="utf-8"))
            for key in base:
                require(key in actual and type(actual[key]) is type(base[key]))
            for key in ("date", "label", "title", "conclusion", "sora_items", "done", "no_impact", "unverified"):
                require(actual[key] == base[key])
            require(actual["counts"] == {"impact": 3, "compromise": 2, "sora_items": 1})
            require(actual["last_scan_at"] == at)
            require(dt.datetime.fromisoformat(actual["updated_at"]).utcoffset() == dt.timedelta(hours=9))
            first, historical, invalid = actual["impact"]
            require(first["review"] == "承認済み" and invalid["review"] == "確認待ち")
            require(first["detail"] == "" and first["status"] == "open")
            claim = first["claims"][0]
            require(claim["result"] == "変化あり" and claim["evidence"]["value"] == asdict(evidence.value))
            require("example-new-boot" in claim["display"] and item["claims"][0]["text"] not in claim["display"])
            require(claim["observed_at"] == item["claims"][0]["observed_at"])
            require(historical["claims"][0]["result"] == "確認できなかった")
            require("2026-11-04" in historical["claims"][0]["display"])
            require(invalid["blocked"] and any("書き方の不備" in d["reason"] for d in invalid["diagnostics"]))
            original = copy.deepcopy(base)
            read = impact.read_for_report(items_path, findings_path, scan_id="example-scan")
            require(build(read, base, now=now)["updated_at"] == now.isoformat() and base == original)
            # The real -I executable must find siblings from a different working directory.
            child = subprocess.run([sys.executable, "-I", "-B", str(HERE / "report_build.py"), *argv],
                                   cwd=root, capture_output=True, encoding="utf-8")
            require(child.returncode == 0 and not child.stderr)
            require(not output_path.read_bytes().startswith(b"\xef\xbb\xbf") and b"\r" not in output_path.read_bytes())

        run("golden出力は既存キー・親記入欄・構造化証拠・承認・不備を保持（別cwdの-Iも検証）", golden)

        def file_failures():
            for path in (items_path, findings_path, base_path):
                saved = path.read_text(encoding="utf-8")
                for bad in (None, "{\n"):
                    output_path.unlink(missing_ok=True)
                    if bad is None:
                        path.unlink()
                    else:
                        path.write_text(bad, encoding="utf-8", newline="\n")
                    code, error = invoke(argv)
                    require(code != 0 and "読み取" in error and not output_path.exists())
                path.write_text(saved, encoding="utf-8", newline="\n")

        run("入力3ファイルの欠落・不正JSONは日本語診断で終了し空出力を作らない", file_failures)

        def empty_base():
            arguments = argv.copy()
            arguments[arguments.index("--base") + 1] = "none"
            require(invoke(arguments)[0] == 0)
            actual = json.loads(output_path.read_text(encoding="utf-8"))
            require(all(actual[k] == "" for k in ("label", "title", "conclusion")))
            require(all(actual[k] == [] for k in ("sora_items", "done", "no_impact", "unverified")))
            require(actual["counts"] == {"impact": 3, "compromise": 0, "sora_items": 0})
            require(dt.datetime.fromisoformat(actual["date"]).utcoffset() == dt.timedelta(hours=9))
            # Confirmed and last-known failure evidence use the same structured renderer.
            row = assessment.items[0]
            from dataclasses import replace
            for outcome, label in ((impact.Confirmed(evidence), "確認済み"),
                                   (impact.Unverified("合成の取得失敗", evidence), "確認できなかった")):
                c = replace(row.claims[0], outcome=outcome, display="採用してはいけない記述文")
                a = replace(assessment, items=(replace(row, claims=(c,)),))
                result = build(a, None, now=now)["impact"][0]["claims"][0]
                require(result["result"] == label and "example-new-boot" in result["display"])
                require(c.display not in result["display"])
            # Invalid IDs are diagnosed by their input index, not by item.id.
            for bad_id in (None, [], {}):
                invalid = copy.deepcopy(item)
                invalid["id"] = bad_id
                rows, errors = impact.validate({"items": [invalid]})
                a = impact.assess(rows, errors, "example-scan", at, lambda *_: None)
                result = build(a, None, now=now)["impact"][0]
                require(result["blocked"] and result["diagnostics"])

        run("base noneは既存の型を初期化・確認済みと最終成功も構造化値から表示", empty_base)

        def required_assessment_fields():
            wrong = {
                "scan_id": (None, 7, ""), "started_at": (None, 7, "invalid", "2026-11-07"),
                "items": (None, {}, ""), "diagnostics": (None, {}, "", [None]),
                "changed_count": (None, "1", True, -1), "required_failure": (None, "false", 0),
            }
            try:
                for key, values in wrong.items():
                    for value in (impact.MISSING, *values):
                        bad = copy.deepcopy(findings)
                        if value is impact.MISSING:
                            del bad["impact_checks"][key]
                        else:
                            bad["impact_checks"][key] = value
                        write(findings_path, bad)
                        try:
                            impact.read_for_report(items_path, findings_path, scan_id="example-scan")
                        except ValueError as exc:
                            require("照合" in str(exc))
                        else:
                            raise AssertionError(f"{key}の欠落・不正を受理")
                        write(output_path, base)
                        code, error = invoke(argv)
                        require(code != 0 and "レポート" in error)
                        kept = json.loads(output_path.read_text(encoding="utf-8"))
                        require(kept["last_scan_at"] == base["last_scan_at"] and kept["impact"] == base["impact"])
                        output_path.unlink()
                        require(invoke(argv)[0] != 0 and not output_path.exists())
            finally:
                write(findings_path, findings)

        run("Assessment必須6項目の欠落・型不正は拒否し旧最終照合日時を保持", required_assessment_fields)

        def last_known_history():
            from dataclasses import replace
            fetched = copy.deepcopy(item)
            fetched["claims"][0].update(field="distro_fix", source_type="distro", release="26.04", package="linux",
                check={"kind": "ubuntu_cve", "cve": "CVE-2099-10001", "release": "26.04", "package": "linux",
                       "expected": {"release": "26.04", "package": "linux", "status": "pending", "fixed_version": None}})
            old = impact.Evidence(impact.UbuntuStatus("26.04", "linux", "pending"),
                "https://ubuntu.com/security/cves/CVE-2099-10001.json", "2026-11-03T00:00:00Z", "scan",
                "2026-11-04T00:00:00Z", "fetched")
            try:
                for fixture, known in ((item, replace(evidence, observed_at="2026-11-03T00:00:00Z",
                                                       retrieved_at="2026-11-04T00:00:00Z")), (fetched, old)):
                    rows, errors = impact.validate({"items": [fixture]})
                    a = impact.assess(rows, errors, "example-scan", at,
                                      lambda *_: impact.Unverified("合成の取得失敗", known))
                    write(items_path, {"items": [fixture]})
                    write(findings_path, {"scan_id": "example-scan", "impact_checks": asdict(a)})
                    require(invoke(argv)[0] == 0)
                    result = json.loads(output_path.read_text(encoding="utf-8"))["impact"][0]["claims"][0]
                    require(result["result"] == "確認できなかった" and result["last_known"] == asdict(known))
                    require("今回の照合で確認" not in result["display"] and "過去" in result["display"])
                    require(all(value in result["display"] for value in (known.observed_at, known.retrieved_at, known.observed_by)))
            finally:
                write(items_path, raw)
                write(findings_path, findings)

        run("取得失敗の最終成功は取得型・在庫型とも日時と観測者付きの過去表示", last_known_history)

        def manual_structured_fields():
            fixtures = read_json(HERE / "impact-items.example.json", "合成例")
            for fixture in fixtures["items"]:
                for claim in fixture["claims"]:
                    claim.pop("check", None)
            rows, errors = impact.validate(fixtures)
            require(not errors)
            a = impact.assess(rows, errors, "example-scan", at, lambda *_: impact.Unverified("今回の機械確認なし"))
            try:
                write(items_path, fixtures)
                write(findings_path, {"scan_id": "example-scan", "impact_checks": asdict(a)})
                require(invoke(argv)[0] == 0)
                actual = json.loads(output_path.read_text(encoding="utf-8"))
                fields = set()
                for fixture, rendered in zip(fixtures["items"], actual["impact"]):
                    for claim, result in zip(fixture["claims"], rendered["claims"]):
                        fields.add(claim["field"])
                        for key in impact.FIELD_RULES[claim["field"]].required:
                            require(key in result and result[key] == claim[key] and type(result[key]) is type(claim[key]))
                        require(result["result"] == "確認できなかった" and "evidence" not in result)
                require(fields == set(impact.FIELD_RULES))
            finally:
                write(items_path, raw)
                write(findings_path, findings)

        run("手動主張は全FIELD_RULES必須属性を構造化値として保持", manual_structured_fields)

        def deterministic_date():
            from dataclasses import replace
            # UTC's previous day is already November 7 in Japan.
            a = replace(assessment, started_at="2026-11-06T23:30:00Z")
            first = build(a, None, now=now)
            later = build(a, None, now=now + dt.timedelta(days=3))
            require(first["date"] == later["date"] == "2026-11-07T09:00:00+09:00")
            require(first["updated_at"] != later["updated_at"])
            first.pop("updated_at")
            later.pop("updated_at")
            require(first == later)
            require(build(a, base, now=now)["date"] == base["date"])

        run("base noneの日付は走査開始の日本時間日付・09時で決定的", deterministic_date)

        def authored_display_fields():
            fixture = copy.deepcopy(raw)
            fixture["items"][0].update(summary="合成の説明。確認した事実は各主張の証拠を参照する。", status="watching")

            def read_fixture(value):
                write(items_path, value)
                return impact.read_for_report(items_path, findings_path, scan_id="example-scan")

            try:
                a = read_fixture(fixture)
                first = a.items[0]
                require(first.review_status == "確認待ち" and first.claims_hash != digest)
                report = build(a, base, now=now)["impact"][0]
                require(report["detail"] == fixture["items"][0]["summary"] and report["status"] == "watching")
                require(report["claims"][0]["evidence"]["value"] == asdict(evidence.value))
                review = fixture["items"][0]["review"]
                review["claims_hash"] = first.claims_hash
                for lane in review["lanes"]:
                    lane["hash"] = first.claims_hash
                require(read_fixture(fixture).items[0].review_status == "確認済み")
                for key, value in (("summary", "変更した合成の説明。"), ("status", "open")):
                    changed = copy.deepcopy(fixture)
                    changed["items"][0][key] = value
                    result = read_fixture(changed).items[0]
                    require(result.review_status == "確認待ち" and result.claims_hash != first.claims_hash)
                for key, values in (("summary", (None, 1, [], {}, "文" * 151)),
                                    ("status", (None, 1, [], {}, "closed", ""))):
                    for value in values:
                        invalid = copy.deepcopy(fixture)
                        invalid["items"][0][key] = value
                        result = read_fixture(invalid)
                        rendered = build(result, base, now=now)["impact"][0]
                        require(rendered["blocked"] and rendered["review"] == "確認待ち")
                        require(any("書き方の不備" in d["reason"] for d in rendered["diagnostics"]))
                boundary = copy.deepcopy(fixture)
                boundary["items"][0]["summary"] = "文" * 150
                require(not read_fixture(boundary).items[0].blocked)
                default = build(read_fixture(raw), base, now=now)["impact"][0]
                require(default["detail"] == "" and default["status"] == "open")
                require(assessment.items[0].claims_hash == impact.claims_hash(
                    impact.validate(raw)[0][0][1], [assessment.items[0].claims[0].outcome]))
            finally:
                write(items_path, raw)

        run("表示用summary・statusは検証・描画・ハッシュに反映し変更時は再承認", authored_display_fields)
        if not failed and show_sample:
            invoke(argv)
            print("合成出力例:")
            print(output_path.read_text(encoding="utf-8").rstrip())
    print(f"selftest-report-build: {'失敗' if failed else '成功'}（{total - len(failed)}/{total}件・合成fixture・通信なし）")
    return 1 if failed else 0


if __name__ == "__main__":
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", newline="\n")
    if sys.argv[1:] == ["--selftest"]:
        raise SystemExit(selftest())
    raise SystemExit(main())
