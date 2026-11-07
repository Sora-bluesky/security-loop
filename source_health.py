"""Diagnose collection failures without treating missing evidence as success.

Paths are relative to this script, including explicitly supplied relative paths.
JSON goes to stdout; the Japanese summary goes to stderr. Only explicit success
evidence resets a source. Unobserved failures stay visible until observed again.
The ledger is a JSON object containing a ``sources`` mapping. This tool proposes
fixes; it never changes watch lists, collector code, or external systems.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve().parent
SUCCESS = {"success", "ok"}


def read_object(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object が必要: {path.name}")
    return value


def atomic_json(path, value):
    """Finish serialization and writing before replacing the previous file."""
    payload = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=path.name + ".", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def lookup_profile(handle):
    if not re.fullmatch(r"[A-Za-z0-9_]{1,15}", handle):
        raise ValueError("X のアカウント名の形式が不正")
    request = Request(
        f"https://api.fxtwitter.com/{handle}",
        headers={"User-Agent": "security-loop-source-health/1.0"},
    )
    try:
        with urlopen(request, timeout=20) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return {"code": 404, "user": None}
        raise


def diagnose_timeline(handle, lookup):
    evidence = {"handle": handle}
    try:
        profile = lookup(handle)
        if not isinstance(profile, dict):
            raise ValueError("プロフィールの応答が object ではない")
        user = profile.get("user") if "user" in profile else profile
        if profile.get("code") == 404:
            evidence.update(display_name=None, creation_date=None, post_count=None)
            return ("not_found", evidence,
                    "公式サイトで公式アカウント名を確認し、見張りリストを修正する。", "data")
        if profile.get("code", 200) != 200 and not (
            isinstance(user, dict) and any(user.get(field) is True for field in
                                          ("suspended", "is_suspended", "protected", "is_protected"))
        ):
            raise ValueError(f"プロフィール API code={profile.get('code')}")
        if "user" in profile and not user:
            evidence.update(display_name=None, creation_date=None, post_count=None)
            return ("not_found", evidence,
                    "公式サイトで公式アカウント名を確認し、見張りリストを修正する。", "data")
        if not isinstance(user, dict) or not user:
            raise ValueError("プロフィールに有効な user が無い")
        evidence.update(display_name=user.get("name"),
                        creation_date=user.get("joined", user.get("created_at")),
                        post_count=user.get("tweets", user.get("statuses_count")))
        if any(user.get(field) is True for field in
               ("suspended", "is_suspended", "protected", "is_protected")):
            return ("suspended_or_protected", evidence,
                    "凍結・非公開の表示を確認し、公開の公式情報源への切替を検討する。", "external")
        posts = evidence["post_count"]
        if isinstance(posts, str) and posts.isdecimal():
            posts = int(posts)
            evidence["post_count"] = posts
        if type(posts) is not int or posts < 0:
            raise ValueError("投稿数を確認できない")
        if posts == 0:
            suggestion = "公式サイトで公式アカウント名を確認し、見張りリストを修正する。"
            if handle.casefold() == "jpcertcc":
                suggestion += " JPCERT/CC は jpcert・jpcert_en を照合候補にする。"
            return "zero_posts", evidence, suggestion, "data"
        return ("mirror_only", evidence,
                "投稿の存在を確認できたため、タイムラインの URL・ミラー・パーサーを調べて修正を委任する。",
                "code")
    except HTTPError as error:
        if error.code == 404:
            evidence.update(display_name=None, creation_date=None, post_count=None)
            return ("not_found", evidence,
                    "公式サイトで公式アカウント名を確認し、見張りリストを修正する。", "data")
        evidence["lookup_error"] = f"{type(error).__name__}: {error}"
    except Exception as error:
        evidence["lookup_error"] = f"{type(error).__name__}: {error}"
    return ("lookup_failed", evidence,
            "プロフィール照会自体が失敗した。通信・API 応答を確認して再照会し、アカウント名は未判定とする。",
            "external")


def source_key(kind, target):
    if kind in ("x_timeline", "timeline"):
        return "x_timeline:" + target.lstrip("@").casefold()
    if kind in ("x_discover", "discover"):
        return "x_discover"
    if kind in ("kev", "osv", "osv_detail", "vps"):
        return "osv" if kind == "osv_detail" else kind
    if kind == "inventory" and target == "vps":
        return "vps"
    if kind in ("runtime_advisory", "gh_advisory"):
        target = target.split()[0]  # repo + GHSA, or ecosystem:package + version
    return f"{kind}:{target}"


def diagnose_other(key, reason):
    lower = reason.casefold()
    if "製品に一致する package" in reason:
        return "advisory_no_package", "GitHub の勧告に package 名が無い。リポ単位の勧告として製品と結びつける照合を直す", "code"
    if "実行ファイルのパスが読めない（アクセス拒否" in reason:
        return "access_denied", "管理者権限なしでは読めない。既知の制約として扱い、別の経路（サービスの登録情報）があるか確かめる", "external"
    if "Docker が止まっている" in reason:
        return "service_stopped", "Docker の稼働状態を確認し、停止が意図した状態か確かめる。", "external"
    if "VPS 在庫・対象パッケージを確認できない" in reason:
        return "vps_inventory", "VPS のタイマー・Taildrop を確認し、最新の在庫と対象パッケージが届いているか確かめる。", "external"
    if key == "x_timeline":
        return "collector_reports_missing", "タイムライン収集の起動・出力先を確認し、レポートを再生成する。", "code"
    if key == "x_discover" and re.search(
        r"(?:exit(?:[_ ]?code)?|終了コード)\s*[:=]?\s*3\b", lower
    ):
        return ("discover_query_path", "検索の経路が x.com を返さない（allowed_domains・クエリの形を疑う）", "data")
    if key == "inventory:listening" and "State が無い" in reason:
        return "collector_state_missing", "収集の判定を疑う。State の取得・保持と待受の判定を確認し、修正を委任する。", "code"
    if key == "vps" and any(word in reason for word in ("古い", "無い", "ない")):
        return "vps_delivery", "VPS のタイマー・Taildrop を疑う。実行時刻・転送先・到着ファイルを確認する。", "external"
    if key.startswith("scanmux:") and "dirty_worktree" in lower:
        return ("dirty_worktree", "そのリポに未コミットの変更（照合の対象外になっている）。変更を所有者が確認して整理し、再実行する。", "external")
    if key.startswith("winget:") and (
        "version mismatch" in lower or "version_mismatch" in lower
        or ("版" in reason and any(word in reason for word in ("一致しない", "比較できない")))
    ):
        return "version_normalization", "版の比較の正規化を疑う。在庫と更新一覧の元の版表記を照合し、修正を委任する。", "code"
    return "unclassified", "原因は未分類。元の理由と収集ログ・設定を照合し、原因を確認してから修正方法を決める。", "external"


def report_observation(key, report):
    status = report.get("status")
    if not isinstance(status, str):
        raise ValueError(f"{key}: status が無い・不正")
    count = report.get("item_count")
    if count is None and isinstance(report.get("items"), list):
        count = len(report["items"])
    success = status in SUCCESS or (key == "x_discover" and status in ("found", "none_in_window"))
    evidence = {"report_status": status, "errors": report.get("errors", []), "item_count": count}
    if key == "x_discover":
        evidence.update({field: report[field] for field in ("query_count", "candidate_count", "summary", "note")
                         if field in report})
        if status == "none_in_window":
            evidence["note"] = "検索は成功したが、対象期間内の候補は無い。"
    return {"key": key, "status": "ok" if success else "failed",
            "reason": "" if success else status, "evidence": evidence}


def exit_code_from_text(text):
    matches = re.findall(r"(?:exit(?:[_ ]?code)?|終了コード)\s*[:=]?\s*(-?\d+)\b", text, re.I)
    if matches:
        return int(matches[-1])
    stripped = text.strip()
    return int(stripped) if re.fullmatch(r"-?\d+", stripped) else None


def collect_observations(run_dir, findings_path):
    if not run_dir.is_dir():
        raise ValueError("X-watch の実行フォルダーが無い")
    observations = []
    timelines = sorted((run_dir / "timelines").glob("*.json"))
    if not timelines:
        observations.append({"key": "x_timeline", "status": "failed",
                             "reason": "タイムラインのレポートが無い", "evidence": {}})
    for path in timelines:
        report = read_object(path)
        handle = report.get("handle", path.stem)
        if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,15}", handle):
            raise ValueError(f"アカウント名が不正: {path.name}")
        observations.append(report_observation(source_key("x_timeline", handle), report))

    discover, discover_out = run_dir / "discover.json", run_dir / "discover.out"
    if discover.exists() or discover_out.exists():
        report, parse_error = {}, None
        try:
            report = read_object(discover) if discover.exists() else {}
        except (ValueError, OSError) as error:
            parse_error = str(error)
        observation = {"key": "x_discover", "status": "failed",
                       "reason": "discover の成功状態を確認できない",
                       "evidence": {"report_present": discover.exists(), "errors": report.get("errors", [])}}
        if isinstance(report.get("status"), str):
            observation = report_observation("x_discover", report)
        if discover_out.exists():
            text = discover_out.read_text(encoding="utf-8")
            code = None if text.lstrip().startswith(("{", "[")) else exit_code_from_text(text)
            observation["evidence"]["exit_code"] = code
            if code is None:
                try:
                    stdout = report_observation("x_discover", read_object(discover_out))
                    observation["evidence"]["stdout"] = stdout["evidence"]
                    if not discover.exists():
                        observation = stdout
                    elif stdout["status"] == "failed":
                        observation.update(status="failed", reason=stdout["reason"])
                except (ValueError, OSError) as error:
                    parse_error = str(error)
            elif code == 3:
                observation["status"] = "failed"
                observation["reason"] += f"; exit code: {code}"
            elif code == 0 and "status" not in report and not report.get("errors"):
                observation.update(status="ok", reason="")
        if parse_error is not None:
            observation.update(status="failed", reason="discover の解析失敗: " + parse_error)
            observation["evidence"]["parse_error"] = parse_error
        observations.append(observation)

    findings = read_object(findings_path)
    rows = findings.get("unverified")
    if not isinstance(rows, list):
        raise ValueError("findings の unverified が無い・不正")
    for row in rows:
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k] for k in ("kind", "target", "reason")):
            raise ValueError("unverified の kind/target/reason が不正")
        observations.append({"key": source_key(row["kind"], row["target"]), "status": "failed",
                             "reason": row["reason"], "evidence": {"target": row["target"]}})

    running_failures = {row["target"] for row in rows if row["kind"] == "running"}
    running = findings.get("running", [])
    blocked_names = {row.get("name") for row in running if isinstance(row, dict)
                     and (row.get("name") in running_failures or row.get("path") in running_failures)}
    for row in running:
        if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"] and row["name"] not in blocked_names:
            observations.append({"key": source_key("running", row["name"]), "status": "ok",
                                 "reason": "", "evidence": {"name": row["name"]}})

    # A negative-only unverified list cannot prove that a collector actually ran.
    counts = findings.get("counts", {})
    for field, key in (("listening", "inventory:listening"), ("vps_package_versions", "vps")):
        if type(counts.get(field)) is int and counts[field] >= 0:
            observations.append({"key": key, "status": "ok", "reason": "", "evidence": {field: counts[field]}})
    if (type(counts.get("osv_queried")) is int and counts["osv_queried"] > 0
            and counts.get("osv_checked") == counts["osv_queried"]
            and counts.get("osv_unverified_packages") == 0):
        observations.append({"key": "osv", "status": "ok", "reason": "", "evidence": {"osv_checked": counts["osv_checked"]}})
    for check in findings.get("winget", {}).get("checks", []):
        if check.get("update_available") is not None:
            observations.append({"key": source_key("winget", check["name"]), "status": "ok",
                                 "reason": "", "evidence": {"result": check.get("result")}})
    for repo, result in findings.get("scanmux", {}).get("repos", {}).items():
        if isinstance(result, dict) and result.get("exitCode") in (0, 10):
            observations.append({"key": source_key("scanmux", repo), "status": "ok", "reason": "", "evidence": {"exitCode": result["exitCode"]}})
    for release in findings.get("releases", []):
        if release.get("repo") and release.get("tag"):
            observations.append({"key": source_key("release", release["repo"]), "status": "ok",
                                 "reason": "", "evidence": {"tag": release["tag"]}})
    if findings.get("kev"):
        observations.append({"key": "kev", "status": "ok", "reason": "", "evidence": {"matched_items": len(findings["kev"])}})
    return observations


def load_ledger(path):
    if not path.exists():
        return {"sources": {}}
    ledger = read_object(path)
    if not isinstance(ledger.get("sources"), dict):
        raise ValueError("状態ファイルの sources が不正")
    for key, row in ledger["sources"].items():
        if (not isinstance(row, dict) or row.get("status") not in ("ok", "failed")
                or type(row.get("consecutive")) is not int or row["consecutive"] < 0
                or not isinstance(row.get("last_reason"), str)
                or (row["status"] == "failed" and (row["consecutive"] < 1 or not isinstance(row.get("first_failed_at"), str)))
                or (row["status"] == "ok" and (row["consecutive"] != 0 or row.get("first_failed_at") is not None))):
            raise ValueError(f"状態ファイルの記録が不正: {key}")
    return ledger


def evaluate(observations, ledger, lookup, now):
    sources = {}
    for key, old in copy.deepcopy(ledger["sources"]).items():
        if key.startswith(("runtime_advisory:", "gh_advisory:")):
            key = source_key(*key.split(":", 1))
        previous = sources.get(key)
        if previous is None or (previous["status"] == "ok" and old["status"] == "failed"):
            sources[key] = old
        elif previous["status"] == old["status"] == "failed":
            # Legacy per-item counters overlap runs; adding them would overcount.
            previous["consecutive"] = max(previous["consecutive"], old["consecutive"])
            previous["first_failed_at"] = min(previous["first_failed_at"], old["first_failed_at"])
            previous["last_reason"] = " / ".join(dict.fromkeys((previous["last_reason"], old["last_reason"])))
    grouped = {}
    for row in observations:
        grouped.setdefault(row["key"], []).append(row)
    results = []
    for key in sorted(set(grouped) | set(sources)):
        rows = grouped.get(key, [])
        old = sources.get(key, {})
        if not rows:
            if old["status"] == "failed":
                results.append({"key": key, "status": "unobserved", "consecutive": old["consecutive"],
                                "cause": "missing_observation", "evidence": {"last_reason": old["last_reason"], "observed": False},
                                "suggestion": "今回の成功証拠が無い。設定からの脱落・収集の未実行を確認し、再収集する。",
                                "fix_kind": "external"})
            continue
        failed = [row for row in rows if row["status"] == "failed"]
        # Aggregate first: many failed items in one run count as one failed source.
        reason = " / ".join(dict.fromkeys(row["reason"] for row in failed))
        consecutive = old.get("consecutive", 0) + 1 if failed else 0
        first = (old.get("first_failed_at") or now) if failed else None
        status = "failed" if failed else "ok"
        sources[key] = {"status": status, "consecutive": consecutive,
                        "first_failed_at": first, "last_reason": reason}
        evidence = {"observations": rows}
        if key.startswith("runtime_advisory:"):
            ids = sorted({ghsa for row in failed for ghsa in
                          re.findall(r"\bGHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\b", row["evidence"].get("target", ""), re.I)})
            evidence.update(advisory_ids=ids, advisory_count=len(ids))
        if not failed:
            cause, suggestion, fix_kind = "ok", "", "external"
        elif key.startswith("x_timeline:"):
            cause, profile, suggestion, fix_kind = diagnose_timeline(key.split(":", 1)[1], lookup)
            evidence["profile"] = profile
        else:
            cause, suggestion, fix_kind = diagnose_other(key, reason)
            evidence["reason"] = reason
        results.append({"key": key, "status": status, "consecutive": consecutive,
                        "cause": cause, "evidence": evidence, "suggestion": suggestion, "fix_kind": fix_kind})
    return {"sources": sources}, results


def summary(results):
    failed = [row for row in results if row["status"] == "failed"]
    repeated = sum(row["consecutive"] >= 2 for row in failed)
    fixes = sum(row["cause"] not in ("unclassified", "lookup_failed", "missing_observation") for row in failed)
    unobserved = sum(row["status"] == "unobserved" for row in results)
    return f"経路の点検: 失敗 {len(failed)} 件（続けて2回以上 {repeated} 件）、直し方の案 {fixes} 件、未観測 {unobserved} 件"


def resolve_path(value):
    path = Path(value)
    return (path if path.is_absolute() else HERE / path).resolve()


def run_health(run_dir, findings, state, output, lookup=lookup_profile):
    for path in (state, output):
        if not path.is_relative_to(HERE):
            raise ValueError("書込み先はスクリプトのディレクトリ内に限定")
    if state == output or any(path == findings or path.is_relative_to(run_dir) for path in (state, output)):
        raise ValueError("入力・出力・状態ファイルのパスが重複")
    observations = collect_observations(run_dir, findings)
    ledger, results = evaluate(observations, load_ledger(state), lookup,
                               datetime.now(timezone.utc).isoformat(timespec="seconds"))
    # Output failure must not advance the ledger. Each file is individually atomic.
    atomic_json(output, results)
    atomic_json(state, ledger)
    return results, 10 if any(row["status"] == "failed" for row in results) else 0


def selftest():
    import subprocess
    from unittest.mock import patch

    fixtures = HERE / "fixtures" / "public" / "health"
    profile = {"screen_name": "example_feed", "name": "example_feed", "tweets": 0,
               "joined": "Fri Jan 01 00:00:00 +0000 2021"}
    calls = []

    def lookup(handle):
        calls.append(handle)
        assert handle == "example_feed", handle
        return profile

    def broken_lookup(handle):
        raise OSError("fixture: profile API unavailable")

    # An accidental real lookup anywhere in the test is a test failure.
    with patch(__name__ + ".urlopen", side_effect=AssertionError("network forbidden")):
        with tempfile.TemporaryDirectory(prefix="source-health-test-", dir=HERE) as temporary:
            root = Path(temporary)
            state, output = root / "state.json", root / "out.json"
            rows, code = run_health(fixtures, fixtures / "findings-unverified.json", state, output, lookup)
            assert code == 10 and json.loads(output.read_text(encoding="utf-8")) == rows
            by_key = {row["key"]: row for row in rows}
            bad = by_key["x_timeline:example_feed"]
            assert bad["cause"] == "zero_posts" and bad["fix_kind"] == "data"
            assert bad["evidence"]["profile"]["display_name"] == "example_feed"
            assert bad["evidence"]["profile"]["post_count"] == 0
            assert "2021" in bad["evidence"]["profile"]["creation_date"]
            assert by_key["inventory:listening"]["cause"] == "collector_state_missing"
            assert by_key["inventory:listening"]["consecutive"] == 1
            assert any(row["cause"] == "dirty_worktree" for row in rows)
            assert any(row["cause"] == "version_normalization" for row in rows)
            first = load_ledger(state)["sources"][bad["key"]]["first_failed_at"]
            rows, code = run_health(fixtures, fixtures / "findings-unverified.json", state, output, lookup)
            assert next(row for row in rows if row["key"] == bad["key"])["consecutive"] == 2
            assert load_ledger(state)["sources"][bad["key"]]["first_failed_at"] == first
            assert calls == ["example_feed", "example_feed"]
            assert diagnose_timeline("example_feed", broken_lookup)[0] == "lookup_failed"
            assert diagnose_timeline("example_feed", lambda _: {"code": 404, "user": None})[0] == "not_found"
            assert diagnose_timeline("example_feed", lambda _: {"user": None})[0] == "not_found"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"protected": True}})[0] == "suspended_or_protected"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"tweets": 12}})[0] == "mirror_only"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"name": "unknown"}})[0] == "lookup_failed"
            assert diagnose_timeline("example_feed", lambda _: {"code": 500})[0] == "lookup_failed"
            assert diagnose_timeline("example_feed", lambda _: {"code": 503, "user": None})[0] == "lookup_failed"
            assert diagnose_timeline("example_feed", lambda _: {"user": {}})[0] == "not_found"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"suspended": True}})[0] == "suspended_or_protected"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"tweets": -1}})[0] == "lookup_failed"
            assert diagnose_timeline("example_feed", lambda _: {"user": {"tweets": True}})[0] == "lookup_failed"

            run_dir = root / "run"
            (run_dir / "timelines").mkdir(parents=True)
            atomic_json(run_dir / "timelines" / "EXAMPLE_FEED.json", {"status": "success", "item_count": 1})
            findings = root / "findings.json"
            atomic_json(findings, {"unverified": []})
            recovered, code = run_health(run_dir, findings, root / "fresh-state.json", output, lookup)
            assert code == 0 and recovered[0]["consecutive"] == 0
            old = {"sources": {bad["key"]: load_ledger(state)["sources"][bad["key"]]}}
            ledger, recovered = evaluate(collect_observations(run_dir, findings), old, lookup, "later")
            assert ledger["sources"][bad["key"]] == {"status": "ok", "consecutive": 0, "first_failed_at": None, "last_reason": ""}
            assert recovered[0]["cause"] == "ok"
            ledger, missing = evaluate([], old, lookup, "later")
            assert missing[0]["cause"] == "missing_observation" and ledger == old
            assert missing[0]["status"] == "unobserved" and missing[0]["fix_kind"] != "data"
            assert "失敗 0 件" in summary(missing) and "未観測 1 件" in summary(missing)
            running_old = {"sources": {"running:python.exe": {"status": "failed", "consecutive": 1,
                           "first_failed_at": "first", "last_reason": "実行ファイルのパスが読めない"}}}
            processes = [{"name": "python.exe", "path": f"C:/python{i}.exe", "result": "判定不能",
                          "reason": "判定の基準がない（照合の対象外の製品）"} for i in range(4)]
            atomic_json(findings, {"unverified": [], "running": processes})
            atomic_json(root / "running-state.json", running_old)
            recovered, code = run_health(run_dir, findings, root / "running-state.json", output, lookup)
            assert code == 0 and next(row for row in recovered if row["key"] == "running:python.exe")["status"] == "ok"
            assert load_ledger(root / "running-state.json")["sources"]["running:python.exe"]["consecutive"] == 0
            atomic_json(findings, {"unverified": [{"kind": "running", "target": "python.exe", "reason": "読めない"}], "running": processes})
            ledger, mixed = evaluate(collect_observations(run_dir, findings), running_old, lookup, "later")
            assert ledger["sources"]["running:python.exe"]["consecutive"] == 2
            assert next(row for row in mixed if row["key"] == "running:python.exe")["status"] == "failed"
            atomic_json(findings, {"unverified": [], "running": []})
            atomic_json(root / "running-state.json", running_old)
            missing, code = run_health(run_dir, findings, root / "running-state.json", output, lookup)
            assert code == 0 and next(row for row in missing if row["key"] == "running:python.exe")["status"] == "unobserved"
            assert load_ledger(root / "running-state.json")["sources"]["running:python.exe"] == running_old["sources"]["running:python.exe"]
            failed_row = {"key": "inventory:listening", "status": "failed", "reason": "State が無い", "evidence": {}}
            ledger, _ = evaluate([failed_row, failed_row], {"sources": {}}, lookup, "first")
            ledger, _ = evaluate([failed_row], ledger, lookup, "second")
            assert ledger["sources"]["inventory:listening"]["consecutive"] == 2
            assert ledger["sources"]["inventory:listening"]["first_failed_at"] == "first"
            atomic_json(findings, {"unverified": [], "counts": {"listening": 0}})
            ledger, _ = evaluate(collect_observations(run_dir, findings), ledger, lookup, "third")
            assert ledger["sources"]["inventory:listening"]["consecutive"] == 0
            # Contradictory evidence must fail closed, independent of input order.
            good_row = {**failed_row, "status": "ok", "reason": ""}
            for mixed in ([failed_row, good_row], [good_row, failed_row]):
                _, mixed_rows = evaluate(mixed, {"sources": {}}, lookup, "now")
                assert mixed_rows[0]["status"] == "failed"
            atomic_json(findings, {
                "unverified": [], "counts": {"osv_queried": 1, "osv_checked": 1,
                                               "osv_unverified_packages": 0, "vps_package_versions": 1},
                "winget": {"checks": [{"name": "example", "update_available": False}]},
                "scanmux": {"repos": {"example/repo": {"exitCode": 0}}},
                "releases": [{"repo": "example/repo", "tag": "v1"}], "kev": [{"cve": "example"}],
            })
            positive = {row["key"] for row in collect_observations(run_dir, findings) if row["status"] == "ok"}
            assert {"osv", "vps", "winget:example", "scanmux:example/repo", "release:example/repo", "kev"} <= positive
            atomic_json(findings, {"unverified": []})

            discover_report = read_object(fixtures / "discover-found.json")
            atomic_json(run_dir / "discover.json", discover_report)
            atomic_json(run_dir / "discover.out", discover_report)
            def discover_row():
                return next(row for row in collect_observations(run_dir, findings) if row["key"] == "x_discover")
            assert discover_row()["status"] == "ok", "found JSON stdout is not an exit-code failure"
            assert discover_row()["evidence"]["candidate_count"] == 1
            assert discover_row()["evidence"]["query_count"] == 1
            atomic_json(run_dir / "discover.out", {**discover_report, "note": "fixture query: exit code: 3"})
            assert discover_row()["status"] == "ok", "JSON content is not a process exit code"
            (run_dir / "discover.out").unlink()
            assert discover_row()["status"] == "ok", "report alone proves success"
            for status in ("none_in_window", "unverified"):
                atomic_json(run_dir / "discover.json", {**discover_report, "status": status, "candidate_count": 0})
                row = discover_row()
                assert row["status"] == ("ok" if status == "none_in_window" else "failed")
                if status == "none_in_window":
                    assert row["evidence"]["note"], "empty window needs a note"
                    (run_dir / "discover.out").write_text("exit code: 1\n", encoding="utf-8", newline="\n")
                    assert discover_row()["status"] == "ok", "only exit 3 overrides a successful report"
                    (run_dir / "discover.out").unlink()
            atomic_json(run_dir / "discover.json", discover_report)
            for text in ('{"status":"unverified"}', "exit code: 3\n", "broken JSON\n"):
                (run_dir / "discover.out").write_text(text, encoding="utf-8", newline="\n")
                assert discover_row()["status"] == "failed", "contradictory/invalid stdout must fail"
            atomic_json(run_dir / "discover.out", discover_report)
            (run_dir / "discover.json").write_text("broken JSON\n", encoding="utf-8", newline="\n")
            assert discover_row()["status"] == "failed", "invalid report must fail"
            atomic_json(run_dir / "discover.json", discover_report)
            (run_dir / "discover.json").unlink()
            assert discover_row()["status"] == "ok", "JSON stdout alone proves success"
            atomic_json(run_dir / "discover.json", discover_report)

            command = [sys.executable, "-I", "-B", str(HERE / "source_health.py"),
                       "--run-dir", str(run_dir), "--findings", str(findings),
                       "--state", str(root / "cli-state.json"), "--output", str(output)]
            completed = subprocess.run(command, capture_output=True, encoding="utf-8", check=False)
            assert completed.returncode == 0, completed.stderr
            assert all(row["status"] == "ok" for row in json.loads(completed.stdout))
            assert "経路の点検: 失敗 0 件" in completed.stderr

            for text in ("exit code: 3", "EXIT_CODE=3", "終了コード 3", "3\n"):
                assert exit_code_from_text(text) == 3
            (run_dir / "discover.out").write_text("exit code: 3\n", encoding="utf-8", newline="\n")
            observations = collect_observations(run_dir, findings)
            assert any(row["key"] == "x_discover" and row["status"] == "failed" for row in observations)
            assert diagnose_other("x_discover", "exit code: 3")[0] == "discover_query_path"
            assert diagnose_other("vps", "在庫が古い")[0] == "vps_delivery"
            assert diagnose_other("kev", "unknown")[0] == "unclassified"
            for key, reason, cause, kind, words in (
                ("runtime_advisory:owner/repo", "製品に一致する package を確認できない", "advisory_no_package", "code", ("リポ単位",)),
                ("inventory:listening", "実行ファイルのパスが読めない（アクセス拒否）", "access_denied", "external", ("管理者権限", "サービスの登録情報")),
                ("inventory:docker", "Docker が止まっている", "service_stopped", "external", ("Docker",)),
                ("vps", "VPS 在庫・対象パッケージを確認できない", "vps_inventory", "external", ("タイマー", "Taildrop")),
            ):
                actual, suggestion, fix_kind = diagnose_other(key, reason)
                assert (actual, fix_kind) == (cause, kind), ("H3", reason, actual, fix_kind)
                assert all(word in suggestion for word in words)
            assert diagnose_other("inventory:docker", "unknown new failure")[0] == "unclassified"
            assert source_key("osv_detail", "pkg") == "osv"
            assert source_key("inventory", "vps") == "vps"
            assert source_key("runtime_advisory", "owner/repo GHSA-aaaa-bbbb-cccc") == "runtime_advisory:owner/repo", "group advisory items by repo"
            atomic_json(findings, {"unverified": [
                {"kind": "runtime_advisory", "target": "owner/repo " + ghsa, "reason": "fixture"}
                for ghsa in ("GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff", "GHSA-aaaa-bbbb-cccc")
            ]})
            advisory_rows = [row for row in collect_observations(run_dir, findings) if row["key"].startswith("runtime_advisory:")]
            _, grouped = evaluate(advisory_rows, {"sources": {}}, lookup, "first")
            assert len(grouped) == 1 and grouped[0]["consecutive"] == 1
            assert grouped[0]["evidence"]["advisory_count"] == 2
            assert grouped[0]["evidence"]["advisory_ids"] == ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
            legacy = {"sources": {
                "runtime_advisory:owner/repo GHSA-aaaa-bbbb-cccc": {"status": "failed", "consecutive": 2, "first_failed_at": "first", "last_reason": "one"},
                "runtime_advisory:owner/repo GHSA-dddd-eeee-ffff": {"status": "failed", "consecutive": 1, "first_failed_at": "later", "last_reason": "two"},
            }}
            ledger, grouped = evaluate(advisory_rows, legacy, lookup, "now")
            assert list(ledger["sources"]) == ["runtime_advisory:owner/repo"]
            assert grouped[0]["consecutive"] == 3 and ledger["sources"][grouped[0]["key"]]["first_failed_at"] == "first"
            assert source_key("gh_advisory", "pip:example 1.0") == source_key("gh_advisory", "pip:example 2.0")
            assert source_key("winget", "one") != source_key("winget", "two")
            atomic_json(findings, {"unverified": []})
            completed = subprocess.run(command, capture_output=True, encoding="utf-8", check=False)
            assert completed.returncode == 10, completed.stderr
            assert any(row["cause"] == "discover_query_path" for row in json.loads(completed.stdout))
            assert "経路の点検: 失敗 1 件" in completed.stderr
            atomic_json(run_dir / "discover.json", {"items": [], "errors": []})
            assert next(row for row in collect_observations(run_dir, findings) if row["key"] == "x_discover")["status"] == "failed"
            (run_dir / "discover.out").write_text("exit code: 0\n", encoding="utf-8", newline="\n")
            assert next(row for row in collect_observations(run_dir, findings) if row["key"] == "x_discover")["status"] == "ok"
            atomic_json(run_dir / "discover.json", {"status": "failed", "errors": ["fixture"]})
            assert next(row for row in collect_observations(run_dir, findings) if row["key"] == "x_discover")["status"] == "failed"
            cli_state = (root / "cli-state.json").read_bytes()
            findings.write_text("broken JSON\n", encoding="utf-8", newline="\n")
            completed = subprocess.run(command, capture_output=True, encoding="utf-8", check=False)
            assert completed.returncode == 2 and completed.stdout == ""
            assert (root / "cli-state.json").read_bytes() == cli_state

            previous = state.read_bytes()
            with patch(__name__ + ".os.replace", side_effect=OSError("fixture: replace failed")):
                try:
                    atomic_json(state, {"sources": {}})
                except OSError:
                    pass
                else:
                    raise AssertionError("replace failure was hidden")
            assert state.read_bytes() == previous and not list(root.glob("*.tmp"))
            with patch(__name__ + ".os.fsync", side_effect=OSError("fixture: write failed")):
                try:
                    atomic_json(state, {"sources": {}})
                except OSError:
                    pass
                else:
                    raise AssertionError("write failure was hidden")
            assert state.read_bytes() == previous and not list(root.glob("*.tmp"))
            try:
                atomic_json(state, {"invalid": object()})
            except TypeError:
                pass
            else:
                raise AssertionError("serialization failure was hidden")
            assert state.read_bytes() == previous
    print("自己テスト成功: 原因分類・連続失敗・成功時リセット・原子的保存を確認しました。")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", help="X-watch run folder; default: latest out/xwatch/YYYYMMDD-HHMM")
    parser.add_argument("--findings", default="out/findings.json")
    parser.add_argument("--state", default="state/source-health.json")
    parser.add_argument("--output", default="out/source-health.json")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.selftest:
            return selftest()
        if args.run_dir:
            run_dir = resolve_path(args.run_dir)
        else:
            candidates = sorted(path for path in (HERE / "out" / "xwatch").glob("*")
                                if path.is_dir() and re.fullmatch(r"\d{8}-\d{4}", path.name))
            if not candidates:
                raise ValueError("out/xwatch に実行フォルダーが無い")
            run_dir = candidates[-1].resolve()
        results, code = run_health(run_dir, resolve_path(args.findings), resolve_path(args.state), resolve_path(args.output))
        print(json.dumps(results, ensure_ascii=False, indent=2, allow_nan=False))
        print(summary(results), file=sys.stderr)
        return code
    except Exception as error:
        print(f"経路の点検を実行できません: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    for standard_stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(standard_stream, "reconfigure"):
            standard_stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
