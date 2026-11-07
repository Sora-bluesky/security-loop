"""Deterministic seen-check for the X watch (x-watch.jsonl vs state/x-seen.txt).

Usage:
  py -3.14 -I xseen.py [--state-dir DIR] classify <x-watch.jsonl>
  py -3.14 -I xseen.py [--state-dir DIR] mark <x-watch.jsonl>
  py -3.14 -I xseen.py [--state-dir DIR] normalize

Key forms (one per line in x-seen.txt):
  id:<ID upper>   name:<normalized name>   url:<normalized url>
"""
import argparse
import datetime
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
DEFAULT_STATE = HERE / "state"
SEEN_FILE = "x-seen.txt"
ALIAS_FILE = "x-aliases.txt"
ALIAS_INITIAL = "node2shell=http2shell\n"

# ASCII alnum + hiragana + katakana (incl. prolonged sound mark) + CJK ideographs
_KEEP = re.compile(r"[^0-9a-z぀-ゟ゠-ヿ㐀-䶿一-鿿豈-﫿]")
_X_HOSTS = {"x.com", "www.x.com", "mobile.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"}


def norm_name(s):
    s = unicodedata.normalize("NFKC", str(s)).lower()
    return _KEEP.sub("", s)


def norm_id(s):
    return str(s).strip().upper()


def norm_url(s):
    u = str(s).strip()
    u = u.split("#", 1)[0].split("?", 1)[0]
    m = re.match(r"^(https?://)([^/]+)(.*)$", u, re.IGNORECASE)
    if m:
        scheme, host, path = m.group(1).lower(), m.group(2).lower(), m.group(3)
        if host in _X_HOSTS:
            scheme, host = "https://", "x.com"
        u = scheme + host + path
    return u.rstrip("/")


def load_aliases(state_dir):
    p = state_dir / ALIAS_FILE
    if not p.exists():
        p.write_bytes(ALIAS_INITIAL.encode("utf-8"))
    table = {}
    for raw in p.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        a, b = line.split("=", 1)
        a, b = norm_name(a), norm_name(b)
        if a and b:
            table[a] = b
    return table


def name_key(name, aliases):
    n = norm_name(name)
    n = aliases.get(n, n)
    return "name:" + n if n else None


def normalize_line(line, aliases):
    """Map one x-seen.txt line (old or new format) to a list of keys. None = unrecognized."""
    s = line.strip().lstrip("﻿")
    if not s:
        return []
    low = s.lower()
    if low.startswith("http://") or low.startswith("https://"):
        u = norm_url(s)
        return ["url:" + u] if u else []
    if low.startswith("ids:"):
        return ["id:" + norm_id(x) for x in s[4:].split(",") if x.strip()]
    if low.startswith("id:"):
        v = norm_id(s[3:])
        return ["id:" + v] if v else []
    if low.startswith("name:"):
        k = name_key(s[5:], aliases)
        return [k] if k else []
    if low.startswith("url:"):
        u = norm_url(s[4:])
        return ["url:" + u] if u else []
    return None


def topic_keys(t, aliases):
    keys = []
    ids = t.get("ids") or []
    if isinstance(ids, str):
        ids = ids.split(",")
    for i in ids:
        v = norm_id(i)
        if v:
            keys.append("id:" + v)
    if t.get("name"):
        k = name_key(t["name"], aliases)
        if k:
            keys.append(k)
    aliases_field = t.get("aliases")
    if isinstance(aliases_field, list):
        for a in aliases_field:
            if isinstance(a, str):
                k = name_key(a, aliases)
                if k:
                    keys.append(k)
    if t.get("url"):
        u = norm_url(t["url"])
        if u:
            keys.append("url:" + u)
    out = []
    for k in keys:
        if k not in out:
            out.append(k)
    return out


def read_seen(state_dir, aliases):
    p = state_dir / SEEN_FILE
    if not p.exists():
        return [], []
    raw = p.read_text(encoding="utf-8-sig").splitlines()
    keys, unknown = [], []
    for line in raw:
        ks = normalize_line(line, aliases)
        if ks is None:
            unknown.append(line.strip())
            continue
        for k in ks:
            keys.append(k)
    return keys, unknown


def parse_watch(path):
    """Yield ("topic", dict) / ("error", msg) / ("warning", msg) / ("none", None)."""
    text = Path(path).read_text(encoding="utf-8-sig")
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            # Grok sometimes glues a preamble onto the first JSON line.
            pos = line.find('{"')
            if pos < 0:
                continue  # pure preamble line
            yield "warning", f"line {n}: stripped {pos} chars of preamble before JSON"
            line = line[pos:]
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            yield "error", f"line {n}: invalid JSON ({e.msg} at col {e.colno}): {line[:120]}"
            continue
        if not isinstance(obj, dict):
            yield "error", f"line {n}: JSON is not an object: {line[:120]}"
            continue
        if obj.get("none") is True:
            yield "none", None
            continue
        yield "topic", obj


def classify(path, state_dir):
    aliases = load_aliases(state_dir)
    seen_list, _ = read_seen(state_dir, aliases)
    seen = set(seen_list)
    rows = []
    summary = {"topics": 0, "new": 0, "seen": 0, "new_ids": 0}
    for kind, val in parse_watch(path):
        if kind == "topic":
            keys = topic_keys(val, aliases)
            status = "seen" if any(k in seen for k in keys) else "new"
            new_ids = [k[3:] for k in keys if k.startswith("id:") and k not in seen]
            row = dict(val)
            row.update({"status": status, "new_ids": new_ids, "keys": keys})
            summary["topics"] += 1
            summary[status] += 1
            summary["new_ids"] += len(new_ids)
            rows.append(("topic", row))
        elif kind in ("error", "warning"):
            rows.append((kind, {kind: val}))
    return rows, summary, seen_list


def emit(rows, summary):
    for _, row in rows:
        print(json.dumps(row, ensure_ascii=False))
    print(json.dumps({"summary": summary}, ensure_ascii=False))


def cmd_classify(args):
    rows, summary, _ = classify(args.file, args.state_dir)
    emit(rows, summary)


def cmd_mark(args):
    rows, summary, seen_list = classify(args.file, args.state_dir)
    seen = set(seen_list)
    add = []
    for kind, row in rows:
        if kind != "topic":
            continue
        for k in row["keys"]:
            if k not in seen:
                seen.add(k)
                add.append(k)
    p = args.state_dir / SEEN_FILE
    if add:
        prefix = b""
        if p.exists():
            data = p.read_bytes()
            if data and not data.endswith(b"\n"):
                prefix = b"\n"
        with open(p, "ab") as f:
            f.write(prefix + ("\n".join(add) + "\n").encode("utf-8"))
    emit(rows, summary)
    print(json.dumps({"marked": len(add), "keys": add}, ensure_ascii=False))


def cmd_normalize(args):
    state_dir = args.state_dir
    p = state_dir / SEEN_FILE
    if not p.exists():
        print(json.dumps({"error": f"{p} not found"}, ensure_ascii=False))
        return 1
    aliases = load_aliases(state_dir)
    raw_bytes = p.read_bytes()
    lines = raw_bytes.decode("utf-8-sig").splitlines()
    out, changed, unknown = [], [], []
    for line in lines:
        ks = normalize_line(line, aliases)
        if ks is None:
            ks = [line.strip()]
            unknown.append(line.strip())
        if [line.strip()] != ks and line.strip():
            changed.append({"from": line.strip(), "to": ks})
        for k in ks:
            if k not in out:
                out.append(k)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = state_dir / f"{SEEN_FILE}.bak-{stamp}"
    bak.write_bytes(raw_bytes)
    tmp = state_dir / f"{SEEN_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + ("\n" if out else ""))
    os.replace(tmp, p)
    print(json.dumps({"before": len(lines), "after": len(out), "changed": len(changed),
                      "unknown": unknown, "backup": str(bak)}, ensure_ascii=False))
    for c in changed:
        print(json.dumps(c, ensure_ascii=False))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("classify", "mark"):
        sp = sub.add_parser(name)
        sp.add_argument("file")
    sub.add_parser("normalize")
    args = ap.parse_args()
    args.state_dir = args.state_dir.resolve()
    args.state_dir.mkdir(parents=True, exist_ok=True)
    fn = {"classify": cmd_classify, "mark": cmd_mark, "normalize": cmd_normalize}[args.cmd]
    return fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
