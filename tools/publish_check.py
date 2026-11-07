"""Local publication gate. No command contacts a remote; publish only updates public.

Development commits are checked for private content and identities. Publication
uses an independent snapshot history, checked again by the URL-aware push hook.
"""
from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PUBLIC_REF = "refs/heads/public"
PUBLIC_TIP = "refs/remotes/origin/main"
SNAPSHOT_MESSAGE = b"Publish snapshot\n"
OBJECT_ID = rb"(?:[0-9a-f]{40}|[0-9a-f]{64})"
SNAPSHOT_HEADERS = re.compile(
    rb"tree " + OBJECT_ID + rb"\n(?:parent " + OBJECT_ID
    + rb"\n)?author [^\n]+\ncommitter [^\n]+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
USER_PATH = re.compile(r"C:[\\/]+Users[\\/]+", re.IGNORECASE)
SAFE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10"))
INTERNAL_DIRS = {"docs", ".local", "state", "out", "fixtures-health"}
INTERNAL_FILES = {"agents.md", "handoff.md", "runbook.md", "ledger.md", "local-config.json"}


class CheckError(Exception):
    pass


def git(*args, data=None, env=None):
    settings = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    if env:
        settings.update(env)
    result = subprocess.run(["git", *args], input=data, capture_output=True, env=settings)
    if result.returncode:
        # Git errors can quote private data. Report the operation, not raw stderr.
        raise CheckError(f"git {args[0]} failed (exit {result.returncode})")
    return result.stdout


def exists(ref):
    result = subprocess.run(["git", "--no-replace-objects", "rev-parse", "--verify", "--quiet", ref],
                            capture_output=True)
    return result.returncode == 0


def complete_history():
    if git("rev-parse", "--is-shallow-repository").strip() != b"false":
        raise CheckError("shallow history cannot prove dev-history isolation")
    grafts = Path(os.fsdecode(git("rev-parse", "--git-path", "info/grafts").strip()))
    if grafts.exists() and grafts.stat().st_size:
        raise CheckError("grafts cannot prove dev-history isolation")


def glob_match(pattern, path):
    """Segment globs; ** matches zero or more complete segments."""
    pat, parts = pattern.split("/"), path.split("/")

    def match(i, j):
        if i == len(pat):
            return j == len(parts)
        if pat[i] == "**":
            return any(match(i + 1, k) for k in range(j, len(parts) + 1))
        return j < len(parts) and fnmatch.fnmatchcase(parts[j], pat[i]) and match(i + 1, j + 1)

    return match(0, 0)


def read_lines(path):
    return Path(path).read_text(encoding="utf-8-sig").splitlines()


def read_markers(path, optional=False):
    try:
        lines = read_lines(path)
    except FileNotFoundError:
        if optional:
            return []
        raise
    markers = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        source = line[3:] if line.startswith("re:") else re.escape(line)
        if not source:
            raise CheckError("empty marker expression")
        markers.append(re.compile(source, re.IGNORECASE))
    return markers


class Policy:
    def __init__(self, guard, markers, allowlist,
                 public_markers=".local/publish-markers-public.txt"):
        data = json.loads(Path(guard).read_text(encoding="utf-8-sig"))
        keys = ("dev_urls", "public_urls", "internal_paths", "allowed_identities", "local_only_refs")
        if not isinstance(data, dict):
            raise CheckError("guard must be an object")
        for key in keys:
            value = data.get(key)
            if not isinstance(value, list) or any(not isinstance(v, str) or not v.strip() for v in value):
                raise CheckError(f"guard requires a string list: {key}")
        if any(not data[k] for k in ("dev_urls", "public_urls", "allowed_identities")):
            raise CheckError("guard URLs and allowed_identities must not be empty")
        if set(data["dev_urls"]) & set(data["public_urls"]):
            raise CheckError("dev and public URLs overlap")
        if any(not re.fullmatch(r"[^<>\r\n]+ <[^<>\s]+@[^<>\s]+>", v)
               for v in data["allowed_identities"]):
            raise CheckError("allowed_identities requires full Name <email> identities")
        if any(not v.startswith("refs/") or any(c.isspace() for c in v)
               for v in data["local_only_refs"]):
            raise CheckError("local_only_refs requires full ref names or globs")
        self.guard = data
        # An existing empty file explicitly requests only the built-in rules.
        # The common markers remain required for development and public checks.
        self.markers = read_markers(markers)
        # Load only during a public check, so this optional policy cannot block dev.
        self.public_markers_path = public_markers
        self.public_markers = None
        self.allowlist = [v.strip() for v in read_lines(allowlist)
                          if v.strip() and not v.lstrip().startswith("#")]
        if not self.allowlist:
            raise CheckError("allowlist is empty")
        self.username = os.environ.get("USERNAME") or os.environ.get("USER")
        if not self.username:
            raise CheckError("cannot determine machine user name")

    def destination(self, url):
        # Deliberately exact: aliases, pushurl and remote names grant no authority.
        for kind in ("dev", "public"):
            if url in self.guard[kind + "_urls"]:
                return kind
        raise CheckError("unknown URL: push rejected (fail closed)")

    def path_reason(self, path):
        parts = path.casefold().split("/")
        if (any(p in INTERNAL_DIRS or p == ".git" for p in parts)
                or any(p in INTERNAL_FILES or fnmatch.fnmatchcase(p, "*.bak-*") for p in parts)
                or any(p.startswith("x-watch-") for p in parts)
                or any(glob_match(p.casefold().rstrip("/") + ("/**" if p.endswith("/") else ""),
                                  path.casefold()) for p in self.guard["internal_paths"])):
            return "internal path"
        if ("\\" in path or ":" in path or any(ord(c) < 32 for c in path)
                or any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts)):
            return "non-canonical path"
        if not any(glob_match(p, path) for p in self.allowlist):
            return "not in allowlist"
        return None

    def reasons(self, text, strict=False):
        found = set()
        if self.username.casefold() in text.casefold():
            found.add("machine user name")
        if USER_PATH.search(text):
            found.add("Windows user-folder absolute path")
        for index, marker in enumerate(self.markers, 1):
            if marker.search(text):
                found.add(f"private marker #{index}")
        if strict:
            if self.public_markers is None:
                self.public_markers = read_markers(self.public_markers_path, optional=True)
            for index, marker in enumerate(self.public_markers, 1):
                if marker.search(text):
                    found.add(f"public-only marker #{index}")
        for line in text.splitlines():
            for match in IPV4.finditer(line):
                try:
                    address = ipaddress.IPv4Address(match.group())
                except ValueError:
                    continue
                if int(address) == 0 or any(address in net for net in SAFE_NETS):
                    continue
                prefix = line[:match.start()]
                if (re.search(r"(?:==\s*|@\s*)$" if strict else r"(?:\bv|==\s*|@\s*)$", prefix)
                        or re.search(r'''["']version["']\s*:\s*["'][^"']*$''', prefix, re.IGNORECASE)):
                    continue
                found.add("IPv4 outside permitted ranges")
        return sorted(found)

    def blob_reasons(self, raw, strict=False):
        views = [raw.decode("utf-8", "replace")]
        for encoding in ("utf-16-le", "utf-16-be"):
            for offset in (0, 1):
                part = raw[offset:]
                views.append(part[:len(part) // 2 * 2].decode(encoding, "replace"))
        return sorted({reason for view in views for reason in self.reasons(view, strict=strict)})

    def identity(self, text):
        match = re.fullmatch(r"(.+ <[^<>]+>) [0-9]+ [+-][0-9]{4}\n?", text)
        allowed = match and match[1] in self.guard["allowed_identities"]
        return ([] if allowed else ["disallowed identity"]) + self.reasons(text)


def entries(tree=None):
    raw = git("ls-tree", "-r", "-z", "--full-tree", tree) if tree else git("ls-files", "--stage", "-z")
    result = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        a, b, c = meta.decode("ascii").split()
        if tree:
            mode, sha = a, c
        else:
            mode, sha = a, b
            if c != "0":
                raise CheckError("unmerged index")
        result.append((mode, sha, name.decode("utf-8", "strict")))
    return result


class Checker:
    def __init__(self, policy):
        self.policy = policy
        self.errors = []
        self.blobs = set()

    def add(self, label, reasons):
        for reason in reasons:
            # Never print matched text, identities, URLs or file names (a file
            # name itself can contain a marker). Object IDs locate the problem.
            self.errors.append(f"{label}: {reason}")

    def tree(self, items, public=False):
        for mode, sha, path in items:
            label = f"blob {sha[:12]}"
            self.add(label + " path", self.policy.reasons(path, strict=public))
            if public:
                reason = self.policy.path_reason(path)
                self.add(label + " path", [reason] if reason else [])
            if public and mode not in ("100644", "100755"):
                self.add(label, ["unsupported mode (symlinks/submodules are rejected)"])
                continue
            if mode == "160000":
                continue  # development gitlinks have no blob in this repository
            if (sha, public) not in self.blobs:
                self.blobs.add((sha, public))
                self.add(label, self.policy.blob_reasons(git("cat-file", "blob", sha), strict=public))

    def idents(self):
        for role in ("AUTHOR", "COMMITTER"):
            self.add("new " + role.lower(), self.policy.identity(git("var", "GIT_" + role + "_IDENT").decode("utf-8")))

    def commits(self, commits, public=False):
        complete_history()
        dev = set()
        if public:
            refs = git("for-each-ref", "--format=%(refname)").decode("utf-8").splitlines()
            refs = [ref for ref in refs if
                    (ref.startswith("refs/heads/") and ref != PUBLIC_REF)
                    or ref.startswith("refs/remotes/dev/")
                    or any(fnmatch.fnmatchcase(ref, pat) for pat in self.policy.guard["local_only_refs"])]
            if refs:
                dev = set(git("rev-list", *refs, "--").decode("ascii").splitlines())
        for sha in commits:
            label = "commit " + sha[:12]
            if sha in dev:
                self.add(label, ["dev-history rule: reachable from a dev/local-only ref"])
            raw = git("cat-file", "commit", sha)
            self.add(label + " object", self.policy.blob_reasons(raw, strict=public))
            header, separator, message = raw.partition(b"\n\n")
            if not separator:
                raise CheckError("malformed commit")
            if public and (not SNAPSHOT_HEADERS.fullmatch(header) or message != SNAPSHOT_MESSAGE):
                self.add(label, ["snapshot shape: requires canonical headers and fixed message"])
            for role in (b"author", b"committer"):
                values = [line[len(role) + 1:] for line in header.splitlines() if line.startswith(role + b" ")]
                if len(values) != 1:
                    raise CheckError("malformed commit identity")
                self.add(label + " " + role.decode(), self.policy.identity(values[0].decode("utf-8")))
            self.tree(entries(sha), public)

    def finish(self):
        for line in self.errors:
            print(line)
        print(f"publish_check: {len(self.errors)} violation(s); " + ("rejected" if self.errors else "PASS"))
        return 1 if self.errors else 0


def range_args(policy, old, new, url, remote_ref):
    kind = policy.destination(url)
    reasons = policy.reasons(remote_ref, strict=kind == "public")
    if reasons:
        raise CheckError("remote ref: " + "; ".join(reasons))
    if kind == "public" and not (remote_ref == "refs/heads/main"
                                  or fnmatch.fnmatchcase(remote_ref, "refs/tags/v*")):
        raise CheckError("public ref name: only main and version tags are permitted")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", old) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", new):
        raise CheckError("range requires object IDs")
    if set(new) == {"0"}:
        if kind == "public":
            raise CheckError("public ref deletion is rejected")
        return [], kind
    if git("cat-file", "-t", new).strip() != b"commit":
        raise CheckError("push only direct commits; annotated tags and other objects are rejected")
    # Public checks traverse the entire ancestry, including an allegedly already
    # published old tip. No remote-tracking exclusion may hide development data.
    args = [new]
    if kind == "dev" and set(old) != {"0"} and exists(old + "^{commit}"):
        args.extend(["--not", old])
    return args, kind


def gitleaks(commit):
    executable = shutil.which("gitleaks")
    if not executable:
        raise CheckError("gitleaks missing; rejected (fail closed)")
    result = subprocess.run([executable, "git", "--log-opts=" + commit, "--no-banner", "--redact", "."],
                            env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1"),
                            capture_output=True)
    if result.returncode:
        raise CheckError("gitleaks rejected snapshot (redacted output suppressed)")


def publish(policy, source):
    complete_history()
    source = git("rev-parse", "--verify", "--end-of-options", source + "^{commit}").strip().decode("ascii")
    parent = git("rev-parse", "--verify", PUBLIC_TIP + "^{commit}").strip().decode("ascii") if exists(PUBLIC_TIP) else None
    old = git("rev-parse", "--verify", PUBLIC_REF).strip().decode("ascii") if exists(PUBLIC_REF) else "0" * len(source)
    if old.strip("0") and old != parent:
        raise CheckError("public contains an unpublished snapshot or a stale tip; inspect it before replacing")
    check = Checker(policy)
    check.idents()
    selected = [item for item in entries(source) if policy.path_reason(item[2]) is None]
    if not selected:
        raise CheckError("snapshot would be empty")
    check.tree(selected, public=True)
    if parent:
        check.commits(git("rev-list", parent, "--").decode("ascii").splitlines(), public=True)
    if check.finish():
        return 1
    # The real index and worktree are untouched. update-index uses raw object
    # IDs, so checkout filters and line-ending conversion cannot alter bytes.
    with tempfile.TemporaryDirectory(prefix="publish-index-") as temporary:
        env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
        git("read-tree", "--empty", env=env)
        records = b"".join(f"{mode} {sha}\t{path}".encode("utf-8") + b"\0" for mode, sha, path in selected)
        git("update-index", "-z", "--index-info", data=records, env=env)
        tree = git("write-tree", env=env).strip().decode("ascii")
    args = ["commit-tree", tree]
    if parent:
        args.extend(["-p", parent])
    commit = git(*args, data=SNAPSHOT_MESSAGE).strip().decode("ascii")
    check = Checker(policy)
    check.commits(git("rev-list", commit, "--").decode("ascii").splitlines(), public=True)
    if check.finish():
        return 1
    gitleaks(commit)
    git("update-ref", PUBLIC_REF, commit, old)
    print(f"publish: {PUBLIC_REF} = {commit}; {len(selected)} files; no push")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("guard", "markers", "allowlist", "public-markers"):
        parser.add_argument("--" + key)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("staged", "all", "selftest"):
        sub.add_parser(name)
    sub.add_parser("message").add_argument("file")
    pub = sub.add_parser("publish")
    pub.add_argument("source", nargs="?", default="HEAD")
    sub.add_parser("destination").add_argument("--url", required=True)
    for name in ("range", "revs"):
        command = sub.add_parser(name)
        command.add_argument("--remote")  # accepted for the reference hook interface
        command.add_argument("--url", required=True)
        command.add_argument("--remote-ref", required=True)
        command.add_argument("old")
        command.add_argument("new")
    args = parser.parse_args(argv)
    try:
        if args.mode == "selftest":
            # -I excludes the script's directory from sys.path.
            import runpy
            scope = runpy.run_path(str(Path(__file__).with_name("publish_selftest.py")))
            return scope["selftest"]()
        overrides = {key: os.path.abspath(getattr(args, key)) if getattr(args, key) else None
                     for key in ("guard", "markers", "allowlist", "public_markers")}
        message = Path(args.file).absolute() if args.mode == "message" else None
        os.chdir(os.fsdecode(git("rev-parse", "--show-toplevel").strip()))
        policy = Policy(overrides["guard"] or ".local/publish-guard.json",
                        overrides["markers"] or ".local/publish-markers.txt",
                        overrides["allowlist"] or "tools/publish-allowlist.txt",
                        overrides["public_markers"] or ".local/publish-markers-public.txt")
        check = Checker(policy)
        if args.mode == "destination":
            policy.destination(args.url)
            return 0
        if args.mode == "publish":
            return publish(policy, args.source)
        if args.mode in ("range", "revs"):
            complete_history()
            revisions, kind = range_args(policy, args.old, args.new, args.url, args.remote_ref)
            if args.mode == "revs":
                print(" ".join(revisions))
                return 0
            commits = git("rev-list", *revisions, "--").decode("ascii").splitlines() if revisions else []
            check.commits(commits, public=kind == "public")
        elif args.mode == "staged":
            check.tree(entries())
            check.idents()
        elif args.mode == "message":
            check.add("commit message", policy.blob_reasons(message.read_bytes()))
        elif args.mode == "all":
            check.commits(git("rev-list", "--all", "--").decode("ascii").splitlines())
        return check.finish()
    except (CheckError, OSError, ValueError, UnicodeError, re.error) as exc:
        # Do not interpolate exceptions that could contain secrets or identities.
        detail = str(exc) if isinstance(exc, CheckError) else type(exc).__name__ + " reading policy/data"
        print("publish_check: " + detail + "; rejected (fail closed)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
    raise SystemExit(main())
