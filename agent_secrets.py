"""Offline scanner for literal credentials in agent settings; never emits values."""
from __future__ import annotations

import argparse
import contextlib
import errno
import fnmatch
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__"}
MAX_DEPTH = 5
HISTORY_LIMIT = 200
NAME = r"(?:PGPASSWORD|MYSQL_PWD|PASSWORD|TOKEN|API_KEY|[A-Z_][A-Z0-9_]*_(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PAT))"
VALUE = r'''(?:"(?P<double>[^"\r\n]*)"|'(?P<single>[^'\r\n]*)'|(?P<bare>(?:\$\{[^}]*\}|[^\s"',;&|)}\]])+))'''
ASSIGN = re.compile(r"(?<![\w-])(?P<name>" + NAME + r")\s*=\s*" + VALUE, re.I)
JSON_PAIR = re.compile(r'"(?P<name>' + NAME + r')"\s*:\s*"(?P<value>(?:\\.|[^"\\])*)"', re.I)
OPTIONS = [
    ("cli:sshpass", r"\bsshpass\s+-p\s*"),
    ("cli:password", r"(?<![\w-])--password(?:=|\s+)"),
    ("cli:token", r"(?<![\w-])--token(?:=|\s+)"),
    ("cli:api-key", r"(?<![\w-])--api-key(?:=|\s+)"),
    ("cli:oauth2-bearer", r"\bcurl\b[^\r\n;&|]*?(?<!\S)--oauth2-bearer(?:=|\s+)"),
    ("cli:redis-pass", r"\bredis-cli\b[^\r\n;&|]*?(?<!\S)(?:-a|--pass)(?:=|\s+)"),
    ("header:bearer", r'''\bAuthorization["']?\s*:\s*["']?Bearer\s+'''),
    ("header:basic", r'''\bAuthorization["']?\s*:\s*["']?Basic\s+'''),
    ("header:token", r'''\bAuthorization["']?\s*:\s*["']?token\s+'''),
    ("header:x-api-key", r'''\bx-api-key["']?\s*:\s*'''),
    ("header:api-key", r'''(?<![\w-])api-key["']?\s*:\s*'''),
]
OPTIONS = [(kind, re.compile(prefix + VALUE, re.I)) for kind, prefix in OPTIONS]
MYSQL = re.compile(r"\bmysql\b[^\r\n;&|]*?(?<!\S)-p(?!\s|$)" + VALUE, re.I)
CURL = re.compile(r"\bcurl\b[^\r\n;&|]*?(?<!\S)(?:-u(?:\s+|=)?|--user(?:\s+|=))" + VALUE, re.I)
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://(?P<user>[^\s/:@]+):(?P<value>[^\s/@]+)@", re.I)
SHAPES = [
    ("ghp", r"(?<![\w])ghp_[A-Za-z0-9]{36}(?![\w])"),
    ("gho", r"(?<![\w])gho_[A-Za-z0-9]{36}(?![\w])"),
    ("ghs", r"(?<![\w])ghs_[A-Za-z0-9]{36}(?![\w])"),
    ("github-pat", r"github_pat_[A-Za-z0-9_]+"),
    ("gitlab", r"glpat-[A-Za-z0-9_-]+"), ("anthropic", r"sk-ant-[A-Za-z0-9_-]+"),
    ("openai", r"sk-(?!ant-)[A-Za-z0-9_-]{20,}"),
    ("slack", r"xox[bp]-[A-Za-z0-9-]+"), ("aws", r"AKIA[0-9A-Z]{16}(?![0-9A-Z])"),
    ("google", r"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    ("private-key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
]
SHAPES = [("shape:" + kind, re.compile(pattern)) for kind, pattern in SHAPES]
PLACEHOLDER_WORDS = {"YOUR", "MY", "EXAMPLE", "PLACEHOLDER", "CHANGEME", "REDACTED",
                     "TOKEN", "KEY", "SECRET", "PASSWORD", "API", "HERE", "VALUE", "XXX"}
ANGLE_SPAN = r"<[^<>]{0,200}>"


def protected_spans(text):
    return [m.span() for m in re.finditer(ANGLE_SPAN + r'''|op://[^\s"'<>\\]+''', text, re.I)]


def inside_span(spans, position):
    return any(start <= position < end for start, end in spans)


def literal(value, generic=False):
    """Decide once for every contextual detector."""
    value = value.strip()
    if not value or (generic and len(value) < 6):
        return False
    if re.fullmatch(r"(?:\$[A-Za-z_]\w*|\$\{[^}]+\}|%[^%]+%|\$env:[A-Za-z_]\w*)", value, re.I):
        return False
    if value.lower().startswith("op://"):
        return False
    if re.fullmatch(ANGLE_SPAN + r"|[xX*.]+", value):
        return False
    if all(part.upper() in PLACEHOLDER_WORDS for part in re.split(r"[_ -]+", value)):
        return False
    return True


def matched_token(match):
    return next((match.group(key), match.start(key)) for key in ("double", "single", "bare")
                if match.group(key) is not None)


def name_kind(name):
    name = name.upper()
    if name in {"PGPASSWORD", "MYSQL_PWD", "PASSWORD", "TOKEN", "API_KEY"}:
        return name
    # Only the recognized suffix is exposed, never arbitrary source identifiers.
    return "*_" + name.rsplit("_", 1)[-1]


def detect(text, key=None):
    hits = []
    protected = protected_spans(text)
    for kind, pattern in SHAPES:
        hits.extend((kind, len(m.group())) for m in pattern.finditer(text)
                    if not inside_span(protected, m.start()))
    # Settings strings can contain JSON escaped once or repeatedly by shell quoting.
    normalized = re.sub(r'\\+"', '"', text)
    protected = protected_spans(normalized)
    for match in ASSIGN.finditer(normalized):
        value, start = matched_token(match)
        if not inside_span(protected, start) and literal(value, generic=True):
            hits.append(("assign:" + name_kind(match["name"]), len(value)))
    for match in JSON_PAIR.finditer(normalized):
        if inside_span(protected, match.start("value")):
            continue
        try:
            value = json.loads('"' + match["value"] + '"')
        except ValueError:
            value = match["value"]
        if literal(value, generic=True):
            prefix = "escaped-json:" if normalized != text else "json:"
            hits.append((prefix + name_kind(match["name"]), len(value)))
    for kind, pattern in OPTIONS + [("cli:mysql", MYSQL)]:
        for match in pattern.finditer(normalized):
            value, start = matched_token(match)
            if not inside_span(protected, start) and literal(value):
                hits.append((kind, len(value)))
    for match in CURL.finditer(normalized):
        value, start = matched_token(match)
        if ":" in value:
            credential = value.split(":", 1)[1]
            if not inside_span(protected, start + value.index(":") + 1) and literal(credential):
                hits.append(("cli:curl-user", len(credential)))
    for match in URL.finditer(normalized):
        if not inside_span(protected, match.start("value")) and literal(match["value"]):
            hits.append(("url:credentials", len(match["value"])))
    if key is not None:
        protected = protected_spans(text)
        starts_protected = inside_span(protected, len(text) - len(text.lstrip()))
        if re.fullmatch(NAME, key, re.I) and not starts_protected and literal(text, generic=True):
            hits.append(("assign:" + name_kind(key), len(text)))
        if key.lower() == "authorization":
            match = re.fullmatch(r"(Bearer|Basic|token)\s+(.+)", text, re.I)
            if match and not inside_span(protected, match.start(2)) and literal(match[2]):
                hits.append(("header:" + match[1].lower(), len(match[2])))
        if key.lower() in {"x-api-key", "api-key"} and not starts_protected and literal(text):
            hits.append(("header:" + key.lower(), len(text)))
    return hits


SCHEMA_KEYS = {"permissions", "allow", "ask", "deny", "env", "mcpServers",
               "args", "headers", "url", "command"}


def children(value, location):
    """Only fixed schema names enter output; user-controlled maps use indices."""
    indexed = location.rsplit(".", 1)[-1] in {"env", "headers", "mcpServers"}
    for index, (key, child) in enumerate(value.items()):
        suffix = "." + key if not indexed and key in SCHEMA_KEYS else f"[{index}]"
        yield key, child, location + suffix


def strings(value, location, key=None):
    if isinstance(value, str):
        yield location, key, value
    elif isinstance(value, dict):
        for child_key, child, child_location in children(value, location):
            yield from strings(child, child_location, child_key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from strings(child, f"{location}[{index}]", key)


def entries(data, mcp):
    if not isinstance(data, dict):
        return
    if mcp:
        yield from strings(data.get("mcpServers", {}), "mcpServers")
        return
    permissions = data.get("permissions", {})
    if isinstance(permissions, dict):
        for category in ("allow", "ask", "deny"):
            values = permissions.get(category, [])
            if isinstance(values, list):
                for index, value in enumerate(values):
                    if isinstance(value, str):
                        yield f"permissions.{category}[{index}]", None, value
    yield from strings(data.get("env", {}), "env")


def argument_hits(data, location=""):
    """Retain flag/value adjacency in MCP argv arrays without echoing commands."""
    if isinstance(data, dict):
        args = data.get("args")
        command = data.get("command", "")
        if isinstance(args, list):
            executable = re.split(r"[/\\]", command)[-1].lower() if isinstance(command, str) else ""
            executable = executable.removesuffix(".exe")
            for index, value in enumerate(args):
                if not isinstance(value, str):
                    continue
                previous = args[index - 1] if index else None
                prefix = None
                if previous in ("--password", "--token", "--api-key"):
                    prefix = previous + " "
                elif previous == "-p" and executable == "sshpass":
                    prefix = "sshpass -p "
                elif previous in ("-u", "--user") and executable == "curl":
                    prefix = "curl -u "
                elif previous == "--oauth2-bearer" and executable == "curl":
                    prefix = "curl --oauth2-bearer "
                elif previous in ("-a", "--pass") and executable == "redis-cli":
                    prefix = "redis-cli " + previous + " "
                elif executable == "curl" and value.startswith("--user="):
                    prefix, value = "curl --user=", value[len("--user="):]
                elif executable == "curl" and value.startswith("--oauth2-bearer="):
                    prefix, value = "curl --oauth2-bearer=", value[len("--oauth2-bearer="):]
                elif executable == "curl" and value.startswith("-u") and len(value) > 2:
                    prefix, value = "curl -u ", value[2:]
                elif executable == "mysql" and value.startswith("-p") and len(value) > 2:
                    prefix, value = "mysql -p", value[2:]
                if prefix is not None:
                    # The detector's quoted token accepts spaces in a single argv value.
                    quoted = "'" + value + "'" if '"' in value else '"' + value + '"'
                    for kind, length in detect(prefix + quoted):
                        if kind.startswith("cli:"):
                            yield f"{location}.args[{index}]", kind, length
        for _key, child, child_location in children(data, location):
            yield from argument_hits(child, child_location)
    elif isinstance(data, list):
        for index, child in enumerate(data):
            yield from argument_hits(child, f"{location}[{index}]")


class ScanError(Exception):
    """Safe diagnostic metadata only; never include subprocess output or input."""
    def __init__(self, path, step, error=None, exit_code=None, reason=None):
        self.path = Path(path)
        self.reason = reason
        message = step + " failed"
        if reason:
            message += ": " + reason
        if error is not None:
            message += ": " + type(error).__name__
            if isinstance(error, OSError):
                message += f" errno={error.errno}"
        if exit_code is not None:
            message += f" exit={exit_code}"
        super().__init__(message)

    def record(self):
        return {"path": display(self.path), "message": str(self)}


def git(directory, *args, acceptable=(0,), data=None, error_path=None, ceiling=None):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1",
               GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    if ceiling is not None:
        env["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    operation = 0
    while args[operation] == "-c":
        operation += 2
    step = "git " + args[operation]
    target = directory if error_path is None else error_path
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), "--no-pager", "--no-replace-objects",
             "-c", "core.quotePath=false", "-c", "color.ui=false", "--no-optional-locks", *args],
            capture_output=True, env=env, input=data,
        )
    except OSError as error:
        raise ScanError(target, step, error) from None
    if result.returncode not in acceptable:
        # Git stderr and exception messages can contain credentials from input paths.
        reason = None
        if result.returncode == 128:
            diagnostic = result.stderr.lower()
            if b"detected dubious ownership" in diagnostic:
                reason = "dubious ownership"
            elif b"not a git repository" in diagnostic:
                reason = "not a git repository"
        raise ScanError(target, step, exit_code=result.returncode, reason=reason)
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeError as error:
        raise ScanError(target, "decode (" + step + ")", error, result.returncode) from None
    return result.returncode, output


def repository(path, notices=None):
    directory = path if path.is_dir() else path.parent
    while not directory.exists() and directory != directory.parent:
        directory = directory.parent
    marker = (directory / ".git").exists()
    try:
        # An invalid marker must not silently fall through to an ancestor repo.
        _, output = git(directory, "rev-parse", "--show-toplevel", error_path=path,
                        ceiling=directory.parent if marker else None)
    except ScanError as error:
        if error.reason != "not a git repository":
            raise
        if notices is not None and marker:
            notice = "skipped invalid git dir: " + json.dumps(display(directory), ensure_ascii=True)
            if notice not in notices:
                notices.append(notice)
        return None
    return Path(output.strip()).resolve()


def file_flags(path, repo):
    if repo is None:
        return {"tracked": False, "ignored": False}
    relative = path.relative_to(repo).as_posix()
    code, _ = git(repo, "ls-files", "--error-unmatch", "--", ":(literal)" + relative,
                  acceptable=(0, 1), error_path=path)
    ignored_code, _ = git(repo, "check-ignore", "--quiet", "--", relative,
                          acceptable=(0, 1), error_path=path)
    return {"tracked": code == 0, "ignored": ignored_code == 0}


def scan_flags(path, errors, repo=None, notices=None):
    try:
        return file_flags(path, repository(path, notices) if repo is None else repo)
    except ScanError as error:
        errors.append(error.record())
        return {"tracked": None, "ignored": None}


def target_name(path):
    return path.name == ".mcp.json" or (
        path.parent.name == ".claude" and path.name in {"settings.local.json", "settings.json"}
    )


def excluded(path, root, patterns, counts=None):
    matched = False
    for pattern in patterns:
        if (fnmatch.fnmatch(path.name, pattern)
                or fnmatch.fnmatch(path.relative_to(root).as_posix(), pattern)):
            matched = True
            if counts is not None:
                counts[pattern].add(path)
    return matched


def discover(root, errors, repos=None, exclusions=(), counts=None):
    def failed(error):
        errors.append(ScanError(error.filename or root, "listdir", error).record())

    if excluded(root, root, exclusions, counts):
        return
    for directory, dirs, files in os.walk(root, onerror=failed, followlinks=False):
        current = Path(directory)
        depth = len(current.relative_to(root).parts)
        if repos is not None and ".git" in dirs + files:
            repos.add(current)
        children = []
        for name in sorted(dirs):
            if name.lower() in SKIP or depth >= MAX_DEPTH:
                continue
            child = current / name
            if excluded(child, root, exclusions, counts):
                continue
            try:
                if not child.is_symlink() and not child.is_junction():
                    children.append(name)
            except OSError as error:
                errors.append(ScanError(child, "stat directory", error).record())
        dirs[:] = children
        for name in sorted(files):
            path = current / name
            if target_name(path):
                yield path


def display(path):
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(path)


def scan_file(path, label, findings, errors, notices=None):
    flags = scan_flags(path, errors, notices=notices)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as error:
        raise ScanError(path, "read", error) from None
    except UnicodeError as error:
        raise ScanError(path, "decode", error) from None
    for item in scan_text(text, path.name == ".mcp.json"):
        findings.append(dict(path=label, **item, **flags))


def scan_text(text, mcp):
    """One structured scanner for working files and complete historical blobs."""
    try:
        data = json.loads(text)
    except ValueError:
        items = ((f"line {i}", None, line) for i, line in enumerate(text.splitlines(), 1))
        unparsed = True
    else:
        items = entries(data, mcp)
        unparsed = False
    for location, key, value in items:
        for kind, length in detect(value, key):
            yield dict(location=location, kind=kind, length=length, unparsed=unparsed)
    if not unparsed and mcp and isinstance(data, dict):
        for location, kind, length in argument_hits(data.get("mcpServers", {}), "mcpServers"):
            yield dict(location=location, kind=kind, length=length, unparsed=False)


def history_scope(path, roots, files, exclusions=(), exclude_roots=()):
    if path in files:
        return True
    for root in exclude_roots:
        if path.is_relative_to(root):
            for parent in path.parents:
                if not parent.is_relative_to(root):
                    break
                if excluded(parent, root, exclusions):
                    return False
    for root in roots:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if (target_name(path)
                and not any(part.lower() in SKIP for part in relative.parts[:-1])):
            return True
    return False


def scan_history(repo, roots, files, findings, notices, errors, exclusions=(), exclude_roots=()):
    specs = {":(literal)" + p.relative_to(repo).as_posix() for p in files}
    for root in roots:
        relative = root.relative_to(repo).as_posix()
        prefix = "" if relative == "." else relative + "/"
        for suffix in ("**/.mcp.json", "**/.claude/settings.local.json", "**/.claude/settings.json"):
            specs.add(":(glob)" + prefix + suffix)
    if not specs:
        return
    _, output = git(repo, "log", "--all", "--full-history", "--topo-order",
                    f"--max-count={HISTORY_LIMIT + 1}", "--format=%H", "--no-color",
                    "--", *sorted(specs))
    commits = output.splitlines()
    if any(not re.fullmatch(r"[0-9a-f]{40,64}", commit) for commit in commits):
        raise ScanError(repo, "decode (git log)")
    if len(commits) > HISTORY_LIMIT:
        notices.append(f"history truncated at {HISTORY_LIMIT} commits for "
                       + json.dumps(display(repo), ensure_ascii=True))
    remote = {}
    flags = {}
    unique = {}
    # Topological order visits descendants first. Keep both observed endpoints,
    # without retaining credential values or fingerprints in the deduplication key.
    for commit in commits[:HISTORY_LIMIT]:
        try:
            _, output = git(repo, "diff-tree", "--root", "-m", "-r", "--no-commit-id",
                            "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT",
                            "--no-color", commit, "--", *sorted(specs))
        except ScanError as error:
            errors.append(error.record())
            continue
        for name in sorted(set(output.split("\0")) - {""}):
            path = repo / name
            if not history_scope(path, roots, files, exclusions, exclude_roots):
                continue
            try:
                _, text = git(repo, "show", "--no-color", "--no-ext-diff", "--no-textconv",
                              commit + ":" + name, error_path=path)
                hits = list(scan_text(text.lstrip("\ufeff"), path.name == ".mcp.json"))
            except ScanError as error:
                errors.append(error.record())
                continue
            if not hits:
                continue
            if commit not in remote:
                try:
                    _, branches = git(repo, "branch", "--no-color", "-r", "--contains", commit,
                                      error_path=path)
                    remote[commit] = bool(branches.strip())
                except ScanError as error:
                    errors.append(error.record())
                    remote[commit] = None
            if path not in flags:
                flags[path] = scan_flags(path, errors, repo)
            for hit in hits:
                identity = (name, hit["location"], hit["kind"], hit["length"])
                if identity not in unique:
                    unique[identity] = dict(path=display(path), **hit, **flags[path],
                                            commit=commit[:12], remote=remote[commit],
                                            newest_commit=commit[:12], newest_remote=remote[commit])
                    findings.append(unique[identity])
                unique[identity].update(oldest_commit=commit[:12], oldest_remote=remote[commit])


def render(result, as_json):
    if as_json:
        print(json.dumps(result, ensure_ascii=True))
        return
    for item in result["findings"]:
        # JSON quoting prevents terminal control characters in paths/locations.
        path = json.dumps(item["path"], ensure_ascii=True)
        location = json.dumps(item["location"], ensure_ascii=True)
        extra = " unparsed" if item.get("unparsed") else ""
        def flag(name):
            return "unknown" if item[name] is None else str(item[name]).lower()

        if "commit" in item:
            extra += (f" commit={item['commit']} remote={flag('remote')}"
                      f" oldest_commit={item['oldest_commit']} oldest_remote={flag('oldest_remote')}"
                      f" newest_commit={item['newest_commit']} newest_remote={flag('newest_remote')}")
        print(f"{path} {location} {item['kind']} length={item['length']} "
              f"tracked={flag('tracked')} ignored={flag('ignored')}{extra}")
    for error in result["errors"]:
        print("error: " + json.dumps(error, ensure_ascii=True))
    for notice in result.get("notices", []):
        print("notice: " + notice)
    print(f"files_scanned={result['files_scanned']} findings={len(result['findings'])} "
          f"errors={len(result['errors'])}")


def run(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", default=[], metavar="DIR")
    parser.add_argument("--file", action="append", default=[], metavar="PATH")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="skip directories matching a name or root-relative path glob")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.root and not args.file:
        parser.error("at least one --root DIR or --file PATH is required (no default root)")
    result = {"files_scanned": 0, "findings": [], "errors": [], "notices": []}
    targets = {}
    repos = {}
    exclusions = dict.fromkeys(args.exclude)
    excluded_dirs = {pattern: set() for pattern in exclusions}
    exclude_roots = []
    for given in args.root:
        try:
            root = Path(given).resolve()
        except OSError as error:
            result["errors"].append(ScanError(given, "resolve root", error).record())
            continue
        discovered_repos = set() if args.history else None
        exclude_roots.append(root)
        if excluded(root, root, exclusions, excluded_dirs):
            continue
        for path in discover(root, result["errors"], discovered_repos, exclusions, excluded_dirs):
            targets.setdefault(path, display(path))
        if args.history:
            for repo in sorted(discovered_repos):
                try:
                    verified = repository(repo, result["notices"])
                    if verified:
                        repos.setdefault(verified, (set(), set()))[0].add(verified)
                except ScanError as error:
                    result["errors"].append(error.record())
            # Also support a root that is a subdirectory of a repository.
            if not any(error["path"] == display(root) for error in result["errors"]):
                try:
                    repo = repository(root, result["notices"])
                    if repo:
                        repos.setdefault(repo, (set(), set()))[0].add(repo)
                except ScanError as error:
                    result["errors"].append(error.record())
    for given in args.file:
        try:
            path = Path(os.path.abspath(given))
            targets.setdefault(path.parent.resolve() / path.name, given)
        except OSError as error:
            result["errors"].append(ScanError(given, "resolve target directory", error).record())
    for path, label in targets.items():
        try:
            scan_file(path, label, result["findings"], result["errors"], result["notices"])
            result["files_scanned"] += 1
        except ScanError as error:
            result["errors"].append(error.record())
        if args.history:
            try:
                repo = repository(path, result["notices"])
                if repo:
                    repos.setdefault(repo, (set(), set()))[1].add(path)
            except ScanError as error:
                result["errors"].append(error.record())
    for repo, (roots, files) in repos.items():
        try:
            scan_history(repo, roots, files, result["findings"], result["notices"], result["errors"],
                         exclusions, exclude_roots)
        except ScanError as error:
            result["errors"].append(error.record())
    for pattern, directories in excluded_dirs.items():
        result["notices"].append(f"excluded directories: {len(directories)} for pattern "
                                 + json.dumps(pattern, ensure_ascii=True))
    render(result, args.json)
    return 2 if result["errors"] else 10 if result["findings"] else 0


def write_fixture(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def selftest():
    """Synthetic values are assembled only in memory or disposable fixture files."""
    try:
        cases = json.loads((HERE / "fixtures/agent-secrets/cases.json").read_text(encoding="utf-8"))
        values = []
        for index, case in enumerate(cases):
            value = "".join(case["parts"])
            values.append(value)
            text = case["template"].replace("{value}", value)
            kinds = {kind for kind, _length in detect(text, case.get("key"))}
            assert kinds == set(case["kinds"]), f"detector case {index + 1}"
        print(f"detectors: {len(cases)} cases passed")
        with tempfile.TemporaryDirectory(prefix="agent-secrets-test-", dir=HERE) as temporary:
            base = Path(temporary)
            value = "".join(["synthetic", "Mixed", "9876"])
            values.append(value)
            settings = base / ".claude/settings.local.json"
            write_fixture(settings, json.dumps({"permissions": {k: ["PGPASSWORD=" + value]
                          for k in ("allow", "ask", "deny")}, "env": {"NESTED": {"API_KEY": value}}}))
            mcp = base / ".mcp.json"
            write_fixture(mcp, json.dumps({"mcpServers": {"demo": {"headers": {"Authorization": "Bearer " + value},
                          "env": {"API_KEY": value}, "args": ["--token " + value],
                          "url": "https://demo:" + value + "@example.test"}}}))
            invalid = base / "invalid/.claude/settings.json"
            write_fixture(invalid, "{\nPGPASSWORD=" + value + "\n")
            for excluded in sorted(SKIP):
                write_fixture(base / excluded / ".mcp.json", "{}")
            write_fixture(base / "a/b/c/d/e/.mcp.json", "{}")
            write_fixture(base / "a/b/c/d/e/f/.mcp.json", "{}")
            discovery_errors = []
            assert len(list(discover(base, discovery_errors))) == 4 and not discovery_errors, "discovery depth and exclusions"
            print("discovery: depth 5 included; depth 6 and excluded directories skipped")
            outputs = []
            for mode in ([], ["--json"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = run(["--root", str(base), *mode])
                assert code == 10, "scan exit"
                outputs.append(output.getvalue())
            data = json.loads(outputs[1])
            assert data["files_scanned"] == 4 and not data["errors"], "file totals"
            found = data["findings"]
            assert any(f["unparsed"] and f["location"] == "line 2" for f in found), "raw fallback"
            for location in ("permissions.allow[0]", "permissions.ask[0]", "permissions.deny[0]",
                             "env[0][0]", "mcpServers[0].headers[0]",
                             "mcpServers[0].env[0]", "mcpServers[0].args[0]", "mcpServers[0].url"):
                assert any(f["location"] == location for f in found), "structured location"
            for index, case in enumerate(cases):
                if not case["kinds"]:
                    continue
                text = case["template"].replace("{value}", values[index])
                document = ({"env": {case["key"]: text}} if "key" in case
                            else {"permissions": {"allow": [text]}})
                write_fixture(settings, json.dumps(document))
                for mode in ([], ["--json"]):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        assert run(["--file", str(settings), *mode]) == 10, "fixture CLI"
                    outputs.append(output.getvalue())
            for output in outputs:
                assert all(v not in output for v in values if v and len(v) >= 6), "output contains fixture value"
            print("output: human and JSON contain no fixture secret values")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--file", str(base / "missing.json"), "--json"]) == 2, "missing file exit"
            assert json.loads(output.getvalue())["errors"], "missing file diagnostic"
            argv_cases = [("demo", ["--password", value], "cli:password"),
                          ("demo", ["--token", value], "cli:token"),
                          ("demo", ["--api-key", value], "cli:api-key"),
                          ("sshpass", ["-p", value], "cli:sshpass"),
                          ("mysql", ["-p" + value], "cli:mysql"),
                          ("curl", ["-u", "demo:" + value], "cli:curl-user"),
                          ("curl", ["-udemo:" + value], "cli:curl-user"),
                          ("curl", ["--user=demo:" + value], "cli:curl-user"),
                          ("curl", ["--oauth2-bearer", value], "cli:oauth2-bearer"),
                          ("redis-cli", ["-a", value], "cli:redis-pass"),
                          ("redis-cli", ["--pass", value], "cli:redis-pass")]
            for command, argv, kind in argv_cases:
                document = {"mcpServers": {"demo": {"command": command, "args": argv}}}
                write_fixture(mcp, json.dumps(document))
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    assert run(["--file", str(mcp), "--json"]) == 10, "MCP argv exit"
                found = json.loads(output.getvalue())["findings"]
                assert any(f["kind"] == kind and f["location"].endswith(f"args[{len(argv) - 1}]")
                           and f["length"] == len(value) for f in found), "MCP argv context"
                assert value not in output.getvalue(), "MCP argv output contains value"
            print("MCP: separate flag/value argv and command-specific flags passed")
            # Arbitrary keys must never become locations, including in argv scanning.
            shape_case = next(case for case in cases if case["kinds"] == ["shape:ghp"])
            shape_value = "".join(shape_case["parts"])
            for document in (
                {"mcpServers": {shape_value: {"headers": {shape_value: value,
                    "Authorization": "Bearer " + shape_value, "api-key": value},
                    "env": {shape_value: value, "API_KEY": value},
                    "args": ["--token", shape_value], shape_value: value}}},
                {"env": {shape_value: {shape_value: "PGPASSWORD=" + value}}},
            ):
                target = mcp if "mcpServers" in document else settings
                write_fixture(target, json.dumps(document))
                for mode in ([], ["--json"]):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        assert run(["--file", str(target), *mode]) == 10, "safe locations exit"
                    assert shape_value not in output.getvalue() and value not in output.getvalue(), "dictionary key leak"
                    if mode:
                        found = json.loads(output.getvalue())["findings"]
                        assert all(re.fullmatch(r"(?:[A-Za-z]+|\[\d+\]|\.)+", f["location"])
                                   for f in found), "indexed locations"
                        if target == mcp:
                            assert any(f["kind"] == "header:api-key" for f in found), "MCP api-key header"
                            assert any(f["location"] == "mcpServers[0].headers[1]" for f in found), "indexed header"
            print("locations: secret-shaped server, env, header, and unknown keys never appear in either output")

            # Complete historical JSON preserves multiline flag/value adjacency.
            structured_repo = base / "structured-history"
            structured_repo.mkdir()
            git(structured_repo, "init", "--quiet", "--template=")
            fixture_commit = ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                              "-c", "core.hooksPath=", "-c", "commit.gpgsign=false", "commit", "--quiet")
            historic_mcp = structured_repo / ".mcp.json"
            historic_invalid = structured_repo / ".claude/settings.json"
            document = {"mcpServers": {shape_value: {"args": ["--token", value],
                         "headers": {"Authorization": "token " + value, "api-key": value}}}}
            write_fixture(historic_mcp, json.dumps(document, indent=2) + "\n")
            write_fixture(historic_invalid, "{\nPGPASSWORD=" + value + "\n")
            git(structured_repo, "add", "--", ".mcp.json", ".claude/settings.json")
            git(structured_repo, *fixture_commit, "-m", "Add multiline fixtures")
            _, first = git(structured_repo, "rev-parse", "HEAD")
            first = first.strip()[:12]
            document["mcpServers"][shape_value]["command"] = "demo"
            write_fixture(historic_mcp, json.dumps(document, indent=2) + "\n")
            git(structured_repo, "add", "--", ".mcp.json")
            git(structured_repo, *fixture_commit, "-m", "Retain credential in changed document")
            _, last = git(structured_repo, "rev-parse", "HEAD")
            last = last.strip()[:12]
            git(structured_repo, "update-ref", "refs/remotes/fixture/main", first)
            git(structured_repo, "rm", "--quiet", "--", ".mcp.json", ".claude/settings.json")
            git(structured_repo, *fixture_commit, "-m", "Remove multiline fixtures")
            observed_git = subprocess.run
            calls = []

            def colored_git(command, **kwargs):
                calls.append(command)
                # Simulate inherited color.ui=always without changing Git config.
                return observed_git([command[0], "-c", "color.ui=always", *command[1:]], **kwargs)

            for mode in ([], ["--json"]):
                output = io.StringIO()
                with patch.object(subprocess, "run", colored_git), contextlib.redirect_stdout(output):
                    assert run(["--root", str(structured_repo), "--history", *mode]) == 10, "structured history exit"
                assert value not in output.getvalue() and shape_value not in output.getvalue(), "structured history output leak"
                if mode:
                    data = json.loads(output.getvalue())
                    assert not data["errors"] and data["files_scanned"] == 0, "structured history totals"
                    found = data["findings"]
                    assert len(found) == 4, "history tuple deduplication"
                    mcp_hits = [f for f in found if f["path"] == display(historic_mcp)]
                    assert {f["kind"] for f in mcp_hits} == {"cli:token", "header:token", "header:api-key"}, "structured history kinds"
                    assert all(f["oldest_commit"] == first and f["newest_commit"] == last
                               and f["commit"] == last and f["oldest_remote"] and not f["newest_remote"]
                               and not f["remote"] for f in mcp_hits), "history endpoints and remote flags"
                    assert any(f["unparsed"] and f["location"] == "line 2" for f in found), "historical invalid JSON"
            assert calls and all("color.ui=false" in command for command in calls), "all git parsing disables color"
            print("history: multiline deleted MCP, invalid JSON, deduplication, oldest/newest commits and remote flags passed")
            print("git color: inherited color.ui=always preserves findings; all Git calls disable color")
            # The side branch leaves the merge tree unchanged for target paths.
            # Default path-history simplification hides its added/deleted blob.
            merged_repo = base / "merged-history"
            merged_repo.mkdir()
            git(merged_repo, "init", "--quiet", "--template=")
            git(merged_repo, *fixture_commit, "--allow-empty", "-m", "Initial fixture")
            _, main_ref = git(merged_repo, "symbolic-ref", "HEAD")
            main_branch = main_ref.strip().removeprefix("refs/heads/")
            git(merged_repo, "-c", "core.hooksPath=", "checkout", "--quiet", "-b", "fixture-side")
            merged_mcp = merged_repo / ".mcp.json"
            write_fixture(merged_mcp, json.dumps({"mcpServers": {"demo": {
                "command": "demo", "args": ["--token", value]}}}, indent=2))
            git(merged_repo, "add", "--", ".mcp.json")
            git(merged_repo, *fixture_commit, "-m", "Add side fixture")
            _, side_commit = git(merged_repo, "rev-parse", "HEAD")
            git(merged_repo, "rm", "--quiet", "--", ".mcp.json")
            git(merged_repo, *fixture_commit, "-m", "Remove side fixture")
            git(merged_repo, "-c", "core.hooksPath=", "checkout", "--quiet", main_branch)
            git(merged_repo, *fixture_commit, "--allow-empty", "-m", "Main fixture")
            git(merged_repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                "-c", "core.hooksPath=", "-c", "commit.gpgsign=false", "merge", "--quiet",
                "--no-ff", "--no-edit", "--no-gpg-sign", "fixture-side")
            git(merged_repo, "branch", "-D", "fixture-side")
            for mode in ([], ["--json"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    assert run(["--root", str(merged_repo), "--history", *mode]) == 10, "merged side history exit"
                assert value not in output.getvalue(), "merged side history output leak"
                if mode:
                    data = json.loads(output.getvalue())
                    assert data["files_scanned"] == 0 and not data["errors"], "merged side history totals"
                    assert len(data["findings"]) == 1, "merged side history finding"
                    hit = data["findings"][0]
                    assert hit["commit"] == side_commit.strip()[:12], "merged side commit"
                    assert hit["kind"] == "cli:token" and not hit["remote"], "merged side kind and remote"
            print("history: merged side branch with deleted ref and deleted MCP detected in both output modes")
            history_repo = base / "history"
            history_repo.mkdir()
            git(history_repo, "init", "--quiet", "--template=")
            historical = history_repo / ".claude/settings.local.json"
            write_fixture(historical, json.dumps({"env": {"API_KEY": value}}) + "\n")
            git(history_repo, "add", "--force", "--", ".claude/settings.local.json")
            # Identity and hook overrides apply only to these disposable test commits.
            commit_args = ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                           "-c", "core.hooksPath=", "-c", "commit.gpgsign=false", "commit", "--quiet")
            git(history_repo, *commit_args, "-m", "Add synthetic fixture")
            assert file_flags(historical, history_repo)["tracked"], "tracked flag"
            _, tip = git(history_repo, "rev-parse", "HEAD")
            first_commit = tip.strip()
            git(history_repo, "rm", "--quiet", "--", ".claude/settings.local.json")
            git(history_repo, *commit_args, "-m", "Remove synthetic fixture")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--root", str(history_repo), "--history", "--json"]) == 10, "history exit"
            data = json.loads(output.getvalue())
            assert data["files_scanned"] == 0 and data["findings"] and not data["errors"], "deleted history"
            assert all(f["commit"] and not f["remote"] for f in data["findings"]), "remote branch status"
            assert value not in output.getvalue(), "history output contains value"
            print("history: deleted file detected only in history; no remote branch")
            write_fixture(history_repo / ".gitignore", ".claude/\n")
            assert file_flags(historical, history_repo)["ignored"], "ignored flag"
            git(history_repo, "update-ref", "refs/remotes/fixture/main", first_commit)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--root", str(history_repo), "--history", "--json"]) == 10, "remote history exit"
            found = json.loads(output.getvalue())["findings"]
            assert all(f["remote"] and f["ignored"] and not f["tracked"] for f in found), "history flags"
            assert value not in output.getvalue(), "remote history output contains value"
            print("git flags: tracked, ignored, and locally known remote containment passed")
            # Fast-import creates a real bounded-history fixture without hundreds
            # of subprocesses or inherited commit hooks/signing configuration.
            imported = bytearray()
            for index in range(HISTORY_LIMIT + 1):
                content = json.dumps({"mcpServers": {}, "fixture": index}).encode("utf-8") + b"\n"
                imported.extend(("commit refs/heads/bounded-fixture\n"
                                 "committer Fixture <fixture@example.test> 1 +0000\n"
                                 "data 7\nfixture\n"
                                 f"M 100644 inline .mcp.json\ndata {len(content)}\n").encode("ascii"))
                imported.extend(content + b"\n\n")
            git(history_repo, "fast-import", "--quiet", data=bytes(imported))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--root", str(history_repo), "--history", "--json"]) in (0, 10), "bounded history exit"
            data = json.loads(output.getvalue())
            assert data["notices"] and "200" in data["notices"][0], "history truncation notice"
            assert not data["errors"], "bounded history errors"
            print("history: 200-commit limit and truncation notice passed")
            # A failed listing must not discard siblings or hide its exact path.
            walk_root = base / "partial"
            blocked = walk_root / "blocked"
            blocked.mkdir(parents=True)
            write_fixture(walk_root / "healthy/.claude/settings.json",
                          json.dumps({"env": {"API_KEY": value}}))
            real_scandir = os.scandir
            for error_type, number in ((PermissionError, errno.EACCES),
                                       (FileNotFoundError, errno.ENOENT)):
                def listing(directory):
                    if Path(directory) == blocked:
                        raise error_type(number, "synthetic listing failure", str(blocked))
                    return real_scandir(directory)

                output = io.StringIO()
                with patch.object(os, "scandir", listing), contextlib.redirect_stdout(output):
                    assert run(["--root", str(walk_root), "--history", "--json"]) == 2, "partial walk exit"
                data = json.loads(output.getvalue())
                assert data["files_scanned"] == 1 and data["findings"], "partial walk retains siblings"
                assert len(data["errors"]) == 1, "one error per failed listing"
                error = data["errors"][0]
                assert error["path"] == display(blocked), "failed directory path"
                assert all(part in error["message"] for part in
                           ("listdir", error_type.__name__, f"errno={number}")), "listing error details"
                assert value not in output.getvalue(), "partial walk output contains value"
            print("discovery: unreadable and vanished directories retain sibling findings; exact errors")

            # Exclusions are checked before stat/listing, including unreadable dirs.
            exclusion_root = base / "exclusions"
            blocked = exclusion_root / "group/blocked"
            blocked.mkdir(parents=True)
            write_fixture(exclusion_root / "healthy/.mcp.json", "{}")
            write_fixture(exclusion_root / "another/.mcp.json", "{}")
            listed = []

            def forbidden_listing(directory):
                listed.append(Path(directory))
                if Path(directory) == blocked:
                    raise PermissionError(errno.EACCES, "synthetic listing failure", str(blocked))
                return real_scandir(directory)

            patterns = ["blocked", "group/bl*", "missing*"]
            if os.name == "nt":
                patterns[0] = "BLOCKED"
            output = io.StringIO()
            with patch.object(os, "scandir", forbidden_listing), contextlib.redirect_stdout(output):
                assert run(["--root", str(exclusion_root), "--json",
                            *[arg for pattern in patterns for arg in ("--exclude", pattern)]]) == 0, "excluded unreadable exit"
            data = json.loads(output.getvalue())
            assert data["files_scanned"] == 2 and not data["errors"], "excluded directory has no error"
            assert blocked not in listed, "excluded directory was entered"
            assert data["notices"] == [f"excluded directories: {count} for pattern " + json.dumps(pattern)
                                       for pattern, count in zip(patterns, (1, 1, 0))], "per-pattern exclusion counts"
            output = io.StringIO()
            with patch.object(os, "scandir", side_effect=AssertionError("excluded root was entered")), \
                    contextlib.redirect_stdout(output):
                assert run(["--root", str(exclusion_root), "--exclude", "exclusions",
                            "--history", "--json"]) == 0, "excluded root exit"
            data = json.loads(output.getvalue())
            assert not data["errors"] and data["files_scanned"] == 0, "excluded root totals"
            print("exclusions: unreadable directories never entered; names, relative globs, counts, and root passed")

            invalid_repo = base / "invalid-repository"
            (invalid_repo / ".git/info").mkdir(parents=True)
            for expected_files in (0, 1):
                if expected_files:
                    write_fixture(invalid_repo / ".mcp.json", "{}")
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    assert run(["--root", str(invalid_repo), "--history", "--json"]) == 0, "invalid git dir exit"
                data = json.loads(output.getvalue())
                assert not data["errors"] and not data["findings"] and data["files_scanned"] == expected_files, "invalid git dir totals"
                assert data["notices"] == ["skipped invalid git dir: " + json.dumps(display(invalid_repo))], "invalid git dir notice"

            real_run = subprocess.run
            for diagnostic, reason in ((b"fatal: detected dubious ownership in repository ", "dubious ownership"),
                                       (b"fatal: unable to access repository ", None)):
                def denied_git(command, **kwargs):
                    if "rev-parse" in command:
                        return subprocess.CompletedProcess(command, 128, b"", diagnostic + value.encode("utf-8"))
                    return real_run(command, **kwargs)

                output = io.StringIO()
                with patch.object(subprocess, "run", denied_git), contextlib.redirect_stdout(output):
                    assert run(["--root", str(invalid_repo), "--history", "--json"]) == 2, "real git failure exit"
                data = json.loads(output.getvalue())
                assert data["errors"] and not data["notices"], "real git failures are errors"
                assert all("git rev-parse" in e["message"] and "exit=128" in e["message"]
                           and (reason is None or reason in e["message"]) for e in data["errors"]), "git failure classification"
                assert value not in output.getvalue(), "git diagnostic contains fixture value"
            print("git discovery: invalid .git is one notice; dubious ownership and other failures stay errors")

            # The root is a plain folder; neither repo has a current target file.
            projects = base / "projects"
            shallow_repo = projects / "shallow"
            nested_repo = projects / "group/deep"
            for repo in (shallow_repo, nested_repo):
                repo.mkdir(parents=True)
                git(repo, "init", "--quiet", "--template=")
                git(repo, *commit_args, "--allow-empty", "-m", "Empty synthetic repository")
            relative = "a/b/c/d/e/f/.claude/settings.local.json"
            historical = nested_repo / relative
            pat_case = next(case for case in cases if case["kinds"] == ["shape:ghp"])
            historical_pat = "".join(pat_case["parts"])
            write_fixture(historical, json.dumps({"permissions": {"allow": ["echo " + historical_pat]},
                                                  "env": {"API_KEY": value}}) + "\n")
            git(nested_repo, "add", "--force", "--", relative)
            git(nested_repo, *commit_args, "-m", "Add nested synthetic fixture")
            git(nested_repo, "rm", "--quiet", "--", relative)
            git(nested_repo, *commit_args, "-m", "Remove nested synthetic fixture")
            write_fixture(nested_repo / ".gitignore", ".claude/\n")
            for mode in ([], ["--history"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = run(["--root", str(projects), *mode, "--json"])
                data = json.loads(output.getvalue())
                assert not data["errors"] and data["files_scanned"] == 0, "plain root scan totals"
                if mode:
                    assert code == 10, "plain root history exit"
                    assert {f["kind"] for f in data["findings"]} == {"shape:ghp", "assign:API_KEY"}, "nested history kinds"
                    assert all(f["path"] == display(historical) and f["commit"] and f["ignored"]
                               and not f["tracked"] for f in data["findings"]), "nested deleted history"
                else:
                    assert code == 0 and not data["findings"], "history-only fixture"
                assert value not in output.getvalue() and historical_pat not in output.getvalue(), "nested history output contains value"
            print("history: plain root with two repos finds deleted/ignored secrets in a repo two levels down")
            for pattern, count in (("group/de*", 1), ("a", 0)):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    assert run(["--root", str(projects), "--history", "--exclude", pattern, "--json"]) == 0, "excluded history exit"
                data = json.loads(output.getvalue())
                assert not data["errors"] and not data["findings"], "excluded repository/history findings"
                assert data["notices"] == [f"excluded directories: {count} for pattern " + json.dumps(pattern)], "history exclusion count"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--file", str(exclusion_root / "healthy/.mcp.json"),
                            "--exclude", "*", "--json"]) == 0, "explicit file bypasses exclusions"
            assert json.loads(output.getvalue())["files_scanned"] == 1, "explicit file exclusion totals"
            print("exclusions: repository and deleted-path history filtered; explicit files still scanned")
            # Git markers may be directories or worktree-style files; the same
            # depth/skip boundary applies to repository discovery and file discovery.
            markers = base / "markers"
            for relative in (".git", "a/b/c/d/e/.git", "a/b/c/d/e/f/.git", "node_modules/hidden/.git"):
                write_fixture(markers / relative, "synthetic marker\n")
            discovered = set()
            errors = []
            assert not list(discover(markers, errors, discovered)), "marker-only targets"
            assert discovered == {markers, markers / "a/b/c/d/e"} and not errors, "repo marker depth and skips"
            print("discovery: .git files, depth boundary, and skipped repositories passed")

            output = io.StringIO()
            with patch.object(os, "scandir", side_effect=PermissionError(errno.EACCES, value, str(walk_root))), \
                    contextlib.redirect_stdout(output):
                assert run(["--root", str(walk_root), "--json"]) == 2, "unreadable root exit"
            data = json.loads(output.getvalue())
            assert len(data["errors"]) == 1 and data["errors"][0]["path"] == display(walk_root), "unreadable root path"
            assert "listdir" in data["errors"][0]["message"] and value not in output.getvalue(), "safe root error"
            undecodable = base / "undecodable.json"
            undecodable.write_bytes(b"\xff")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                assert run(["--file", str(undecodable), "--json"]) == 2, "decode exit"
            errors = json.loads(output.getvalue())["errors"]
            assert len(errors) == 1 and errors[0]["path"] == display(undecodable), "decode error path"
            assert "decode" in errors[0]["message"] and "UnicodeDecodeError" in errors[0]["message"], "decode error step"

            write_fixture(nested_repo / ".mcp.json", json.dumps({"mcpServers": {"demo": {"env": {"API_KEY": value}}}}))
            real_run = subprocess.run
            for step in ("ls-files", "check-ignore", "log", "diff-tree", "show", "branch"):
                def failing_git(command, **kwargs):
                    if step in command:
                        return subprocess.CompletedProcess(command, 7, b"", value.encode("utf-8"))
                    return real_run(command, **kwargs)

                output = io.StringIO()
                with patch.object(subprocess, "run", failing_git), contextlib.redirect_stdout(output):
                    assert run(["--root", str(nested_repo), "--history", "--json"]) == 2, "git failure exit"
                data = json.loads(output.getvalue())
                assert data["findings"], "git failure retains findings"
                assert data["errors"] and all("git " + step in e["message"] and "exit=7" in e["message"]
                                              for e in data["errors"]), "git failure step and exit"
                expected_paths = ({display(nested_repo)} if step in {"log", "diff-tree"}
                                  else {display(nested_repo / ".mcp.json"), display(historical)})
                assert all(e["path"] in expected_paths for e in data["errors"]), "git failure exact path"
                assert value not in output.getvalue() and historical_pat not in output.getvalue(), "git error leaks fixture value"
            print("errors: unreadable root, decode, and Git steps/exit codes retain findings without values")
        print("agent_secrets selftest: PASS")
        return 0
    except (AssertionError, OSError, ValueError, ScanError) as error:
        # Never print input, captured output, or exception details containing fixtures.
        detail = str(error) if isinstance(error, (AssertionError, ScanError)) else type(error).__name__
        print("agent_secrets selftest: FAIL (" + detail + ")")
        return 2


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(run())
