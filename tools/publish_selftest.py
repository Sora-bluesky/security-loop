"""Offline acceptance cases for publish_check.py, using real Git hooks."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def selftest():
    failures = []

    def case(name, action):
        try:
            action()
        except Exception as exc:
            failures.append(name)
            print(f"{name}: FAIL ({type(exc).__name__})", flush=True)
        else:
            print(f"{name}: PASS", flush=True)

    def require(condition):
        if not condition:
            raise AssertionError("unexpected gate result")

    source = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="publish-selftest-") as temporary:
        root = Path(temporary)
        repo = root / "work"
        repo.mkdir()
        # Prevent inherited Git config, hooks, signing, alternate object stores,
        # index overrides or private home files from affecting throwaway repos.
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL=str(root / "global.gitconfig"), GIT_CONFIG_NOSYSTEM="1",
                   GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="file", GIT_NO_REPLACE_OBJECTS="1",
                   GIT_AUTHOR_NAME="Example Publisher", GIT_AUTHOR_EMAIL="publisher@example.test",
                   GIT_COMMITTER_NAME="Example Publisher", GIT_COMMITTER_EMAIL="publisher@example.test",
                   USERNAME="synthetic-user-for-gate", USER="synthetic-user-for-gate")
        stub = root / "bin"
        write(stub / "gitleaks", '#!/bin/sh\ncase " $* " in *" --redact "*) ;; *) exit 9 ;; esac\nprintf "%s\\n" "$*" >> "$GATE_LEAKS_LOG"\nexit "${GATE_LEAKS_FAIL:-0}"\n')
        write(stub / "gitleaks.cmd", '@echo off\necho %* >> "%GATE_LEAKS_LOG%"\nif defined GATE_LEAKS_FAIL exit /b %GATE_LEAKS_FAIL%\nexit /b 0\n')
        (stub / "gitleaks").chmod(0o755)
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        env["GATE_LEAKS_LOG"] = str(root / "gitleaks.log")

        def run(*args, data=None, extra=None, cwd=repo):
            return subprocess.run(list(args), cwd=cwd, input=data, capture_output=True,
                                  env=dict(env, **(extra or {})))

        def git(*args, data=None):
            result = run("git", *args, data=data)
            require(result.returncode == 0)
            return result.stdout.decode("utf-8").strip()

        git("init", "-q", "-b", "dev")
        git("config", "user.name", "Example Publisher")
        git("config", "user.email", "publisher@example.test")
        git("config", "core.autocrlf", "false")
        git("config", "core.hooksPath", ".githooks")
        # Only this temp config defines global hooks. Their stdin is saved to
        # prove that the real pre-push chains before local checks without loss.
        global_hooks = root / "global-hooks"
        for name in ("pre-push", "pre-commit", "commit-msg", "post-commit", "post-checkout", "post-merge"):
            text = '#!/bin/sh\nprintf "%s\\n" "' + name + '" >> .local/global-events\n'
            if name == "pre-push":
                text += 'cat > .local/global-push-input\n'
            write(global_hooks / name, text)
            (global_hooks / name).chmod(0o755)
        write(root / "global.gitconfig", '[core]\n\thooksPath = ' + global_hooks.as_posix() + '\n')
        for name in ("publish_check.py", "publish_selftest.py"):
            write(repo / "tools" / name, (source / "tools" / name).read_text(encoding="utf-8"))
        for path in (source / ".githooks").iterdir():
            if path.is_file():
                write(repo / ".githooks" / path.name, path.read_text(encoding="utf-8"))
                (repo / ".githooks" / path.name).chmod(0o755)
        write(repo / "tools/publish-allowlist.txt", "good.txt\ncode.py\n")
        write(repo / ".local/publish-markers.txt", "# Synthetic only\nPRIVATE-GATE-MARKER\nre:account-test-[0-9]+\n")
        remotes = {}
        for name in ("public", "dev", "unknown"):
            target = root / (name + ".git")
            result = run("git", "init", "--bare", "-q", str(target))
            require(result.returncode == 0)
            remotes[name] = target.as_uri()
        guard = {"dev_urls": [remotes["dev"]], "public_urls": [remotes["public"]],
                 "internal_paths": ["extra-private/"],
                 "allowed_identities": ["Example Publisher <publisher@example.test>"],
                 "local_only_refs": ["refs/archive/*"]}

        def save_guard():
            write(repo / ".local/publish-guard.json", json.dumps(guard) + "\n")

        save_guard()

        def gate(*args, extra=None):
            return run(sys.executable, "-I", "-B", "tools/publish_check.py", *args, extra=extra)

        def rejected(result, reason):
            require(result.returncode != 0)
            require(reason in (result.stdout + result.stderr).decode("utf-8", "replace"))

        def staged(text, reason):
            write(repo / "good.txt", text)
            git("add", "good.txt")
            rejected(gate("staged"), reason)

        case("reject-staged-marker", lambda: staged("PRIVATE-GATE-MARKER\n", "private marker"))
        case("reject-staged-user-path", lambda: staged("C:" + chr(92) + "Users" + chr(92) + "Example/file\n", "Windows user-folder"))
        case("reject-staged-username", lambda: staged(env["USERNAME"] + "\n", "machine user name"))
        case("reject-staged-ipv4", lambda: staged(".".join(["8"] * 4) + "\n", "IPv4 outside"))
        def wide_marker(encoding="utf-16-le"):
            sha = git("hash-object", "-w", "--stdin", data="PRIVATE-GATE-MARKER".encode(encoding))
            git("update-index", "--cacheinfo", "100644," + sha + ",good.txt")
            rejected(gate("staged"), "private marker")

        case("reject-utf16-marker", wide_marker)
        case("reject-utf16be-marker", lambda: wide_marker("utf-16-be"))
        def dev_v_version():
            write(repo / "good.txt", "endpoint=v" + ".".join(["8"] * 4) + "\n")
            git("add", "good.txt")
            require(gate("staged").returncode == 0)

        case("pass-dev-staged-v-version", dev_v_version)
        version = ".".join(["8"] * 4)
        write(repo / "good.txt", 'clean 192.0.2.1 127.0.0.1 100.64.0.1 0.0.0.0 '
              + f'v1.2.3 =={version} @{version} "version": "{version}"\n')
        git("add", "good.txt")
        case("pass-version-and-address-controls", lambda: require(gate("staged").returncode == 0))

        def version_controls():
            write(repo / "good.txt", 'v1.2.3 "version": "1.2.3.4"\n')
            git("add", "good.txt")
            require(gate("staged").returncode == 0)

        case("pass-three-part-and-keyed-version", version_controls)
        write(repo / ".local/message", "PRIVATE-GATE-MARKER\n")
        case("reject-message-marker", lambda: rejected(gate("message", ".local/message"), "private marker"))
        case("reject-disallowed-identity", lambda: rejected(gate("staged", extra={"GIT_AUTHOR_EMAIL": "other@example.test"}), "disallowed identity"))
        write(repo / "docs/internal.md", "development notes\n")
        write(repo / "unlisted.txt", "unlisted development data\n")
        git("add", "docs/internal.md", "unlisted.txt")
        git("commit", "-q", "-m", "Clean development commit")
        dev = git("rev-parse", "HEAD")
        dev_tree = git("rev-parse", "HEAD^{tree}")

        def push(sha, kind, branch):
            # Existing negative public cases use allowed tag names so they still
            # exercise their original commit/tree rule after ref filtering.
            ref = "refs/tags/v" + branch if kind == "public" and branch != "main" else "refs/heads/" + branch
            return run("git", "push", "--porcelain", remotes[kind], sha + ":" + ref)

        case("pass-clean-dev-push", lambda: require(push(dev, "dev", "main").returncode == 0))
        case("reject-dev-branch-public", lambda: rejected(push("refs/heads/dev", "public", "dev-leak"), "dev-history rule"))

        def make_commit(tree, parent=None, message="Publish snapshot\n", extra=None):
            args = ["git", "commit-tree", tree]
            if parent:
                args += ["-p", parent]
            result = run(*args, data=message.encode("utf-8"), extra=extra)
            require(result.returncode == 0)
            return result.stdout.decode("ascii").strip()

        def tree_with(path, payload=b"clean payload\n"):
            git("read-tree", "--empty")
            sha = git("hash-object", "-w", "--stdin", data=payload)
            git("update-index", "--add", "--cacheinfo", "100644," + sha + "," + path)
            tree = git("write-tree")
            git("read-tree", dev_tree)
            return tree

        bad_path = make_commit(tree_with("non-allowlisted.txt"))
        case("reject-handmade-unlisted-public", lambda: rejected(push(bad_path, "public", "bad-path"), "not in allowlist"))
        # Wildcards must not override built-in exclusions, including case variants.
        write(repo / "tools/publish-allowlist.txt", "**\n")
        internal = make_commit(tree_with("Docs/internal.md"))
        case("reject-handmade-internal-public", lambda: rejected(push(internal, "public", "bad-internal"), "internal path"))
        write(repo / "tools/publish-allowlist.txt", "good.txt\ncode.py\n")
        clean_tree = tree_with("good.txt")
        descendant = make_commit(clean_tree, parent=dev)
        case("reject-dev-ancestry-public", lambda: rejected(push(descendant, "public", "bad-ancestor"), "dev-history rule"))
        clean = make_commit(clean_tree)

        case("pass-missing-public-markers", lambda: require(
            push(clean, "public", "optional-missing").returncode == 0))
        public_markers = repo / ".local/publish-markers-public.txt"
        write(public_markers, "# Synthetic publication-only values\nPUBLIC-ONLY-MARKER\nre:public-account-[0-9]+\n")
        marked_tree = tree_with("good.txt", b"public-only-marker\n")
        marked_dev = make_commit(marked_tree, parent=dev, message="PUBLIC-ONLY-MARKER development\n")
        git("update-ref", "refs/heads/marker-dev", marked_dev)
        case("pass-public-only-marker-dev-push", lambda: require(
            push(marked_dev, "dev", "public-only-marker").returncode == 0))
        case("reject-public-only-marker-publish", lambda: rejected(
            gate("publish", marked_dev), "public-only marker"))
        case("reject-public-only-marker-public-push", lambda: rejected(
            push(make_commit(marked_tree), "public", "marked-content"), "public-only marker"))

        def dev_public_marker_controls():
            git("read-tree", marked_tree)
            try:
                require(gate("staged").returncode == 0)
                write(repo / ".local/message", "PUBLIC-ONLY-MARKER\n")
                require(gate("message", ".local/message").returncode == 0)
                require(gate("all").returncode == 0)
            finally:
                git("read-tree", dev_tree)

        case("pass-public-only-marker-dev-staged-message-all", dev_public_marker_controls)

        def public_marker_override():
            write(repo / "override-markers.txt", "re:public-account-[0-9]+\n")
            tree = tree_with("good.txt", b"PUBLIC-ACCOUNT-42\n")
            rejected(gate("--public-markers", "override-markers.txt", "publish", make_commit(tree)),
                     "public-only marker")
            # An explicit missing file is also optional, even with a default file present.
            missing = gate("--public-markers", "missing-markers.txt", "range",
                           "--url", remotes["public"], "--remote-ref", "refs/heads/main",
                           "0" * len(clean), make_commit(marked_tree))
            require(missing.returncode == 0)

        case("public-marker-override-regex-and-missing", public_marker_override)

        def malformed_public_markers():
            write(public_markers, "re:[\n")
            try:
                dev_public_marker_controls()
                require(push(marked_dev, "dev", "malformed-public-markers").returncode == 0)
                rejected(gate("publish", marked_dev), "fail closed")
            finally:
                write(public_markers, "PUBLIC-ONLY-MARKER\n")

        case("public-marker-errors-only-affect-public", malformed_public_markers)

        def deleted_dev_branch():
            commit = make_commit(clean_tree, message="Clean development commit\n")
            git("update-ref", "refs/heads/disposable-dev", commit)
            git("update-ref", "-d", "refs/heads/disposable-dev")
            rejected(push(commit, "public", "deleted-dev"), "snapshot shape")

        case("reject-deleted-dev-branch-public", deleted_dev_branch)

        def raw_commit(header=b"", message=b"Publish snapshot\n", parents=()):
            raw = ("tree " + clean_tree + "\n" + "".join("parent " + p + "\n" for p in parents)
                   + "author Example Publisher <publisher@example.test> 1700000000 +0000\n"
                   + "committer Example Publisher <publisher@example.test> 1700000000 +0000\n").encode("ascii")
            return git("hash-object", "-t", "commit", "-w", "--stdin", data=raw + header + b"\n" + message)

        def extra_header_marker():
            commit = raw_commit(b"x-private PRIVATE-GATE-MARKER\n")
            rejected(push(commit, "dev", "extra-header"), "private marker")

        case("reject-dev-extra-header-marker", extra_header_marker)

        def public_shape_headers():
            for header in (b"encoding UTF-8\n", b"gpgsig synthetic\n continuation\n",
                           b"mergetag synthetic\n continuation\n", b"x-extra clean\n"):
                rejected(push(raw_commit(header), "public", "shape-header"), "snapshot shape")

        case("reject-public-extra-headers", public_shape_headers)
        case("reject-public-merge-commit", lambda: rejected(
            push(raw_commit(parents=(clean, dev)), "public", "merge"), "snapshot shape"))
        case("reject-public-nonexact-message", lambda: rejected(
            push(raw_commit(message=b"Publish snapshot\n\n"), "public", "message-shape"), "snapshot shape"))

        def hidden_ancestor():
            ancestor = make_commit(clean_tree, message="Earlier development commit\n")
            tip = make_commit(clean_tree, parent=ancestor)
            rejected(push(tip, "public", "hidden-ancestor"), "snapshot shape")

        case("reject-public-nonsnapshot-ancestor", hidden_ancestor)
        case("reject-unknown-url", lambda: rejected(push(clean, "unknown", "main"), "unknown URL"))

        def unknown_noop():
            guard["dev_urls"].append(remotes["unknown"])
            save_guard()
            try:
                require(push(clean, "unknown", "main").returncode == 0)
            finally:
                guard["dev_urls"].remove(remotes["unknown"])
                save_guard()
            rejected(push(clean, "unknown", "main"), "unknown URL")

        case("reject-unknown-url-no-updates", unknown_noop)

        def missing(name):
            path = repo / ".local" / name
            text = path.read_text(encoding="utf-8")
            path.unlink()
            try:
                rejected(push(dev, "dev", "missing-" + name.split(".")[0]), "fail closed")
            finally:
                write(path, text)

        case("reject-missing-guard", lambda: missing("publish-guard.json"))
        case("reject-missing-markers", lambda: missing("publish-markers.txt"))

        first = None

        def first_publish():
            nonlocal first
            index_before = git("write-tree")
            require(gate("publish").returncode == 0)
            require(git("write-tree") == index_before)
            first = git("rev-parse", "refs/heads/public")
            require(git("rev-list", "--parents", first) == first)
            require(git("ls-tree", "-r", "--name-only", first) == "good.txt")
            require(push("refs/heads/public", "public", "main").returncode == 0)

        case("pass-first-snapshot-drops-unlisted", first_publish)

        def snapshot_ref(ref, source_ref="refs/heads/public"):
            return run("git", "push", "--porcelain", remotes["public"], source_ref + ":" + ref)

        case("reject-public-other-branch", lambda: rejected(
            snapshot_ref("refs/heads/other"), "public ref name"))
        case("reject-dev-ref-marker", lambda: rejected(
            push(dev, "dev", "PRIVATE-GATE-MARKER"), "private marker"))
        case("reject-dev-ref-username", lambda: rejected(
            push(dev, "dev", env["USERNAME"]), "machine user name"))
        case("reject-public-ref-marker", lambda: rejected(
            snapshot_ref("refs/tags/vPRIVATE-GATE-MARKER"), "private marker"))
        case("reject-public-nonversion-tag", lambda: rejected(
            snapshot_ref("refs/tags/release"), "public ref name"))
        case("pass-public-lightweight-version-tag", lambda: require(
            snapshot_ref("refs/tags/v1.0.0").returncode == 0))
        case("reject-public-branch-deletion", lambda: rejected(
            snapshot_ref("refs/heads/main", ""), "public ref deletion"))
        case("reject-public-tag-deletion", lambda: rejected(
            snapshot_ref("refs/tags/v1.0.0", ""), "public ref deletion"))

        def annotated_tag():
            git("tag", "-a", "vannotated", first, "-m", "Synthetic release")
            rejected(snapshot_ref("refs/tags/vannotated", "refs/tags/vannotated"), "only direct commits")

        case("reject-public-annotated-tag", annotated_tag)

        def second_publish():
            require(first is not None)
            git("update-ref", "refs/remotes/origin/main", first)
            write(repo / "good.txt", "second snapshot\n")
            git("add", "good.txt")
            git("commit", "-q", "-m", "Second development commit")
            require(gate("publish").returncode == 0)
            second = git("rev-parse", "refs/heads/public")
            require(git("rev-list", "--parents", "-n", "1", second) == second + " " + first)
            require(push("refs/heads/public", "public", "main").returncode == 0)

        case("pass-second-snapshot-public-parent", second_publish)
        case("reject-overwrite-unpublished-snapshot", lambda: rejected(gate("publish"), "unpublished snapshot"))
        marker_commit = make_commit(clean_tree, message="PRIVATE-GATE-MARKER\n")
        case("reject-public-message-marker", lambda: rejected(push(marker_commit, "public", "bad-message"), "private marker"))
        identity_commit = make_commit(clean_tree, extra={"GIT_COMMITTER_NAME": "Unlisted Identity"})
        case("reject-public-identity", lambda: rejected(push(identity_commit, "public", "bad-identity"), "disallowed identity"))

        def public_blob():
            git("read-tree", "--empty")
            sha = git("hash-object", "-w", "--stdin", data=b"PRIVATE-GATE-MARKER\n")
            git("update-index", "--add", "--cacheinfo", "100644," + sha + ",good.txt")
            tree = git("write-tree")
            git("read-tree", "HEAD")
            rejected(push(make_commit(tree), "public", "bad-blob"), "private marker")

        case("reject-public-blob-marker", public_blob)

        def public_v_ipv4():
            git("read-tree", "--empty")
            sha = git("hash-object", "-w", "--stdin", data=("endpoint=v" + ".".join(["8"] * 4) + "\n").encode())
            git("update-index", "--add", "--cacheinfo", "100644," + sha + ",good.txt")
            tree = git("write-tree")
            git("read-tree", "HEAD")
            rejected(push(make_commit(tree), "public", "v-ipv4"), "IPv4 outside")

        case("reject-public-snapshot-v-ipv4", public_v_ipv4)

        def snapshot_leaks_failure():
            before = git("rev-parse", "refs/heads/public")
            git("update-ref", "refs/remotes/origin/main", before)
            rejected(gate("publish", extra={"GATE_LEAKS_FAIL": "1"}), "gitleaks rejected")
            require(git("rev-parse", "refs/heads/public") == before)

        case("reject-gitleaks-snapshot-no-ref-update", snapshot_leaks_failure)

        def local_only():
            git("update-ref", "refs/archive/private", clean)
            try:
                rejected(push(clean, "public", "local-only"), "dev-history rule")
            finally:
                git("update-ref", "-d", "refs/archive/private")

        case("reject-configured-local-only", local_only)

        def no_gitleaks():
            names = ("gitleaks", "gitleaks.exe", "gitleaks.cmd", "gitleaks.bat", "gitleaks.com")
            paths = [p for p in env["PATH"].split(os.pathsep)
                     if not any(os.path.lexists(Path(p) / name) for name in names)]
            result = run("git", "push", "--porcelain", remotes["dev"], dev + ":refs/heads/no-gitleaks",
                         extra={"PATH": os.pathsep.join(paths)})
            rejected(result, "gitleaks")

        case("reject-missing-gitleaks-hook", no_gitleaks)

        def hook_chain():
            events = (repo / ".local/global-events").read_text(encoding="utf-8").splitlines()
            require("pre-commit" in events and "commit-msg" in events and "post-commit" in events and "pre-push" in events)
            require("refs/heads/no-gitleaks" in (repo / ".local/global-push-input").read_text(encoding="utf-8"))
            lines = (root / "gitleaks.log").read_text(encoding="utf-8").splitlines()
            require(lines and all("--redact" in line for line in lines))

        case("pass-global-hook-stdin-and-redaction", hook_chain)
        print("gitleaks: PATH stub used; secret detection itself is not tested", flush=True)
    print(f"selftest: {len(failures)} failed", flush=True)
    return 1 if failures else 0
