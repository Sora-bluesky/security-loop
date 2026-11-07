export GIT_NO_REPLACE_OBJECTS=1
export GIT_NO_LAZY_FETCH=1
# Sourced by the hooks in this directory (POSIX sh).
#
# A repo-local core.hooksPath hides the global hooks, so each hook here first
# runs the global hook of the same name (found through the global
# core.hooksPath) and stops if it fails.

hook_dir=$(cd "$(dirname "$0")" && pwd -P)

# global_hook <name> [args...]: run the global hook <name>; stdin passes through.
global_hook() {
	gh_name=$1
	shift
	gh_dir=$(git config --global --path --get core.hooksPath 2>/dev/null) || return 0
	[ -n "$gh_dir" ] || return 0
	case $gh_dir in
	"~" | "~/"*) gh_dir="$HOME${gh_dir#\~}" ;;
	esac
	[ -d "$gh_dir" ] || return 0
	gh_dir=$(cd "$gh_dir" && pwd -P) || return 0
	[ "$gh_dir" = "$hook_dir" ] && return 0
	gh_hook="$gh_dir/$gh_name"
	if [ -f "$gh_hook" ] && [ -x "$gh_hook" ]; then
		"$gh_hook" "$@"
		return $?
	fi
	return 0
}

# run_python [args...]: py -3.14 -I -B, else python3 -I, else python -I; fail closed.
run_python() {
	if command -v py >/dev/null 2>&1 && py -3.14 -I -B -c "" >/dev/null 2>&1; then
		py -3.14 -I -B "$@"
		return $?
	fi
	for rp_exe in python3 python; do
		if command -v "$rp_exe" >/dev/null 2>&1 && "$rp_exe" -I -B -c "" >/dev/null 2>&1; then
			"$rp_exe" -I -B "$@"
			return $?
		fi
	done
	echo "publish check: no Python interpreter found; rejecting (fail closed)" >&2
	return 2
}

# run_gitleaks [args...]: gitleaks with redacted output; fail closed when absent.
run_gitleaks() {
	if ! command -v gitleaks >/dev/null 2>&1; then
		echo "publish check: gitleaks is not on PATH; rejecting (fail closed)" >&2
		return 2
	fi
	gitleaks "$@" --no-banner --redact
}
