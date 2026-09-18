# Shared pid tracking. Source this; do not execute it.
#
# WHY NOT pgrep -f: `pgrep -f "bash ./scripts/leobench/claude_windows.sh"` matches ANY process
# whose command line contains that string -- including an unrelated shell that merely passes it
# as an argument (a `pgrep -f`/`grep` in another script, a monitoring one-liner). On 2026-09-18
# that produced a false positive that convinced the watchdog a dead scheduler was alive, which
# would have silently stalled an unattended overnight run. A pidfile plus an identity check
# cannot collide that way.
PIDDIR=${PIDDIR:-outputs/inscope/_genlogs}

pid_write() {  # $1 = logical name; records this process and clears it on exit
  mkdir -p "$PIDDIR"
  echo $$ > "$PIDDIR/$1.pid"
  # shellcheck disable=SC2064
  trap "rm -f '$PIDDIR/$1.pid'" EXIT
}

pid_alive() {  # $1 = logical name, $2 = script basename that must own the pid
  local f="$PIDDIR/$1.pid" p
  [ -f "$f" ] || return 1
  p=$(cat "$f" 2>/dev/null) || return 1
  case "$p" in ''|*[!0-9]*) return 1;; esac
  kill -0 "$p" 2>/dev/null || return 1
  # Guard against pid reuse: the live pid must actually be running that script.
  ps -o command= -p "$p" 2>/dev/null | grep -q "$2" || return 1
  return 0
}

pid_of() { cat "$PIDDIR/$1.pid" 2>/dev/null; }
