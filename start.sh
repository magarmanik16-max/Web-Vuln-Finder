#!/usr/bin/env bash
#
# WebVulnApp — plug-and-play startup for the authorized assessment platform.
#
# Starts (and reuses where practical): MongoDB -> Express API -> Vite frontend.
# Manages only the processes it starts; never kills unrelated processes;
# never installs system packages; never weakens the application's security
# defaults (MongoDB stays loopback-bound, the API keeps its configured HOST).
#
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"

# ---------------------------------------------------------------- output ----
BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; DIM=$'\033[2m'; OFF=$'\033[0m'
step()  { printf '%s\n' "${DIM}==> ${OFF}${BOLD}$*${OFF}"; }
ok()    { printf '%s\n' "  ${GREEN}✓${OFF} $*"; }
warn()  { printf '%s\n' "  ${YELLOW}!${OFF} $*"; }
die()   { printf '%s\n' "${RED}ERROR:${OFF} $*" >&2; exit 1; }

LOGS="$ROOT/.data/logs"
mkdir -p "$LOGS"

PIDS=()   # process-group leaders started by this script (killed via their group)
NAMES=()
CLEANED=0

cleanup() {
  [ "$CLEANED" -eq 1 ] && return
  CLEANED=1
  trap - EXIT INT TERM
  if [ "${#PIDS[@]}" -gt 0 ]; then
    printf '%s\n' ""
    printf '%s\n' "${DIM}Stopping services started by start.sh…${OFF}"
    for i in "${!PIDS[@]}"; do
      if kill -0 "${PIDS[$i]}" 2>/dev/null; then
        kill -TERM -- "-${PIDS[$i]}" 2>/dev/null || kill "${PIDS[$i]}" 2>/dev/null || true
      fi
    done
    for i in "${!PIDS[@]}"; do
      for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "${PIDS[$i]}" 2>/dev/null || break; sleep 0.3; done
      kill -KILL -- "-${PIDS[$i]}" 2>/dev/null || true
      printf '%s\n' "  stopped: ${NAMES[$i]}"
    done
  fi
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------ preflight -----
step "Preflight"
for cmd in bash node npm python3 setsid; do
  command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: '$cmd'. Install it and re-run. (No system packages are installed automatically.)"
done
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 20 ] || die "Node.js >= 20 required (found $(node -v)). Upgrade Node and re-run."
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0]*100+sys.version_info[1])')
[ "$PYTHON_MAJOR" -ge 310 ] || die "Python >= 3.10 required (found $(python3 -V 2>&1))."
for d in server client scanner; do
  [ -d "$ROOT/$d" ] || die "Project directory '$ROOT/$d' is missing — run this script from the repository root of a complete checkout."
done
[ -f "$ROOT/server/package.json" ] && [ -f "$ROOT/client/package.json" ] || die "server/package.json or client/package.json missing — incomplete checkout."
ok "bash, node $(node -v), npm $(npm -v), $(python3 -V), process groups available"

# ------------------------------------------------------------ config --------
step "Configuration"
ENV_FILE="$ROOT/server/.env"
FIRST_RUN_ENV=0
if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/server/.env.example" "$ENV_FILE"
  # Replace placeholder secrets with real random LOCAL DEV values.
  # (Generated at runtime, stored only in the gitignored .env — never printed.)
  JWT=$(node -p "require('crypto').randomBytes(48).toString('base64url')")
  PW=$(node -p "require('crypto').randomBytes(12).toString('base64url')")
  node -e "
    const fs = require('fs');
    const f = process.argv[1], jwt = process.argv[2], pw = process.argv[3];
    let t = fs.readFileSync(f, 'utf8');
    t = t.replace(/^JWT_SECRET=.*$/m, 'JWT_SECRET=' + jwt).replace(/^ADMIN_PASSWORD=.*$/m, 'ADMIN_PASSWORD=' + pw);
    fs.writeFileSync(f, t);
  " "$ENV_FILE" "$JWT" "$PW"
  unset JWT PW
  FIRST_RUN_ENV=1
  ok "server/.env created from .env.example — configuration was initialized (JWT secret and admin password were generated into server/.env, which is gitignored; they are NOT printed)"
else
  ok "server/.env found — existing configuration reused (never overwritten)"
fi

envval() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*$//; s/^"//; s/"$//' || true; }

PORT="${PORT:-$(envval PORT)}";  PORT="${PORT:-5000}"
HOST="${HOST:-$(envval HOST)}";  HOST="${HOST:-127.0.0.1}"
MONGODB_URI="$(envval MONGODB_URI)"; MONGODB_URI="${MONGODB_URI:-mongodb://127.0.0.1:27017/webvulnapp}"
CLIENT_PORT="${CLIENT_PORT:-5173}"   # matches client/vite.config.js

JWT_SECRET_VAL="$(envval JWT_SECRET)"
[ -n "$JWT_SECRET_VAL" ] || die "JWT_SECRET is missing in server/.env. Generate one with: node -e \"console.log(require('crypto').randomBytes(48).toString('base64url'))\" and put it in server/.env as JWT_SECRET=<value>"
if [ "$JWT_SECRET_VAL" = "change-me-to-a-long-random-secret" ]; then
  die "server/.env still contains the example placeholder JWT_SECRET. Replace it with a real random value: node -e \"console.log(require('crypto').randomBytes(48).toString('base64url'))\""
fi
ADMIN_PASSWORD_VAL="$(envval ADMIN_PASSWORD)"
[ -n "$ADMIN_PASSWORD_VAL" ] && [ "${#ADMIN_PASSWORD_VAL}" -ge 12 ] || die "ADMIN_PASSWORD in server/.env is missing or shorter than 12 characters (the seed script requires 12+). Set it in server/.env."
unset JWT_SECRET_VAL ADMIN_PASSWORD_VAL

if [ "$PORT" != "5000" ]; then
  warn "PORT=$PORT — note: client/vite.config.js proxies /api to http://localhost:5000, so a non-5000 API port needs that file adjusted too."
fi
ok "API: ${HOST}:${PORT} · Frontend port: ${CLIENT_PORT} · MongoDB: ${MONGODB_URI%%\?*}"

# ------------------------------------------------------------ dependencies --
step "Dependencies"
if [ -d "$ROOT/server/node_modules" ]; then
  ok "server dependencies present (skipped install)"
else
  (cd "$ROOT/server" && npm install --no-audit --no-fund) || die "npm install failed for server/"
  ok "server dependencies installed"
fi
if [ -d "$ROOT/client/node_modules" ]; then
  ok "client dependencies present (skipped install)"
else
  (cd "$ROOT/client" && npm install --no-audit --no-fund) || die "npm install failed for client/"
  ok "client dependencies installed"
fi

# ------------------------------------------------------------ helpers -------
tcp_up() { # host port -> exit 0 if a TCP connection succeeds
  node -e "
    const net = require('net');
    const s = net.connect({ host: process.argv[1], port: Number(process.argv[2]), timeout: 1500 });
    s.on('connect', () => { s.destroy(); process.exit(0); });
    s.on('timeout', () => { s.destroy(); process.exit(1); });
    s.on('error', () => process.exit(1));
  " "$1" "$2"
}

port_up() { # port -> exit 0 if anything listens on IPv4 or IPv6 loopback
  tcp_up 127.0.0.1 "$1" || tcp_up ::1 "$1"
}

api_healthy() { # -> exit 0 if the API answers and MongoDB reports connected
  node -e "
    fetch('http://127.0.0.1:' + process.argv[1] + '/api/health', { signal: AbortSignal.timeout(2000) })
      .then(r => r.json())
      .then(j => process.exit(j.ok === true && j.mongo === 'connected' ? 0 : 1))
      .catch(() => process.exit(1));
  " "$PORT"
}

vite_up() { # -> exit 0 if the port serves the Vite dev frontend (IPv4 or IPv6)
  node -e "
    const tryUrl = (url) => fetch(url, { signal: AbortSignal.timeout(2000) })
      .then(r => r.text())
      .then(t => { if (t.includes('@vite') || t.includes('/src/main.jsx')) process.exit(0); })
      .catch(() => {});
    (async () => {
      for (const host of ['127.0.0.1', '[::1]']) {
        await tryUrl('http://' + host + ':' + process.argv[1] + '/');
        if (process.exitCode === 0) return;
      }
      process.exit(1);
    })();
  " "$CLIENT_PORT"
}

wait_for() { # description seconds command...
  local desc="$1" tries="$2"; shift 2
  for _ in $(seq 1 "$tries"); do
    if "$@"; then return 0; fi
    sleep 1
  done
  die "$desc did not become ready in ${tries}s. Check logs in .data/logs/ (process output below if it just failed)."
}

start_managed() { # name command...
  local name="$1"; shift
  setsid "$@" >> "$LOGS/$name.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid"); NAMES+=("$name")
}

# ------------------------------------------------------------ MongoDB -------
step "MongoDB"
MONGO_HOST="$(printf '%s' "$MONGODB_URI" | sed -n 's|^mongodb://\([^:/]*\):.*|\1|p')"; MONGO_HOST="${MONGO_HOST:-127.0.0.1}"
MONGO_PORT="$(printf '%s' "$MONGODB_URI" | sed -n 's|^mongodb://[^:/]*:\([0-9]*\)/.*|\1|p')"; MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_OURS=""

if tcp_up "$MONGO_HOST" "$MONGO_PORT"; then
  ok "already reachable at ${MONGO_HOST}:${MONGO_PORT} — reusing (data untouched)"
else
  if [ "$MONGO_HOST" != "127.0.0.1" ] && [ "$MONGO_HOST" != "localhost" ]; then
    die "MongoDB at ${MONGO_HOST}:${MONGO_PORT} is not reachable. Start it or fix MONGODB_URI in server/.env."
  fi
  MONGOD_BIN="$(command -v mongod 2>/dev/null || true)"
  [ -z "$MONGOD_BIN" ] && [ -x "$HOME/.local/opt/mongodb/bin/mongod" ] && MONGOD_BIN="$HOME/.local/opt/mongodb/bin/mongod"
  if [ -z "$MONGOD_BIN" ]; then
    printf '%s\n' "${RED}ERROR:${OFF} MongoDB is not running and no 'mongod' binary was found." >&2
    printf '%s\n' "Start MongoDB yourself OR download a userspace copy (no sudo needed):" >&2
    printf '%s\n' "  mkdir -p ~/.local/opt $ROOT/.data/db" >&2
    printf '%s\n' "  curl -L -o ~/.local/opt/mongodb.tgz https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2404-8.0.29.tgz" >&2
    printf '%s\n' "  tar -xzf ~/.local/opt/mongodb.tgz -C ~/.local/opt && mv ~/.local/opt/mongodb-linux-x86_64-ubuntu2404-* ~/.local/opt/mongodb" >&2
    printf '%s\n' "Then re-run ./start.sh" >&2
    exit 1
  fi
  mkdir -p "$ROOT/.data/db"
  start_managed "mongod" "$MONGOD_BIN" --dbpath "$ROOT/.data/db" --bind_ip 127.0.0.1 --port "$MONGO_PORT" --logpath "$LOGS/mongod.log"
  MONGO_OURS=1
  wait_for "MongoDB" 60 tcp_up "$MONGO_HOST" "$MONGO_PORT"
  ok "started userspace MongoDB on 127.0.0.1:${MONGO_PORT} (dbpath .data/db — existing data preserved)"
fi

# ------------------------------------------------------------ seed ----------
step "Admin account"
if npm --prefix server run seed >> "$LOGS/seed.log" 2>&1; then
  ok "bootstrap admin present (seed is idempotent — credentials live in server/.env, never printed)"
else
  die "Admin seed failed — see $LOGS/seed.log (usually invalid ADMIN_EMAIL/ADMIN_PASSWORD in server/.env)."
fi

# ------------------------------------------------------------ API -----------
step "Express API"
if tcp_up "$HOST" "$PORT" || tcp_up 127.0.0.1 "$PORT"; then
  if api_healthy; then
    ok "already running and healthy on port $PORT — reusing (not started by this script; it will NOT be stopped on exit)"
  else
    die "Port $PORT is occupied by another process that is not this API. Free the port or set PORT in server/.env — start.sh never kills processes it did not start."
  fi
else
  start_managed "api" npm --prefix server run dev
  wait_for "Express API" 60 api_healthy
  ok "started and healthy on http://${HOST}:${PORT} (log: .data/logs/api.log)"
fi

# ------------------------------------------------------------ Frontend ------
step "Frontend"
if port_up "$CLIENT_PORT"; then
  if vite_up; then
    ok "Vite frontend already running on port $CLIENT_PORT — reusing (not started by this script)"
  else
    die "Port $CLIENT_PORT is occupied by another process that is not the Vite frontend. Free it or set CLIENT_PORT here — start.sh never kills processes it did not start."
  fi
else
  start_managed "client" npm --prefix client run dev
  wait_for "Vite frontend" 60 vite_up
  ok "started on http://127.0.0.1:${CLIENT_PORT} (log: .data/logs/client.log)"
fi

# ------------------------------------------------------------ ready ---------
printf '%s\n' ""
printf '%s\n' "$BOLD========================================${OFF}"
printf '%s\n' "$BOLD  Web Vulnerability Assessment Platform${OFF}"
printf '%s\n' "$BOLD========================================${OFF}"
printf '%s\n' "MongoDB:  ready${MONGO_OURS:+ (started by start.sh)}"
printf '%s\n' "API:      http://${HOST}:${PORT}"
printf '%s\n' "Frontend: http://127.0.0.1:${CLIENT_PORT}"
printf '%s\n' ""
printf '%s\n' "Log in with the admin credentials from server/.env (ADMIN_EMAIL / ADMIN_PASSWORD)."
if [ "$FIRST_RUN_ENV" -eq 1 ]; then
  printf '%s\n' "${YELLOW}First run: server/.env was initialized for you${OFF} — the admin password inside it is shown only there (it is never printed)."
fi
printf '%s\n' ""
printf '%s\n' "Press Ctrl+C to stop all services.${OFF}"

# Keep the script in the foreground; the EXIT/INT/TERM traps clean everything up.
wait || true
