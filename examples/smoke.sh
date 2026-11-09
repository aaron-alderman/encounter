#!/usr/bin/env bash
set -euo pipefail

binary=$(realpath -- "${1:-target/release/encounter}")
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
scratch=$(mktemp -d)
server=
cleanup() {
  if [[ -n $server ]]; then
    kill "$server" 2>/dev/null || true
    wait "$server" || true
  fi
  rm -r -- "$scratch"
}
trap cleanup EXIT

[[ $("$binary" run --declaration examples/hello application.rel) == 'Hello, world!' ]]
[[ $("$binary" run --declaration examples/cli application.rel 'Ada Lovelace') == 'Hello, Ada Lovelace!' ]]
[[ $("$binary" run --declaration examples/cli application.rel) == 'Usage: greet NAME' ]]
if "$binary" run --declaration examples/cli application.rel Ada Grace 2>"$scratch/error"; then
  echo 'The CLI accepted too many arguments.' >&2
  exit 1
fi
grep -Fx 'Expected one name.' "$scratch/error"

[[ $("$binary" test --declaration examples/cli application.rel) == $'ok - test.greeting\nok - test.usage' ]]
cp -- examples/cli/{application.rel,greet.encounter} "$scratch/"
sed -i 's/The greeting must preserve spaces inside the name./Intentional demo test failure./; s/eq(\$greeting, "Hello, Ada Lovelace!")/eq($greeting, "wrong")/' "$scratch/greet.encounter"
if "$binary" test --declaration "$scratch" application.rel >"$scratch/test-out" 2>"$scratch/error"; then
  echo 'An intentionally failing test exited successfully.' >&2
  exit 1
fi
grep -Fx 'test.greeting: Intentional demo test failure.' "$scratch/error"

pin=$("$binary" build examples/web application.rel "$scratch/web.rel")
credential=$(printf '%s' 'demo:disposable-smoke-credential-only' | base64 -w0)
operator_pin=$(printf '%s' "$credential" | sha256sum | cut -d' ' -f1)
(
  umask 077
  printf '("operators", "version", "encounter/operators/1")\n("demo", "role", "demo-editor")\n("demo", "basicSha256", "%s")\n' "$operator_pin" > "$scratch/operators.rel"
)
printf '("launch", "version", "encounter/launch/1")\n("launch", "mode", "image")\n("launch", "image", "web.rel")\n("launch", "sha256", "%s")\n("launch", "store", "store")\n("launch", "port", "0")\n("launch", "operators", "operators.rel")\n' "$pin" > "$scratch/launch.rel"
"$binary" --config "$scratch/launch.rel" serve >"$scratch/ready" &
server=$!
for attempt in {1..100}; do
  origin=$(sed -n 's/^Encounter \(http:\/\/127\.0\.0\.1:[0-9]\+\)$/\1/p' "$scratch/ready")
  [[ -z $origin ]] || break
  sleep .05
done
[[ -n $origin ]]
[[ $(curl --silent --max-time 5 -o /dev/null -w '%{http_code}' "$origin/") == 401 ]]
curl --fail --silent --show-error --max-time 5 -H "Authorization: Basic $credential" "$origin/" | grep -F '<h1>Hello from Encounter</h1>' >/dev/null
curl --fail --silent --show-error --max-time 5 -H "Authorization: Basic $credential" "$origin/styles.css" | grep -F 'system-ui' >/dev/null
kill "$server"
wait "$server"
server=
printf '%s\n' 'ok - stdout, CLI, declared tests and compiled web demo'
