# Encounter

Encounter is a Rust host for REL applications. A declaration names the
application's process modules, entry points, data and port grants. The host
admits those entries, runs them under a shared execution budget, and
supplies mechanisms such as HTTP and SQLite revision storage.

## Four small examples

Build on Linux with Rust 1.88 or newer and SQLite development libraries.

```bash
cargo build --locked --release
encounter=target/release/encounter

# Hello world on stdout
"$encounter" run --declaration examples/hello application.rel

# Read one command-line argument. Omit it to see usage.
"$encounter" run --declaration examples/cli application.rel "Ada Lovelace"

# Run the declared Encounter tests. Failures exit nonzero.
"$encounter" test --declaration examples/cli application.rel

# Serve the Encounter page on loopback.
store=$(mktemp -d)
"$encounter" serve --declaration examples/web application.rel "$store" 8080
```

Open [the demo](http://127.0.0.1:8080/) or request it with `curl`. The web
demo uses the same server as the compiled apps. It runs in the foreground
and exits cleanly on SIGTERM, so a supervisor can run it as a daemon.

```bash
systemd-run --user --collect --unit=encounter-demo \
  --property="WorkingDirectory=$PWD" \
  "$PWD/$encounter" serve --declaration examples/web application.rel "$store" 8080
systemctl --user stop encounter-demo
```

Stop the foreground instance before starting the supervised instance on
the same port. `examples/smoke.sh "$encounter"` exercises stdout, CLI
arguments and failures, the declared tests, and a pinned compiled web
image on an ephemeral port.

## Compile and serve an image

```bash
scratch=$(mktemp -d)
pin=$("$encounter" build examples/web application.rel "$scratch/web.rel")
"$encounter" serve --image "$scratch/web.rel" "$pin" "$scratch/store" 8080
```

An image binds its compiled instructions and data to the exact executable.
Rebuild the image after changing the runtime. For a supervisor, a
[REL launch file](spec/platform.rel) pins the executable's image and
selects the external store and loopback port.

## Contracts

- [Platform](spec/platform.rel) defines declarations, CLI and test entries,
  image identity, launch configuration and store compatibility.
- [Application ports](spec/application-ports.rel) defines the available
  capabilities. Each application declares its own grants.
- The process module uses the Temple surface syntax. This crate builds from
  its own checkout. A journal-backed application can use a separate Temple3
  adapter at its own boundary.
