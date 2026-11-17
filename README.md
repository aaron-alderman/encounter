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
the same port. Run `cargo test --test example_smoke` from this package to
exercise stdout, CLI arguments and failures, the declared Encounter tests,
and a pinned compiled web image on an ephemeral port.

The CLI, hello and web example declarations are authored in
`examples/*/application.loader.encounter`. In the shared development checkout,
run these commands from this package to regenerate or check their loader REL.

```bash
node ../encounter-platform/shared/node/loader-declarations.cjs --write examples/{cli,hello,web}/application.rel
node ../encounter-platform/shared/node/loader-declarations.cjs --check examples/{cli,hello,web}/application.rel
```

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

### Application packages

Use `encounter check-package PACKAGE_DIRECTORY` before installing a staged
application. The image builder, browser builder, and boot paths check the
package themselves. A package fails if any file has a JSON, MJS, Python, or Rust
extension, regardless of case or whether a declaration references the file.
Package entries must be regular files or directories. Supply the staged package
root to build and boot commands. Keep development tools, test runners, native
adapter sources, and build diagnostics outside that directory.

The legacy browser build format uses JSON inputs and emits JSON projections.
Those releases need to migrate their app data to REL and keep diagnostics
outside the package before they can pass the gate.

### Linux release packaging

`encounter package-release RUNTIME_SOURCE VERSION BINARY OUTPUT_DIRECTORY [BINARY_SHA256]`
verifies the loader projections, guard locks, and compiled image pins. Supply
the independent build artifact SHA-256 when packaging a separate runtime.
The packager uses the running executable in-process when its bytes match
the supplied runtime. The preserved 0.1.0 baseline already has an authored
pin. A separate admitted runtime still builds and checks its own images.

`encounter package-platform-release RUNTIME_SOURCE VERSION BINARY OUTPUT_DIRECTORY [BINARY_SHA256]`
uses the 12-app platform catalogue and its loader and guard checks.
`encounter stage-temple3 PLATFORM_RUNTIME TEMPLE3_SOURCE` verifies the platform
runtime's `temple3.sha256` and publishes the pinned intake to a fresh
`research/temple3` directory in that platform checkout.

`encounter check-guard-pins PROJECTS_ROOT [APPLICATION]` checks the guard
library and each selected application's source lock. Use
`encounter build-guarded-image PROJECTS_ROOT APPLICATION VERSION BINARY OUTPUT [BINARY_SHA256]`
to build and publish an individual guarded image with the same checks.
`encounter promote-guards PROJECTS_ROOT GUARD_VERSION CANDIDATE_DIRECTORY COMPILERS_REL`
runs the mixed-version qualification and rollback before publishing a new
canonical guard version.

The native archive writer keeps the existing sorted GNU tar payload and writes
a deterministic gzip stream. Its compressed checksum can differ from the
historical GNU gzip output. Existing archives and checksum files are kept
intact.

### Native browser host

`encounter browser-host APP_ROOT DECLARATION ASSETS PORT` serves a loopback
publication with a native Encounter session per browser connection. The REL
declaration lists `browser.boot`, any event entries, and their grants. Load
`/_encounter/browser.mjs` as a module in the page to connect. Rust owns the
process, volatile state, registered event routes, and admission. The browser
bridge supplies DOM observations and origin-local storage.

Children are admitted from Encounter source and executed with a connection-bound
ticket, fresh locals, and the caller's meter. Keep source or a domain receipt
for replay across reloads. A ticket expires with its connection. The
[browser port contract](spec/browser-ports.rel) lists the supported effects.

Ask Aster uses the platform `browser.asterStream` port. The application
declares the port and the browser event entry. The operator approves it with
`browser-host --allow-aster-stream`. The bridge takes the short-lived watch
from the authorized Aster response, strips its credential before returning
the fragment, and opens a stream for that thread at the fixed same-origin
Aster event endpoint.

Run the example with `encounter browser-host examples/browser application.rel
examples/browser/assets 0`. The Chromium verification on aaron-dev is
`node tests/browser-example.mjs PATH_TO_ENCOUNTER` after sourcing the workspace
browser profile.


`encounter browser-host --surface CONFIG ASSETS PORT` also runs a pinned
Temple surface-process image. This is a compatibility launch profile for
already lowered publications. Its REL configuration declares the image and
SHA-256 pin, boot and preparation entries, optional local agent entry, granted
ports and the bindings a prepared child may receive. The checked image contains
`model` and `data`. See [the surface profile](spec/browser-surface.rel).

A successful configured preparation seals the exact admitted child for the
current connection. Native execution checks the seal and the model identity.
The seal is private to the evaluator and absent from JSON, browser effects,
and persisted values. Children share the caller's meter and use only the
restricted child ports. Saved work replays by preparing its source again.

`encounter build --browser APP_ROOT DECLARATION LIBRARIES OUTPUT` compiles a
surface publication with its pinned Encounter frontend, lowerer and admission
algebra. The REL build declaration selects source owners and render entries.
The output directory must be new. It contains `published.surface`, a pinned
`launch.rel`, `assets/`, source projections and maps, and a deterministic
`build-receipt.rel`. Serve it with the surface browser profile above.
See the [browser build declaration and receipt](spec/browser-build.rel).

The same command accepts a browser Wasm declaration. From the Encounter
checkout, build the Front Gate countdown into a new directory:

```sh
encounter build --browser browser countdown.rel browser /path/to/countdown-build
node tests/browser-wasm.mjs /path/to/encounter
node tests/browser-clients-wasm.mjs /path/to/encounter
```

The builder emits `browser.wasm`, a REL export-to-source map, and a receipt
pinning the inputs, outputs, and compiler. The output directory becomes visible
once the complete bundle is written. This target accepts finite Number and
Boolean parameters, local bindings, conditional scalar expressions,
and the supported `number.calculate` operations. Text observations can be
compared with each other or with short authored literals. The browser lowering
of `text.matches` accepts a literal, fully anchored character class
such as `\\A[A-Za-z0-9_-]{1,80}\\z`. A literal prefix and a leading
single-character class are both optional, as in `\\Adata-[a-z][a-z0-9-]{0,63}\\z`.
The complete match spans at most 128 UTF-16 code units. Each class admits
up to 16 ASCII ranges or individual
characters from Unicode's Basic Multilingual Plane.
A process can call a
declared straight-line scalar helper with typed inputs and return a scalar or a
record of scalar fields. Use a `helper` declaration to keep a scalar helper
private to its module. Helpers can call other declared scalar helpers in an
acyclic chain. Browser code supplies observations as arguments and
performs effects outside the module. A browser declaration can request
`("wasm", "math", "sin")`, `("wasm", "math", "cos")`, `("wasm", "math", "hypot")`, or
`("wasm", "math", "remainder")` for the matching `number.calculate` operations.
The bootstrap supplies those pure functions.

The browser client test uses disposable loopback hosts to check live draft
retention, canvas playback, and preview context selection. Set
ENCOUNTER_ENFORCE_BROWSER_CSP=1 to qualify the pinned clients with CSP
enforced. The test first reports served policy failures for Live Events,
Canvas, and authenticated Preview in one run. Once all three clients
start, it runs the full behavior suite and carries the served policies
over to the synthetic browser documents. The CSP preflight uses the candidate
alone. Pass `--previous-runtime PATH` after the candidate executable to exercise
rollback and compare behavior against a retained Encounter executable that serves
the compatibility clients.

For staged Live Events and Canvas, build `live-events.rel` and `canvas.rel`
with the same command. Set `directory` and `receiptSha256` on the
`live-events` and `canvas` subjects in the image launch configuration.
Pin both clients for a live application that declares `app.canvas`.
For staged Preview, build `preview.rel` and set the same fields on
`preview-client` in the gateway configuration. Use the digest printed by
each build. The hosts verify the receipt, running executable, source pins,
module, and map before listening. The bundled runtime rebuilds the module and
map from its Encounter sources and requires identical bytes. Hosts serve the
admitted module bytes under the existing script URL with an `X-Encounter-Browser-Wasm` receipt header.
Pinned scripts require WebAssembly and omit the JavaScript compatibility
policies. Unpinned configurations retain those policies.

Build Home's complete catalog with browser/appdev.rel. The current runtime
rejects partial Home catalogs bound to its executable. Retained releases
with older catalog formats use their bundled runtime.

Launch a native build release with
`encounter browser-host --release DIRECTORY RECEIPT_SHA256 PORT`.
Capture the receipt digest from the verified build and retain it separately
from the release directory. The release launcher checks the running executable,
launch declaration, image, and artifact bytes before listening. It serves the
verified asset bytes captured at startup. The `--surface` profile remains
available for an operator-supplied surface image and asset directory.

The package-policy browser regression runs with
`node tests/package-policy.mjs PATH_TO_ENCOUNTER` after sourcing the
workspace browser profile. It checks unreferenced forbidden files, nested
files, symlink refusal, clean native packaging, boot refusal, both stream
permissions, the fixed stream route and credential removal.

### Gateway identity admission

The gateway evaluates [the Encounter identity policy](src/gateway_identity.encounter)
for the configured identity mode, provider and owner admission, and identity
continuity at sign-in, on HTTP requests, and during WebSocket rechecks.
The same policy selects the private Workspace access and sign-out operations.
Rust validates the token format, reads the fixed loopback identity endpoint,
compares the internal authorization header in constant time, and holds the
session state. The identity endpoint returns length-delimited JSON bounded to
64 KiB. The gateway checks the deadline and body length before evaluating
the policy.

### Public MCP read gateway

`encounter hosted-mcp-authorization SCHEMA SHA256 POLICY SHA256 [LOOPBACK_PORT]`
compiles the authored `stdlib.rel` and `policy.rel` from the hosted control
plane. Supply absolute paths and independent SHA-256 pins. Encounter checks
the authorization interfaces, tool assignments, scope implication graph,
and token lifetimes. With a loopback port it projects the development
resource at `127.0.0.1`. The public profile takes canonical HTTPS URLs.

`encounter hosted-mcp-client CLIENTS SHA256 HOSTS SHA256 SCHEMA SHA256 POLICY SHA256`
reads a client ID and redirect URI as `clientId` and `redirectUri` in a
JSON object on standard input. The pinned client file uses the hosted
preregistration format. The pinned hosts file contains an array of exact
lowercase DNS names for client metadata. Encounter checks the registration
and the exact callback. Metadata requests use a bounded native HTTPS GET
with no redirects or proxies and a connection pinned to an address checked
against the full DNS answer. This command resolves one request. The staged
browser authorization GET uses the service below for cached lookups.

The self-hosted production supervisor uses the same Encounter host, DNS,
and document policy through `hosted-mcp-metadata-settings` and
`hosted-mcp-metadata-resolve` on its release-local native executable. Each
lookup receives the exact manifest hosts and client ID on stdin. It has a
five-second DNS and TLS deadline and returns only the admitted client
identity, display name, and callback URLs. The supervisor retains positive
results using the policy's cache bounds.

The staged [OAuth client service](deployment/sourcery-hosted-mcp-client.service)
uses a dedicated `sourcery-mcp-client` account in group `sourcery-dev`.
It keeps validated metadata for five minutes with a 256-entry cap and accepts
only client ID and callback lookups from the configured Unix peer.
`encounter hosted-mcp-client lookup SOCKET RESOLVER_UID CLIENTS_SHA256 HOSTS_SHA256 SCHEMA_SHA256 POLICY_SHA256`
uses the same standard input. The socket matches the executable and all four
pins. Configure the consumer UID and the pinned client and host files in
`/etc/sourcery-dev/hosted-mcp-client.env`. The resolver has HTTPS egress and
uses no OAuth journal connection or browser signing keys.

`encounter public-mcp-read 8151 SCHEMA SHA256 POLICY SHA256 PROJECT_SOCKET PROJECT_UID` serves the
public read boundary on loopback. It serves both OAuth discovery documents
from the pinned contract and answers anonymous MCP challenges locally.
Modern `server/discover`, `tools/list`, `ping`, and `sourcery_project`
calls go to the native authority over its Unix socket. It verifies the
mirrored MCP headers and the current OAuth or personal application-portfolio
grant. The modern tool list includes the project tool when the grant has
read scope. The public gateway refuses the development catalogue and
answers public dynamic client registration requests locally with 404.
The gateway refuses project-connection coordinates,
which can retain session state, and accepts a project context only on a
tool call. A socket failure or release mismatch returns 503.
Encounter handles public code exchange, refresh, and revocation through the
native authority. Exchange checks the exact retained resource and redirect,
client binding, PKCE, and read scope. PostgreSQL checks the current revision
under the shared OAuth journal lock before consuming a code, rotating a
refresh token, or revoking a credential. Refresh replay revokes the matching
read-only family. Unknown credentials and grants outside the public read
scope return an empty 200 on revocation without changing the journal.
Encounter handles `GET /oauth/authorize` through the matched authority. It
checks the exact resource, S256 PKCE, browser session, portfolio, client and
callback. It creates a pending request under the OAuth journal lock before
serving the consent form. The staged gateway has no upstream HTTP service.
`POST /oauth/portfolio` verifies the existing signed double-submit form
against the current browser session and available applications, then returns
an encrypted continuation to the native authorization handler.
The workspace-selection key is the same
owner-only key used by the existing project-context issuer, with separate
authenticated encryption domains. All admitted MCP calls, including handshake
initialization, notification, and legacy project calls, use the matched
native authority. Handshake clients receive a hash of the public tool
contract and a list-change notification until they list tools on this
authority. The bounded cache keeps no bearer tokens and grants no access.
Encounter handles `POST /oauth/consent` through the matched authority. It
checks the signed form and current session, requires a pending public read
grant, and rechecks portfolio access on approval. It returns the registered
callback after the journal commits the denial or a single code digest.
[The Encounter policy](src/public_mcp.encounter) owns route admission,
the tool and argument allowlists, OAuth scope limits, header custody, and the
JSON and SSE response projections. The host adapter buffers bounded HTTP
requests and replies and sends the same JSON object that passed admission.
Before binding, Encounter requires the pinned authorization contract to match
the public audience, issuer, and tool scopes. The public read scope must grant
no additional scopes through implications.

The [service unit](deployment/sourcery-public-mcp-read.service) expects this
runtime at `/usr/local/libexec/sourcery-public-mcp-read`. It uses the
existing loopback ports and service account. The release supplies
`SOURCERY_MCP_SCHEMA`, `SOURCERY_MCP_SCHEMA_SHA256`,
`SOURCERY_MCP_POLICY`, `SOURCERY_MCP_POLICY_SHA256`, and
`SOURCERY_MCP_PROJECT_UID` in
`/etc/sourcery-dev/public-mcp-authorization.env`. If the public ingress
provides a browser login route, set `SOURCERY_HOSTED_BROWSER_LOGIN_PATH` to
its same-origin path.

### Hosted MCP workspace authority

`encounter hosted-mcp-workspace-access SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256 TENANT APP PROJECT WORKSPACE`
reads one OAuth access token or personal application-portfolio credential
from standard input. Supply the exact workspace
coordinates resolved by the host. The command checks the token's audience,
expiry and revocation, the current tenant and project membership, and the
complete workspace lineage. Its grant includes only scopes shared by the
token and current role.

The native mechanism uses `libpq.so.5` with a local Unix socket. The
[PostgreSQL projection](deployment/hosted-mcp-access.sql) reads the OAuth and
control-plane documents in one statement snapshot. Apply it using the
database owner, then grant a dedicated peer-authenticated role only
`USAGE` on `sourcery_mcp_access` and `EXECUTE` on the projections
`sourcery_mcp_access.workspace_snapshot(text, text, text, text, text)`,
`sourcery_mcp_access.portfolio_snapshot(text)`,
`sourcery_mcp_access.credential_snapshot(text)`, and
`sourcery_mcp_access.oauth_scope_snapshot(text, text)`. Discovery methods
use the credential projection, which omits workspace inventory. The OAuth
scope projection returns scope and resource evidence without retained
credential digests or grant contents. Grant `EXECUTE` on
`sourcery_mcp_access.oauth_exchange_snapshot(text,text,text,text,text,text)`,
`sourcery_mcp_access.public_oauth_exchange(text,text,text,text,text,text,bigint,jsonb)`,
and `sourcery_mcp_access.public_oauth_revoke(text,bigint)` to the same
dedicated role. The exchange write is capped at 900 seconds for access
tokens and 2,592,000 seconds for refresh tokens. PostgreSQL receives token
digests and the PKCE proof digest. The role needs no direct table write
permission.
Grant `EXECUTE` on `sourcery_mcp_access.browser_session_snapshot(text)` and
`sourcery_mcp_access.browser_portfolio_snapshot(text)` for the private browser
operations. The portfolio lookup derives the verified subject and eligible
applications from one control-plane snapshot and returns only the subject,
portfolio IDs, scope, and display names. It shares the project inventory's
membership, lineage, ordering, and workspace cap. PostgreSQL receives only the
session token digest. The native portfolio POST uses this projection. Grant
`EXECUTE` on `sourcery_mcp_access.browser_consent_snapshot(text,text,text)`,
`sourcery_mcp_access.browser_consent_ready(text)`, and
`sourcery_mcp_access.commit_browser_consent(text,text,text,bigint,bigint,bigint,text,text,text)`
for consent. The commit checks a purpose-bound proof from the native
authority and locks the matched control-plane and OAuth revisions. A stale
revision triggers one fresh evaluation of the signed request. The database
role needs no access to the key table or the proof helper.
Grant `EXECUTE` on
`sourcery_mcp_access.begin_browser_authorization(text,bigint,bigint,text,text)`
for pending requests. The journal checks a distinct proof bound to the
session, current control-plane revision, deadline, and exact request.
The command sends the token digest, the credential ID for a personal token,
and the workspace coordinates. The projection omits stored digests,
secrets, and unrelated authority records. The staged project authority
checks the projection version before binding its socket.

`encounter hosted-mcp-project open KEY SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256 TENANT APP PROJECT WORKSPACE`
reads a hosted MCP credential from standard input. It checks current read
access before issuing an opaque project context for that workspace. The
`resolve` operation uses the same configuration without workspace
coordinates and reads a two-element JSON array containing the access token
and the context. Encounter checks the context's expiry and binds it to the
current user, client, credential family, and workspace.

The key is an owner-only 32-byte file. The hosted authority can use the same
key as the existing issuer to preserve issued contexts. Rust uses the
existing AES-256-GCM format and the fixed project-context associated data.

`encounter hosted-mcp-project tool KEY SOCKET PORT DATABASE ROLE SCHEMA SHA256 POLICY SHA256`
reads a two-element JSON array containing the access token and a
`tools/call` request for `sourcery_project`. Encounter returns the MCP
`list` or `open` result from one database snapshot. It derives the
portfolio from the bearer grant, applies current membership, and issues a
context only for a unique accessible workspace. The projection omits labels
and coordinates from other portfolios. The inventory preserves the existing
500-workspace limit and rejects a projection above 4,096 candidates or 4 MiB.

The staged [project authority service](deployment/sourcery-hosted-mcp-project.service)
keeps the project-context key under the hosted service account. The gateway
account can connect to its group-restricted Unix socket. Each side verifies
the peer UID and a release identifier derived from the running executable
and both authorization pins. The hosted service environment file supplies
`SOURCERY_MCP_GATEWAY_UID`, `SOURCERY_MCP_PROJECT_KEY`, `SOURCERY_MCP_CONSENT_KEY`,
`SOURCERY_MCP_CONSENT_COMMIT_KEY`,
`SOURCERY_MCP_DATABASE_SOCKET`, `SOURCERY_MCP_DATABASE_PORT`,
`SOURCERY_MCP_DATABASE_NAME`, and `SOURCERY_MCP_DATABASE_ROLE`.
The consent key is the owner-only 32-byte key used by the retained form
signer. Use a separate owner-only 32-byte file for the commit key. As the
database owner, provision the same raw bytes in the `secret` column of
`sourcery_mcp_access.browser_consent_key` with `singleton = true`, using a
bound bytea parameter. The service verifies the key matches PostgreSQL
before binding its socket.
Set `SOURCERY_MCP_CLIENT_UID` in the client service environment and set
`SOURCERY_MCP_CLIENT_CONSUMER_UID` to the project authority's UID. The project
authority requires the resolver to match both client configuration pins and
both authorization contract pins before binding.

### Server Temple startup readiness

`encounter server-temple-readiness CONFIG` uses the Server Temple host's
existing configuration and readiness receipt format. Encounter verifies the
capsule manifest, journal, objects, projections, and bridge messages against
one read-only SQLite snapshot. It then checks the declared loopback endpoint
and, when configured, the transit endpoint's capsule identity. The Rust
adapter reads the database and uses bounded, redirect-free loopback HTTP.
`encounter inspect-server-temple-capsule FILE` runs the capsule check by itself.

`encounter server-temple-checkpoint CONFIG` takes a one-shot checkpoint of an
initialized capsule with no writer lease. It uses the existing state-source
manifest and owner-only Temple key, and commits the retained objects, live-state
projection, and journal event in one SQLite transaction. Use the command on
an offline capsule or a disposable copy.

`encounter server-temple-custody CONFIG` holds the initialized capsule's
writer lease and checkpoints its configured sources. It uses the existing
lease and checkpoint intervals. Encounter admits each acquisition and renewal,
and rechecks the lease before a checkpoint commits. On exit, the process
releases its own lease.
When the existing configuration declares `transport`, custody also serves
`GET /health` and `POST /v1/transit` on its loopback listener. Encounter
checks the bundle, peer admission, signed envelope, and receipt correlation.
The adapter signs the admitted acknowledgement with the Temple identity and
commits the inbox, outbox, and journal together under the same writer lease.

With `publicPublication` configured, custody serves Temple discovery, the
signed catalogue retained in the capsule, and its exact plugin bytes.
Encounter checks host, method, expiry, and artifact identity. The adapter
verifies the retained catalogue signature and signs the discovery descriptor
with the Temple key. Fresh catalogue authoring still uses the plugin validator
and signed catalogue producer. A configuration with a pending publication
fails startup until that authoring step is complete and the pending request is
cleared.

`encounter server-temple-host CONFIG` adds application supervision to
custody. Its `nativeApplication` record has five fields. Set `protocol` to
`encounter/server-temple-application/1`, `image` to the absolute canonical
Encounter image path, `sha256` to the image digest, `store` to an existing
owner-only directory, and `port` to the loopback port (or zero to allocate
one). The launcher verifies the image and its Encounter runtime pin before
acquiring the writer lease. It accepts only the native image launch
contract and rejects legacy executable, argument, and environment overrides.
It records application lifecycle events in the capsule and takes a final
checkpoint after the child exits on graceful shutdown.
The installed development MCP service still uses the Node supervisor and
application.

The [staged drop-in](deployment/sourcery-development-mcp.service.d/zzzzzzzz-native-readiness.conf)
uses the native runtime at `/usr/local/libexec/sourcery-server-temple-readiness`
for the development MCP unit's startup readiness step.

For an artifact with a pinned native application image and a protected
`encounter` executable, run the installer from that artifact. The existing
host configuration must already declare the native application. The command
updates readiness and transit settings and writes the native systemd drop-in.
Pass an empty JSON object for the defaults. The optional fields are
`endpoint`, `timeoutMs`, and `intervalMs`.

```sh
/absolute/artifact/encounter install-server-temple-readiness \
  /absolute/artifact /etc/sourcery-dev/server-temple-host.json \
  /etc/systemd/system/sourcery-development-mcp.service.d/zzzzzzzz-native-readiness.conf <<'JSON'
{}
JSON
```

### Runtime grant authority

`encounter runtime-authority` uses the existing
`SOURCERY_RUNTIME_AUTHORITY_*` settings, private Ed25519 PKCS#8 key, and
workload registry. [The Encounter policy](src/runtime_authority.encounter)
admits exact workload scopes and operations, projects evidence hashes, and
authorizes signing only for canonical runtime grants with bounded lifetimes.
The Rust adapter owns the Unix socket and signs the exact admitted bytes.

The [hosted unit](../game-migration/sourcery-platform/deployment/hosted/sourcery-runtime-authority.service)
expects this runtime at `/usr/local/libexec/sourcery-runtime-authority`.
The private key must be owner-only, and the socket directory must be owned
by the service user. Run the existing client and service regression tests
with `ENCOUNTER_RUNTIME_AUTHORITY_BINARY` pointing to the built executable.

### Hosted Google identity

The [hosted unit](../game-migration/sourcery-platform/deployment/hosted/sourcery-google-identity.service)
expects the Encounter executable at `/usr/local/libexec/sourcery-google-identity`.
It runs `google-identity-custody` before starting `google-identity` under the
existing `sourcery-identity` service account. The broker opens the verified
credential through the fixed `/etc/sourcery-google` directory and binds to
loopback. [Encounter policy](src/google_identity.encounter) governs login,
PKCE and nonce checks, and browser session cookies. The broker submits the ID
token to the existing loopback control plane for signature and identity
admission before setting a session cookie.

For installations with retained credentials under `/etc/sourcery-google-identity`,
run `/usr/local/libexec/sourcery-google-identity google-identity-migrate-custody`
as root while the service is inactive. The command takes the matching unit from
the hosted release, retains the legacy credentials and original unit backup,
and verifies canonical custody before reloading systemd. On interruption or
reload failure it restores the prior unit and credential files.

### Self-hosted operator identity

The [hosted operator unit](../game-migration/sourcery-platform/deployment/hosted/sourcery-identity.service)
expects the Encounter executable at `/usr/local/libexec/sourcery-self-hosted-identity`.
`self-hosted-identity` loads the existing protected P-256 private JWK and
scrypt record. [Encounter policy](src/self_hosted_identity.encounter) admits
the login request and challenge, sets assertion claims, and validates the
session issued by the loopback OIDC control plane. Rust supplies bounded
request handling, password verification and ES256 signing. Run the existing
identity test with `ENCOUNTER_SELF_HOSTED_IDENTITY_BINARY` set to the built
executable to exercise the native broker with the hosted OIDC verifier.

Use `sudo /usr/local/libexec/sourcery-self-hosted-identity self-hosted-identity-prompt`
to enter the secret on a terminal. Encounter admits the secret length and
credential parameters. The command stages the protected JWK and password
record at `/run/sourcery-identity-staging` and writes the public key ID to
`/run/sourcery-identity-key-id`. It refuses to replace either path. For
automation, `self-hosted-identity-provision DIRECTORY` reads from standard
input and prints only the key ID.

`self-hosted-production-custody DIRECTORY` generates separate protected
assignment and runtime authority Ed25519 keys and interaction secrets. Its
Encounter policy binds the local preflight OAuth client, verification key and
workload scope. It publishes the complete custody directory only when the
target is absent and prints a receipt with public identifiers.

### Hosted TLS deployment and Timesheet rehearsal

For the hosted certificate deploy hook, place the built Encounter executable
at `/etc/letsencrypt/renewal-hooks/deploy/sourcery-nginx-reload`. Certbot calls
that executable with no arguments. Encounter admits the reload only after
the fixed nginx configuration validation succeeds.

`rehearse-timesheet-restore ARCHIVE EXPECTED_SHA256 BEFORE_MANIFEST AFTER_MANIFEST TARGET`
checks the archive digest and matching manifests before restoring to a private
staging directory. It admits only path-bound regular files and directories
and publishes a complete rehearsal under `/srv/sourcery/restore-rehearsals`.
It prints a receipt for the restored file set and never starts Timesheet.

### Hosted PostgreSQL provisioning

`encounter provision-self-hosted-postgres` runs under root and uses the
dedicated `postgres` and `sourcery` Unix accounts. It connects only through
the local PostgreSQL socket and applies the bounded role, database and
schema grants selected by [Encounter policy](src/postgres_provision.encounter).
It reports readiness after checking primary status, checksums, privileges
and application peer authentication. The command can be rerun after an
interruption. It uses no PostgreSQL CLI or shell script.

Production startup uses `encounter hosted-postgres-readiness` to check the
configured database and role in a serializable, read-only transaction over
the Unix socket. It checks primary status and checksums. PostgreSQL 16 and
later must also report peer authentication. The Node transaction pool uses
the same Encounter connection configuration and refuses password requests.

The runtime grant audit uses [Encounter policy](src/runtime_grant_audit.encounter)
for event projection, hash-chain validation, retention, and snapshots. Its
PostgreSQL adapter locks the existing journal and commits the next revision
in a serializable transaction over the peer socket.

### Sourcery development receive hook

Install the Encounter executable as `/srv/git/sourcery.git/hooks/post-receive`
for Git receives running under `sourcery-dev`. The hook advances only
`refs/heads/codex/self-hosted-production` in `/srv/sourcery/dev/sourcery`,
and only when the checkout is clean and the received commit is still the
canonical branch tip. The native Git adapter imports a checked object pack
from the fixed local repository and performs a fast-forward merge. The hook
leaves service lifecycle management to the development supervisor.

### Hosted workspace storage

Production invokes fixed native operations for workspace durability,
provisioning, and lookup. Encounter admits the immediate-child storage
root, excludes memory filesystems, and binds the exact workspace marker
to tenant and workspace lineage. The native probe synchronizes, reopens,
and removes a private test file. It preserves the existing volume identity.
Provisioning stages a complete marker before publishing it and compares
existing marker bytes on retries. Directory descriptors prevent namespace
traversal through symlinks.

### Hosted workspace source bootstrap

Run the Encounter executable from the release named by the production
manifest. The operator command accepts the same authorization file and
manifest options as the retired JavaScript entry point.

```sh
./encounter hosted-workspace-bootstrap --authorization-evidence-file /path/to/authorization.json
./encounter hosted-workspace-bootstrap --authorization-evidence-file /path/to/authorization.json --execute PLAN_SHA256
```

Use the plan hash returned by the first command. The authorization and
manifest files must be root-owned, group-read-only at most, and inaccessible
publicly. Encounter binds the plan to the exact authorization bytes, the
workspace allocation, the approved source tree, and its placement. Publication
exchanges the staged and active directories atomically and retains the
original workspace at the recovery path recorded in the receipt.

### Hosted capability reconciliation

The hosted reconciliation scheduler uses Encounter for its run bounds,
retry delay, and public status. The native inventory reads the existing
private storage markers through directory descriptors and checks the
scope, activation, and binding identities before projecting active targets.
The provider retains the existing marker format and activation IDs.
Activation and unbind use fixed native operations. Activation never
replaces a retained marker, and unbind publishes a tombstone without
removing the resource data. The adapter synchronizes the marker before
its atomic rename and synchronizes the containing directory before
returning a receipt.

### Hosted release identity

The production service runs the release's Encounter executable directly
with the hosted-production-supervisor command. The native supervisor
owns the stable loopback listener, starts the fixed hosted generation on
a private endpoint, and drains its predecessor after a successful cutover.

Prepare a physical source assembly with
`encounter hosted-prepare-production-release RELEASE_ROOT`. Encounter
derives the production package, flat dependency lockfile, and input proof.
The dependency gate checks the generated lockfile before publication.
Release composition refuses an unfinished preparation. If a process dies
during publication, rebuild the inputs in a fresh source assembly.

Stage the selected release executable with
`encounter stage-hosted-release-runtime RELEASE_ROOT EXPECTED_SHA256` before
composing the hosted dependency closure. It publishes `RELEASE_ROOT/encounter`
only when the executable matches the supplied pin. The supervisor and its
generation worker use that bundled executable for Temple freeze attestation
and source-tree identity. The source identity includes the executable bytes,
so a generation cannot attest against a different runtime than its release.
Encounter admits the hosted listener, proxy mode, state paths, worker
limits, and operations enablement. The production worker uses the fixed
self-hosted infrastructure factory in its own release. The configured
module path must name that factory, and the source tree observation always
includes the production plugin tree. The state directory cannot overlap
that tree or the release executable.
After the child reports readiness, the supervisor reads the admitted release
again and gives that observation to Encounter's cutover decision. An unavailable
or changed pointer closes the candidate and leaves the prior generation
eligible to serve. Shutdown also closes a pending candidate before stopping
the active generation.
The dependency installer uses that executable to check the Temple archive
pin and unpack it into a private staging directory. It publishes the SDK
only after the staged tree matches the freeze pin.
Encounter also checks the release inputs before dependency installation and
rechecks them against the retained payload before publishing its dependency
view, composition receipt, and rollback evidence. It refuses to replace an
existing view or receipt.
The dependency composer populates the flat production lockfile emitted by
the release generator with `hosted-populate-dependencies`. Each package
comes from its fixed registry URL and must match the locked SHA-512 before
it can be unpacked. The command creates binary links without executing any
package code. The population protocol uses a distinct closure key from
older npm-populated releases.

Use `encounter hosted-compose-release RELEASE_ROOT TEMPLE_ARCHIVE ARCHIVE_SHA256 TREE_SHA256 RELEASE_EVIDENCE_INPUT CLOSURE_ROOT NODE_VERSION NODE_ABI`
to retain and publish a hosted closure. The explicit version and ABI describe
the target application runtime and are part of the closure key. The command
does not run that runtime during composition.

Use `encounter hosted-audit-dependencies RELEASE_ROOT CLOSURE_ROOT` to
verify the sealed receipts, payload, and dependency links. The hosted
supervisor requires `SOURCERY_HOSTED_DEPENDENCY_CLOSURE_ROOT` and
`SOURCERY_HOSTED_DEPENDENCY_COMPOSITION_SHA256`. Set the latter to the
composer's `composition.compositionHash` for the exact release being started.
The supervisor checks the pinned dependency closure before launching each
generation and again before exposing its route. The worker's native
attestation also checks the closure before and after infrastructure startup.
While the hosted worker still uses Node, set `SOURCERY_HOSTED_NODE_SHA256`
to the verified SHA-256 of `/usr/bin/node`. The supervisor hashes and launches
through the same open descriptor. Before routing, Encounter checks the reported
runtime version, ABI, OS, and architecture against the sealed composition.

`encounter build-self-hosted-worker-image sha256:BASE_IMAGE` builds the
isolated authoring worker image from a pinned Linux amd64 image already in
the operator's local Podman store. It exports the stopped base, stages only
the declared runtime files and package records, then builds from scratch
with pulling and networking disabled. It prints the resulting local image
ID for the existing image admission workflow.

Hosted and local authoring dispatchers use the staged Encounter executable
to issue Ed25519 worker assignments. The issuer sends the request claims and
PKCS#8 key over a bounded stdin pipe. The isolated worker verifies the signed
assignment and checks the request lease when execution starts.

The hosted runtime authority client uses the staged Encounter executable for
readiness, grant signing, and workload identity requests. It connects to the
protected Unix socket and checks the reply against the request and operation
before returning it to the hosted service.

### Assurance report viewer

`encounter assurance-view /srv/sourcery/assurance/current 8145` serves the
retained assurance report families over loopback. [The Encounter policy](src/assurance_view.encounter)
selects the reports and their media types. The host opens each report under the
configured directory and supports GET, HEAD, and Last-Modified revalidation.
The [service unit](deployment/sourcery-assurance-view.service) expects the
runtime at `/usr/local/libexec/sourcery-assurance-view`.

### Disk-pressure assessment

`encounter disk-pressure-assess OBSERVATIONS` reads a bounded
`sourcery/disk-pressure-observations.v1` JSON file and writes a dry-run
assessment to stdout. [The Encounter policy](src/disk_pressure.encounter)
classifies runtimes, releases and dependency closures from inventory and
live-reference observations. It checks evidence seals, file digest
observations and path bindings, retains current and rollback assets, and
recomputes the existing assessment hash.

The observation record carries the existing policy, creation time, authority
marker, active release ID, disk measurements, service and readiness
observations, and the runtime, release, dependency closure and ancillary
inventories. Evidence observations must come from a collector that reads the
underlying artifacts and measures their bytes.

`encounter disk-pressure-scan POLICY` collects those observations from the
host and prints the assessment. `encounter disk-pressure-publish POLICY`
uses the same scan, writes the hash-addressed history record, and updates
`assessment.json`, `index.html`, `approval-gate.html`, and
`assessment.identity` in the existing publication directory. The collector
requires Linux `openat2` for evidence files and refuses publication if it
cannot check the reference inventory or the active release changes mid-scan.
The [staged service unit](deployment/sourcery-disk-pressure-assurance.service)
uses the existing policy, service account, and timer.

### Private file index

`encounter file-index --refresh SOURCES_REL CACHE_DIRECTORY` builds a private
`index.rel` snapshot. `encounter file-index --watch SOURCES_REL CACHE_DIRECTORY 60`
refreshes immediately and then every 60 seconds. Give the cache an existing
private parent directory. The index creates an owner-only cache directory and
replaces the snapshot atomically. Run the watcher as a user who can read the
configured releases and stores.

The watcher and private reader use the same Encounter source in
[`file_index_policy.encounter`](src/file_index_policy.encounter). It declares
provider collections, their permission and authority labels, media roots, and
the current North River ownership rule. The reader supplies the project and
task facts only when their pinned image and store revision match the snapshot.
Rust handles the private socket, store reads, mounted paths, and byte and digest
checks. The policy uses no native grants.

```rel
("index", "format", "encounter/file-index/1")
("index", "source", "home")
("home", "provider", "home-release")
("home", "location", "/absolute/path/to/active-home-release")
("home", "steward", "role:platform-steward")
("index", "source", "kernel")
("kernel", "provider", "kernel-release")
("kernel", "location", "/absolute/path/to/installed-kernel-release")
("index", "source", "games")
("games", "provider", "game-hub")
("games", "unit", "encounter-game-hub-preview.service")
("index", "source", "north-river")
("north-river", "provider", "north-river")
("north-river", "unit", "encounter-https-pilot-live.service")
```

Release locations point to directories containing the pinned manifest and may
be active-release symlinks. App sources accept either an absolute image-mode
Encounter launch configuration as their `location` or a user systemd service
as their `unit`. The watcher resolves the binding each cycle and reads app
documents from a consistent committed revision through a read-only connection.
Changing the path of a fixed release location requires updating the sources file.
For user-service sources, Encounter admits the provider and unit name before
the host reads the loaded service's main PID over the invoking UID's Unix
systemd bus. The two read-only calls share a two-second deadline. The reader
then checks the running Encounter launch configuration and verifies its image
pin before indexing any documents.

The release providers index their manifests and pinned artifacts. Game Hub
indexes verified catalog images and published Store asset metadata. North River
indexes pinned North River source modules and canonical plan, import, and demo
decision receipts when present. Files carry logical byte length, digest,
ownership evidence, and a provider read policy. Folders carry file count,
logical bytes, and bytes deduplicated by digest within the folder. Rollups stop
at the collection's permission boundary. Store asset lengths come from
publication metadata. Receipt lengths measure canonical REL exports.

Every provider records its revision, last attempt, and last successful refresh.
When a provider fails, its last successful snapshot for that source binding is
retained with status `stale`. A provider with no previous snapshot is marked
`unavailable`. One-shot refresh reports an incomplete snapshot with a nonzero
exit. `encounter file-index --serve SOURCES_REL CACHE_DIRECTORY SOCKET`
offers a scoped metadata view over a private Unix socket for a trusted
workspace host. The workspace host checks current provider admission before
requesting any collection. See the AppDev workspace setup for socket
permissions and gateway bindings.
