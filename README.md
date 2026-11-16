# Dengel Git

Dengel Git is a standalone Git server for smart HTTP. Use stock Git to
clone, fetch, and push. The hosted Dengel Git adapter uses the same engine.
RustGit, the bundled Rust implementation of Git object and repository
storage, lives under `rustgit/`. A fresh source checkout builds with
locked crates.io dependencies and needs no GitHub credentials.

Dengel Git and RustGit are distributed under
[AGPL-3.0-or-later](LICENSE). The source distribution contains both crates.
See [NOTICE](NOTICE) for copyright information.
See [RustGit provenance](rustgit/README.md) for the imported revision.

## Quickstart

Install stable Rust, a C linker (for example, the Ubuntu `build-essential`
package), and Git. From the source directory, build the server and start it
with an empty bare repository:

```sh
cargo build --release --locked --bin dengel-git
target/release/dengel-git --version
mkdir -p repositories/example
git init --bare --initial-branch=main repositories/example/demo.git
target/release/dengel-git serve-http --root repositories
```

Leave the server running. In a second terminal, clone, push one commit,
then verify it in a fresh clone:

```sh
git clone http://127.0.0.1:8080/example/demo.git demo
printf 'Hello from Dengel Git\n' > demo/README.md
git -C demo add README.md
git -C demo -c user.name="Dengel Example" -c user.email=example@example.com commit -m "First commit"
git -C demo push origin HEAD:refs/heads/main
git clone http://127.0.0.1:8080/example/demo.git readback
git -C readback log -1 --oneline
git -C readback fsck --full --strict
```

The log should show `First commit`. Stop the local server with Ctrl-C.
The default listener is loopback-only and allows local read and write access.

## Deploy with authentication and TLS

For network access, provide a mode-0600 JSON file via
`DENGEL_GIT_TOKEN_FILE` with a list of grants:

```json
[
  {"repository":"example/demo.git","token":"<long random secret>","access":"write"}
]
```

Use distinct tokens per repository or client. A read grant can fetch and
clone. A write grant also permits Git pushes. Expose the listener behind
TLS. Restart after changing credentials or provisioning repositories.
The directory catalog serves case variants of a canonical ASCII address
and refuses startup on collisions. Use `org/repo.git` subdirectories
or a flat `repo.git` layout for a single owner.

Let the listener own writes to the served repository directories. Stop all
writers before running stock Git maintenance directly on those directories.
After an interrupted push the listener checks the durable publication
intent before serving a wire snapshot. Use strict `git fsck` to verify a
restored backup.

Current experimental receive ceilings are 64 MiB of pack input,
256 MiB of inflated entry data and delta work, 100,000 objects and 1,024
ref commands. The standalone listener admits two simultaneous HTTP receives.
HTTP and stdio stage the wire pack on disk. Incoming blob contents, delta
instructions and results stay in a temporary spool, and the standalone pack
is encoded directly to disk before quota admission and publication. The
connectivity walk retains object IDs, and parsing structured objects or
resolving bases from existing deltified packs can still allocate per object.
The receive ceilings apply to each push, independent of repository size.

## Back up and restore

Stop every writer before backing up the repository root. Back up the token
configuration separately with its original access restrictions. Extract the
backup into a fresh directory and run `git --git-dir=<restored-repo> fsck
--full --strict` for each repository. Compare `git show-ref` with the inventory
recorded at backup time, then point the listener at the restored root.
Verify fresh clones and ref readback before serving writes again.

See [Security](SECURITY.md) and [Contributing](CONTRIBUTING.md).

## Test the same wire contract

```sh
cargo test --locked --workspace
bash tests/git-conformance.sh local
```

The hosted fixture calls this script with a scoped candidate token. Both
modes check stock Git clone, two-ref atomic push, fetch, exact refs and strict
`git fsck`. The standalone mode also checks mixed-case addresses and tags.
The hosted mode verifies protection of the primary branch.

## Project links

Dengel hosts the canonical public source. GitHub mirrors released source
at [dengel-dev/dengel-git](https://github.com/dengel-dev/dengel-git).
[Dengel CLI](https://dengel.dev/docs/cli) is the separate client for the
hosted Dengel Gateway.
