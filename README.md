# Dengel Git

Dengel Git is a standalone Git server for smart HTTP. Use stock Git to
clone, fetch, and push to bare repositories you control. The hosted Dengel
Git adapter uses the same engine. The bundled [RustGit crate](rustgit/README.md)
implements pack and object storage, Git protocol framing, and ref updates.

The release includes the `dengel-git` server source, RustGit, a Cargo lockfile,
and stock Git conformance tests. You can run the server locally without a
Dengel account. Hosted workflows such as Guard reviews and signed delivery
Receipts are part of the [Dengel service](https://dengel.dev/docs).

Dengel Git and RustGit are distributed under
[AGPL-3.0-or-later](LICENSE). The source distribution contains both crates.
See [NOTICE](NOTICE) for copyright information.
See [RustGit provenance](rustgit/README.md) for the imported revision.

## Quickstart

Use two terminals on the same machine. You need stable Rust with Cargo, a
system linker (Xcode Command Line Tools on macOS or `build-essential` on
Ubuntu), and Git 2.28 or later for `git init --initial-branch`. Cargo downloads
the locked dependencies from crates.io on the first build.

### 1. Get the release and start the server

Clone the v1.0.0 tag from Dengel, or download the source archive and its
SHA-256 checksum from the [GitHub release](https://github.com/dengel-dev/dengel-git/releases/tag/v1.0.0).
If you use the archive, check it with
`shasum -a 256 -c dengel-git-v1.0.0-source.tar.gz.sha256`, extract it, and run
the build commands from the directory containing `Cargo.toml`.

In the first terminal, run:

```sh
git clone --branch v1.0.0 https://git.dengel.dev/dengel/dengel-git.git
cd dengel-git
cargo build --release --locked --bin dengel-git
target/release/dengel-git --version
mkdir -p repositories/example
git init --bare --initial-branch=main repositories/example/demo.git
target/release/dengel-git serve-http --addr 127.0.0.1:8080 --root repositories
```

The version command should print `dengel-git 1.0.0`. Leave the server running
on loopback. On this default configuration, local clients can read and write
without credentials. Use a disposable repository for this exercise.

### 2. Push a commit and verify the result

In a second terminal, start in a directory with no `demo` or `readback`
directory. Clone, push one commit, and read it back in a fresh clone:

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

The empty repository warning on the first clone is expected. The final log
should show `First commit`, and `git fsck` should exit successfully. Stop the
server with Ctrl-C when finished.

- If the address is already in use, choose another loopback port with
  `--addr` and use that port in both clone URLs.
- If the repository returns 404, check the case-normalized address and
  restart the server if you initialized the bare repository after starting it.
- If Git asks for credentials during the local exercise, check whether
  `DENGEL_GIT_TOKEN_FILE` or `DENGEL_GIT_TOKEN` is set in the server environment.

## Deploy with authentication and TLS

For network access, provide a mode-0600 JSON file via
`DENGEL_GIT_TOKEN_FILE` with a list of grants:

```json
[
  {"repository":"example/demo.git","token":"<long random secret>","access":"write"}
]
```

Use distinct tokens per repository or client. A read grant can fetch and
clone. A write grant also permits Git pushes. When Git prompts, use a username
such as `git` and enter the token as the password. Use a credential helper
to store it. Terminate TLS at a reverse proxy and keep the listener behind
it. Restart after changing credentials or provisioning repositories.
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

- [Canonical Dengel repository](https://dengel.dev/dengel/dengel-git)
- [GitHub mirror and issue tracker](https://github.com/dengel-dev/dengel-git)
- [v1.0.0 source archive and checksum](https://github.com/dengel-dev/dengel-git/releases/tag/v1.0.0)
- [Hosted Git quickstart](https://dengel.dev/docs/git)
- [Dengel CLI](https://dengel.dev/docs/cli), the separate Apache-2.0 client for the hosted Gateway
