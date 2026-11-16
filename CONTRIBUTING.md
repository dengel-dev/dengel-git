# Contributing

Open a GitHub issue for a bug or use a pull request to propose a change.
For bug reports, include the Dengel Git version, Git client version, operating
system and the expected and observed behavior. Use [private reporting](SECURITY.md)
for security issues. Community support is best effort.

Run `cargo test --locked --workspace` and
`bash tests/git-conformance.sh local` before sending a patch. Changes to the
Git primitives belong in the bundled RustGit crate and are tested alongside
the server. Contributions to this source tree use the [project license](LICENSE).
