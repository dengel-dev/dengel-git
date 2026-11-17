# RustGit

RustGit supplies the pack codec, protocol framing, and ref primitives shared
by standalone Dengel Git and the hosted adapter. It is included in the
Dengel Git source distribution under the [GNU AGPL](../LICENSE).
RustGit ships with Dengel Git. See the [server quickstart](../README.md)
for a working clone and push with stock Git.

## Code and tests

- `src/pack/` handles pack data, indexes, deltas, and object storage.
- `src/protocol/` handles Git protocol framing and fetch negotiation.
- `src/refs/` handles loose and packed refs, locking, and ref transactions.

From the Dengel Git checkout root, run `cargo test --locked -p rustgit`.
The differential tests compare behavior against stock Git. The release
gate uses Git 2.47.3 as its oracle. See the [corpus instructions](corpus/README.md)
for the optional external fixture runs.

## Provenance

The source, test harnesses, and fixture descriptions come from the RustGit
revision `a033d530126c87ba424ae38ab0b2b4006e864eae`. The revision and its
19 ancestors are attributed to Nico Lumma. The upstream spike records
describe the use of Git format documentation and stock Git as a
behavioral oracle. The fixture directory contains generation instructions
and repository references. External fixture repositories are fetched
separately by people who choose to run the corpus tests.
