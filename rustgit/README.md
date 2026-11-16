# RustGit

RustGit supplies the pack codec, protocol framing, and ref primitives shared
by standalone Dengel Git and the hosted adapter. It is included in the
Dengel Git source distribution under the [GNU AGPL](../LICENSE).
This crate has no separate release.

The source, test harnesses, and fixture descriptions come from the RustGit
revision `a033d530126c87ba424ae38ab0b2b4006e864eae`. The revision and its
19 ancestors are attributed to Nico Lumma. The upstream spike records
describe the use of Git format documentation and stock Git as a
behavioral oracle. The fixture directory contains generation instructions
and repository references. External fixture repositories are fetched
separately by people who choose to run the corpus tests.
