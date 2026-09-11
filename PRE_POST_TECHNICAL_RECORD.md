# AetherGraph — Pre/Post Technical Record

## 1. Purpose

This document records the technical state of the AetherGraph system before a forensic audit and correction, the problems identified during that audit, the changes made, and the resulting corrected state.

It is a technical change record. It does not distinguish between authors, assign ownership of changes, or assess contribution.

**Note on provenance of this document.** The project was not under version control for any of the work described here, so **no commit IDs can be cited for the PRE state or for any individual correction**. A Git repository was initialised only after the work was complete; its initial commit (`c2465aa`) records the corrected state as a whole and does not decompose the change history. Commit hashes in this repository were rewritten twice after that commit was first created --- once to satisfy GitHub's private-email protection, once to remove an automated co-author trailer --- so any hash cited in an earlier revision of this document will not resolve. The PRE state was instead recovered from the archive `E:\AetherGraph.rar` (RAR5, timestamped before the correction work began) and extracted to `E:\AetherGraph\_pre_state_reference\AetherGraph\` for verification. All PRE claims below cite line numbers in that extracted tree. All POST claims cite the live tree at `E:\AetherGraph\AetherGraph\`. Numerical results are read from generated artifacts, not from prose.

---

## 2. PRE — What Was Inherited

### 2.1 Original Architecture

The pipeline collected heterogeneous security evidence, normalised it to JSON Lines, loaded it into a single directed graph, scored nodes and paths, and enumerated cross-layer paths.

| Stage | File (PRE) |
|---|---|
| Active scanning (Nmap + Gobuster, in Docker) | `collectors/run_active.py` |
| Identity / OSINT collection | `collectors/run_identity.py` |
| Repository secret scanning | `collectors/run_secret_scan.py` |
| Manual VAPT report ingestion | `collectors/run_manual.py` |
| Bounded Nuclei scan (digest-pinned) | `collectors/run_nuclei.py` |
| Graph construction, scoring, traversal | `core/scorer.py` |
| Orchestration | `run.py` |
| Testbed definition | `testbed/docker-compose.yml`, `testbed/setup_gitea.py` |
| Figures | `scripts/generate_paper_graphs.py` |

`core/` contained exactly one module, `scorer.py`. There were no separate provenance, derivation, or semantics modules.

Two additional files, `collectors/mock_active.py` and `collectors/mock_identity.py`, were present but not referenced by `run.py` (`grep -c "mock_" run.py` returns `0`).

### 2.2 Original Graph Model

Records had a uniform shape: an identifier, an attribute object, and zero or more outgoing edges.

```json
{"id": "svc-192.168.65.254-21",
 "attrs": {"type": "Service", "port": "21", "product": "vsftpd",
           "severity": 0.53, "asset_class": "dmz-web", "origin": "active"},
 "edges": [{"to": "host-192.168.65.254", "type": "HOSTS_SERVICE", "conf": 1.0}]}
```

- **Node IDs** were built from templates: `svc-{ip}-{port}`, `host-{ip}`, `path-{ip}-{port}-{name}`, `persona-{localpart}`, `cred-{localpart}`, `finding-{report_id}`.
- **Fusion** occurred solely through identifier string equality. Two collectors referred to the same entity if and only if they emitted byte-identical ID strings. There was no entity resolution.
- **Confidence** was a float on each edge (`conf`).
- **Severity** was a float attribute on nodes, read with `float(attr.get("severity", 0.0))` (`core/scorer.py:41`).
- **Origin** was `active`, `identity`, or `manual`, and was the basis of the cross-layer predicate.
- **Provenance did not exist.** The string `provenance` appears zero times in the entire PRE source tree (`grep -rn "provenance" --include=*.py` returns 0 hits). The edge constructor signature was `def edge(self, u, v, etype, conf)` (`core/scorer.py:25`).

### 2.3 Original Scoring

Recorded verbatim from PRE `core/scorer.py`, unmodified:

```
CONF_FLOOR = 0.60
LAMBDA     = 0.95
MAXLEN     = 5
W          = dict(sev=.40, reach=.25, blast=.25, asset=.10)
ASSET_W    = {"identity-provider": 1.0, "database": .9,
              "internal-app": .6, "dmz-web": .5, "decoy": 0.0}
```

Criticality:

```
cr = (W["sev"] * sev) + (W["reach"] * reach) + (W["blast"] * blast) + (W["asset"] * aw)
```

with `reach = 1.0 / (1.0 + d)` where `d` is the shortest directed distance from any entry node (`d = 99` when unreachable), `blast` the fraction of designated jewel nodes reachable from the node, and `aw` an asset-class weight defaulting to `0.1`.

Path score:

```
path_score = round(conf * gain * (LAMBDA**(len(pth)-1)), 3)
```

where `conf` is the product of edge confidences and `gain` the sum of node severities. `MAXLEN` bounds the **node** count of a path, so at most four edges.

The cross-layer ("tri-layer") condition was `required_layers.issubset(layers)` over the set of node origins in the path, with `required_layers` supplied by the caller; `run.py` passed `{"active", "identity", "manual"}`.

Entry nodes were those with `origin` in `{manual, identity}` and jewels were `type == "Service"` records. Both were conventions of `run.py`, not properties of the scorer.

### 2.4 What the Original System Produced

The stored baseline run is `out/integrated_experiment_20260824_000517/`, which has not been modified by any correction work (verified by MD5 comparison before and after — see §9).

Recomputing that run from its own stored streams (`scripts/compare_baseline_corrected.py`) yields:

- 13 nodes, 13 edges
- edge provenance: all 13 load as `declared` (the PRE artifacts carry no provenance annotation, and the corrected loader treats an unlabelled edge as `declared`, the most conservative reading)
- edge semantics under the corrected classification: containment 6, access 3, evidence 1, validation 2, correlation 1
- 2 cross-layer paths under all-edge traversal, highest score **0.914**

The highest-scoring path was:

```
finding-MAN-DVWA-LOGIN -> cred-git-1 -> svc-192.168.65.254-3000
```

The arithmetic reproduces exactly. Edge confidences 0.75 and 0.75; node severities 0.6, 0.9, 0.3; length discount 0.95^2:

```
0.5625 x 1.8 x 0.9025 = 0.9137  ->  0.914
```

**Terminology.** The original implementation traversed every edge type and called this result a cross-layer path, and the manuscript at the time presented it as an attack path. Under the corrected semantic model (§5, Change 9) the first relationship in that path is a `CORRELATES` edge, classified as *correlation* — an asserted association with no stated mechanism — which is not attacker movement. The corrected model therefore classifies this result as an **evidence path**, not an attack path. Under access-only traversal the baseline yields **0** attack paths.

---

## 3. INVESTIGATION — What Was Found

Sixteen items are recorded. Findings 1-6 and 10-14 were confirmed present in the PRE state (eleven items). Findings 8 and 9 were present in PRE source but as latent conditions that never triggered in a recorded run, rather than observed failures. Findings 7, 15 and 16 were **not** present in PRE: they are defects introduced or exposed during the correction itself, and are recorded here so the change history is not presented as cleaner than it was.

### Finding 1 — Secret scanner hardcoded its target service

**Observed behavior.** Every credential found in any repository received an edge to a fixed port.

**Evidence.** PRE `collectors/run_secret_scan.py:48`:

```python
"edges": [{"to": f"svc-{target_ip}-3000", "type": "ENABLES_ACCESS", "conf": 0.75}]
```

**Why it was problematic.** The port `3000` is a literal. No property of the credential, the repository, or the observed environment participated in selecting the target. The scanner had no mechanism to decline.

**Effect.** An AWS-shaped canary (`AKIAEXAMPLE000000000`, planted by `testbed/setup_gitea.py`) was linked to a Gitea service. The two are unrelated technologies, and the seed repository had no configured remote of any kind. This edge is the second hop of the 0.914 path.

### Finding 2 — Manual collector converted an analyst field directly into a relationship

**Observed behavior.** A field in the human-authored report became a graph edge with no evidentiary check.

**Evidence.** PRE `collectors/run_manual.py:12-16`:

```python
service_id = f"svc-{target_ip}-{finding['target_service']}"
edges = [{"to": service_id, "type": "VALIDATES", "conf": 1.0}]
edges.extend(
    {"to": credential, "type": "CORRELATES", "conf": 0.75}
    for credential in finding.get("related_credentials", [])
)
```

`collectors/vapt_report.json` contained `"related_credentials": ["cred-git-1"]`.

**Why it was problematic.** Two distinct issues. First, `target_service` let the analyst address a graph node directly by port. Second, `related_credentials` placed a conclusion in the pipeline's input, which the pipeline then ranked.

**Effect.** The `CORRELATES` edge is the first hop of the 0.914 path. The evaluation was to that extent circular.

### Finding 3 — Identity collector generated account relationships from email addresses

**Observed behavior.** Every harvested email address produced an FTP account node linked to port 21, unconditionally.

**Evidence.** PRE `collectors/run_identity.py`:

```python
# 3. Discover Accounts (Simulating Sherlock username -> platform account)
account_id = f"account-{username}-ftp"
target_svc_id = f"svc-{target_ip}-21"
persona_record["edges"].append({"to": account_id, "type": "OWNS_ACCOUNT", "conf": 0.75})
```

**Why it was problematic.** No check that the account existed, that port 21 was open, or that the username corresponded to anything. `testbed/docker-compose.yml` provisions the FTP container with `FTP_USER=test`.

**Effect.** The node `account-c.brown-ftp` corresponded to no entity in the environment. It did not appear in the highest-scoring path but was present in the graph.

### Finding 4 — Confidence existed without provenance

**Observed behavior.** Edges carried a confidence float and nothing describing how the relationship was obtained.

**Evidence.** PRE `core/scorer.py:25`: `def edge(self, u, v, etype, conf)`. `grep -rn "provenance" --include=*.py` over the PRE tree returns **0 hits**.

**Why it was problematic.** A scanner observation, a rule inference, and a human assertion were represented identically. No downstream computation could separate them.

**Effect.** A confidence of 0.75 produced by a tool and a confidence of 0.75 supplied by a person were arithmetically equivalent, and the path score multiplied them together indiscriminately.

### Finding 5 — Edges could introduce phantom graph endpoints

**Observed behavior.** The loader passed edge endpoints straight to NetworkX, which creates missing nodes silently.

**Evidence.** PRE `core/scorer.py`, `load_records`:

```python
fg.node(r["id"], **r["attrs"])
for e in r.get("edges", []):
    fg.edge(r["id"], e["to"], e["type"], e["conf"])
```

`AetherGraph.edge` calls `self.g.add_edge(...)`, whose documented behaviour is to create absent endpoints.

**Why it was problematic.** A node created this way has no `type`, no `origin`, and no `severity`, yet participates in scoring: severity defaults to 0, origin is excluded from layer sets, and asset weight falls to the 0.1 default.

**Effect.** Demonstrated during the audit: loading a single record whose edge referenced `persona-ghost` produced a node with attributes `{}`. In the corrected pipeline this became an observed problem rather than a hypothetical one — see Change 3.

### Finding 6 — Derived edges had no justification requirement

**Observed behavior.** There was no notion of a derived edge, therefore no requirement that one record why it exists.

**Evidence.** Absence of any derivation module in PRE `core/` (contains only `scorer.py`), and the four-argument `edge()` signature.

**Why it was problematic.** An inferred relationship could not be audited after the fact; nothing recorded which evidence supported it.

**Effect.** The relationships in Findings 1–3 entered the graph with no record of their basis, which is why detecting them required reading collector source rather than inspecting artifacts.

### Finding 7 — Port-only service matching (NOT a PRE defect)

**Status.** This item does **not** describe the inherited system. PRE had no derivation rule at all; the manual collector used the analyst-supplied `target_service` field directly (Finding 2).

The port-only matching defect was introduced *during* the correction, in the first version of `derive_finding_service`, which matched a finding's location to an observed service on port number alone and returned the first match. It was identified in a later audit pass and corrected before completion (Change 7). It is recorded here so that the change history is not presented as cleaner than it was.

### Finding 8 — Missing or null severity could break scoring

**Observed behavior.** Severity was coerced with `float(attr.get("severity", 0.0))` (PRE `core/scorer.py:41`, and again at line 92 in the traversal).

**Why it was problematic.** `.get(key, default)` returns the *stored* value when the key exists. A record containing `"severity": null` yields `None`, and `float(None)` raises `TypeError`.

**Effect.** This is a **latent condition, not an observed failure**. No PRE collector emitted an explicit null, so it never triggered in the recorded runs. It was demonstrated during the audit by constructing such a node, which raised `TypeError: float() argument must be a string or a real number, not 'NoneType'` in both `calculate_criticality` and `enumerate_crosslayer_paths`.

### Finding 9 — Exception handling did not cover `NodeNotFound`

**Observed behavior.** The reachability computation wrapped `nx.has_path` in `except ValueError` (PRE `core/scorer.py:50`).

**Why it was problematic.** `networkx.NodeNotFound` derives from `NetworkXException`, not `ValueError`, so an entry node absent from the graph would propagate rather than being handled.

**Effect.** **Latent, not observed.** Entry nodes were selected from graph nodes in `run.py`, so the condition did not arise in the recorded runs.

### Finding 10 — Traversal treated every edge type as attacker movement

**Observed behavior.** `enumerate_crosslayer_paths` filtered edges only by confidence. Inspecting the PRE function body shows a single predicate, `dg.edges[u, v]["conf"] >= CONF_FLOOR`, and expansion over `dg.successors(v)`. No reference to `etype` or any semantic category appears in the traversal.

**Why it was problematic.** Asset-containment relationships (`HOSTS_SERVICE`, `SERVES_PATH`) and evidence-lineage relationships (`EXPOSED_BY`, `EXPOSES_CREDENTIAL`) describe structure and observation history, not capability. Walking them as transitions attributes a meaning to the edge that the edge does not carry.

**Effect.** Independent of Findings 1–3. A chain of directly observed evidence relationships in the corrected graph (`cred-web-1 -> path-...-80-backup -> svc-...-80`) scores **1.354** under all-edge traversal with a two-origin predicate — higher than the 0.914 result. Verified by `scripts/verify_evidence_chain.py`; see §6.

### Finding 11 — Dead mock collectors duplicated the fabricated relationships

**Observed behavior.** Two unreferenced modules emitted hardcoded cross-layer relationships with no provenance field.

**Evidence.** PRE `collectors/mock_identity.py:11,18,26`:

```python
{"to": "persona-1", "type": "EXPOSES_CREDENTIAL", "conf": 0.90}
{"to": "account-p1-files", "type": "OWNS_ACCOUNT", "conf": 0.75}
{"to": "svc-files-21", "type": "ENABLES_ACCESS", "conf": 0.80}
```

`collectors/mock_active.py` similarly hardcodes `svc-files-21` and a `CONNECTS_TO` edge type not emitted by any real collector.

**Why it was problematic.** These reproduce the exact pattern of Findings 1 and 3 and would load as `declared` edges if their output were used. They were not referenced by `run.py`.

**Effect.** No effect on recorded results; a latent route to reintroducing the pattern.

### Finding 12 — Duplicate test file and an inaccurate test count

**Observed behavior.** `tests/test_phase3.py` is byte-identical to `tests/test_integrated_pipeline.py` (verified with `diff -q`).

**Evidence.** PRE test definitions: `test_active.py` 3, `test_integrated_pipeline.py` 3, `test_phase3.py` 3, `test_scorer.py` 2 — 11 definitions, 11 discovered. PRE `paper.tex:268` claimed "eight passing tests", which counts the unique 8 and omits the duplicate.

**Effect.** The stated test count did not match what `unittest discover` ran.

### Finding 13 — Two PRE tests asserted the defective behaviour as correct

**Observed behavior.** The suite pinned the fabricated relationships in place.

**Evidence.** PRE `tests/test_integrated_pipeline.py` asserts `record["edges"][1]["to"] == "cred-git-1"` — that is, it asserts the `related_credentials` pass-through of Finding 2 produces an edge. PRE `tests/test_scorer.py:56` asserts the path `["cred-p1", "persona-1", "account-p1-files", "svc-files-21"]`, which is the fabricated chain of Finding 3 in fixture form.

**Effect.** Correcting Findings 2 and 3 necessarily broke these tests, which is how the suite behaved when the corrections were applied.

### Finding 14 — Runner drift relative to the recorded baseline artifacts

**Observed behavior.** The PRE `run.py` loads five record streams including `real_nuclei.jsonl`, exports GraphML (`nx.write_graphml`), and records `nuclei_status` and `gitea_publication` in its result JSON.

**Evidence.** PRE `run.py:52,63-67,75,84`. The stored baseline directory `out/integrated_experiment_20260824_000517/` contains **no** `real_nuclei.jsonl`, no `.graphml`, and its `experiment_results.json` carries neither added field.

**Effect.** The recorded baseline artifacts were produced by an earlier revision of the runner than the one in the archive. Re-executing the archived `run.py` would not reproduce that directory byte-for-byte. This is a reproducibility caveat, documented in `paper.tex`.

### Finding 15 — Replay fixture attributed evidence to a URL that does not serve it

**Observed behavior.** A replay fixture asserted that `http://127.0.0.1/.git/config` returns the planted Git configuration. The live server returns **HTTP 404** at that URL.

**Evidence.** `testbed/nginx/nginx.conf` defines two name-based virtual hosts: a default server rooted at `html/www`, and a second rooted at `html/dev` with `server_name dev.corp-testbed.local`. The `.git/config` is in the dev root. Live probes confirm 404 on the default vhost and **HTTP 200** with `Host: dev.corp-testbed.local`.

**Why it was problematic.** The fixture was constructed from the file on disk rather than from a response the server actually returns at that URL. The evidence is real, but its stated location was wrong.

**Effect.** The replay's `exposure-git-config-2` record, and therefore the manifest's `LINK-GITCONFIG-PERSONA` expected relationship, rested on that misattribution. This is the same class of defect the project is about — evidence asserted without adequate support — occurring inside the correction itself. It was found only by executing the pipeline live, and is corrected by Change 21.

### Finding 16 — GraphML export failed on list-valued attributes

**Observed behavior.** `run.py` raised `TypeError: GraphML does not support type <class 'list'> as data values` at the export step.

**Evidence.** Several collectors legitimately emit list attributes (`repo_remotes`, `evidence_refs`, `names_services`). `nx.write_graphml` has no list type.

**Why it was problematic.** The export aborted the run after all collection had succeeded.

**Effect.** Latent until the first live end-to-end execution, because the replay path used `scripts/regenerate_results.py`, which does not export GraphML. Corrected by Change 22.

---

## 4. PRE — Why the Existing Safeguards Did Not Catch It

The system had five safeguards. Every one of them passed on the 0.914 path.

| Safeguard | Where | Why it was insufficient |
|---|---|---|
| Confidence floor `CONF_FLOOR = 0.60` | `core/scorer.py` | Both fabricated edges carried 0.75 and cleared it. |
| Path-length penalty `lambda = 0.95` | path score | Applies to length, not to whether a relationship is supported. |
| Tri-layer origin requirement | `enumerate_crosslayer_paths` | Checks which layers a path spans, not how its edges were obtained. |
| Score recomputation from artifacts | `scripts/verify_recorded_run.py` | Confirms the arithmetic is reproducible; the arithmetic was never wrong. |
| Unit tests (8 unique) | `tests/` | Verified that rules **produced** edges. Two asserted the defective behaviour as correct (Finding 13). |

**The empirical lesson: confidence is not provenance.**

Confidence answers *how strongly is this relationship asserted?* Provenance answers *what is its evidentiary origin?* These vary independently. In the PRE schema only the former was recorded, so a directly observed relationship and a hardcoded constant with the same confidence value were indistinguishable to every downstream computation, and the path score aggregated them multiplicatively without distinction.

Concretely: the 0.914 path consists of one edge originating in `related_credentials` typed into a JSON input file, and one edge originating in the literal `3000` in collector source. Both scored 0.75. Every check above passed. Detection required reading the collectors, because no artifact recorded the difference.

This is stated as the project's empirical and design finding from one documented case. It is not presented as a formal theorem, and no claim is made that this failure mode is novel or has not occurred elsewhere.

---

## 5. POST — What Was Changed

### Change 1 — Provenance model

**Before.** No provenance concept; `edge(self, u, v, etype, conf)`.

**After.** Three mutually exclusive levels: `observed` (a tool reported the relationship directly), `derived` (a deterministic rule combined two or more observations), `declared` (a human asserted it). Provenance is a **required** parameter; an unknown value raises `ValueError`. Unlabelled legacy edges load as `declared`, the most conservative reading. `MODES` maps ablation modes to admitted provenance sets.

The taxonomy is documented in the module as an operational choice for this prototype, not a claim of theoretical completeness.

**Files.** `core/provenance.py` (new); `core/scorer.py` (`AetherGraph.edge`, `load_records`).

**Validation.** `tests/test_graph_integrity.py::TestProvenanceIsMandatory` (4 tests), `::TestProvenanceFiltering` (4 tests).

### Change 2 — Mandatory justification for derived edges

**Before.** No such requirement.

**After.** `core/provenance.py::edge` raises `ValueError` if a `DERIVED` edge is constructed with an empty justification string.

**Files.** `core/provenance.py`.

**Validation.** `test_derived_edge_without_justification_is_rejected`; `tests/test_manifest_regression.py::test_every_derived_edge_carries_a_justification` over the recorded artifacts.

### Change 3 — Endpoint validation

**Before.** `add_edge` silently created missing endpoints (Finding 5).

**After.** `load_records` inserts all nodes from all streams first, then validates both endpoints of every edge. A dangling reference raises `MissingEndpoint` naming the offending stream. Ablations, which deliberately withhold streams, pass `strict_endpoints=False`; such edges are **skipped and counted**, never materialised.

**Files.** `core/scorer.py` (`MissingEndpoint`, `load_records`).

**Validation.** `tests/test_graph_integrity.py::TestPhantomNodes` (4 tests).

This check found a real defect on introduction: `collectors/run_web_evidence.py` emits an `IDENTIFIES` edge to a persona produced by a different collector, so the `+ web evidence` ablation rows had been counting a phantom node. Those rows were corrected from 10 nodes / 9 edges to **9 nodes / 8 edges**.

### Change 4 — Derivation rules that can decline

**Before.** No derivation layer.

**After.** `core/derive.py` implements four rules, each a conjunction so that a missing conjunct yields no edge. Rules append human-readable reasons to an optional `declines` list, printed at run time.

**Files.** `core/derive.py` (new).

**Validation.** `tests/test_derive.py` — of its tests, the majority assert that a rule **declines**.

### Change 5 — Corrected secret to service derivation

**Before.** `f"svc-{target_ip}-3000"` for every secret (Finding 1).

**After.** `derive_repo_service_access` requires all three of: a repository remote whose host and port identify a service; that service having been independently observed; and the secret kind being compatible with the observed product (`SECRET_KIND_TARGETS`). The synthetic AWS canary maps to the empty set and therefore can never link to a local product.

**Files.** `core/derive.py`; `collectors/run_secret_scan.py` (reads remotes via `git remote -v` in `repository_remotes`, and observed services via `load_observed_services`).

**Validation.** `TestRepoServiceAccess` (5 tests, 4 of them declines); `tests/test_manifest_regression.py::test_hardcoded_secret_to_gitea_target_cannot_return`. On the recorded testbed the collector reports `0 of 1 have an evidence-derived service link`.

### Change 6 — Corrected persona/account derivation

**Before.** `account-{username}-ftp` to `svc-{ip}-21` for every email (Finding 3).

**After.** `derive_account_access` emits an Account node and its access edge only when a corroboration record names both the username and a specific observed service. A harvested email address is not corroboration.

**Files.** `core/derive.py`; `collectors/run_identity.py`.

**Validation.** `TestAccountAccess` (3 tests, 2 declines); `test_harvested_identity_creates_no_ftp_account`. On the recorded testbed the collector reports `1 persona(s) produced no account link`.

### Change 7 — Corrected manual finding to service derivation

**Before.** `target_service` named the port directly (Finding 2). An intermediate correction then matched on port number alone (Finding 7).

**After.** `derive_finding_service` parses the analyst's recorded `location` and matches it against observed services. Host identity must match exactly **or** be covered by an explicitly declared alias supplied by the operator (`run_manual.py --host-alias`); port agreement alone is not a match. Ambiguous matches (more than one candidate) are declined. The `CORRELATES` relationship from `related_credentials` is retained but labelled `declared`.

The host alias is necessary because the analyst reaches the testbed on a published loopback address while the scanner records the Docker gateway address; nothing in the evidence establishes that these are the same host, so the equivalence is declared rather than assumed.

**Files.** `core/derive.py`; `collectors/run_manual.py`.

**Validation.** `TestFindingServiceMatching` (6 tests, 4 declines); `test_asserted_correlation_stays_declared`; `test_declared_edges_remain_declared`.

### Change 8 — Web evidence collector

**Before.** The active layer recorded that a web path existed but never retrieved what it served.

**After.** `collectors/run_web_evidence.py` follows discovered paths, parses directory listings, retrieves files, and probes for exposed `.git/config`. It supports `--replay-dir` for execution against saved response bodies.

This produced two genuinely observed cross-layer records that no earlier run had collected: `cred-web-1` (a credential retrieved from the file behind the discovered `/backup` listing) and `exposure-git-config-2` (an exposed Git configuration naming a persona).

**Files.** `collectors/run_web_evidence.py` (new); `run.py` (ordering — web evidence runs before identity so it can supply corroborations).

**Validation.** `TestCredentialExtraction`, `TestExposedGitConfig` in `tests/test_derive.py`; manifest entries `LINK-BACKUP-CRED` and `LINK-GITCONFIG-PERSONA`.

### Change 9 — Semantic edge classification

**Before.** Edge types had no declared meaning (Finding 10).

**After.** `core/semantics.py` classifies every edge type into one of five categories. An edge type absent from the registry raises `UnknownEdgeType` rather than receiving a default.

| Category | Edge types |
|---|---|
| containment | `HOSTS_SERVICE`, `SERVES_PATH` |
| evidence | `EXPOSED_BY`, `IDENTIFIES`, `EXPOSES_CREDENTIAL` |
| validation | `VALIDATES` |
| access | `OWNS_ACCOUNT`, `ENABLES_ACCESS` |
| correlation | `CORRELATES` |

**Files.** `core/semantics.py` (new); `core/scorer.py`.

**Validation.** `tests/test_graph_integrity.py::TestEdgeSemantics` (3 tests).

### Change 10 — `ATTACK_TRAVERSABLE = {ACCESS}`

**Before.** All edge types were walked.

**After.** Attack-path traversal admits only capability relationships. `ALL_TRAVERSABLE` is retained for evidence-graph traversal, which is a distinct and explicitly labelled diagnostic. This is documented as a prototype operational definition and a controlled design decision, not a claimed universal ontology of attack relationships.

**Files.** `core/semantics.py`; `core/scorer.py` (`enumerate_crosslayer_paths(traversable_semantics=...)`).

**Validation.** `tests/test_scorer.py::TestAttackTraversalSemantics` (5 tests), including `test_evidence_and_containment_edges_are_not_attacker_movement` and `test_asserted_correlation_is_never_attacker_movement`.

### Change 11 — Traversal no longer treats every relationship as movement

**Before / After.** Covered by Changes 9 and 10; recorded separately because it is the behavioural consequence. Edge **directions were not reversed**. Edges were classified according to what they assert, which leaves the schema's directions heterogeneous by design; this is recorded as a limitation rather than resolved.

### Change 12 — Severity normalisation

**Before.** `float(attr.get("severity", 0.0))` (Finding 8).

**After.** `core/scorer.py::severity_of` normalises both an absent key and an explicit `None` to `0.0`, and is used at every call site.

**Validation.** `tests/test_scorer.py::TestSeverityHandling` (3 tests), including an end-to-end scoring pass over a node with `severity=None`.

### Change 13 — `NodeNotFound` handling

**Before.** `except ValueError` only (Finding 9).

**After.** `calculate_criticality` catches `(nx.NodeNotFound, nx.NetworkXNoPath, ValueError)` and filters entries to those present in the graph.

**Files.** `core/scorer.py`.

### Change 14 — Removal of dead mock collectors

**Before.** `collectors/mock_active.py`, `collectors/mock_identity.py` (Finding 11).

**After.** Both deleted. They were unreferenced, and reproduced the fabrication patterns with no provenance field.

**Validation.** The final consistency check asserts both files are absent.

### Change 15 — Removal of stale VAPT fields

**Before.** `collectors/vapt_report.json` carried `target_service` values (`21`, `8080`).

**After.** Removed, since `run_manual.py` no longer reads them; a `_schema_note` records that findings describe *where* the analyst tested, not which graph node to attach to. `related_credentials` is retained and enters the graph as a `declared` edge only.

**Verified.** The field is present in PRE `vapt_report.json` and absent in POST.

### Change 16 — Regression and manifest methodology

**Before.** No ground-truth record.

**After.** `testbed/seed_manifest.json` records five **expected** relationships (each with an identifier pattern and required provenance) and two **forbidden** relationships naming the fabrication patterns and the source construct responsible for each. The manifest is explicitly documented as regression criteria, not independent ground truth.

**Files.** `testbed/seed_manifest.json`; `scripts/run_ablation.py`; `tests/test_manifest_regression.py` (11 tests).

### Change 17 — Positive live ACCESS validation experiment

**Before.** No demonstration that the corrected rules could fire at all.

**After.** A live experiment in an isolated directory. See §7.

**Files.** `testbed/setup_positive_access.py` (new, opt-in); `scripts/run_positive_access_experiment.py` (new); `out/positive_access_live/` (new).

### Change 18 — Product identification from observed evidence

**Before.** Product identity came only from Nmap's version probe.

**After.** `collectors/run_active.py` additionally requests `--script http-title` and stores the result as `http_title` on the Service record, separate from the version probe's own `product`. `derive_repo_service_access` accepts either as product evidence and names which one matched in the justification.

**Why.** Required by the positive control. Nmap's version probe identifies the testbed's Gitea only as `Golang net/http server` and explicitly reports `1 service unrecognized`, so a product identifiable only from its own response could not be recognised. The observed title is `Gitea: Git with a cup of tea`.

**Validation.** `tests/test_derive.py::TestProductIdentificationEvidence` (3 tests, 2 declines).

### Change 19 — Gitea secret pattern corrected to the real token format

**Before.** `SECRET_PATTERNS` matched `gitea_pat_[0-9a-zA-Z]{32,}`.

**After.** A `gitea-token` pattern was added requiring a Gitea keyword adjacent to a 40-character hexadecimal value.

**Why.** Gitea 1.22.6 issues unprefixed 40-hex tokens, so the original pattern matched nothing the running version produced. Matching bare hex would match every commit hash, so keyword proximity is required — the approach used by production secret scanners.

**Validation.** `tests/test_secret_patterns.py` (7 tests), including `test_does_not_match_a_bare_hex_value` and `test_does_not_match_a_commit_hash_in_context`.

### Change 20 — Nmap timeout made configurable

**Before.** A hardcoded 90-second subprocess timeout.

**After.** `NMAP_TIMEOUT`, default 600 s, overridable via `AETHERGRAPH_NMAP_TIMEOUT`.

**Why.** The measured runtime of `-sV --version-all` against four ports on the reference testbed is 272–286 s; the original timeout aborted every live scan.

### Change 21 — Virtual-host probing in the web-evidence collector

**Before.** The collector probed well-known paths on the default virtual host only, and a replay fixture misattributed dev-vhost content to it (Finding 15).

**After.** `fetch()` accepts an explicit `Host` header and `collect()` probes each operator-declared virtual host in addition to the default. The vhost is part of the replay fixture key, and is recorded in the observation's `source` and `vhost` attributes so the retrieval is auditable. Declared explicitly via `--vhost` (and `run.py --vhost`), on the same principle as `--host-alias`: nothing in the collected evidence reveals which names a server answers to.

**Files.** `collectors/run_web_evidence.py`; `run.py`.

**Validation.** Live: with `--vhost dev.corp-testbed.local` the exposure is retrieved (`source: http://127.0.0.1/.git/config (Host: dev.corp-testbed.local)`) and `LINK-GITCONFIG-PERSONA` is recovered; without it the collector correctly finds nothing at that URL.

### Change 22 — GraphML export handles non-scalar attributes

**Before.** `nx.write_graphml(graph.g, ...)` raised `TypeError` on list attributes (Finding 16).

**After.** The export operates on a copy in which list, dict, tuple and `None` values are JSON-encoded or emptied. The in-memory graph used for scoring and traversal is left untouched.

**Files.** `run.py`.

**Validation.** The live end-to-end run completes and writes `out/live_run/aethergraph_export.graphml`.

---

## 6. POST — Corrected Graph and Results

Read from `out/derived_experiment_20260908/experiment_results_all.json`:

| Quantity | Value |
|---|---|
| Nodes | 14 |
| Edges | 13 |
| Observed edges | 9 |
| Derived edges | 3 |
| Declared edges | 1 |
| Fabricated relationships | 0 of 2 forbidden patterns |
| Capability (access) edges | **0** |
| Edge semantics | containment 6, evidence 4, validation 2, correlation 1 |
| Attack paths (`ATTACK_TRAVERSABLE={ACCESS}`) | 0 |
| Evidence paths (three-origin, all edge types) | 0 |

Layer x provenance ablation (`scripts/run_ablation.py`); attack and evidence path counts are **0 in all twelve cells**:

| Layer subset | observed-only | derived | all |
|---|---|---|---|
| active only | 7 nodes / 6 edges | 7 / 6 | 7 / 6 |
| + web evidence | 9 / 8 | 9 / 8 | 9 / 8 |
| + identity, secret | 12 / 9 | 12 / 10 | 12 / 10 |
| + manual (full) | 14 / 9 | 14 / 12 | 14 / 13 |

Manifest check: **all five expected relationships recovered; neither forbidden pattern emitted.**

### Why the corrected replay has zero attack paths

The corrected graph contains **no access-category relationship at all** (semantics: containment 6, evidence 4, validation 2, correlation 1). Attack traversal admits only access edges, so the count is necessarily zero. This follows from the environment, not from a rule incapable of firing — which is what the positive control in §7 establishes.

Two structural contributors: `cred-git-1` lost its fabricated outgoing edge and is now a leaf, so the analyst's `CORRELATES` edge points at a sink; and the genuinely observed cross-layer relationships run *from* active-origin evidence *to* identity-origin nodes, the opposite direction from manual findings, which point at services.

### The observed evidence chain — a diagnostic, not an attack path

```
cred-web-1 --EXPOSED_BY--> path-...-80-backup --SERVES_PATH--> svc-...-80
```

This chain **is present in the corrected graph** and both relationships are directly observed. It is an **evidence chain**, not an attack path: `EXPOSED_BY` records where a credential was retrieved and `SERVES_PATH` records asset containment. Neither asserts a capability.

It does not appear in the reported results because every reported configuration requires a path to span all three evidence origins and this chain spans two. Under a relaxed two-origin predicate with all-edge traversal it scores **1.354** (extensions: 1.286, 1.14), verified by `scripts/verify_evidence_chain.py` and recorded in `out/derived_experiment_20260908/evidence_chain_scores.json`.

**This figure is an evidence-path diagnostic characterising the traversal defect of Finding 10. It is not a headline attack-path result.** Under access-only traversal the same graph yields 0 paths at both two-origin and three-origin predicates.

### Live end-to-end confirmation

The corrected results above were first obtained by replay. The complete pipeline
was subsequently executed live against the running testbed into
`out/live_run/` (runtime 289 s), with the baseline and corrected directories
left untouched (MD5 verified).

| Quantity | Replay | Live |
|---|---|---|
| Provenance (observed / derived / declared) | 9 / 3 / 1 | **9 / 3 / 1** |
| Semantics (containment / evidence / validation / correlation) | 6 / 4 / 2 / 1 | **6 / 4 / 2 / 1** |
| Capability (access) edges | 0 | **0** |
| Edges (`all` mode) | 13 | **13** |
| Attack paths | 0 | **0** |
| Evidence paths (three-origin) | 0 | **0** |
| Expected relationships recovered | 5/5 | **5/5** |
| Forbidden patterns emitted | 0/2 | **0/2** |
| Nodes | 14 | 17 |

The node count differs because the Nuclei collector completed in the live run and
contributed three finding records that the replay stream did not contain. Those
records carry no outgoing relationships and affect no path count.

The live run is what exposed Findings 15 and 16.

---

## 7. Positive Control — Live ACCESS Validation

Every result above is a negative or a decline. A rule that always declines would satisfy all of them. The positive control tests whether the same rule emits a capability relationship when the required evidence genuinely exists.

**Isolation.** All output in `out/positive_access_live/`. The baseline and corrected directories were verified byte-identical (MD5) before and after.

**Conditions established live**, not by replay:

| Condition | Evidence |
|---|---|
| Docker ran | Engine 29.7.2; four containers up |
| Gitea ran | 1.22.6, self-reported via `/api/v1/version`; health `healthy` |
| Genuine PAT | Issued by the Gitea instance's own API |
| Token authenticates | `/api/v1/user` returned `login='pactest', id=1`; a deliberately wrong token returned **HTTP 401** |
| Real repository remote | `http://10.41.159.81:3000/pactest/pac-positive.git`, and a `git push` through it **succeeded** |
| Service independently observed | Active collector recorded `http_title = 'Gitea: Git with a cup of tea'` on port 3000 |
| Secret discovered normally | Secret scanner reported `secret_kind: gitea-token` via its own pattern |

The address `10.41.159.81` was used because the scan target and the git remote must be one address reachable from both the host (so the token and remote actually work) and from inside a container (so the scanner can reach it). Loopback does not satisfy both.

**The secret collector was not told the target service.** It receives a repository path and the set of observed services.

**Result — derived ACCESS edge:**

```
cred-git-1 --ENABLES_ACCESS [derived, conf 0.75]--> svc-10.41.159.81-3000
```

Justification recorded on the edge:

> repository remote http://10.41.159.81:3000/pactest/pac-positive.git resolves to observed service svc-10.41.159.81-3000 on port 3000; its observed http title is 'Gitea: Git with a cup of tea', which identifies product 'gitea'; secret kind gitea-token authenticates to that product

**Attack traversal**, restricted to `ATTACK_TRAVERSABLE={ACCESS}` and **not** relaxed, returned **1 path**:

```
cred-git-1 -> svc-10.41.159.81-3000        score 0.855
```

Arithmetic: `0.75 x (0.9 + 0.3) x 0.95 = 0.855`.

**The three-origin count remains 0**, because this path spans two origins (identity, active). The positive result concerns emission of a capability relationship and its acceptance by attack traversal, not the three-origin predicate.

**Negative controls**, same live token and repository, only the evidence differs:

| Condition | Result |
|---|---|
| Remote removed | Rule **declined** (`0 of 1`) |
| Gitea observation withheld from the observed set | Rule **declined** (`0 of 1`) |

**Independence from the original defect.** Neither fabrication pattern is present in the source; every access relationship in the graph carries provenance `derived`; no relationship was inserted manually; the token value appears in no artifact (`secret_leaked_into_artifacts: false`, 0 stray 40-hex values excluding commit ids).

**Purpose and limits.** This demonstrates that the corrected rule is capable of producing an ACCESS relationship when its required evidence genuinely exists, and therefore that the zero results elsewhere follow from absent evidence rather than from a rule that cannot fire. It is one controlled case, exercising one rule against one product. It is **not** a measure of precision, recall, general correctness, or production readiness, and carries no statistical weight.

---

## 8. PRE vs POST Comparison

| Area | PRE | POST | Evidence |
|---|---|---|---|
| Provenance | Absent (0 occurrences in source) | `observed` / `derived` / `declared`, mandatory | `core/provenance.py`; PRE `core/scorer.py:25` |
| Derived-edge justification | No concept | Required; `ValueError` if empty | `core/provenance.py::edge` |
| Endpoint validation | `add_edge` created phantoms | `MissingEndpoint`; ablations skip and count | `core/scorer.py::load_records`; `TestPhantomNodes` |
| Secret to service | `f"svc-{ip}-3000"`, unconditional | Remote + observed service + compatible kind | PRE `run_secret_scan.py:48`; `core/derive.py` |
| Identity to FTP | `account-{user}-ftp` for every email | Requires corroboration naming a service | PRE `run_identity.py`; `derive_account_access` |
| Manual finding | `target_service` field to edge | Location parsed, matched to observed service, alias declared | PRE `run_manual.py:12`; `derive_finding_service` |
| Analyst correlation | Edge with no provenance | Retained, labelled `declared` | `run_manual.py`; `test_declared_edges_remain_declared` |
| Edge semantics | Undeclared | 5 categories; unknown type rejected | `core/semantics.py` |
| Attack traversal | All edge types walked | `ATTACK_TRAVERSABLE={ACCESS}` | `enumerate_crosslayer_paths` |
| Confidence handling | Sole edge property | One of three recorded properties | §4 |
| Severity | `float(...)` — `None` raises | `severity_of` normalises absent and null | `TestSeverityHandling` |
| Mock collectors | 2 files, fabricated + no provenance | Removed | Finding 11 / Change 14 |
| Test coverage | 11 discovered (8 unique); 2 asserted the defect | **74 passing, 35 negative** | `unittest discover` |
| Fabricated relationships | 2 present in baseline graph | 0 of 2 forbidden patterns | `run_ablation.py` |
| Baseline result | 2 paths, top 0.914, called an attack path | Reclassified: 2 **evidence** paths; 0 attack paths under access-only | `compare_baseline_corrected.py` |
| Corrected result | — | 14 nodes / 13 edges; 9/3/1; 0 access edges; 0 attack paths | `experiment_results_all.json` |
| Positive capability validation | None | Live derived ACCESS edge; 1 attack path, score 0.855 | `out/positive_access_live/experiment_report.json` |

---

## 9. Tests and Verification

Final state, read from the repository:

| Check | Result |
|---|---|
| Total tests (`python -m unittest discover -s tests -p "test_*.py"`) | **74 passing** |
| Live end-to-end run | Completed; reproduces replay provenance, semantics, manifest and path counts |
| Negative / regression-oriented tests | **35** |
| Test files | `test_active.py`, `test_derive.py`, `test_graph_integrity.py`, `test_integrated_pipeline.py`, `test_manifest_regression.py`, `test_scorer.py`, `test_secret_patterns.py` |
| Mathematical checks (equations vs implementation) | 16/16 |
| Structural / overclaim checks on `paper.tex` | 37/37 |
| Baseline reproduction | 0.914 reproduced exactly from stored baseline streams |
| Corrected pipeline reproduces the 0.914 path | No |
| Baseline under access-only traversal | 0 attack paths |
| Manifest check | 5/5 expected recovered; 0/2 forbidden emitted |
| Ablation | 0 attack and 0 evidence paths in all 12 cells |
| Positive control | Derived ACCESS edge; 1 attack path; score 0.855 |
| Negative controls | 2/2 declined |
| Baseline artifacts modified | No — MD5 identical before/after |
| Corrected artifacts modified by the positive experiment | No — MD5 identical before/after |

Tests establish software behaviour for the cases tested. **They do not establish real-world accuracy.**

---

## 10. What the Evidence Actually Establishes

On the controlled testbed, the work establishes that:

- unsupported relationships in the inherited implementation could survive every downstream confidence, path-length, layer-predicate, score-reproduction and unit-test check;
- provenance-aware construction prevents the two identified fabrication patterns, enforced by regression tests over recorded artifacts;
- evidence-backed derivation rules decline when required evidence is absent, demonstrated by 35 negative tests and by two live negative controls;
- evidence relationships can be separated from attacker-capability relationships, and the separation changes the result: honest evidence scored 1.354 under all-edge traversal, above the 0.914 unsupported path;
- the corrected ACCESS derivation can fire under genuine evidence, demonstrated by one live positive control (derived edge, attack path, score 0.855);
- graph construction cannot silently create attribute-less endpoint nodes.

It does **not** establish:

- general attack-path discovery accuracy;
- recall or precision in any statistical sense — the "five of five" figure is a controlled regression check against expectations the same authors wrote, not a recall statistic;
- production-scale reliability;
- generality across products or credential types — one product, one rule, one credential type were exercised;
- any statistical conclusion from a single positive case;
- the real-world prevalence of the identified failure modes;
- that the scoring function is a validated measure of attack risk.

---

## 11. Remaining Limitations

- **One controlled environment.** A four-container synthetic testbed with no production traffic, organisational noise or real identity owners.
- **Replay origin of the main evaluation.** The corrected run in `out/derived_experiment_20260908/` was produced by replay rather than live execution. It has since been confirmed by a fresh live end-to-end run (`out/live_run/`) that reproduces its provenance composition, semantic composition, manifest outcome and every path count. The replay directory is retained as recorded, including its `exposure-git-config-2` source attribution, which Finding 15 shows to be incorrect; the live run supersedes it.
- **Positive control is separate from the main replay.** It is a distinct experiment in its own directory, not a re-run of the main evaluation.
- **No three-origin positive attack path.** The live positive path spans two origins; the three-origin count is 0 in every configuration.
- **One demonstrated positive ACCESS case**, exercising one rule against one product with one credential type.
- **Mixed edge directions.** Containment points from contained entity to container, evidence lineage from fact to location, validation from finding to asset. Edges were classified rather than reversed. A coherent directional ontology is future work.
- **Manifest is regression criteria, not independent ground truth.** The expected relationships were planted, and the rules designed to recover them, by the same authors in an environment they constructed.
- **Provenance taxonomy and semantic classification are design choices**, not claimed to be complete, minimal, or universally correct.
- **Scoring function is a prototype convention.** Weights, lambda, the confidence floor and the length bound are not validated as an objective risk measure.
- **Runner drift** relative to the recorded baseline artifacts (Finding 14): the archived `run.py` post-dates the stored baseline directory, so re-executing it would not reproduce that directory byte-for-byte.
- **No independently labelled corpus and no replicate runs**, therefore no detection-quality metrics and no inferential statistics.

---

## 12. Summary

**PRE.** The system fused heterogeneous security evidence into a directed graph and produced a high-scoring cross-layer result (two paths, highest 0.914). Forensic inspection of the archived source showed that several graph relationships were introduced without adequate evidentiary support — a hardcoded service target for every repository secret, an analyst-supplied field converted directly into a relationship, and account relationships generated from email addresses alone — while the graph model recorded confidence but no provenance, so downstream scoring safeguards could not detect the problem. A second, independent issue was that path traversal treated every relationship, including asset containment and evidence lineage, as attacker movement.

**POST.** The system now records provenance on every edge, requires justification for derived relationships, validates graph endpoints and refuses to create phantom nodes, uses evidence-backed derivation rules that decline when required evidence is absent, and distinguishes evidence relationships from attack-traversable capability relationships. The corrected replay contains 14 nodes and 13 edges (9 observed, 3 derived, 1 declared), no capability relationship, and no attack path under access-only traversal; the earlier 0.914 result is reclassified as an evidence path and yields 0 attack paths under the corrected semantics. A seed manifest with expected and forbidden relationships provides regression criteria, and a live positive control demonstrates that the corrected ACCESS derivation does fire when genuine evidence exists (derived edge, one attack path, score 0.855), with two negative controls confirming it declines when that evidence is removed. The suite is 74 tests, 35 of them negative.
