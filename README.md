# AetherGraph

A prototype for fusing heterogeneous security evidence — active reconnaissance, identity/OSINT collection, repository secret scanning, web evidence, and manual VAPT findings — into a directed graph with confidence-weighted path scoring.

This repository is also a documented failure analysis. An earlier version of the pipeline produced a high-scoring cross-layer result whose critical relationships turned out not to be supported by evidence. The paper here (`paper.tex` / `paper.pdf`) reports that failure, its root cause, the correction, and a live-validated positive control — not a system that "finds attacks."

**Paper:** *Confidence Is Not Provenance: A Failure Analysis and Correction of Cross-Layer Security-Evidence Fusion*
**Full technical change record:** [`PRE_POST_TECHNICAL_RECORD.md`](PRE_POST_TECHNICAL_RECORD.md)

## The short version

> A confidence score tells you how strongly a relationship is asserted. It does not tell you whether that relationship was observed, derived from evidence, or simply declared by a human. In this prototype's original implementation, those were indistinguishable — and a high-scoring "attack path" turned out to be built from a hardcoded service target and an analyst-typed field passed straight into the graph. Every downstream safeguard (confidence floor, path-length penalty, multi-origin predicate, score recomputation, unit tests) passed on it anyway, because none of them checked *how* a relationship came to exist.

The correction: every edge now carries **provenance** (`observed` / `derived` / `declared`), derivation rules can **decline** when evidence is insufficient, graph construction **rejects edges into nodes nobody emitted**, and attack-path traversal is restricted to edges whose **semantics** actually describe attacker capability — not asset containment, not evidence lineage, not an analyst's unmechanized correlation.

## Repository layout

```
core/            provenance.py, semantics.py, derive.py, scorer.py — the graph engine
collectors/      run_active.py, run_identity.py, run_secret_scan.py,
                 run_manual.py, run_web_evidence.py, run_nuclei.py
testbed/         docker-compose.yml + planted evidence + seed_manifest.json (ground truth)
tests/           74 tests, 35 of them negative (assert a rule declines / rejects)
scripts/         ablation, baseline-vs-corrected comparison, figure generation
out/             recorded runs — baseline, corrected replay, live run, positive control
paper.tex/.pdf   the manuscript
PRE_POST_TECHNICAL_RECORD.md   full findings/changes record, cross-checked against the repo
```

## Verified current state

| | |
|---|---|
| Tests | **74 passing, 35 negative/regression** |
| Corrected graph | 14 nodes / 13 edges — 9 observed, 3 derived, 1 declared |
| Capability (ACCESS) edges in the replay graph | **0** |
| Manifest recall (controlled testbed only — see note below) | 5/5 expected recovered, 0/2 forbidden emitted |
| Baseline result | reproducible exactly (score 0.914) from its own stored artifacts — and reclassified as an *evidence* path, not an attack path, under the corrected semantics |
| Live end-to-end run | confirms the replay exactly (`out/live_run/`) |
| Live positive control | real Gitea + real access token + real remote → derived ACCESS edge → 1 attack path, score 0.855 (`out/positive_access_live/`) |

**Note on "5/5 recall":** this is a controlled regression check against a manifest of relationships the authors planted in a testbed the authors built. It is not a detection-performance or generality claim — see the paper's Discussion and Limitations for the full scoping.

## Reproducing

```bash
python -m unittest discover -s tests -p "test_*.py"        # 74 tests, no Docker needed
python scripts/run_ablation.py out/derived_experiment_20260908
python scripts/compare_baseline_corrected.py
```

A live end-to-end run and the positive-control experiment require Docker; see `out/positive_access_live/REPRODUCE.md` for exact steps. No secret is ever committed — the positive control's repository working tree and issued token are excluded by `.gitignore` and were revoked after use.

## Authors

Hardik (IIT Patna & VIPS-TC) and Parth (VIPS-TC, Delhi) — joint first authors.
