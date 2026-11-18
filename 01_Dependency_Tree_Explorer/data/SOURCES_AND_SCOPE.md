# Local evidence and study boundaries

**Snapshot checked:** 12 November 2026. **No APIs are used to execute any project.** All programs read the bundled CSV files.

These are **three explicitly illustrative software profiles**, not downloaded lockfiles from genuine deployed applications. The selected package versions existed in the 2022 period and are deliberately held constant so that the effect of direct versus transitive status can be studied without changing version choices. They must not be described as audited real repositories. Dependencies are a small, hand-curated subset of Python runtime metadata, not a full resolver output or supply-chain inventory. Extra/optional and platform-specific edges are intentionally excluded.

`packages.csv` records package/version pairs and release page links. `dependencies.csv` supplies the runtime relationships used in the study, with package project metadata references. `profiles.csv` defines the **hypothetical** direct package selections. These profiles are original educational examples, not external factual claims.

`advisories.csv` contains nine real CVE records. CVSS 3.1 values are from the NVD base score, **not** from a live OSV feed; in particular CVE-2022-23491 and CVE-2023-30608 have lower CNA scores. The matching logic treats `introduced_inclusive <= version < fixed_exclusive`. This simplified single-range representation is correct for the pinned versions and the one historical release branch used in each case, but must not be extrapolated to every future release line. Sources link to each NVD record; verify fixes/branch exceptions there before updating the snapshots.

`patched_controls.csv` lists versions at the fix boundaries for these **specific nine records**. A negative result for one advisory does not mean a version has no other vulnerabilities.

The script cannot discover unlisted advisories, prove exploitability, or make production security decisions. A 'match' means a package version lies within a documented advisory range. A missing match means 'not found within this nine-record local corpus', not 'safe'.
