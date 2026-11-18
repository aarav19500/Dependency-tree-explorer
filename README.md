# Dependency Tree Explorer

**Research question:** How many extra packages appear when we follow Python dependencies?

The script expands three direct-package selections into directed dependency graphs, identifies transitive packages, calculates minimum depth, and exports readable network diagrams.

## How to run

From this folder, using Python 3.10 or newer:

```bash
python -m pip install -r requirements.txt
python project.py --self-test
python project.py
```

On Windows, `py -m pip install -r requirements.txt` and `py project.py` are alternatives. No notebook, UI, network connection, API key, or API call is involved. All input data are bundled in `data/`; all output folders are regenerated when the main script runs.

## Where to look first

1. Read **`report/Research_Report.pdf`** for the question, experiments, figures, interpretation, and limitations. An editable text version is in `report/Research_Report.md`.
2. Open **`results/`** to inspect the actual calculated tables; open **`figures/`** to inspect exported publication-style PNGs.
3. Read **`project.py`** top to bottom. Inputs are deliberately small and transparent.

Key files: results/profile_metrics.csv; results/package_roles.csv; results/profile_edges.csv; results/*.graphml; figures/*_network.png; figures/direct_transitive_comparison.png.

## Evidence and boundaries

The historical package names and releases are real, and the nine CVEs are real publicly documented records. The **three application profiles are constructed examples**, not downloaded lockfiles or scans of actual public repositories. The source and scope of every input table are recorded in `data/SOURCES_AND_SCOPE.md`. The selected CVE list is not comprehensive and must not be mistaken for a live vulnerability scanner. All claims about remediation ranking are comparative properties of the scoring rules, not measurements of real incident prevention.

## Dependencies

- Python 3.10+
- NetworkX for directed graphs
- Matplotlib for static figures
- packaging for reliable version comparisons
- ReportLab and Pillow for PDF generation and embedded charts

## Reproducibility note

Generated results were produced and checked with Python 3.13.5, NetworkX 3.6.1, Matplotlib 3.10.8, packaging 25.0, ReportLab 4.4.9, and Pillow 12.3.0 on 12 November 2026. Compatible versions are constrained in requirements.txt. Figures, rankings, and reports are all rebuilt by `python project.py`.

## Responsible usage

No exploits, network probes, scanning, or external targets are included. The project is an educational analysis of public records. It does not establish exploitability, compliance, or production deployment risk.
