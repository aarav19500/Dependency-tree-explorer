#!/usr/bin/env python3
"""Offline, reproducible educational cybersecurity case study. No networking or APIs."""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from xml.sax.saxutils import escape

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
from packaging.version import Version
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, Image, PageBreak, KeepTogether)

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
RESULTS = HERE / "results"
FIGURES = HERE / "figures"
REPORT = HERE / "report"
for _directory in (RESULTS, FIGURES, REPORT):
    _directory.mkdir(parents=True, exist_ok=True)


def rows(name):
    with (DATA / name).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def save_csv(name, records, columns):
    with (RESULTS / name).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows([{key: record.get(key, "") for key in columns} for record in records])


def load_study():
    packages = {r["package"]: r["version"] for r in rows("packages.csv")}
    dependencies = [(r["parent"], r["child"]) for r in rows("dependencies.csv")]
    profile_info = defaultdict(lambda: {"roots": [], "description": ""})
    for r in rows("profiles.csv"):
        profile_info[r["profile"]]["roots"].append(r["direct_package"])
        profile_info[r["profile"]]["description"] = r["description"]
    return packages, dependencies, dict(profile_info)


def build_graph(roots, dependencies):
    """Parent -> installed dependency. Include only nodes reachable from direct roots."""
    whole = nx.DiGraph()
    whole.add_edges_from(dependencies)
    whole.add_nodes_from(roots)
    reached = set(roots)
    for root in roots:
        reached.update(nx.descendants(whole, root))
    graph = whole.subgraph(reached).copy()
    if not nx.is_directed_acyclic_graph(graph):
        raise ValueError("The local dependency example must be acyclic")
    depth = {}
    for root in roots:
        for node, dist in nx.single_source_shortest_path_length(graph, root).items():
            depth[node] = min(depth.get(node, 10**6), dist)
    return graph, depth


def source_match(version, advisory):
    """The selected historical branch uses a documented half-open version interval."""
    value = Version(version)
    return Version(advisory["introduced_inclusive"]) <= value < Version(advisory["fixed_exclusive"])


def matches(packages, advisories, subset=None):
    """One row per CVE-package pair. No remote lookup or fuzzy package matching."""
    records = []
    for entry in advisories:
        name = entry["package"]
        if name not in packages or (subset is not None and name not in subset):
            continue
        if source_match(packages[name], entry):
            records.append({"package": name, "version": packages[name],
                            "cve_id": entry["cve_id"],
                            "cvss": float(entry["cvss31_nvd"]),
                            "summary": entry["summary"],
                            "reference": entry["advisory_reference"],
                            "scope_note": entry["scope_note"]})
    unique = {(r["cve_id"], r["package"]): r for r in records}
    return sorted(unique.values(), key=lambda r: (-r["cvss"], r["cve_id"]))


def save_figure(name):
    plt.savefig(FIGURES / name, dpi=190, bbox_inches="tight", facecolor="white")
    plt.close()


def draw_network(graph, depth, roots, title, filename):
    """Depth-layer diagram with separated text labels rather than overlapping circles."""
    positions = {}
    layers = defaultdict(list)
    for node, level in depth.items():
        layers[level].append(node)
    for layer, names in layers.items():
        names.sort()
        for index, node in enumerate(names):
            positions[node] = (float(layer) * 4.2, (len(names) - 1) * 0.7 - index * 1.4)
    fig, ax = plt.subplots(figsize=(11.3, 7.3))
    nx.draw_networkx_edges(graph, positions, ax=ax, arrows=True,
                           arrowstyle="-|>", arrowsize=14, width=1.15,
                           edge_color="#9B9B9B", node_size=1800,
                           connectionstyle="arc3,rad=0.02")
    for node, (x, y) in positions.items():
        direct = node in roots
        ax.text(x, y, node, ha="center", va="center", fontsize=12.2,
                color="white" if direct else "black",
                bbox={"boxstyle": "round,pad=0.30", "facecolor": "#202020" if direct else "#F3F3F3",
                      "edgecolor": "#3B3B3B", "linewidth": 0.9}, zorder=4)
    ax.set_title(title, loc="left", fontweight="bold", fontsize=13, pad=22)
    ax.text(.01, -.03, "Black: directly selected  |  Light: transitive  |  Arrow: requires", transform=ax.transAxes,
            fontsize=10, color="#444444")
    ax.axis("off")
    save_figure(filename)


def draw_horizontal(labels, values, title, xlabel, filename, width=10.0):
    fig, ax = plt.subplots(figsize=(width, max(4.0, 0.45 * len(labels) + 1.4)))
    ax.barh(range(len(labels)), values, color="#565656")
    ax.set_yticks(range(len(labels)), labels=labels)
    ax.invert_yaxis()
    ax.set_xlim(left=0)
    ax.set_title(title, fontweight="bold", loc="left", pad=15)
    ax.set_xlabel(xlabel)
    ax.grid(axis="x", alpha=.18)
    ax.set_axisbelow(True)
    for i, val in enumerate(values):
        ax.text(val, i, f"  {val:g}", va="center", fontsize=9)
    fig.tight_layout()
    save_figure(filename)


def title_for_footer(doc):
    return doc.title


def _numbered_page(canvas, doc):
    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.drawString(21*mm, 16*mm, title_for_footer(doc))
    canvas.drawRightString(A4[0]-21*mm, 16*mm, str(doc.page))
    canvas.setStrokeColor(colors.HexColor("#CCCCCC"))
    canvas.line(21*mm, 19*mm, A4[0]-21*mm, 19*mm)


def publish_report(title, subtitle, sections, references, metadata):
    """Create both a structured, searchable PDF and a readable Markdown source."""
    out_pdf = REPORT / "Research_Report.pdf"
    out_md = REPORT / "Research_Report.md"
    markdown = [f"# {title}", "", subtitle, ""]
    styles = getSampleStyleSheet()
    cover = ParagraphStyle("CoverX", parent=styles["Title"], fontName="Times-Bold",
                           fontSize=21, leading=25, spaceAfter=9, alignment=0, textColor=colors.black)
    sub = ParagraphStyle("SubX", parent=styles["Normal"], fontName="Times-Roman",
                         fontSize=11, leading=15, alignment=0, spaceAfter=14)
    heading = ParagraphStyle("SectionX", parent=styles["Heading2"], fontName="Times-Bold",
                             fontSize=14, leading=17, spaceBefore=15, spaceAfter=9, textColor=colors.black)
    body = ParagraphStyle("BodyX", parent=styles["BodyText"], fontName="Times-Roman",
                          fontSize=10.4, leading=15.6, spaceAfter=10, textColor=colors.black)
    small = ParagraphStyle("SmallX", parent=body, fontSize=8.3, leading=11.6)
    cap = ParagraphStyle("CaptionX", parent=body, fontName="Times-Italic", fontSize=9,
                         leading=12, spaceBefore=5, spaceAfter=15)
    doc = SimpleDocTemplate(str(out_pdf), pagesize=A4, leftMargin=21*mm,
                            rightMargin=21*mm, topMargin=24*mm, bottomMargin=25*mm,
                            title=title, author="")
    # A conventional research-paper opening: title, a descriptive subtitle, then the abstract.
    # Data limitations are discussed in the methods and limitations, not on a cover page.
    story = [Paragraph(escape(title), cover), Paragraph(escape(subtitle), sub), Spacer(1, 5*mm)]
    for section_index, (section_title, blocks) in enumerate(sections, 1):
        story.append(Paragraph(f"{section_index}. {escape(section_title)}", heading))
        markdown.extend([f"## {section_index}. {section_title}", ""])
        for item in blocks:
            kind = item[0]
            if kind == "p":
                paragraph = item[1]
                story.append(Paragraph(escape(paragraph), body))
                markdown.extend([paragraph, ""])
            elif kind == "fig":
                filename, caption = item[1], item[2]
                img_path = FIGURES / filename
                from PIL import Image as PILImage
                with PILImage.open(img_path) as im:
                    w, h = im.size
                ratio = min(1.0, (A4[0]-49*mm) / (w*72/190), 89*mm/(h*72/190))
                iw, ih = w*72/190*ratio, h*72/190*ratio
                story.append(KeepTogether([Image(str(img_path), width=iw, height=ih), Paragraph(escape(caption), cap)]))
                markdown.extend([f"![{caption}](../figures/{filename})", "", f"*{caption}*", ""])
            elif kind == "table":
                headers, table_rows, caption = item[1], item[2], item[3]
                width = (A4[0]-42*mm) / len(headers)
                cells = [[Paragraph(escape(str(v)), small) for v in headers]]
                cells.extend([[Paragraph(escape(str(v)), small) for v in row] for row in table_rows])
                tbl = Table(cells, colWidths=[width] * len(headers), repeatRows=1, hAlign="CENTER")
                tbl.setStyle(TableStyle([
                    ("LINEBELOW", (0,0),(-1,0), 0.7, colors.black),
                    ("LINEBELOW", (0,-1),(-1,-1), 0.5, colors.HexColor("#999999")),
                    ("ROWBACKGROUNDS", (0,1),(-1,-1), [colors.white,colors.HexColor("#F6F6F6")]),
                    ("VALIGN",(0,0),(-1,-1), "TOP"),
                    ("TOPPADDING",(0,0),(-1,-1),5),
                    ("BOTTOMPADDING",(0,0),(-1,-1),5),
                ]))
                story.extend([tbl, Paragraph(escape(caption), cap)])
                markdown.extend(["| " + " | ".join(map(str,headers)) + " |",
                                 "|" + "|".join(["---"]*len(headers)) + "|"])
                markdown.extend(["| " + " | ".join(map(str,row)) + " |" for row in table_rows])
                markdown.extend(["", f"*{caption}*", ""])
    story.append(Paragraph(f"{len(sections)+1}. References and data provenance", heading))
    markdown.extend(["## References and data provenance", ""])
    for i,(label,url) in enumerate(references,1):
        story.append(Paragraph(escape(f"[{i}] {label}: {url}"), small))
        markdown.append(f"[{i}] {label}. {url}")
    story.append(Spacer(1, 12*mm))
    story.append(Paragraph("Reproduction note: install requirements.txt, then run the one Python file in this folder. The input tables are local, and the program overwrites its own results, figures, and report. No API or network access is used.", body))
    markdown.extend(["", "## Reproduction", "", "`python project.py` — no network calls. Input files are in `data/`; outputs are regenerated in `results/`, `figures/` and `report/`."])
    out_md.write_text("\n".join(markdown)+"\n", encoding="utf-8")
    doc.build(story, onFirstPage=_numbered_page, onLaterPages=_numbered_page)
    print(f"Report: {out_pdf.relative_to(HERE)}")


def validate_inputs():
    packages, dep_edges, profile_info = load_study()
    assert len(packages) == len(set(packages)), "Duplicate package"
    assert all(p in packages and c in packages for p,c in dep_edges)
    assert all(root in packages for info in profile_info.values() for root in info["roots"])
    assert all(0 <= float(a["cvss31_nvd"]) <= 10 for a in rows("advisories.csv"))
    assert len({a["cve_id"] for a in rows("advisories.csv")}) == len(rows("advisories.csv"))
    assert not source_match("2.31.0", {"introduced_inclusive":"2.3.0", "fixed_exclusive":"2.31.0"})
    assert source_match("2.28.1", {"introduced_inclusive":"2.3.0", "fixed_exclusive":"2.31.0"})
    return packages, dep_edges, profile_info


def main():
    parser = argparse.ArgumentParser(description="Explore three offline example dependency networks")
    parser.add_argument("--self-test", action="store_true", help="Run input and graph checks")
    args = parser.parse_args()
    packages, edges, profiles = validate_inputs()
    if args.self_test:
        for item in profiles.values():
            graph, depth = build_graph(item["roots"], edges)
            assert all(depth[r] == 0 for r in item["roots"])
            assert nx.is_directed_acyclic_graph(graph)
            assert all(u in graph and v in graph for u, v in graph.edges)
        print("PASS: profiles, edge direction, reachability, and graph acyclicity")
        return

    stats, roles, edge_rows = [], [], []
    slugs = {"Web API example":"web_api", "Report CLI example":"report_cli", "Admin portal example":"admin_portal"}
    for name, info in profiles.items():
        graph, depth = build_graph(info["roots"], edges)
        slug = slugs[name]
        nx.write_graphml(graph, RESULTS / f"{slug}.graphml")
        draw_network(graph, depth, info["roots"], f"{name}: dependency network", f"{slug}_network.png")
        transitive = len(graph)-len(info["roots"])
        stats.append({"profile":name, "direct_packages":len(info["roots"]),
                      "transitive_packages":transitive, "total_packages":len(graph),
                      "dependency_edges":graph.number_of_edges(),
                      "max_depth":max(depth.values()),
                      "shared_requirements":sum(graph.in_degree(node)>1 for node in graph)})
        for pkg in sorted(graph):
            roles.append({"profile":name,"package":pkg,"version":packages[pkg],
                          "role":"direct" if pkg in info["roots"] else "transitive", "depth":depth[pkg],
                          "required_by":",".join(sorted(graph.predecessors(pkg)))})
        for src,dst in sorted(graph.edges):
            edge_rows.append({"profile":name,"parent":src,"required_dependency":dst})
    save_csv("profile_metrics.csv",stats,list(stats[0]))
    save_csv("package_roles.csv",roles,list(roles[0]))
    save_csv("profile_edges.csv",edge_rows,list(edge_rows[0]))

    fig, ax = plt.subplots(figsize=(9.4,4.9))
    labels = [r["profile"].replace(" example","") for r in stats]
    x = range(len(labels))
    ax.bar([i-.18 for i in x],[r["direct_packages"] for r in stats],width=.36, label="Direct",color="#303030")
    ax.bar([i+.18 for i in x],[r["transitive_packages"] for r in stats],width=.36, label="Transitive",color="#A0A0A0")
    ax.set_xticks(list(x),labels)
    ax.set_ylabel("Distinct packages")
    ax.set_title("Packages visible beyond direct selections",loc="left",fontweight="bold")
    ax.legend(frameon=False)
    ax.grid(axis="y", alpha=.18)
    ax.set_axisbelow(True)
    fig.tight_layout(); save_figure("direct_transitive_comparison.png")
    maxprofile = max(stats, key=lambda r: r["total_packages"])
    mean_trans = sum(r["transitive_packages"] for r in stats)/len(stats)
    sections = [
      ("Abstract", [
       ("p", f"This exercise reconstructed three small Python dependency networks using a fixed set of real 2022-era package releases. The inputs are illustrative application profiles, not claims about particular deployed repositories. There were {len(profiles)} profiles and {len(packages)} candidate packages in the shared local catalogue. Each profile was expanded from its directly selected packages and inspected for transitive requirements, dependency depth, and shared parent relationships. The study is intentionally small: its contribution is a transparent reconstruction method and an auditable output, not a large-scale estimate of ecosystem risk."),
       ("p", "The networks were generated entirely from bundled tables. Their resulting GraphML and CSV files make it possible to check every connection shown in a figure.")]),
      ("Research question and motivation", [
       ("p", "When a developer selects a Python library, the installed set often contains several other packages that the developer did not choose directly. A list of top-level requirements therefore hides some of the software that will need maintenance. The question examined here is straightforward: how much dependency information becomes visible after following requirement edges, and which packages occupy different depths in the resulting graph?"),
       ("p", "The useful distinction is between a package deliberately selected by an example application and a package reached through one or more dependency steps. Neither category is inherently safe or unsafe. Directness is a structural property of a particular application, not a severity label.")]),
      ("Data and graph construction", [
       ("p", "The package catalogue fixes one historical version for each package. Three small profiles choose different direct roots from that catalogue. Flask brings in Werkzeug, Jinja2, Click and ItsDangerous; Jinja2 and Werkzeug both reach MarkupSafe. Requests brings in urllib3, certifi, idna and charset-normalizer. Django brings in asgiref, sqlparse and pytz. These are a deliberately selected subset of runtime requirements rather than complete resolver results; optional and environment-specific dependencies are omitted."),
       ("p", "Each directed edge points from the package that has a requirement to the package it requires. A separate directed graph is built for each profile by taking the union of the descendants of its direct roots. Minimum depth is computed with a shortest-path search from each root. A package at depth zero is direct; all other reachable packages are transitive. Repeated paths are counted as one distinct package."),
       ("table", ["Profile","Direct","Transitive","Max depth"], [[r["profile"],r["direct_packages"],r["transitive_packages"],r["max_depth"]] for r in stats], "Table 1. Profile statistics computed directly from the bundled edge list.")]),
      ("Observed dependency structure", [
       ("p", f"The {maxprofile['profile']} profile contains the largest distinct package set in this collection ({maxprofile['total_packages']} packages). On average, each profile includes {mean_trans:.1f} transitive packages beyond its direct selections. All counts are tied to this deliberately small catalogue: they cannot be used as estimates for typical Python applications."),
       ("fig","direct_transitive_comparison.png", "Figure 1. Direct selections versus additional reachable packages for the three illustrative profiles."),
       ("fig","web_api_network.png", "Figure 2. Web API example. Arrows point from a requirement owner to its dependency."),
       ("fig","report_cli_network.png", "Figure 3. Report CLI example. The same package may be a direct selection in one profile and a transitive requirement in another."),
       ("fig","admin_portal_network.png", "Figure 4. Admin portal example. Structural depth depends on which roots the profile selected.")]),
      ("Checks and interpretation", [
       ("p", "I checked that every edge endpoint exists in the package catalogue, every direct root is present, the profile networks have no directed cycles, and each root receives depth zero. The program exports edge lists and per-package roles as well as the diagrams, so the drawing can be checked against the underlying graph. Running the built-in self-test repeats the main checks."),
       ("p", "This experiment clarified why an installation list is not the same as a dependency explanation. For example, a transitive package may have two parents, and its shortest depth does not preserve every path that reaches it. An analyst looking only at the package count would miss that distinction. A dependency graph preserves the relationship, which becomes useful when known vulnerabilities are added in the later projects.")]),
      ("Limitations and next step", [
       ("p", "The profiles are constructed educational cases, not snapshots extracted from real production lockfiles. The dependency list omits optional requirements, environment markers, extras and differences across Python interpreter versions. It also does not establish which code paths are executed at runtime. Therefore the exported graph should not be presented as a verified software bill of materials."),
       ("p", "The logical next step is to attach version-specific, sourced vulnerability records to the reachable packages. That is the purpose of the second project. For now, the useful result is the reproducible structure itself.")])
    ]
    sections.extend([
      ("Appendix A: a worked path through the network", [
       ("p","Consider the Web API profile. It explicitly selects Flask and Requests. Requests has four immediate requirements in the local data: urllib3, certifi, idna and charset-normalizer. Each is one step away from the Requests root, so each has minimum depth one. Flask has its own immediate requirements, including Jinja2 and Werkzeug. Both Jinja2 and Werkzeug require MarkupSafe. As a result, MarkupSafe is not one step from a root, but two steps from Flask along two different paths. The shortest-distance metric correctly records depth two while the directed graph preserves both incoming edges. This shows why depth and number of parents answer different questions."),
       ("p","The example also demonstrates the importance of choosing the direction of the arrows. If an edge were accidentally drawn from MarkupSafe to Flask, starting at the selected Flask root would not discover MarkupSafe as a requirement. A graph can be visually attractive and still encode the wrong relationship; that is why I exported a plain edge list next to each diagram."),
       ("p","The direct-versus-transitive distinction belongs to a profile, not permanently to the package. Jinja2 is directly selected in the Report CLI example, but it is reached through Flask in two other profiles. The same version therefore has different roles depending on the application's direct selections. That becomes relevant later when the portfolio compares remediation ranking rules."),
       ("table",["Package","Pinned version","Role in Web API","Minimum depth"],[[r["package"],r["version"],r["role"],r["depth"]] for r in roles if r["profile"]=="Web API example"],"Table A1. A row-level view of the Web API network, taken from the exact exported role table.")]),
      ("Appendix B: reproducibility and design decisions", [
       ("p","The script does not run pip to install the historical packages, because installation would modify the current environment and need not reproduce the older resolution. Instead, it reads the pinned version catalogue and requirement edges as data. This isolates the graph algorithm from package installation behavior. The trade-off is clear: the table can be inspected and reproduced offline, but it does not test whether a modern resolver would choose the same versions or additional platform-specific requirements."),
       ("p","To check a result by hand, open profiles.csv and note the roots of the chosen profile. Follow those package names as parents in dependencies.csv, then repeat for newly reached child packages until no new names appear. Count the roots, count all other unique names, and record the fewest number of edges from any root to each reached package. These manual steps should match profile_metrics.csv and package_roles.csv. The GraphML files let a reviewer check that the figures have not hidden or invented edges."),
       ("p","Two mistakes would produce convincing-looking but incorrect outputs. Counting the same transitive package twice would exaggerate dependency size, especially for shared requirements such as MarkupSafe. Treating every child as one level deep would erase the distinction between a direct requirement of Flask and a second-level requirement of Jinja2. The program avoids the first by using a set of reached nodes and the second by using shortest-path lengths rather than a flat package list."),
       ("p","The analysis intentionally stops before answering any vulnerability question. A dependency graph describes package relationships, not whether a particular release contains a known flaw or whether an application executes the relevant code. Keeping these concepts separate made it easier to design the next two projects with fewer unsupported security claims.")])
    ])
    refs=[("Python Package Index historical releases","https://pypi.org/"),
          ("Flask installation and dependency documentation","https://flask.palletsprojects.com/en/stable/installation/"),
          ("Requests source history","https://github.com/psf/requests/tree/v2.28.1"),
          ("Django 3.2 documentation","https://docs.djangoproject.com/en/3.2/"),
          ("NetworkX shortest-path documentation","https://networkx.org/documentation/stable/reference/algorithms/shortest_paths.html")]
    publish_report("Dependency Tree Explorer", "Mapping direct and transitive dependencies in Python packages", sections, refs, {})
    print(f"Completed: {len(stats)} profiles, {len(roles)} profile-package records, {len(edge_rows)} edges")

if __name__ == "__main__":
    main()
