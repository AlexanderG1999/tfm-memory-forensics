from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any


MODELS = ("A", "B", "C")


def load_json(path: Path) -> Any:
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def load_csv(
    path: Path,
) -> list[dict[str, str]]:

    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def relative_url(
    source: Path,
    destination_dir: Path,
) -> str:

    return os.path.relpath(
        source,
        destination_dir,
    ).replace("\\", "/")


def discover_samples(
    graph_root: Path,
    output_dir: Path,
) -> dict[str, Any]:

    samples: dict[str, Any] = {}

    for sample_dir in sorted(
        path
        for path in graph_root.iterdir()
        if path.is_dir()
    ):

        summary_path = (
            sample_dir
            / "graph_summary.json"
        )

        process_graph_path = (
            sample_dir
            / "process_graph.json"
        )

        if (
            not summary_path.exists()
            or not process_graph_path.exists()
        ):
            continue

        summary = load_json(
            summary_path
        )

        graphs: dict[str, Any] = {}

        for model in MODELS:

            analyst = (
                sample_dir
                / f"graph_{model}.html"
            )

            evaluation = (
                sample_dir
                / (
                    f"graph_{model}"
                    "_evaluation.html"
                )
            )

            graphs[model] = {
                "analyst": (
                    relative_url(
                        analyst,
                        output_dir,
                    )
                    if analyst.exists()
                    else None
                ),
                "evaluation": (
                    relative_url(
                        evaluation,
                        output_dir,
                    )
                    if evaluation.exists()
                    else None
                ),
            }

        samples[sample_dir.name] = {
            "summary": summary,
            "graphs": graphs,
        }

    return samples


def load_aggregate_metrics(
    aggregate_dir: Path,
) -> dict[str, Any]:

    path = (
        aggregate_dir
        / "aggregate_models.csv"
    )

    rows = load_csv(path)

    output = {}

    for row in rows:

        model = row[
            "feature_set"
        ]

        output[model] = {
            "sample_count":
                int(row["sample_count"]),

            "malicious_process_count":
                int(
                    row[
                        "malicious_process_count"
                    ]
                ),

            "mean_first_malicious_rank":
                float(
                    row[
                        "mean_first_malicious_rank"
                    ]
                ),

            "weighted_mean_malicious_rank":
                float(
                    row[
                        "weighted_mean_malicious_rank"
                    ]
                ),

            "mean_mrr":
                float(row["mean_mrr"]),

            "micro_recall_at_3":
                float(
                    row[
                        "micro_recall_at_3"
                    ]
                ),

            "micro_recall_at_5":
                float(
                    row[
                        "micro_recall_at_5"
                    ]
                ),

            "micro_recall_at_10":
                float(
                    row[
                        "micro_recall_at_10"
                    ]
                ),
        }

    return output


def build_html(
    samples: dict[str, Any],
    aggregate: dict[str, Any],
) -> str:

    data_json = json.dumps(
        {
            "samples": samples,
            "aggregate": aggregate,
        },
        ensure_ascii=False,
    ).replace("<", "\\u003c")

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Memory Forensics Triage MVP</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background: #f4f6f8;
    color: #1f2937;
}}

header {{
    background: #182433;
    color: white;
    padding: 18px 28px;
}}

header h1 {{
    margin: 0;
    font-size: 22px;
}}

header p {{
    margin: 6px 0 0;
    opacity: 0.8;
    font-size: 13px;
}}

.controls {{
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    align-items: end;
    background: white;
    padding: 18px 28px;
    border-bottom: 1px solid #d5dbe1;
}}

.control {{
    display: flex;
    flex-direction: column;
    gap: 5px;
}}

.control label {{
    font-size: 12px;
    font-weight: bold;
    color: #4b5563;
}}

select {{
    min-width: 170px;
    padding: 8px;
    border: 1px solid #c8d0d8;
    border-radius: 5px;
    background: white;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(145px, 1fr)
        );
    gap: 12px;
    padding: 18px 28px;
}}

.card {{
    background: white;
    border: 1px solid #dfe4e8;
    border-radius: 7px;
    padding: 14px;
}}

.card-label {{
    color: #6b7280;
    font-size: 12px;
}}

.card-value {{
    font-size: 24px;
    font-weight: bold;
    margin-top: 5px;
}}

.layout {{
    display: grid;
    grid-template-columns:
        minmax(0, 1fr)
        300px;
    gap: 16px;
    padding: 0 28px 28px;
}}

.panel {{
    background: white;
    border: 1px solid #dfe4e8;
    border-radius: 7px;
    overflow: hidden;
}}

.panel-title {{
    padding: 12px 16px;
    font-weight: bold;
    border-bottom:
        1px solid #e5e7eb;
}}

iframe {{
    display: block;
    width: 100%;
    height: 830px;
    border: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

th,
td {{
    padding: 9px 10px;
    text-align: left;
    border-bottom:
        1px solid #eceff2;
}}

th {{
    background: #f8fafc;
}}

.rank {{
    font-weight: bold;
}}

#rankingBody tr {{cursor:pointer;}}
#rankingBody tr:hover {{background:#f0f5fb;}}
#rankingBody tr[aria-current="true"] {{background:#e2ebf5;box-shadow:inset 3px 0 #2563eb;}}
.process-select {{font:inherit;color:inherit;text-align:left;background:none;border:0;padding:0;cursor:pointer;}}
.process-select:focus-visible {{outline:2px solid #2563eb;outline-offset:3px;}}
#selectionStatus {{font-size:12px;color:#526071;padding:10px 16px;margin:0;}}

.label-malicious {{
    color: #a00000;
    font-weight: bold;
}}

.label-unknown {{
    color: #a85d00;
}}

.aggregate {{
    padding: 0 16px 16px;
    font-size: 13px;
}}

.aggregate-grid {{
    display: grid;
    grid-template-columns:
        1fr 1fr;
    gap: 8px;
}}

.metric {{
    background: #f8fafc;
    padding: 9px;
    border-radius: 5px;
}}

.metric span {{
    display: block;
    color: #6b7280;
    font-size: 11px;
}}

.hidden {{
    display: none;
}}

.notice {{
    padding: 30px;
    text-align: center;
    color: #6b7280;
}}

@media (
    max-width: 1200px
) {{
    .layout {{
        grid-template-columns: 1fr;
    }}
}}

</style>
</head>

<body>

<header>
    <h1>
        Memory Forensics Triage
    </h1>

    <p>
        Priorización de procesos,
        correlación multi-plugin y
        contexto relacional.
    </p>
</header>

<section class="controls">

    <div class="control">
        <label>Muestra</label>

        <select id="sampleSelect">
        </select>
    </div>

    <div class="control">
        <label>Modelo</label>

        <select id="modelSelect">
            <option value="A">
                A — Individual
            </option>

            <option value="B">
                B — Multi-plugin
            </option>

            <option value="C">
                C — Relacional
            </option>
        </select>
    </div>

    <div class="control">
        <label>Modo</label>

        <select id="modeSelect">
            <option value="analyst">
                Analista
            </option>

            <option value="evaluation">
                Evaluación
            </option>
        </select>
    </div>

</section>


<section class="cards">

    <div class="card">
        <div class="card-label">
            Procesos
        </div>

        <div
            class="card-value"
            id="processCount">
        </div>
    </div>

    <div class="card">
        <div class="card-label">
            Relaciones
        </div>

        <div
            class="card-value"
            id="edgeCount">
        </div>
    </div>

    <div class="card">
        <div class="card-label">
            Con actividad de red
        </div>

        <div
            class="card-value"
            id="networkCount">
        </div>
    </div>

    <div class="card">
        <div class="card-label">
            Con malfind
        </div>

        <div
            class="card-value"
            id="malfindCount">
        </div>
    </div>

    <div class="card">
        <div class="card-label">
            psscan-only
        </div>

        <div
            class="card-value"
            id="psscanCount">
        </div>
    </div>

</section>


<section class="layout">

    <div class="panel">

        <div
            class="panel-title"
            id="graphTitle">
            Grafo
        </div>

        <iframe
            id="graphFrame"
            title="Grafo de procesos">
        </iframe>

        <div
            id="missingGraph"
            class="notice hidden">
            Visualización no disponible.
        </div>

    </div>


    <div>

        <div class="panel">

            <div class="panel-title">
                Top 10
            </div>

            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>PID</th>
                        <th>Proceso</th>
                        <th
                            id="labelHeader">
                            Etiqueta
                        </th>
                    </tr>
                </thead>

                <tbody
                    id="rankingBody">
                </tbody>
            </table>

            <p id="selectionStatus" role="status">Selecciona una fila para localizar el proceso.</p>

        </div>


        <div
            class="panel hidden"
            id="evaluationPanel"
            style="margin-top:16px">

            <div class="panel-title">
                Evaluación agregada
            </div>

            <div
                class="aggregate">

                <div
                    class="aggregate-grid">

                    <div class="metric">
                        <span>
                            Mean first rank
                        </span>
                        <b id="meanRank"></b>
                    </div>

                    <div class="metric">
                        <span>
                            Mean MRR
                        </span>
                        <b id="mrr"></b>
                    </div>

                    <div class="metric">
                        <span>
                            Weighted mean rank
                        </span>
                        <b id="weightedRank"></b>
                    </div>

                    <div class="metric">
                        <span>
                            Micro Recall@5
                        </span>
                        <b id="recall5"></b>
                    </div>

                    <div class="metric">
                        <span>
                            Micro Recall@10
                        </span>
                        <b id="recall10"></b>
                    </div>

                </div>

            </div>

        </div>

    </div>

</section>


<script>

const APP_DATA = {data_json};
let viewToken = "";
let viewSequence = 0;
let graphReady = false;
let pendingSelection = null;

function sendSelection(selection) {{
    const frame = document.getElementById("graphFrame");
    if (!frame.getAttribute("src")) {{
        document.getElementById("selectionStatus").textContent = "Visualización no disponible.";
        return;
    }}
    pendingSelection = selection;
    document.getElementById("selectionStatus").textContent = graphReady ? "Localizando proceso…" : "Esperando al grafo…";
    if (graphReady) {{
        frame.contentWindow.postMessage({{type:"tfm:select-process",token:viewToken,...selection}},
            location.protocol === "file:" ? "*" : location.origin);
        pendingSelection = null;
    }}
}}

window.addEventListener("message", event => {{
    const frame = document.getElementById("graphFrame");
    const message = event.data;
    if (event.source !== frame.contentWindow || !message || message.token !== viewToken || !viewToken) return;
    if (location.protocol !== "file:" && event.origin !== location.origin) return;
    if (message.type === "tfm:ready") {{
        graphReady = true;
        if (pendingSelection) sendSelection(pendingSelection);
    }} else if (message.type === "tfm:process-selected") {{
        document.querySelectorAll("#rankingBody tr").forEach(row => {{
            row.setAttribute("aria-current", String(row.dataset.processUid === message.uid));
        }});
        document.getElementById("selectionStatus").textContent = message.uid
            ? "Proceso seleccionado · PID " + message.pid : "Selecciona una fila para localizar el proceso.";
    }} else if (message.type === "tfm:selection-unavailable") {{
        document.getElementById("selectionStatus").textContent = "No se pudo identificar un proceso único en esta vista.";
    }}
}});

const sampleSelect =
    document.getElementById(
        "sampleSelect"
    );

const modelSelect =
    document.getElementById(
        "modelSelect"
    );

const modeSelect =
    document.getElementById(
        "modeSelect"
    );


function populateSamples() {{

    const samples =
        Object.keys(
            APP_DATA.samples
        );

    samples.forEach(
        sample => {{

            const option =
                document.createElement(
                    "option"
                );

            option.value = sample;
            option.textContent = sample;

            sampleSelect.appendChild(
                option
            );
        }}
    );

    if (samples.length > 0) {{
        sampleSelect.value =
            samples[
                samples.length - 1
            ];
    }}
}}


function updateCards(summary) {{

    document.getElementById(
        "processCount"
    ).textContent =
        summary.node_count;

    document.getElementById(
        "edgeCount"
    ).textContent =
        summary.edge_count;

    document.getElementById(
        "networkCount"
    ).textContent =
        summary.nodes_with_network;

    document.getElementById(
        "malfindCount"
    ).textContent =
        summary.nodes_with_malfind;

    document.getElementById(
        "psscanCount"
    ).textContent =
        summary.psscan_only_count;
}}


function updateRanking(
    summary,
    model,
    mode
) {{

    const body =
        document.getElementById(
            "rankingBody"
        );

    body.innerHTML = "";

    const rows =
        summary[
            "top10_" + model
        ] || [];

    rows.forEach(row => {{

        const tr =
            document.createElement(
                "tr"
            );

        tr.dataset.processUid = row.process_uid || "";
        tr.setAttribute("aria-current", "false");
        tr.addEventListener("click", () => sendSelection({{
            uid: row.process_uid || null, pid: Number(row.pid)
        }}));

        let label = "";

        if (mode === "evaluation") {{
            label =
                row.label_text || "";
        }}

        let labelClass = "";

        if (label === "Malicious") {{
            labelClass =
                "label-malicious";
        }}

        if (label === "Unknown") {{
            labelClass =
                "label-unknown";
        }}

        tr.innerHTML = `
            <td class="rank">
                ${{row.rank}}
            </td>

            <td>
                ${{row.pid}}
            </td>

            <td>
                <button type="button" class="process-select">${{escapeText(row.image_name)}}</button>
            </td>

            <td class="${{labelClass}}">
                ${{escapeText(label)}}
            </td>
        `;

        body.appendChild(tr);
    }});

    document.getElementById(
        "labelHeader"
    ).style.display =
        mode === "evaluation"
        ? ""
        : "none";

    Array.from(
        body.querySelectorAll("tr")
    ).forEach(tr => {{
        tr.children[3].style.display =
            mode === "evaluation"
            ? ""
            : "none";
    }});
}}


function updateAggregate(
    model,
    mode
) {{

    const panel =
        document.getElementById(
            "evaluationPanel"
        );

    if (mode !== "evaluation") {{
        panel.classList.add(
            "hidden"
        );
        return;
    }}

    panel.classList.remove(
        "hidden"
    );

    const metrics =
        APP_DATA.aggregate[
            model
        ];

    if (!metrics) {{
        return;
    }}

    document.getElementById(
        "meanRank"
    ).textContent =
        metrics
        .mean_first_malicious_rank
        .toFixed(3);

    document.getElementById(
        "weightedRank"
    ).textContent =
        metrics
        .weighted_mean_malicious_rank
        .toFixed(3);

    document.getElementById(
        "mrr"
    ).textContent =
        metrics.mean_mrr
        .toFixed(3);

    document.getElementById(
        "recall5"
    ).textContent =
        metrics.micro_recall_at_5
        .toFixed(3);

    document.getElementById(
        "recall10"
    ).textContent =
        metrics.micro_recall_at_10
        .toFixed(3);
}}


function escapeText(value) {{
    const span = document.createElement("span");
    span.textContent = value ?? "";
    return span.innerHTML;
}}

function updateGraph(
    sampleData,
    sample,
    model,
    mode
) {{

    const previousFrame =
        document.getElementById(
            "graphFrame"
        );

    // Replace the document immediately so evaluation details cannot persist
    // while the next analyst graph is loading (or when a graph is missing).
    const frame = previousFrame.cloneNode(false);
    frame.removeAttribute("src");
    previousFrame.replaceWith(frame);
    viewToken = String(Date.now()) + "-" + (++viewSequence);
    graphReady = false;
    pendingSelection = null;
    document.getElementById("selectionStatus").textContent = "Selecciona una fila para localizar el proceso.";

    const missing =
        document.getElementById(
            "missingGraph"
        );

    const graphUrl =
        sampleData
        .graphs[model][mode];

    document.getElementById(
        "graphTitle"
    ).textContent =
        `${{sample}} — Modelo ${{model}}`;

    if (!graphUrl) {{
        frame.style.display =
            "none";

        missing.classList.remove(
            "hidden"
        );

        return;
    }}

    missing.classList.add(
        "hidden"
    );

    frame.style.display =
        "block";

    frame.addEventListener("load", () => {{
        frame.contentWindow.postMessage({{type:"tfm:ping",token:viewToken}},
            location.protocol === "file:" ? "*" : location.origin);
    }}, {{once:true}});
    frame.src = graphUrl + "#view=" + encodeURIComponent(viewToken);
}}


function refresh() {{

    const sample =
        sampleSelect.value;

    const model =
        modelSelect.value;

    const mode =
        modeSelect.value;

    const sampleData =
        APP_DATA.samples[
            sample
        ];

    if (!sampleData) {{
        return;
    }}

    updateCards(
        sampleData.summary
    );

    updateRanking(
        sampleData.summary,
        model,
        mode
    );

    updateAggregate(
        model,
        mode
    );

    updateGraph(
        sampleData,
        sample,
        model,
        mode
    );
}}


sampleSelect.addEventListener(
    "change",
    refresh
);

modelSelect.addEventListener(
    "change",
    refresh
);

modeSelect.addEventListener(
    "change",
    refresh
);


populateSamples();
refresh();

</script>

</body>
</html>
"""


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--graph-root",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--aggregate-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    output_dir = (
        args.output.parent
    )

    samples = discover_samples(
        args.graph_root,
        output_dir,
    )

    if not samples:
        raise ValueError(
            "No se encontraron "
            "grafos procesados."
        )

    aggregate = (
        load_aggregate_metrics(
            args.aggregate_dir
        )
    )

    html_content = build_html(
        samples,
        aggregate,
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with args.output.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        file.write(
            html_content
        )

    print(
        "Dashboard generado correctamente."
    )

    print(
        f"Muestras: {len(samples)}"
    )

    print(
        "Samples:",
        ", ".join(samples.keys()),
    )

    print(
        f"Salida: {args.output}"
    )


if __name__ == "__main__":
    main()
