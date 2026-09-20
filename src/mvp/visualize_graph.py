from __future__ import annotations

import argparse
import html
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx
from pyvis.network import Network


MODELS = ("A", "B", "C")


def load_graph(path: Path) -> nx.DiGraph:
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    graph = nx.DiGraph()

    for node in data["nodes"]:
        node = dict(node)
        uid = node.pop("id")

        graph.add_node(
            uid,
            **node,
        )

    for edge in data["edges"]:
        edge = dict(edge)

        source = edge.pop("source")
        target = edge.pop("target")

        graph.add_edge(
            source,
            target,
            **edge,
        )

    return graph


def select_focus_nodes(
    graph: nx.DiGraph,
    model: str,
    top_n: int,
    context_depth: int,
    max_children: int,
) -> tuple[set[str], set[str]]:

    rank_field = f"rank_{model}"

    ordered = sorted(
        graph.nodes,
        key=lambda uid: (
            int(graph.nodes[uid][rank_field]),
            int(graph.nodes[uid]["pid"]),
        ),
    )

    ordered_seeds = ordered[:top_n]

    seeds = set(
        ordered_seeds
    )

    included = set(
        ordered_seeds
    )

    queue = deque(
        (uid, 0)
        for uid in ordered_seeds
    )

    while queue:

        uid, depth = queue.popleft()

        if depth >= context_depth:
            continue

        # ---------------------------------
        # PADRES
        # ---------------------------------

        parents = sorted(
            graph.predecessors(uid),
            key=lambda candidate: (
                int(
                    graph.nodes[candidate][
                        rank_field
                    ]
                ),
                int(
                    graph.nodes[candidate][
                        "pid"
                    ]
                ),
            ),
        )

        # ---------------------------------
        # HIJOS
        # ---------------------------------

        children = sorted(
            graph.successors(uid),
            key=lambda candidate: (
                int(
                    graph.nodes[candidate][
                        rank_field
                    ]
                ),
                int(
                    graph.nodes[candidate][
                        "pid"
                    ]
                ),
            ),
        )

        # Limitamos únicamente hijos.
        children = children[
            :max_children
        ]

        neighbors = (
            parents + children
        )

        for neighbor in neighbors:

            if neighbor in included:
                continue

            included.add(
                neighbor
            )

            queue.append(
                (
                    neighbor,
                    depth + 1,
                )
            )

    return seeds, included


def format_score(value: Any) -> str:
    try:
        return f"{float(value):.6f}"
    except (TypeError, ValueError):
        return ""


def build_tooltip(
    node: dict[str, Any],
    selected_model: str,
    evaluation_mode: bool,
) -> str:

    lines = [
        f"Proceso: {node.get('image_name', '')}",
        (
            f"PID / PPID: "
            f"{node.get('pid')} / "
            f"{node.get('ppid')}"
        ),
        f"Modelo mostrado: {selected_model}",
        (
            "Rank A / B / C: "
            f"{node.get('rank_A')} / "
            f"{node.get('rank_B')} / "
            f"{node.get('rank_C')}"
        ),
        (
            "Score A: "
            f"{format_score(node.get('anomaly_score_A'))}"
        ),
        (
            "Score B: "
            f"{format_score(node.get('anomaly_score_B'))}"
        ),
        (
            "Score C: "
            f"{format_score(node.get('anomaly_score_C'))}"
        ),
        f"Threads: {node.get('threads', '')}",
        f"WOW64: {node.get('wow64', '')}",
        (
            "Duración: "
            f"{node.get('process_duration_seconds', '')} s"
        ),
        (
            "pslist / psscan: "
            f"{node.get('in_pslist')} / "
            f"{node.get('in_psscan')}"
        ),
        (
            "Cmdline length: "
            f"{node.get('cmdline_length', '')}"
        ),
        (
            "Malfind regiones: "
            f"{node.get('malfind_region_count', '')}"
        ),
        (
            "Malfind RWX: "
            f"{node.get('malfind_rwx_count', '')}"
        ),
        (
            "TCP / UDP: "
            f"{node.get('tcp_object_count')} / "
            f"{node.get('udp_object_count')}"
        ),
        (
            "IPs remotas únicas: "
            f"{node.get('unique_remote_ip_count', '')}"
        ),
        (
            "IPs públicas: "
            f"{node.get('public_remote_ip_count', '')}"
        ),
        (
            "Padre resuelto: "
            f"{node.get('parent_resolved', '')}"
        ),
        (
            "Hijos: "
            f"{node.get('child_count', '')}"
        ),
        (
            "Ancestros resueltos: "
            f"{node.get('resolved_ancestor_count', '')}"
        ),
        (
            "Padre con red: "
            f"{node.get('parent_has_network', '')}"
        ),
        (
            "Padre con malfind: "
            f"{node.get('parent_has_malfind', '')}"
        ),
        (
            "Hijos psscan-only: "
            f"{node.get('children_psscan_only_count', '')}"
        ),
    ]

    if evaluation_mode:
        lines.append(
            "Ground truth: "
            f"{node.get('label_text', '')}"
        )

    return "\n".join(lines)


def format_timestamp(value: Any) -> str:
    """Format presentation timestamps; never infer a timezone for naive values."""
    if value is None or value == "":
        return "—"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return parsed.strftime("%Y-%m-%d %H:%M:%S") + " (zona no indicada)"
    except (TypeError, ValueError):
        return "Fecha no interpretable"


def build_detail(node: dict[str, Any], model: str, evaluation: bool, seed: bool,
                 graph: nx.DiGraph, uid: str, visible: set[str]) -> str:
    """Whitelist display evidence and resolve identities from existing graph edges."""
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None and value != "" else "—"))

    def section(title: str, fields: list[tuple[str, str]]) -> str:
        rows = []
        for label, key in fields:
            timestamp = key in ("create_time", "exit_time")
            value = format_timestamp(node.get(key)) if timestamp else node.get(key)
            rows.append(f'<dt>{label}</dt><dd class="{"timestamp" if timestamp else ""}">{esc(value)}</dd>')
        return "<section><h3>" + title + "</h3><dl>" + "".join(rows) + "</dl></section>"

    def identities(title: str, relatives: list[str]) -> str:
        items = []
        for relative in sorted(relatives, key=lambda key: (int(graph.nodes[key]["pid"]), str(key))):
            data = graph.nodes[relative]
            text = f"{esc(data.get('image_name'))} [{esc(data.get('pid'))}]"
            if int(data.get("in_pslist", 0)) == 0 and int(data.get("in_psscan", 0)) == 1:
                text += " · <strong>psscan-only</strong>"
            if relative not in visible:
                text += ' <span class="outside-view">(fuera de esta vista)</span>'
            items.append("<li>" + text + "</li>")
        return f'<h4>{title}</h4><ul class="relations">' + ("".join(items) or '<li>—</li>') + '</ul>'

    result = '<div class="process-heading">'
    result += f"<h2>{esc(node.get('image_name'))}</h2>"
    result += f"<p>PID {esc(node.get('pid'))} · PPID {esc(node.get('ppid'))}</p>"
    result += f"<p class='active-summary'>Modelo {model} · Rank #{esc(node.get('rank_' + model))}</p></div>"
    result += "<p class='role'>" + ("Top-N" if seed else "Contexto")
    if int(node.get("in_pslist", 0)) == 0 and int(node.get("in_psscan", 0)) == 1:
        result += " · psscan-only"
    result += "</p><h3>Priorización A/B/C</h3>"
    result += "<table><thead><tr><th>Modelo</th><th>Rank</th><th>Score</th></tr></thead><tbody>"
    for current in MODELS:
        result += (f"<tr{' class=active-model' if current == model else ''}><th>{current}</th>"
                   f"<td>#{esc(node.get('rank_' + current))}</td>"
                   f"<td>{esc(format_score(node.get('anomaly_score_' + current)))}</td></tr>")
    result += "</tbody></table>"
    result += section("Evidencia individual", [
        ("Threads", "threads"), ("WOW64", "wow64"),
        ("Creación", "create_time"), ("Salida", "exit_time"),
        ("Duración (s)", "process_duration_seconds")])
    result += section("Evidencia multi-plugin", [
        ("pslist", "in_pslist"), ("psscan", "in_psscan"),
        ("Longitud cmdline", "cmdline_length"), ("Regiones malfind", "malfind_region_count"),
        ("Regiones RWX", "malfind_rwx_count"), ("Commit charge malfind", "malfind_total_commit_charge"),
        ("Objetos de red", "network_object_count"), ("TCP", "tcp_object_count"), ("UDP", "udp_object_count"),
        ("IPs remotas únicas", "unique_remote_ip_count"), ("IPs públicas", "public_remote_ip_count")])
    result += '<section><h3>Contexto relacional</h3>'
    result += identities("Padre", list(graph.predecessors(uid)))
    result += identities("Hijos", list(graph.successors(uid))) + '</section>'
    result += section("Evidencias relacionales", [
        ("Padre resuelto", "parent_resolved"), ("Número de hijos", "child_count"),
        ("Ancestros resueltos", "resolved_ancestor_count"), ("Padre con red", "parent_has_network"),
        ("Padre con malfind", "parent_has_malfind"), ("Padre psscan-only", "parent_psscan_only"),
        ("Hijos con red", "children_with_network_count"), ("Hijos con malfind", "children_with_malfind_count"),
        ("Hijos psscan-only", "children_psscan_only_count")])
    if evaluation:
        result += section("Evaluación", [("Ground truth", "label_text")])
    return result


def add_process_inspector(network: Network, graph: nx.DiGraph, model: str,
                          top_n: int, evaluation: bool) -> str:
    visible = {str(n["id"]) for n in network.nodes}
    details = {uid: build_detail(graph.nodes[uid], model, evaluation,
               int(graph.nodes[uid][f"rank_{model}"]) <= top_n, graph, uid, visible) for uid in visible}
    # PID fallback must be unambiguous in the full sample, not just the focused view.
    identities = {str(uid): {"pid": int(data["pid"])} for uid, data in graph.nodes(data=True)}
    payload = json.dumps({"details": details, "identities": identities}, ensure_ascii=False).replace("<", "\\u003c")
    precedence = ("Malicious / Unknown prevalece sobre psscan-only. " if evaluation else "")
    precedence += "psscan-only prevalece sobre Top-N / Contexto. El borde grueso identifica Top-N. El halo azul indica la selección y su vecindad."
    legend = f"""<div id="graph-legend" aria-label="Leyenda del grafo">
      <span><i class="key top"></i>Top-{top_n}</span>
      <span><i class="key context"></i>Contexto</span>
      <span><i class="key scan"></i>psscan-only</span>"""
    if evaluation:
        legend += '<span><i class="key malicious"></i>Malicious</span><span><i class="key unknown"></i>Unknown</span>'
    legend += '<span>Padre → hijo</span>'
    legend += f'<button type="button" class="legend-help" title="{html.escape(precedence, quote=True)}" aria-label="Ayuda de estilos" aria-expanded="false">ⓘ</button></div>'
    legend += '<p id="legend-help-text" hidden>' + html.escape(precedence) + '</p>'
    base = Path(__file__).resolve().parent
    css = (base / 'process_inspector.css').read_text(encoding='utf-8')
    script = (base / 'process_inspector.js').read_text(encoding='utf-8')
    script = script.replace('__INSPECTOR_DATA__', payload)
    return (network.html.replace("</head>", '<style>' + css + '</style></head>')
            .replace("<body>", '<body>' + legend)
            .replace("</body>", '<script>' + script + '</script></body>'))


def visual_style(
    node: dict[str, Any],
    is_seed: bool,
    selected_model: str,
    evaluation_mode: bool,
) -> dict[str, Any]:

    rank = int(
        node[
            f"rank_{selected_model}"
        ]
    )

    if is_seed:
        size = max(
            22,
            38 - rank,
        )
    else:
        size = 17

    # Modo forense:
    # los colores no dependen del ground truth.
    color = {
        "background": "#D9EAF7",
        "border": "#456B8C",
    }

    shape = "dot"

    if is_seed:
        color = {
            "background": "#FFD966",
            "border": "#A66A00",
        }

    # Artefacto exclusivo de psscan.
    if (
        int(node.get("in_pslist", 0)) == 0
        and
        int(node.get("in_psscan", 0)) == 1
    ):
        color = {
            "background": "#D9D2E9",
            "border": "#674EA7",
        }

    # Solo en evaluación utilizamos el ground truth
    # para distinguir visualmente los malware conocidos.
    if evaluation_mode:

        label = node.get(
            "label_text",
            "",
        )

        if label == "Malicious":
            color = {
                "background": "#F4CCCC",
                "border": "#990000",
            }
            shape = "diamond"

        elif label == "Unknown":
            color = {
                "background": "#FCE5CD",
                "border": "#B45F06",
            }

    return {
        "size": size,
        "color": color,
        "shape": shape,
    }


def build_visualization(
    graph: nx.DiGraph,
    model: str,
    top_n: int,
    context_depth: int,
    evaluation_mode: bool,
    max_children: int,
) -> Network:

    seeds, included = (
        select_focus_nodes(
            graph,
            model,
            top_n,
            context_depth,
            max_children,
        )
    )

    network = Network(
        height="850px",
        width="100%",
        directed=True,
        notebook=False,
        cdn_resources="in_line",
    )

    network.focus_seed_count = len(seeds)
    network.focus_node_count = len(included)

    network.focus_edge_count = sum(
        1
        for source, target in graph.edges
        if source in included
        and target in included
    )

    for uid in included:

        node = graph.nodes[uid]

        style = visual_style(
            node,
            uid in seeds,
            model,
            evaluation_mode,
        )

        rank = node[
            f"rank_{model}"
        ]

        label = (
            f"{node.get('image_name')}\n"
            f"PID {node.get('pid')}\n"
            f"{model} #{rank}"
        )

        network.add_node(
            uid,
            label=label,
            title=build_tooltip(
                node,
                model,
                evaluation_mode,
            ),
            font={"size": 15 if uid in seeds else 14},
            size=style["size"],
            shape=style["shape"],
            color=style["color"],
            borderWidth=(
                4
                if uid in seeds
                else 2
            ),
        )

    for source, target, attributes in (
        graph.edges(data=True)
    ):

        if (
            source not in included
            or target not in included
        ):
            continue

        network.add_edge(
            source,
            target,
            title=(
                "Relación padre → hijo"
            ),
            arrows="to",
            width=2,
        )

    network.set_options(
        """
        {
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "UD",
              "sortMethod": "directed",
              "levelSeparation": 130,
              "nodeSpacing": 170,
              "treeSpacing": 220
            }
          },
          "physics": {
            "enabled": false
          },
          "interaction": {
            "hover": true,
            "navigationButtons": true,
            "keyboard": true,
            "multiselect": true,
            "zoomView": true,
            "dragView": true
          },
          "edges": {
            "smooth": {
              "enabled": true,
              "type": "cubicBezier",
              "forceDirection": "vertical",
              "roundness": 0.35
            }
          }
        }
        """
    )

    return network


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--graph",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--model",
        choices=MODELS,
        default="A",
    )

    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--context-depth",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--max-children",
        type=int,
        default=5,
        help=(
            "Número máximo de hijos mostrados "
            "por nodo durante la expansión "
            "del contexto."
        ),
    )

    parser.add_argument(
        "--evaluation-mode",
        action="store_true",
        help=(
            "Muestra ground truth únicamente "
            "para evaluación del dataset."
        ),
    )

    args = parser.parse_args()

    graph = load_graph(
        args.graph
    )

    network = build_visualization(
        graph,
        args.model,
        args.top_n,
        args.context_depth,
        args.evaluation_mode,
        args.max_children,
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    network.generate_html(
        notebook=False
    )

    tooltip_css = """
        <style>
        .vis-tooltip {
            white-space: pre-line !important;
            max-width: 420px !important;
            line-height: 1.4 !important;
        }
        </style>
        """

    network.html = network.html.replace(
        "</head>",
        tooltip_css + "\n</head>",
    )

    network.html = add_process_inspector(
        network, graph, args.model, args.top_n, args.evaluation_mode
    )

    print(
        f"Nodos mostrados: "
        f"{network.focus_node_count}"
    )

    print(
        f"Aristas mostradas: "
        f"{network.focus_edge_count}"
    )

    print(
        f"Semillas Top-N: "
        f"{network.focus_seed_count}"
    )

    with args.output.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        file.write(network.html)

    print(
        "Visualización generada correctamente."
    )

    print(
        f"Modelo: {args.model}"
    )

    print(
        f"Top N: {args.top_n}"
    )

    print(
        f"Context depth: "
        f"{args.context_depth}"
    )

    print(
        f"Evaluation mode: "
        f"{args.evaluation_mode}"
    )

    print(
        f"Salida: {args.output}"
    )

    print(
        f"Max children: "
        f"{args.max_children}"
    )


if __name__ == "__main__":
    main()
