from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, deque
from pathlib import Path
from typing import Any

import networkx as nx


MODELS = ("A", "B", "C")


INTEGER_FIELDS = {
    "pid",
    "ppid",
    "network_object_count",
    "threads",
    "wow64",
    "has_exit_time",
    "in_pslist",
    "in_psscan",
    "cmdline_length",
    "malfind_region_count",
    "malfind_rwx_count",
    "malfind_total_commit_charge",
    "tcp_object_count",
    "udp_object_count",
    "unique_remote_ip_count",
    "public_remote_ip_count",
    "parent_resolved",
    "child_count",
    "resolved_ancestor_count",
    "parent_has_malfind",
    "parent_has_network",
    "parent_psscan_only",
    "children_with_malfind_count",
    "children_with_network_count",
    "children_psscan_only_count",
}


FLOAT_FIELDS = {
    "process_duration_seconds",
}


def load_csv(
    path: Path,
) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def parse_value(
    field: str,
    value: str | None,
) -> Any:

    if value is None:
        return ""

    if value == "":
        return ""

    if field in INTEGER_FIELDS:
        return int(float(value))

    if field in FLOAT_FIELDS:
        return float(value)

    return value


def load_rankings(
    ranking_dir: Path,
) -> dict[str, dict[str, dict[str, Any]]]:

    rankings: dict[
        str,
        dict[str, dict[str, Any]]
    ] = {}

    for model in MODELS:

        path = ranking_dir / f"rank_{model}.csv"

        if not path.exists():
            raise FileNotFoundError(
                f"No existe ranking {model}: {path}"
            )

        rows = load_csv(path)

        rankings[model] = {}

        for row in rows:

            uid = row["process_uid"]

            rankings[model][uid] = {
                "rank": int(row["rank"]),
                "raw_score": float(
                    row["raw_score"]
                ),
                "anomaly_score": float(
                    row["anomaly_score"]
                ),
            }

    return rankings


def load_labels(
    path: Path | None,
) -> dict[str, dict[str, str]]:

    if path is None:
        return {}

    if not path.exists():
        raise FileNotFoundError(
            f"No existe labels.csv: {path}"
        )

    rows = load_csv(path)

    return {
        row["process_uid"]: row
        for row in rows
    }


def validate_process_sets(
    master_rows: list[dict[str, str]],
    rankings: dict[
        str,
        dict[str, dict[str, Any]]
    ],
) -> None:

    master_uids = {
        row["process_uid"]
        for row in master_rows
    }

    for model in MODELS:

        ranking_uids = set(
            rankings[model]
        )

        if master_uids != ranking_uids:

            missing = (
                master_uids - ranking_uids
            )

            extra = (
                ranking_uids - master_uids
            )

            raise ValueError(
                f"Diferencia entre master "
                f"y ranking {model}: "
                f"missing={len(missing)}, "
                f"extra={len(extra)}"
            )


def build_graph(
    master_rows: list[dict[str, str]],
    rankings: dict[
        str,
        dict[str, dict[str, Any]]
    ],
    labels: dict[str, dict[str, str]],
) -> nx.DiGraph:

    graph = nx.DiGraph()

    # ----------------------------------------
    # NODOS
    # ----------------------------------------

    for row in master_rows:

        uid = row["process_uid"]

        attributes: dict[str, Any] = {}

        for field, value in row.items():

            if field == "process_uid":
                continue

            attributes[field] = parse_value(
                field,
                value,
            )

        for model in MODELS:

            ranking = rankings[model][uid]

            attributes[
                f"rank_{model}"
            ] = ranking["rank"]

            attributes[
                f"anomaly_score_{model}"
            ] = ranking["anomaly_score"]

            attributes[
                f"raw_score_{model}"
            ] = ranking["raw_score"]

        label = labels.get(uid)

        if label is not None:

            attributes["label_text"] = (
                label["label_text"]
            )

            attributes["label_binary"] = (
                label["label_binary"]
            )

            attributes["mapping_status"] = (
                label["mapping_status"]
            )

        else:

            attributes["label_text"] = ""
            attributes["label_binary"] = ""
            attributes["mapping_status"] = ""

        graph.add_node(
            uid,
            **attributes,
        )

    # ----------------------------------------
    # ARISTAS PADRE → HIJO
    # ----------------------------------------

    for row in master_rows:

        child_uid = row["process_uid"]

        parent_uid = row.get(
            "parent_process_uid",
            "",
        )

        parent_resolved = (
            row.get("parent_resolved", "0")
            == "1"
        )

        if (
            parent_resolved
            and parent_uid
            and parent_uid in graph
        ):

            graph.add_edge(
                parent_uid,
                child_uid,
                relation="parent_child",
                source_type="PPID",
                temporally_validated=1,
            )

    return graph


def graph_to_json(
    graph: nx.DiGraph,
) -> dict[str, Any]:

    nodes = []

    for uid, attributes in graph.nodes(
        data=True
    ):
        nodes.append({
            "id": uid,
            **attributes,
        })

    edges = []

    for source, target, attributes in (
        graph.edges(data=True)
    ):
        edges.append({
            "source": source,
            "target": target,
            **attributes,
        })

    return {
        "directed": True,
        "nodes": nodes,
        "edges": edges,
    }


def build_focus_graph(
    graph: nx.DiGraph,
    model: str,
    top_n: int,
    context_depth: int,
) -> nx.DiGraph:

    rank_field = f"rank_{model}"

    ordered_nodes = sorted(
        graph.nodes,
        key=lambda uid: (
            graph.nodes[uid][rank_field],
            graph.nodes[uid]["pid"],
        ),
    )

    seeds = set(
        ordered_nodes[:top_n]
    )

    included = set(seeds)

    queue = deque(
        (uid, 0)
        for uid in seeds
    )

    while queue:

        uid, depth = queue.popleft()

        if depth >= context_depth:
            continue

        neighbors = (
            set(graph.predecessors(uid))
            | set(graph.successors(uid))
        )

        for neighbor in neighbors:

            if neighbor in included:
                continue

            included.add(neighbor)

            queue.append(
                (
                    neighbor,
                    depth + 1,
                )
            )

    focus = graph.subgraph(
        included
    ).copy()

    for uid in focus.nodes:

        focus.nodes[uid][
            "focus_seed"
        ] = int(uid in seeds)

        focus.nodes[uid][
            "focus_model"
        ] = model

    return focus


def write_json(
    path: Path,
    data: Any,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


def build_summary(
    graph: nx.DiGraph,
) -> dict[str, Any]:

    node_count = graph.number_of_nodes()

    edge_count = graph.number_of_edges()

    roots = [
        uid
        for uid in graph.nodes
        if graph.in_degree(uid) == 0
    ]

    leaves = [
        uid
        for uid in graph.nodes
        if graph.out_degree(uid) == 0
    ]

    labels = Counter(
        graph.nodes[uid].get(
            "label_text",
            "",
        )
        for uid in graph.nodes
    )

    psscan_only = sum(
        graph.nodes[uid].get(
            "in_pslist",
            0,
        ) == 0
        and
        graph.nodes[uid].get(
            "in_psscan",
            0,
        ) == 1
        for uid in graph.nodes
    )

    with_malfind = sum(
        graph.nodes[uid].get(
            "malfind_region_count",
            0,
        ) > 0
        for uid in graph.nodes
    )

    with_network = sum(
        (
            graph.nodes[uid].get(
                "tcp_object_count",
                0,
            )
            +
            graph.nodes[uid].get(
                "udp_object_count",
                0,
            )
        ) > 0
        for uid in graph.nodes
    )

    resolved_parent_nodes = sum(
        graph.nodes[uid].get(
            "parent_resolved",
            0,
        ) == 1
        for uid in graph.nodes
    )

    summary: dict[str, Any] = {
        "node_count": node_count,
        "edge_count": edge_count,
        "root_count": len(roots),
        "leaf_count": len(leaves),
        "resolved_parent_nodes":
            resolved_parent_nodes,
        "psscan_only_count":
            psscan_only,
        "nodes_with_malfind":
            with_malfind,
        "nodes_with_network":
            with_network,
        "labels": dict(labels),
    }

    for model in MODELS:

        rank_field = f"rank_{model}"

        top10 = sorted(
            graph.nodes,
            key=lambda uid: (
                graph.nodes[uid][rank_field],
                graph.nodes[uid]["pid"],
            ),
        )[:10]

        summary[
            f"top10_{model}"
        ] = [
            {
                "process_uid": uid,
                "pid": graph.nodes[uid][
                    "pid"
                ],
                "image_name":
                    graph.nodes[uid][
                        "image_name"
                    ],
                "rank":
                    graph.nodes[uid][
                        rank_field
                    ],
                "label_text":
                    graph.nodes[uid].get(
                        "label_text",
                        "",
                    ),
            }
            for uid in top10
        ]

    return summary


def graphml_safe_copy(
    graph: nx.DiGraph,
) -> nx.DiGraph:

    output = nx.DiGraph()

    for uid, attributes in graph.nodes(
        data=True
    ):

        safe_attributes = {}

        for key, value in attributes.items():

            if value is None:
                value = ""

            if isinstance(
                value,
                (str, int, float, bool),
            ):
                safe_attributes[key] = value

            else:
                safe_attributes[key] = str(
                    value
                )

        output.add_node(
            uid,
            **safe_attributes,
        )

    for source, target, attributes in (
        graph.edges(data=True)
    ):

        safe_attributes = {}

        for key, value in attributes.items():

            if value is None:
                value = ""

            if isinstance(
                value,
                (str, int, float, bool),
            ):
                safe_attributes[key] = value

            else:
                safe_attributes[key] = str(
                    value
                )

        output.add_edge(
            source,
            target,
            **safe_attributes,
        )

    return output


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--master",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--rankings-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--labels",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--focus-model",
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

    args = parser.parse_args()

    master_rows = load_csv(
        args.master
    )

    rankings = load_rankings(
        args.rankings_dir
    )

    labels = load_labels(
        args.labels
    )

    validate_process_sets(
        master_rows,
        rankings,
    )

    graph = build_graph(
        master_rows,
        rankings,
        labels,
    )

    focus_graph = build_focus_graph(
        graph,
        args.focus_model,
        args.top_n,
        args.context_depth,
    )

    summary = build_summary(
        graph
    )

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_json(
        args.output_dir
        / "process_graph.json",
        graph_to_json(graph),
    )

    write_json(
        args.output_dir
        / "focus_graph.json",
        graph_to_json(focus_graph),
    )

    write_json(
        args.output_dir
        / "graph_summary.json",
        summary,
    )

    safe_graph = graphml_safe_copy(
        graph
    )

    nx.write_graphml(
        safe_graph,
        args.output_dir
        / "process_graph.graphml",
    )

    print(
        "Grafo construido correctamente."
    )

    print(
        f"Nodos: {graph.number_of_nodes()}"
    )

    print(
        f"Aristas: {graph.number_of_edges()}"
    )

    print(
        f"Grafo focal ({args.focus_model}): "
        f"{focus_graph.number_of_nodes()} nodos, "
        f"{focus_graph.number_of_edges()} aristas"
    )

    print(
        f"Salida: {args.output_dir}"
    )


if __name__ == "__main__":
    main()