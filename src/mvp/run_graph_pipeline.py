from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


MODELS = ("A", "B", "C")


def run(command: list[str]) -> None:
    print()
    print("=" * 72)
    print(" ".join(command))
    print("=" * 72)

    subprocess.run(
        command,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sample",
        required=True,
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
    )

    args = parser.parse_args()

    project_root = (
        Path(__file__)
        .resolve()
        .parents[2]
    )

    python = sys.executable

    src_dir = (
        project_root
        / "src"
        / "mvp"
    )

    features_dir = (
        project_root
        / "data"
        / "output"
        / "features"
        / args.sample
    )

    detection_dir = (
        project_root
        / "data"
        / "output"
        / "detection"
        / "isolation"
        / args.sample
    )

    ground_truth_dir = (
        project_root
        / "data"
        / "output"
        / "ground_truth"
        / args.sample
    )

    graph_dir = (
        project_root
        / "data"
        / "output"
        / "graph"
        / args.sample
    )

    master = (
        features_dir
        / "process_master.csv"
    )

    labels = (
        ground_truth_dir
        / "labels.csv"
    )

    required = [
        master,
        labels,
        detection_dir / "rank_A.csv",
        detection_dir / "rank_B.csv",
        detection_dir / "rank_C.csv",
    ]

    missing = [
        path
        for path in required
        if not path.exists()
    ]

    if missing:
        raise FileNotFoundError(
            "Faltan archivos requeridos:\n"
            + "\n".join(
                str(path)
                for path in missing
            )
        )

    graph_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"Graph pipeline: {args.sample}"
    )

    # -------------------------------------------------
    # 1. Construcción del grafo
    # -------------------------------------------------

    run([
        python,
        str(
            src_dir
            / "build_process_graph.py"
        ),
        "--master",
        str(master),
        "--rankings-dir",
        str(detection_dir),
        "--labels",
        str(labels),
        "--output-dir",
        str(graph_dir),
        "--focus-model",
        "A",
        "--top-n",
        str(args.top_n),
        "--context-depth",
        str(args.context_depth),
    ])

    graph_json = (
        graph_dir
        / "process_graph.json"
    )

    # -------------------------------------------------
    # 2. Modo analista A/B/C
    # -------------------------------------------------

    for model in MODELS:

        run([
            python,
            str(
                src_dir
                / "visualize_graph.py"
            ),
            "--graph",
            str(graph_json),
            "--output",
            str(
                graph_dir
                / f"graph_{model}.html"
            ),
            "--model",
            model,
            "--top-n",
            str(args.top_n),
            "--context-depth",
            str(args.context_depth),
            "--max-children",
            str(args.max_children),
        ])

    # -------------------------------------------------
    # 3. Evaluación A/B/C
    # -------------------------------------------------

    for model in MODELS:

        run([
            python,
            str(
                src_dir
                / "visualize_graph.py"
            ),
            "--graph",
            str(graph_json),
            "--output",
            str(
                graph_dir
                / (
                    f"graph_{model}"
                    "_evaluation.html"
                )
            ),
            "--model",
            model,
            "--top-n",
            str(args.top_n),
            "--context-depth",
            str(args.context_depth),
            "--max-children",
            str(args.max_children),
            "--evaluation-mode",
        ])

    print()
    print("=" * 72)
    print("GRAPH PIPELINE COMPLETADO")
    print("=" * 72)

    print(
        f"Sample: {args.sample}"
    )

    print(
        f"Salida: {graph_dir}"
    )


if __name__ == "__main__":
    main()