from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
import sklearn


IDENTITY_COLUMNS = [
    "process_uid",
    "sample_id",
    "pid",
    "ppid",
    "image_name",
]


FEATURES = {
    "A": [
        "threads",
        "wow64",
        "has_exit_time",
        "process_duration_seconds",
    ],
    "B": [
        "threads",
        "wow64",
        "has_exit_time",
        "process_duration_seconds",
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
    ],
    "C": [
        "threads",
        "wow64",
        "has_exit_time",
        "process_duration_seconds",
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
    ],
}


MODEL_CONFIG = {
    "n_estimators": 500,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": -1,
}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def build_matrix(
    rows: list[dict[str, str]],
    feature_names: list[str],
) -> np.ndarray:

    matrix = []

    for row_index, row in enumerate(rows):

        values = []

        for feature in feature_names:
            raw_value = row.get(feature)

            if raw_value is None or raw_value == "":
                raise ValueError(
                    f"Valor ausente: fila={row_index}, "
                    f"PID={row.get('pid')}, "
                    f"feature={feature}"
                )

            try:
                value = float(raw_value)
            except ValueError as exc:
                raise ValueError(
                    f"Valor no numérico: PID={row.get('pid')}, "
                    f"feature={feature}, valor={raw_value!r}"
                ) from exc

            if not np.isfinite(value):
                raise ValueError(
                    f"Valor no finito: PID={row.get('pid')}, "
                    f"feature={feature}, valor={value}"
                )

            values.append(value)

        matrix.append(values)

    return np.asarray(matrix, dtype=float)


def run_model(
    rows: list[dict[str, str]],
    feature_set: str,
) -> list[dict]:

    feature_names = FEATURES[feature_set]

    matrix = build_matrix(
        rows,
        feature_names,
    )

    model = IsolationForest(
        **MODEL_CONFIG,
    )

    model.fit(matrix)

    # En sklearn:
    # score_samples más bajo = más anómalo.
    raw_scores = model.score_samples(matrix)

    # Para nuestro ranking:
    # mayor anomaly_score = más anómalo.
    anomaly_scores = -raw_scores

    results = []

    for row, raw_score, anomaly_score in zip(
        rows,
        raw_scores,
        anomaly_scores,
    ):
        results.append({
            "process_uid": row["process_uid"],
            "sample_id": row["sample_id"],
            "pid": int(row["pid"]),
            "ppid": int(row["ppid"]),
            "image_name": row["image_name"],
            "feature_set": feature_set,
            "raw_score": float(raw_score),
            "anomaly_score": float(anomaly_score),
        })

    # Determinismo también en caso de empate.
    results.sort(
        key=lambda item: (
            -item["anomaly_score"],
            item["pid"],
            item["process_uid"],
        )
    )

    for rank, result in enumerate(
        results,
        start=1,
    ):
        result["rank"] = rank

    return results


def write_ranking(
    path: Path,
    rows: list[dict],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    columns = [
        "rank",
        "process_uid",
        "sample_id",
        "pid",
        "ppid",
        "image_name",
        "feature_set",
        "raw_score",
        "anomaly_score",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns,
        )

        writer.writeheader()
        writer.writerows(rows)


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--features-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    summary = {}

    for feature_set in ("A", "B", "C"):

        input_path = (
            args.features_dir
            / f"features_{feature_set}.csv"
        )

        rows = load_csv(input_path)

        results = run_model(
            rows,
            feature_set,
        )

        output_path = (
            args.output_dir
            / f"rank_{feature_set}.csv"
        )

        write_ranking(
            output_path,
            results,
        )

        summary[feature_set] = {
            "process_count": len(rows),
            "feature_count": len(FEATURES[feature_set]),
            "output": str(output_path),
        }

        print(
            f"Modelo {feature_set}: "
            f"{len(rows)} procesos, "
            f"{len(FEATURES[feature_set])} features"
        )

    metadata = {
        "algorithm": "IsolationForest",
        "sklearn_version": sklearn.__version__,
        "model_config": MODEL_CONFIG,
        "feature_sets": FEATURES,
        "runs": summary,
        "score_definition": (
            "anomaly_score = -IsolationForest.score_samples(X); "
            "higher means more anomalous"
        ),
    }

    metadata_path = (
        args.output_dir
        / "run_config.json"
    )

    with metadata_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            indent=2,
        )

    print(
        f"Configuración guardada en: {metadata_path}"
    )


if __name__ == "__main__":
    main()