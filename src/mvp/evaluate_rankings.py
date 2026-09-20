from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean
from typing import Any


FEATURE_SETS = ("A", "B", "C")
RECALL_K_VALUES = (1, 3, 5, 10)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    columns: list[str],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

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


def load_labels(
    path: Path,
) -> dict[str, dict[str, str]]:
    rows = load_csv(path)

    labels: dict[str, dict[str, str]] = {}

    for row in rows:
        process_uid = row["process_uid"]

        if process_uid in labels:
            raise ValueError(
                f"process_uid duplicado en labels: "
                f"{process_uid}"
            )

        labels[process_uid] = row

    return labels


def validate_ranking(
    ranking: list[dict[str, str]],
    labels: dict[str, dict[str, str]],
    feature_set: str,
) -> None:
    seen_uids: set[str] = set()
    seen_ranks: set[int] = set()

    for row in ranking:
        uid = row["process_uid"]
        rank = int(row["rank"])

        if uid in seen_uids:
            raise ValueError(
                f"UID duplicado en ranking {feature_set}: "
                f"{uid}"
            )

        if rank in seen_ranks:
            raise ValueError(
                f"Rank duplicado en ranking {feature_set}: "
                f"{rank}"
            )

        if uid not in labels:
            raise ValueError(
                f"Proceso de ranking {feature_set} "
                f"sin entrada en labels.csv: {uid}"
            )

        seen_uids.add(uid)
        seen_ranks.add(rank)

    expected_ranks = set(
        range(1, len(ranking) + 1)
    )

    if seen_ranks != expected_ranks:
        raise ValueError(
            f"Ranking {feature_set} no es continuo "
            f"entre 1 y {len(ranking)}"
        )

    label_uids = set(labels)

    if seen_uids != label_uids:
        missing = label_uids - seen_uids
        extra = seen_uids - label_uids

        raise ValueError(
            f"Diferencia entre ranking {feature_set} "
            f"y ground truth. "
            f"Missing={len(missing)}, "
            f"Extra={len(extra)}"
        )


def attach_labels(
    ranking: list[dict[str, str]],
    labels: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    for row in ranking:
        label = labels[row["process_uid"]]

        output.append({
            "rank": int(row["rank"]),
            "process_uid": row["process_uid"],
            "sample_id": row["sample_id"],
            "pid": int(row["pid"]),
            "ppid": int(row["ppid"]),
            "image_name": row["image_name"],
            "feature_set": row["feature_set"],
            "raw_score": float(row["raw_score"]),
            "anomaly_score": float(
                row["anomaly_score"]
            ),
            "label_text": label["label_text"],
            "label_binary": label["label_binary"],
            "mapping_status": label[
                "mapping_status"
            ],
        })

    return output


def compute_metrics(
    rows: list[dict[str, Any]],
    feature_set: str,
) -> dict[str, Any]:

    malicious_rows = [
        row
        for row in rows
        if row["label_text"] == "Malicious"
    ]

    benign_rows = [
        row
        for row in rows
        if row["label_text"] == "Benign"
    ]

    unknown_rows = [
        row
        for row in rows
        if row["label_text"] == "Unknown"
    ]

    if not malicious_rows:
        raise ValueError(
            f"No existen procesos Malicious "
            f"para evaluar modelo {feature_set}"
        )

    malicious_ranks = sorted(
        row["rank"]
        for row in malicious_rows
    )

    first_malicious_rank = malicious_ranks[0]

    # MRR por dump:
    # recíproco de la posición del primer proceso
    # relevante/malicioso.
    mrr = 1.0 / first_malicious_rank

    result: dict[str, Any] = {
        "feature_set": feature_set,
        "process_count": len(rows),
        "known_count": (
            len(malicious_rows)
            + len(benign_rows)
        ),
        "benign_count": len(benign_rows),
        "malicious_count": len(malicious_rows),
        "unknown_count": len(unknown_rows),
        "first_malicious_rank": (
            first_malicious_rank
        ),
        "mean_malicious_rank": mean(
            malicious_ranks
        ),
        "mrr": mrr,
    }

    for k in RECALL_K_VALUES:
        malicious_in_top_k = sum(
            rank <= k
            for rank in malicious_ranks
        )

        recall = (
            malicious_in_top_k
            / len(malicious_ranks)
        )

        result[f"recall_at_{k}"] = recall

    rows_before_first = [
        row
        for row in rows
        if row["rank"] < first_malicious_rank
    ]

    result[
        "known_benign_before_first_malicious"
    ] = sum(
        row["label_text"] == "Benign"
        for row in rows_before_first
    )

    result[
        "unknown_before_first_malicious"
    ] = sum(
        row["label_text"] == "Unknown"
        for row in rows_before_first
    )

    return result


def build_comparison(
    metrics_by_model: dict[
        str,
        dict[str, Any]
    ],
) -> list[dict[str, Any]]:

    comparisons = [
        ("A", "B", "correlation_multi_plugin"),
        ("B", "C", "relational_context"),
        ("A", "C", "total_change"),
    ]

    rows = []

    for source, target, comparison_name in comparisons:

        source_metrics = metrics_by_model[
            source
        ]
        target_metrics = metrics_by_model[
            target
        ]

        source_rank = source_metrics[
            "first_malicious_rank"
        ]
        target_rank = target_metrics[
            "first_malicious_rank"
        ]

        rank_delta = (
            target_rank - source_rank
        )

        review_reduction = (
            (source_rank - target_rank)
            / source_rank
            * 100.0
        )

        rows.append({
            "comparison": comparison_name,
            "from_model": source,
            "to_model": target,
            "from_first_malicious_rank":
                source_rank,
            "to_first_malicious_rank":
                target_rank,
            "rank_delta": rank_delta,
            "review_depth_reduction_pct":
                review_reduction,
            "from_mrr":
                source_metrics["mrr"],
            "to_mrr":
                target_metrics["mrr"],
            "mrr_delta":
                target_metrics["mrr"]
                - source_metrics["mrr"],
        })

    return rows


def print_top10(
    feature_set: str,
    rows: list[dict[str, Any]],
) -> None:

    print(
        f"\n=== TOP 10 MODELO "
        f"{feature_set} ==="
    )

    for row in rows[:10]:
        print(
            "{:>3} | PID {:>5} | "
            "{:<20} | {:<9} | {:.6f}".format(
                row["rank"],
                row["pid"],
                row["image_name"],
                row["label_text"],
                row["anomaly_score"],
            )
        )


def print_metrics(
    metrics: dict[str, Any],
) -> None:

    print(
        f"\n=== MÉTRICAS MODELO "
        f"{metrics['feature_set']} ==="
    )

    print(
        "Procesos:",
        metrics["process_count"],
    )
    print(
        "Benign:",
        metrics["benign_count"],
    )
    print(
        "Malicious:",
        metrics["malicious_count"],
    )
    print(
        "Unknown:",
        metrics["unknown_count"],
    )
    print(
        "First malicious rank:",
        metrics["first_malicious_rank"],
    )
    print(
        "Mean malicious rank:",
        round(
            metrics["mean_malicious_rank"],
            6,
        ),
    )
    print(
        "MRR:",
        round(metrics["mrr"], 6),
    )

    for k in RECALL_K_VALUES:
        print(
            f"Recall@{k}:",
            round(
                metrics[f"recall_at_{k}"],
                6,
            ),
        )

    print(
        "Known benign before first malicious:",
        metrics[
            "known_benign_before_first_malicious"
        ],
    )

    print(
        "Unknown before first malicious:",
        metrics[
            "unknown_before_first_malicious"
        ],
    )


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--rankings-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--labels",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    labels = load_labels(args.labels)

    metrics_by_model: dict[
        str,
        dict[str, Any]
    ] = {}

    all_labeled_rankings: dict[
        str,
        list[dict[str, Any]]
    ] = {}

    for feature_set in FEATURE_SETS:

        ranking_path = (
            args.rankings_dir
            / f"rank_{feature_set}.csv"
        )

        ranking = load_csv(
            ranking_path
        )

        validate_ranking(
            ranking,
            labels,
            feature_set,
        )

        labeled = attach_labels(
            ranking,
            labels,
        )

        all_labeled_rankings[
            feature_set
        ] = labeled

        metrics = compute_metrics(
            labeled,
            feature_set,
        )

        metrics_by_model[
            feature_set
        ] = metrics

        output_path = (
            args.output_dir
            / f"rank_{feature_set}_labeled.csv"
        )

        write_csv(
            output_path,
            labeled,
            [
                "rank",
                "process_uid",
                "sample_id",
                "pid",
                "ppid",
                "image_name",
                "feature_set",
                "raw_score",
                "anomaly_score",
                "label_text",
                "label_binary",
                "mapping_status",
            ],
        )

        print_top10(
            feature_set,
            labeled,
        )

        print_metrics(
            metrics,
        )

    summary_rows = [
        metrics_by_model[
            feature_set
        ]
        for feature_set in FEATURE_SETS
    ]

    summary_columns = [
        "feature_set",
        "process_count",
        "known_count",
        "benign_count",
        "malicious_count",
        "unknown_count",
        "first_malicious_rank",
        "mean_malicious_rank",
        "mrr",
        "recall_at_1",
        "recall_at_3",
        "recall_at_5",
        "recall_at_10",
        "known_benign_before_first_malicious",
        "unknown_before_first_malicious",
    ]

    write_csv(
        args.output_dir
        / "evaluation_summary.csv",
        summary_rows,
        summary_columns,
    )

    comparison_rows = build_comparison(
        metrics_by_model
    )

    write_csv(
        args.output_dir
        / "model_comparison.csv",
        comparison_rows,
        [
            "comparison",
            "from_model",
            "to_model",
            "from_first_malicious_rank",
            "to_first_malicious_rank",
            "rank_delta",
            "review_depth_reduction_pct",
            "from_mrr",
            "to_mrr",
            "mrr_delta",
        ],
    )

    json_output = {
        "metrics": metrics_by_model,
        "comparisons": comparison_rows,
    }

    with (
        args.output_dir
        / "evaluation.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            json_output,
            file,
            indent=2,
        )

    print(
        "\nEvaluación completada."
    )
    print(
        f"Salida: {args.output_dir}"
    )


if __name__ == "__main__":
    main()