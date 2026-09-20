from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
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


def collect_samples(
    evaluation_root: Path,
) -> list[dict[str, Any]]:

    samples: list[dict[str, Any]] = []

    for sample_dir in sorted(
        path
        for path in evaluation_root.iterdir()
        if path.is_dir()
    ):
        summary_path = (
            sample_dir / "evaluation_summary.csv"
        )

        comparison_path = (
            sample_dir / "model_comparison.csv"
        )

        if not summary_path.exists():
            continue

        summary = load_csv(summary_path)

        if len(summary) != 3:
            raise ValueError(
                f"{sample_dir.name}: "
                f"se esperaban 3 modelos, "
                f"se encontraron {len(summary)}"
            )

        by_model = {
            row["feature_set"]: row
            for row in summary
        }

        if set(by_model) != set(FEATURE_SETS):
            raise ValueError(
                f"{sample_dir.name}: "
                f"Feature Sets inesperados: "
                f"{set(by_model)}"
            )

        row: dict[str, Any] = {
            "sample": sample_dir.name,
        }

        for model in FEATURE_SETS:
            metrics = by_model[model]

            row[f"{model}_process_count"] = int(
                metrics["process_count"]
            )

            row[f"{model}_malicious_count"] = int(
                metrics["malicious_count"]
            )

            row[f"{model}_unknown_count"] = int(
                metrics["unknown_count"]
            )

            row[f"{model}_first_malicious_rank"] = float(
                metrics["first_malicious_rank"]
            )

            row[f"{model}_mean_malicious_rank"] = float(
                metrics["mean_malicious_rank"]
            )

            row[f"{model}_mrr"] = float(
                metrics["mrr"]
            )

            for k in RECALL_K_VALUES:
                row[f"{model}_recall_at_{k}"] = float(
                    metrics[f"recall_at_{k}"]
                )

        if comparison_path.exists():
            comparisons = load_csv(
                comparison_path
            )

            by_comparison = {
                item["comparison"]: item
                for item in comparisons
            }

            for name in (
                "correlation_multi_plugin",
                "relational_context",
                "total_change",
            ):
                comparison = by_comparison.get(name)

                if comparison is None:
                    continue

                row[
                    f"{name}_rank_delta"
                ] = float(
                    comparison["rank_delta"]
                )

                row[
                    f"{name}_review_depth_reduction_pct"
                ] = float(
                    comparison[
                        "review_depth_reduction_pct"
                    ]
                )

        samples.append(row)

    return samples


def aggregate_models(
    sample_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    output: list[dict[str, Any]] = []

    for model in FEATURE_SETS:

        malicious_total = sum(
            int(row[f"{model}_malicious_count"])
            for row in sample_rows
        )

        result: dict[str, Any] = {
            "feature_set": model,
            "sample_count": len(sample_rows),
            "malicious_process_count": (
                malicious_total
            ),
            "mean_first_malicious_rank": mean(
                row[
                    f"{model}_first_malicious_rank"
                ]
                for row in sample_rows
            ),
            "mean_mrr": mean(
                row[f"{model}_mrr"]
                for row in sample_rows
            ),
        }

        weighted_rank_sum = sum(
            row[
                f"{model}_mean_malicious_rank"
            ]
            * row[f"{model}_malicious_count"]
            for row in sample_rows
        )

        result[
            "weighted_mean_malicious_rank"
        ] = (
            weighted_rank_sum / malicious_total
            if malicious_total
            else None
        )

        for k in RECALL_K_VALUES:

            # Macro:
            # Cada dump aporta el mismo peso.
            result[f"macro_recall_at_{k}"] = mean(
                row[f"{model}_recall_at_{k}"]
                for row in sample_rows
            )

            # Micro:
            # Cada proceso malicioso aporta el mismo peso.
            hits = sum(
                row[f"{model}_recall_at_{k}"]
                * row[f"{model}_malicious_count"]
                for row in sample_rows
            )

            result[f"micro_recall_at_{k}"] = (
                hits / malicious_total
                if malicious_total
                else None
            )

        output.append(result)

    return output


def summarize_pairwise_changes(
    sample_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    comparisons = (
        (
            "A",
            "B",
            "correlation_multi_plugin",
        ),
        (
            "B",
            "C",
            "relational_context",
        ),
        (
            "A",
            "C",
            "total_change",
        ),
    )

    output = []

    for source, target, name in comparisons:

        improved = 0
        unchanged = 0
        worsened = 0

        deltas = []

        for row in sample_rows:
            source_rank = row[
                f"{source}_first_malicious_rank"
            ]

            target_rank = row[
                f"{target}_first_malicious_rank"
            ]

            delta = target_rank - source_rank
            deltas.append(delta)

            if delta < 0:
                improved += 1
            elif delta > 0:
                worsened += 1
            else:
                unchanged += 1

        output.append({
            "comparison": name,
            "from_model": source,
            "to_model": target,
            "sample_count": len(sample_rows),
            "improved_samples": improved,
            "unchanged_samples": unchanged,
            "worsened_samples": worsened,
            "mean_rank_delta": mean(deltas),
        })

    return output


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--evaluation-root",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    sample_rows = collect_samples(
        args.evaluation_root
    )

    if not sample_rows:
        raise ValueError(
            "No se encontraron evaluaciones."
        )

    aggregate_rows = aggregate_models(
        sample_rows
    )

    comparison_rows = summarize_pairwise_changes(
        sample_rows
    )

    sample_columns = [
        "sample",
    ]

    for model in FEATURE_SETS:
        sample_columns.extend([
            f"{model}_process_count",
            f"{model}_malicious_count",
            f"{model}_unknown_count",
            f"{model}_first_malicious_rank",
            f"{model}_mean_malicious_rank",
            f"{model}_mrr",
            f"{model}_recall_at_1",
            f"{model}_recall_at_3",
            f"{model}_recall_at_5",
            f"{model}_recall_at_10",
        ])

    sample_columns.extend([
        "correlation_multi_plugin_rank_delta",
        "correlation_multi_plugin_review_depth_reduction_pct",
        "relational_context_rank_delta",
        "relational_context_review_depth_reduction_pct",
        "total_change_rank_delta",
        "total_change_review_depth_reduction_pct",
    ])

    write_csv(
        args.output_dir / "sample_results.csv",
        sample_rows,
        sample_columns,
    )

    aggregate_columns = [
        "feature_set",
        "sample_count",
        "malicious_process_count",
        "mean_first_malicious_rank",
        "weighted_mean_malicious_rank",
        "mean_mrr",
        "macro_recall_at_1",
        "macro_recall_at_3",
        "macro_recall_at_5",
        "macro_recall_at_10",
        "micro_recall_at_1",
        "micro_recall_at_3",
        "micro_recall_at_5",
        "micro_recall_at_10",
    ]

    write_csv(
        args.output_dir / "aggregate_models.csv",
        aggregate_rows,
        aggregate_columns,
    )

    comparison_columns = [
        "comparison",
        "from_model",
        "to_model",
        "sample_count",
        "improved_samples",
        "unchanged_samples",
        "worsened_samples",
        "mean_rank_delta",
    ]

    write_csv(
        args.output_dir / "aggregate_comparisons.csv",
        comparison_rows,
        comparison_columns,
    )

    json_output = {
        "samples": sample_rows,
        "models": aggregate_rows,
        "comparisons": comparison_rows,
    }

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with (
        args.output_dir / "aggregate_evaluation.json"
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
        f"Samples agregados: {len(sample_rows)}"
    )

    print()

    for row in aggregate_rows:
        print(
            "Modelo {} | "
            "Mean rank {:.4f} | "
            "MRR {:.4f} | "
            "Micro Recall@5 {:.4f}".format(
                row["feature_set"],
                row[
                    "mean_first_malicious_rank"
                ],
                row["mean_mrr"],
                row["micro_recall_at_5"],
            )
        )

    print()

    for row in comparison_rows:
        print(
            "{} | mejora={} | igual={} | "
            "empeora={} | delta medio={:.4f}".format(
                row["comparison"],
                row["improved_samples"],
                row["unchanged_samples"],
                row["worsened_samples"],
                row["mean_rank_delta"],
            )
        )


if __name__ == "__main__":
    main()