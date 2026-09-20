from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean
from typing import Any


MODELS = ("A", "B", "C")


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


def collect_malicious_processes(
    evaluation_root: Path,
) -> list[dict[str, Any]]:

    output: list[dict[str, Any]] = []

    for sample_dir in sorted(
        path
        for path in evaluation_root.iterdir()
        if path.is_dir()
    ):
        ranking_paths = {
            model: (
                sample_dir
                / f"rank_{model}_labeled.csv"
            )
            for model in MODELS
        }

        if not all(
            path.exists()
            for path in ranking_paths.values()
        ):
            continue

        rankings = {
            model: load_csv(path)
            for model, path
            in ranking_paths.items()
        }

        by_uid = {
            model: {
                row["process_uid"]: row
                for row in rows
            }
            for model, rows
            in rankings.items()
        }

        malicious_a = [
            row
            for row in rankings["A"]
            if row["label_text"] == "Malicious"
        ]

        for process in malicious_a:
            uid = process["process_uid"]

            if not all(
                uid in by_uid[model]
                for model in MODELS
            ):
                raise ValueError(
                    f"{sample_dir.name}: "
                    f"{uid} no existe en todos "
                    f"los rankings"
                )

            a = by_uid["A"][uid]
            b = by_uid["B"][uid]
            c = by_uid["C"][uid]

            rank_a = int(a["rank"])
            rank_b = int(b["rank"])
            rank_c = int(c["rank"])

            output.append({
                "sample": sample_dir.name,
                "process_uid": uid,
                "pid": int(process["pid"]),
                "image_name": process["image_name"],

                "rank_A": rank_a,
                "rank_B": rank_b,
                "rank_C": rank_c,

                "delta_A_B":
                    rank_b - rank_a,

                "delta_B_C":
                    rank_c - rank_b,

                "delta_A_C":
                    rank_c - rank_a,

                "A_to_B_result":
                    classify_delta(
                        rank_b - rank_a
                    ),

                "B_to_C_result":
                    classify_delta(
                        rank_c - rank_b
                    ),

                "A_to_C_result":
                    classify_delta(
                        rank_c - rank_a
                    ),
            })

    return output


def classify_delta(delta: int) -> str:
    if delta < 0:
        return "improved"

    if delta > 0:
        return "worsened"

    return "unchanged"


def summarize_comparison(
    rows: list[dict[str, Any]],
    source: str,
    target: str,
) -> dict[str, Any]:

    delta_column = (
        f"delta_{source}_{target}"
    )

    deltas = [
        int(row[delta_column])
        for row in rows
    ]

    improved = sum(
        delta < 0
        for delta in deltas
    )

    unchanged = sum(
        delta == 0
        for delta in deltas
    )

    worsened = sum(
        delta > 0
        for delta in deltas
    )

    return {
        "comparison":
            f"{source}_to_{target}",

        "malicious_process_count":
            len(rows),

        "improved":
            improved,

        "unchanged":
            unchanged,

        "worsened":
            worsened,

        "mean_rank_delta":
            mean(deltas),

        "improvement_rate":
            improved / len(rows),

        "worsening_rate":
            worsened / len(rows),
    }


def build_model_summary(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    output = []

    for model in MODELS:
        ranks = [
            int(row[f"rank_{model}"])
            for row in rows
        ]

        output.append({
            "feature_set": model,
            "malicious_process_count":
                len(ranks),
            "mean_malicious_rank":
                mean(ranks),
            "top_1_hits":
                sum(rank <= 1 for rank in ranks),
            "top_3_hits":
                sum(rank <= 3 for rank in ranks),
            "top_5_hits":
                sum(rank <= 5 for rank in ranks),
            "top_10_hits":
                sum(rank <= 10 for rank in ranks),
            "recall_at_1":
                sum(rank <= 1 for rank in ranks)
                / len(ranks),
            "recall_at_3":
                sum(rank <= 3 for rank in ranks)
                / len(ranks),
            "recall_at_5":
                sum(rank <= 5 for rank in ranks)
                / len(ranks),
            "recall_at_10":
                sum(rank <= 10 for rank in ranks)
                / len(ranks),
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

    malicious_rows = (
        collect_malicious_processes(
            args.evaluation_root
        )
    )

    if not malicious_rows:
        raise ValueError(
            "No se encontraron procesos "
            "maliciosos evaluados."
        )

    model_summary = build_model_summary(
        malicious_rows
    )

    comparison_summary = [
        summarize_comparison(
            malicious_rows,
            "A",
            "B",
        ),
        summarize_comparison(
            malicious_rows,
            "B",
            "C",
        ),
        summarize_comparison(
            malicious_rows,
            "A",
            "C",
        ),
    ]

    write_csv(
        args.output_dir
        / "malicious_process_results.csv",
        malicious_rows,
        [
            "sample",
            "process_uid",
            "pid",
            "image_name",
            "rank_A",
            "rank_B",
            "rank_C",
            "delta_A_B",
            "delta_B_C",
            "delta_A_C",
            "A_to_B_result",
            "B_to_C_result",
            "A_to_C_result",
        ],
    )

    write_csv(
        args.output_dir
        / "malicious_process_model_summary.csv",
        model_summary,
        [
            "feature_set",
            "malicious_process_count",
            "mean_malicious_rank",
            "top_1_hits",
            "top_3_hits",
            "top_5_hits",
            "top_10_hits",
            "recall_at_1",
            "recall_at_3",
            "recall_at_5",
            "recall_at_10",
        ],
    )

    write_csv(
        args.output_dir
        / "malicious_process_comparisons.csv",
        comparison_summary,
        [
            "comparison",
            "malicious_process_count",
            "improved",
            "unchanged",
            "worsened",
            "mean_rank_delta",
            "improvement_rate",
            "worsening_rate",
        ],
    )

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with (
        args.output_dir
        / "malicious_process_evaluation.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            {
                "processes":
                    malicious_rows,
                "models":
                    model_summary,
                "comparisons":
                    comparison_summary,
            },
            file,
            indent=2,
        )

    print(
        "Procesos maliciosos:",
        len(malicious_rows),
    )

    print()

    for row in malicious_rows:
        print(
            "{} | PID {:>5} | {:<18} | "
            "A={:>2} B={:>2} C={:>2}".format(
                row["sample"],
                row["pid"],
                row["image_name"],
                row["rank_A"],
                row["rank_B"],
                row["rank_C"],
            )
        )

    print()

    for row in model_summary:
        print(
            "Modelo {} | mean rank {:.3f} | "
            "R@3 {:.3f} | R@5 {:.3f} | "
            "R@10 {:.3f}".format(
                row["feature_set"],
                row["mean_malicious_rank"],
                row["recall_at_3"],
                row["recall_at_5"],
                row["recall_at_10"],
            )
        )

    print()

    for row in comparison_summary:
        print(
            "{} | mejora={} | igual={} | "
            "empeora={} | delta medio={:.3f}".format(
                row["comparison"],
                row["improved"],
                row["unchanged"],
                row["worsened"],
                row["mean_rank_delta"],
            )
        )


if __name__ == "__main__":
    main()