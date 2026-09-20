from __future__ import annotations

import argparse
import csv
from pathlib import Path

from openpyxl import load_workbook


def normalize_name(value: object) -> str:
    return str(value or "").strip().lower()


def load_master(path: Path) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def load_xai_ground_truth(
    xlsx_path: Path,
    sheet_name: str,
) -> dict[int, dict]:
    workbook = load_workbook(
        xlsx_path,
        read_only=True,
        data_only=True,
    )

    sheet = workbook[sheet_name]

    rows = sheet.iter_rows(values_only=True)

    headers = next(rows)

    columns = {
        name: index
        for index, name in enumerate(headers)
    }

    required = [
        "Process_Name",
        "PID",
        "PPID",
        "Label",
    ]

    missing = [
        column
        for column in required
        if column not in columns
    ]

    if missing:
        raise ValueError(
            f"Columnas no encontradas: {missing}"
        )

    result: dict[int, dict] = {}

    for row in rows:
        pid_value = row[columns["PID"]]

        if pid_value is None:
            continue

        pid = int(pid_value)

        if pid in result:
            raise ValueError(
                f"PID duplicado en ground truth: {pid}"
            )

        result[pid] = {
            "pid": pid,
            "ppid": int(row[columns["PPID"]]),
            "image_name": str(
                row[columns["Process_Name"]]
            ),
            "label": str(
                row[columns["Label"]]
            ),
        }

    workbook.close()

    return result


def map_ground_truth(
    master: list[dict[str, str]],
    ground_truth: dict[int, dict],
    source: str,
) -> list[dict]:
    output = []

    for process in master:
        pid = int(process["pid"])
        ppid = int(process["ppid"])
        image_name = process["image_name"]

        reference = ground_truth.get(pid)

        if reference is None:
            label_text = "Unknown"
            label_binary = ""
            mapping_status = "not_in_ground_truth"

        else:
            same_name = (
                normalize_name(image_name)
                == normalize_name(
                    reference["image_name"]
                )
            )

            same_ppid = (
                ppid == reference["ppid"]
            )

            if same_name and same_ppid:
                label_text = reference["label"]

                if label_text == "Malicious":
                    label_binary = 1
                elif label_text == "Benign":
                    label_binary = 0
                else:
                    label_binary = ""

                mapping_status = "exact"

            else:
                # Nunca asignar una etiqueta dudosa.
                label_text = "Unknown"
                label_binary = ""
                mapping_status = (
                    "pid_match_identity_mismatch"
                )

        output.append({
            "process_uid": process["process_uid"],
            "sample_id": process["sample_id"],
            "pid": pid,
            "ppid": ppid,
            "image_name": image_name,
            "label_text": label_text,
            "label_binary": label_binary,
            "label_source": source,
            "mapping_status": mapping_status,
        })

    return output


def write_csv(
    output_path: Path,
    rows: list[dict],
) -> None:
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    columns = [
        "process_uid",
        "sample_id",
        "pid",
        "ppid",
        "image_name",
        "label_text",
        "label_binary",
        "label_source",
        "mapping_status",
    ]

    with output_path.open(
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
        "--master",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--xlsx",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--sheet",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    master = load_master(args.master)

    ground_truth = load_xai_ground_truth(
        args.xlsx,
        args.sheet,
    )

    labels = map_ground_truth(
        master,
        ground_truth,
        source=(
            f"XAI-DF:"
            f"{args.xlsx.name}:"
            f"{args.sheet}"
        ),
    )

    write_csv(
        args.output,
        labels,
    )

    exact = sum(
        row["mapping_status"] == "exact"
        for row in labels
    )

    unknown = sum(
        row["label_text"] == "Unknown"
        for row in labels
    )

    benign = sum(
        row["label_text"] == "Benign"
        for row in labels
    )

    malicious = sum(
        row["label_text"] == "Malicious"
        for row in labels
    )

    mismatches = sum(
        row["mapping_status"]
        == "pid_match_identity_mismatch"
        for row in labels
    )

    print(f"Procesos master: {len(master)}")
    print(f"Ground truth Excel: {len(ground_truth)}")
    print(f"Mapeo exacto: {exact}")
    print(f"Benign: {benign}")
    print(f"Malicious: {malicious}")
    print(f"Unknown: {unknown}")
    print(f"Identity mismatches: {mismatches}")


if __name__ == "__main__":
    main()