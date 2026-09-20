from __future__ import annotations

import argparse
import subprocess
import sys
import json
import hashlib
from pathlib import Path


REQUIRED_RAW_FILES = (
    "pslist.json",
    "psscan.json",
    "cmdline.json",
    "malfind.json",
    "netscan.json",
)


def run_command(command: list[str], label: str) -> None:
    print()
    print("=" * 72)
    print(label)
    print("=" * 72)
    print(" ".join(str(part) for part in command))
    print()

    subprocess.run(
        command,
        check=True,
    )


def validate_raw_files(raw_dir: Path) -> None:
    missing = []
    empty = []

    for filename in REQUIRED_RAW_FILES:
        path = raw_dir / filename

        if not path.exists():
            missing.append(filename)
            continue

        if path.stat().st_size == 0:
            empty.append(filename)

    if missing:
        raise FileNotFoundError(
            "Faltan archivos RAW: "
            + ", ".join(missing)
        )

    if empty:
        raise ValueError(
            "Archivos RAW vacíos: "
            + ", ".join(empty)
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Ejecuta el pipeline completo del MVP "
            "sobre un sample cuyos JSON de "
            "Volatility ya han sido generados."
        )
    )

    parser.add_argument(
        "--sample",
        required=True,
        help="Clave corta, por ejemplo win10dump2",
    )

    parser.add_argument(
        "--sample-id",
        required=True,
        help="Identificador lógico, por ejemplo XAI_WIN10_DUMP02",
    )

    parser.add_argument(
        "--sheet",
        required=True,
        help="Hoja de ground truth, por ejemplo Win10_dump#2",
    )

    parser.add_argument(
        "--system-time",
        required=True,
        help="SystemTime ISO-8601 obtenido con windows.info",
    )

    parser.add_argument(
        "--evidence-file",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--sha256",
        default=None,
    )

    parser.add_argument(
        "--xlsx",
        type=Path,
        default=None,
        help=(
            "Ruta de Memory_Features_Separate.xlsx. "
            "Si se omite se usa "
            "data/reference/xai_df/Memory_Features_Separate.xlsx"
        ),
    )

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]

    python_executable = sys.executable

    xlsx_path = (
        args.xlsx
        if args.xlsx is not None
        else project_root
        / "data"
        / "reference"
        / "xai_df"
        / "Memory_Features_Separate.xlsx"
    )

    raw_dir = (
        project_root
        / "data"
        / "raw"
        / "volatility"
        / args.sample
    )

    features_dir = (
        project_root
        / "data"
        / "output"
        / "features"
        / args.sample
    )

    ground_truth_dir = (
        project_root
        / "data"
        / "output"
        / "ground_truth"
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

    evaluation_dir = (
        project_root
        / "data"
        / "output"
        / "evaluation"
        / args.sample
    )

    scripts_dir = project_root / "src" / "mvp"

    if not xlsx_path.exists():
        raise FileNotFoundError(
            f"No existe el ground truth: {xlsx_path}"
        )

    validate_raw_files(raw_dir)

    print("Pipeline MVP")
    print(f"Sample:      {args.sample}")
    print(f"Sample ID:   {args.sample_id}")
    print(f"Sheet:       {args.sheet}")
    print(f"SystemTime:  {args.system_time}")
    print(f"RAW:         {raw_dir}")

    run_command(
        [
            python_executable,
            str(scripts_dir / "build_features.py"),
            "--input-dir",
            str(raw_dir),
            "--output-dir",
            str(features_dir),
            "--sample-id",
            args.sample_id,
            "--system-time",
            args.system_time,
        ],
        "1/4 - CONSTRUCCIÓN DE FEATURES",
    )

    run_command(
        [
            python_executable,
            str(scripts_dir / "build_ground_truth.py"),
            "--master",
            str(features_dir / "process_master.csv"),
            "--xlsx",
            str(xlsx_path),
            "--sheet",
            args.sheet,
            "--output",
            str(ground_truth_dir / "labels.csv"),
        ],
        "2/4 - GROUND TRUTH",
    )

    run_command(
        [
            python_executable,
            str(scripts_dir / "run_isolation_forest.py"),
            "--features-dir",
            str(features_dir),
            "--output-dir",
            str(detection_dir),
        ],
        "3/4 - ISOLATION FOREST",
    )

    run_command(
        [
            python_executable,
            str(scripts_dir / "evaluate_rankings.py"),
            "--rankings-dir",
            str(detection_dir),
            "--labels",
            str(ground_truth_dir / "labels.csv"),
            "--output-dir",
            str(evaluation_dir),
        ],
        "4/4 - EVALUACIÓN",
    )

    run_config_path = (
        detection_dir / "run_config.json"
    )

    run_config = {}

    if run_config_path.exists():
        with run_config_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            run_config = json.load(file)

    manifest = {
        "sample": args.sample,
        "sample_id": args.sample_id,
        "ground_truth_sheet": args.sheet,
        "system_time": args.system_time,
        "evidence_file": (
            args.evidence_file.name
            if args.evidence_file
            else None
        ),
        "sha256": args.sha256,
        "volatility_version": "2.28.0",
        "feature_version": "v1",
        "feature_sets": {
            "A": 4,
            "B": 14,
            "C": 23,
        },
        "detector": run_config.get(
            "algorithm"
        ),
        "sklearn_version": run_config.get(
            "sklearn_version"
        ),
        "model_config": run_config.get(
            "model_config"
        ),
    }

    evaluation_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest_path = (
        evaluation_dir
        / "experiment_manifest.json"
    )

    with manifest_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            manifest,
            file,
            indent=2,
        )

    print(
        f"Manifest:     {manifest_path}"
    )

    print()
    print("=" * 72)
    print("PIPELINE COMPLETADO")
    print("=" * 72)
    print(f"Features:     {features_dir}")
    print(f"Ground truth: {ground_truth_dir}")
    print(f"Detection:    {detection_dir}")
    print(f"Evaluation:   {evaluation_dir}")


if __name__ == "__main__":
    main()