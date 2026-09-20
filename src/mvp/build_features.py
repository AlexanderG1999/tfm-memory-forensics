from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


FEATURES_A = [
    "threads",
    "wow64",
    "has_exit_time",
    "process_duration_seconds",
]

FEATURES_B = FEATURES_A + [
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
]

FEATURES_C = FEATURES_B + [
    "parent_resolved",
    "child_count",
    "resolved_ancestor_count",
    "parent_has_malfind",
    "parent_has_network",
    "parent_psscan_only",
    "children_with_malfind_count",
    "children_with_network_count",
    "children_psscan_only_count",
]

IDENTITY_COLUMNS = [
    "process_uid",
    "sample_id",
    "pid",
    "ppid",
    "image_name",
]


def load_json(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError(f"{path} no contiene una lista JSON")

    return data


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def build_process_uid(
    sample_id: str,
    pid: int,
    image_name: str,
    create_time: str | None,
) -> str:
    raw = f"{sample_id}|{pid}|{image_name}|{create_time or ''}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"proc_{digest}"


def process_identity(record: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (
        record.get("PID"),
        record.get("ImageFileName"),
        record.get("CreateTime"),
    )


def is_public_ip(value: Any) -> bool:
    if value in (None, "", "*"):
        return False

    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def build_process_universe(
    sample_id: str,
    pslist: list[dict[str, Any]],
    psscan: list[dict[str, Any]],
    system_time: datetime,
) -> list[dict[str, Any]]:

    combined: dict[tuple[Any, Any, Any], dict[str, Any]] = {}

    # Primera fuente: pslist
    for row in pslist:
        key = process_identity(row)

        combined[key] = {
            "pslist_record": row,
            "psscan_record": None,
        }

    # Segunda fuente: psscan
    for row in psscan:
        key = process_identity(row)

        if key in combined:
            combined[key]["psscan_record"] = row
        else:
            combined[key] = {
                "pslist_record": None,
                "psscan_record": row,
            }

    processes = []

    for _, source in combined.items():

        pslist_record = source["pslist_record"]
        psscan_record = source["psscan_record"]

        # pslist tiene prioridad para los atributos básicos.
        base = pslist_record or psscan_record

        pid = int(base["PID"])
        ppid = int(base["PPID"])
        image_name = str(base.get("ImageFileName") or "")
        create_time_raw = base.get("CreateTime")
        exit_time_raw = base.get("ExitTime")

        create_time = parse_datetime(create_time_raw)
        exit_time = parse_datetime(exit_time_raw)

        process_uid = build_process_uid(
            sample_id,
            pid,
            image_name,
            create_time_raw,
        )

        if create_time is None:
            process_duration_seconds = None
        else:
            effective_end = exit_time or system_time
            process_duration_seconds = (
                effective_end - create_time
            ).total_seconds()

        process = {
            # Identidad
            "process_uid": process_uid,
            "sample_id": sample_id,
            "pid": pid,
            "ppid": ppid,
            "image_name": image_name,

            # Metadatos
            "create_time": create_time_raw,
            "exit_time": exit_time_raw,

            # Feature A
            "threads": int(base.get("Threads") or 0),
            "wow64": int(bool(base.get("Wow64"))),
            "has_exit_time": int(exit_time is not None),
            "process_duration_seconds": process_duration_seconds,

            # Correlación pslist / psscan
            "in_pslist": int(pslist_record is not None),
            "in_psscan": int(psscan_record is not None),

            # B: valores iniciales
            "cmdline_length": 0,

            "malfind_region_count": 0,
            "malfind_rwx_count": 0,
            "malfind_total_commit_charge": 0,

            "tcp_object_count": 0,
            "udp_object_count": 0,
            "unique_remote_ip_count": 0,
            "public_remote_ip_count": 0,

            # Información auxiliar
            "network_object_count": 0,

            # C
            "parent_resolved": 0,
            "parent_process_uid": None,
            "parent_pid_resolved": None,
            "parent_name": None,

            "child_count": 0,
            "resolved_ancestor_count": 0,

            "parent_has_malfind": 0,
            "parent_has_network": 0,
            "parent_psscan_only": 0,

            "children_with_malfind_count": 0,
            "children_with_network_count": 0,
            "children_psscan_only_count": 0,
        }

        processes.append(process)

    return processes


def find_process_for_artifact(
    processes: list[dict[str, Any]],
    pid: Any,
    process_name: Any = None,
    event_time: datetime | None = None,
) -> dict[str, Any] | None:

    if pid is None:
        return None

    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None

    candidates = [
        p for p in processes
        if p["pid"] == pid
    ]

    if process_name:
        name = str(process_name).lower()

        named = [
            p for p in candidates
            if p["image_name"].lower() == name
        ]

        if named:
            candidates = named

    if not candidates:
        return None

    if len(candidates) == 1:
        return candidates[0]

    if event_time is not None:
        valid = []

        for process in candidates:
            created = parse_datetime(process["create_time"])
            exited = parse_datetime(process["exit_time"])

            if created is None:
                continue

            if created <= event_time and (
                exited is None or exited >= event_time
            ):
                valid.append(process)

        if valid:
            return max(
                valid,
                key=lambda p: parse_datetime(p["create_time"])
                or datetime.min.replace(tzinfo=event_time.tzinfo),
            )

    # Preferir proceso activo visible mediante pslist.
    active = [
        p for p in candidates
        if p["in_pslist"] == 1
        and p["has_exit_time"] == 0
    ]

    if len(active) == 1:
        return active[0]

    # Último recurso: proceso más reciente.
    dated = [
        p for p in candidates
        if parse_datetime(p["create_time"]) is not None
    ]

    if dated:
        return max(
            dated,
            key=lambda p: parse_datetime(p["create_time"]),
        )

    return candidates[0]


def add_cmdline_features(
    processes: list[dict[str, Any]],
    cmdline: list[dict[str, Any]],
) -> None:

    for row in cmdline:
        process = find_process_for_artifact(
            processes,
            row.get("PID"),
            row.get("Process"),
        )

        if process is None:
            continue

        args = row.get("Args") or ""

        process["cmdline_length"] = max(
            process["cmdline_length"],
            len(str(args)),
        )


def add_malfind_features(
    processes: list[dict[str, Any]],
    malfind: list[dict[str, Any]],
) -> None:

    for row in malfind:
        process = find_process_for_artifact(
            processes,
            row.get("PID"),
            row.get("Process"),
        )

        if process is None:
            continue

        process["malfind_region_count"] += 1

        if row.get("Protection") == "PAGE_EXECUTE_READWRITE":
            process["malfind_rwx_count"] += 1

        commit_charge = row.get("CommitCharge")

        if isinstance(commit_charge, (int, float)):
            process["malfind_total_commit_charge"] += commit_charge


def add_network_features(
    processes: list[dict[str, Any]],
    netscan: list[dict[str, Any]],
) -> None:

    grouped_objects: dict[
        tuple[int, Any],
        list[dict[str, Any]]
    ] = defaultdict(list)

    for row in netscan:
        pid = row.get("PID")
        offset = row.get("Offset")

        if pid is None or offset is None:
            continue

        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue

        # Unidad de deduplicación acordada:
        # (PID, Offset)
        grouped_objects[(pid, offset)].append(row)

    per_process_objects: dict[str, list[list[dict[str, Any]]]] = defaultdict(list)

    for (pid, _offset), rows in grouped_objects.items():

        # Netscan incorpora Created; lo usamos si existe.
        timestamps = [
            parse_datetime(row.get("Created"))
            for row in rows
        ]
        timestamps = [
            value for value in timestamps
            if value is not None
        ]

        event_time = min(timestamps) if timestamps else None

        owner = next(
            (
                row.get("Owner")
                for row in rows
                if row.get("Owner")
            ),
            None,
        )

        process = find_process_for_artifact(
            processes,
            pid,
            owner,
            event_time,
        )

        if process is None:
            continue

        per_process_objects[process["process_uid"]].append(rows)

    by_uid = {
        process["process_uid"]: process
        for process in processes
    }

    for process_uid, objects in per_process_objects.items():

        process = by_uid[process_uid]

        tcp_offsets = 0
        udp_offsets = 0

        remote_ips: set[str] = set()
        public_remote_ips: set[str] = set()

        for rows in objects:

            protocols = {
                str(row.get("Proto") or "").upper()
                for row in rows
            }

            if any(proto.startswith("TCP") for proto in protocols):
                tcp_offsets += 1

            if any(proto.startswith("UDP") for proto in protocols):
                udp_offsets += 1

            for row in rows:
                remote = row.get("ForeignAddr")

                if remote in (None, "", "*"):
                    continue

                remote = str(remote)

                try:
                    ipaddress.ip_address(remote)
                except ValueError:
                    continue

                remote_ips.add(remote)

                if is_public_ip(remote):
                    public_remote_ips.add(remote)

        process["network_object_count"] = len(objects)
        process["tcp_object_count"] = tcp_offsets
        process["udp_object_count"] = udp_offsets
        process["unique_remote_ip_count"] = len(remote_ips)
        process["public_remote_ip_count"] = len(public_remote_ips)


def temporal_parent_valid(
    parent: dict[str, Any],
    child: dict[str, Any],
) -> bool:

    parent_create = parse_datetime(parent["create_time"])
    parent_exit = parse_datetime(parent["exit_time"])
    child_create = parse_datetime(child["create_time"])

    if parent_create is None or child_create is None:
        return False

    if parent_create > child_create:
        return False

    if parent_exit is not None and parent_exit < child_create:
        return False

    return True


def resolve_parent_relationships(
    processes: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:

    by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for process in processes:
        by_pid[process["pid"]].append(process)

    children_by_parent_uid: dict[
        str,
        list[dict[str, Any]]
    ] = defaultdict(list)

    for child in processes:

        if child["ppid"] in (0, child["pid"]):
            continue

        candidates = [
            candidate
            for candidate in by_pid.get(child["ppid"], [])
            if candidate["process_uid"] != child["process_uid"]
            and temporal_parent_valid(candidate, child)
        ]

        if not candidates:
            continue

        child_create = parse_datetime(child["create_time"])

        # Padre válido más recientemente creado.
        parent = max(
            candidates,
            key=lambda p: parse_datetime(p["create_time"]),
        )

        child["parent_resolved"] = 1
        child["parent_process_uid"] = parent["process_uid"]
        child["parent_pid_resolved"] = parent["pid"]
        child["parent_name"] = parent["image_name"]

        children_by_parent_uid[parent["process_uid"]].append(child)

    return children_by_parent_uid


def add_relational_features(
    processes: list[dict[str, Any]],
    children_by_parent_uid: dict[
        str,
        list[dict[str, Any]]
    ],
) -> None:

    by_uid = {
        process["process_uid"]: process
        for process in processes
    }

    # Primero: propiedades del padre y de los hijos directos.
    for process in processes:

        children = children_by_parent_uid.get(
            process["process_uid"],
            [],
        )

        process["child_count"] = len(children)

        process["children_with_malfind_count"] = sum(
            child["malfind_region_count"] > 0
            for child in children
        )

        process["children_with_network_count"] = sum(
            (
                child["tcp_object_count"]
                + child["udp_object_count"]
            ) > 0
            for child in children
        )

        process["children_psscan_only_count"] = sum(
            child["in_psscan"] == 1
            and child["in_pslist"] == 0
            for child in children
        )

        parent_uid = process["parent_process_uid"]

        if parent_uid is None:
            continue

        parent = by_uid.get(parent_uid)

        if parent is None:
            continue

        process["parent_has_malfind"] = int(
            parent["malfind_region_count"] > 0
        )

        process["parent_has_network"] = int(
            (
                parent["tcp_object_count"]
                + parent["udp_object_count"]
            ) > 0
        )

        process["parent_psscan_only"] = int(
            parent["in_psscan"] == 1
            and parent["in_pslist"] == 0
        )

    # Segundo: profundidad relacional reconstruible.
    for process in processes:

        visited: set[str] = set()
        current = process
        count = 0

        while current.get("parent_process_uid"):

            parent_uid = current["parent_process_uid"]

            if parent_uid in visited:
                break

            visited.add(parent_uid)

            parent = by_uid.get(parent_uid)

            if parent is None:
                break

            count += 1
            current = parent

        process["resolved_ancestor_count"] = count


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    columns: list[str],
) -> None:

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--sample-id",
        required=True,
    )

    parser.add_argument(
        "--system-time",
        required=True,
        help="Fecha ISO-8601 obtenida mediante windows.info",
    )

    args = parser.parse_args()

    system_time = parse_datetime(args.system_time)

    if system_time is None:
        raise ValueError("--system-time no es válido")

    pslist = load_json(args.input_dir / "pslist.json")
    psscan = load_json(args.input_dir / "psscan.json")
    cmdline = load_json(args.input_dir / "cmdline.json")
    malfind = load_json(args.input_dir / "malfind.json")
    netscan = load_json(args.input_dir / "netscan.json")

    processes = build_process_universe(
        args.sample_id,
        pslist,
        psscan,
        system_time,
    )

    add_cmdline_features(processes, cmdline)
    add_malfind_features(processes, malfind)
    add_network_features(processes, netscan)

    children = resolve_parent_relationships(processes)

    add_relational_features(
        processes,
        children,
    )

    # Orden reproducible.
    processes.sort(
        key=lambda p: (
            p["pid"],
            p["image_name"],
            p["create_time"] or "",
        )
    )

    master_columns = (
        IDENTITY_COLUMNS
        + [
            "create_time",
            "exit_time",
            "parent_process_uid",
            "parent_pid_resolved",
            "parent_name",
            "network_object_count",
        ]
        + FEATURES_C
    )

    write_csv(
        args.output_dir / "process_master.csv",
        processes,
        master_columns,
    )

    write_csv(
        args.output_dir / "features_A.csv",
        processes,
        IDENTITY_COLUMNS + FEATURES_A,
    )

    write_csv(
        args.output_dir / "features_B.csv",
        processes,
        IDENTITY_COLUMNS + FEATURES_B,
    )

    write_csv(
        args.output_dir / "features_C.csv",
        processes,
        IDENTITY_COLUMNS + FEATURES_C,
    )

    print(f"Procesos normalizados: {len(processes)}")
    print(f"Features A: {len(FEATURES_A)}")
    print(f"Features B: {len(FEATURES_B)}")
    print(f"Features C: {len(FEATURES_C)}")
    print(f"Salida: {args.output_dir}")


if __name__ == "__main__":
    main()