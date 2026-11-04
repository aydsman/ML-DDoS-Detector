"""Collect repeated legitimate-client trials; lab acceptance needs separate review."""
import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from uuid import uuid4

import httpx

from ddos_detector.http_client import ClientSettings, RunExport, RunSettings, run_requests


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(path, manifest):
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def code_provenance():
    root = Path(__file__).resolve().parents[1]
    try:
        def git(*args):
            return subprocess.run(["git", "-C", str(root), *args], check=True,
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        return {"git_commit": git("rev-parse", "HEAD"),
                "git_dirty": bool(git("status", "--porcelain")), "unavailable_reason": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"git_commit": None, "git_dirty": None,
                "unavailable_reason": f"Git provenance unavailable: {type(exc).__name__}"}


def environment_snapshot():
    packages = [{"name": dist.metadata.get("Name", "unknown"), "version": dist.version}
                for dist in metadata.distributions()]
    return {"os": platform.platform(), "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "installed_distributions": sorted(packages, key=lambda p: (p["name"].lower(), p["version"]))}


def machine_resources():
    """Observe the collector OS, not hypervisor allocations or the target server."""
    memory = None
    method = None
    reasons = []
    try:
        if platform.system() == "Darwin":
            memory = int(subprocess.run(["sysctl", "-n", "hw.memsize"], check=True,
                                       capture_output=True, text=True, timeout=5).stdout)
            method = "sysctl hw.memsize"
        elif platform.system() == "Windows":
            import ctypes
            class MemoryStatus(ctypes.Structure):
                _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                            *[(name, ctypes.c_ulonglong) for name in
                              ("total", "available", "page_total", "page_available",
                               "virtual_total", "virtual_available", "extended_available")]]
            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                raise OSError("GlobalMemoryStatusEx failed")
            memory, method = status.total, "GlobalMemoryStatusEx total physical memory"
        else:
            memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
            method = "sysconf SC_PHYS_PAGES * SC_PAGE_SIZE"
        if memory <= 0:
            raise ValueError("Memory observation is not positive")
    except (OSError, ValueError, AttributeError, subprocess.SubprocessError) as exc:
        memory, method = None, None
        reasons.append(f"memory_bytes unavailable: {type(exc).__name__}")
    cpu = os.cpu_count()
    if cpu is None:
        reasons.append("cpu_logical_count unavailable")
    return {"observed_at": utc_now(), "scope": "collector_os_visible",
            "cpu_logical_count": cpu, "memory_bytes": memory, "memory_method": method,
            "unavailable_reason": "; ".join(reasons) or None,
            "interpretation": "OS-visible logical CPUs and total physical memory, not free RAM, "
                              "CPU affinity/container limits, hypervisor allocations or target-server resources."}


def collect_baselines(output, settings, run, repetitions=3, resource_record=None):
    """Return the checkpointed manifest path, retaining interrupted/error trials."""
    if type(repetitions) is not int or repetitions <= 0:
        raise ValueError("Repetitions must be a positive integer")
    # Revalidate API callers as well as CLI input before creating files/traffic.
    settings = ClientSettings(**asdict(settings))
    run = RunSettings(**asdict(run))
    source = Path(resource_record).expanduser().resolve() if resource_record is not None else None
    if source is not None and not source.is_file():
        raise ValueError("Resource record must be an existing file")
    collection_id = str(uuid4())
    directory = Path(output).expanduser().resolve() / collection_id
    directory.mkdir(parents=True, exist_ok=False)
    path = directory / "collection.json"
    manifest = {
        "schema_version": "1", "collection_id": collection_id,
        "evidence_kind": ("lab_baseline_candidate" if httpx.URL(settings.target).host == "10.10.10.10"
                          else "local_smoke"),
        "status": "running", "started_at": utc_now(), "ended_at": None,
        "settings": {**asdict(settings), **asdict(run), "repetitions": repetitions,
                     "timeout_semantics": "httpx_per_operation"},
        "code": code_provenance(), "environment": environment_snapshot(),
        "acceptance": {"status": "pending_review", "comparable_baseline": False,
                       "reason": "Collection alone does not establish VM allocations, service/firewall "
                                 "configuration, isolation, clock alignment or matched workloads."},
        "resource_record": {"status": "missing", "path": None, "sha256": None,
                            "reason": "No hypervisor/resource evidence supplied; OS observations are not allocation evidence."},
        "trials": [], "error": None,
    }
    write_manifest(path, manifest)

    class TrialExport(RunExport):
        def begin(self, client_settings, run_settings, run_id, started_at):
            super().begin(client_settings, run_settings, run_id, started_at)
            trial.update(run_id=run_id, export_directory=str(self.run_dir.relative_to(directory)),
                         client_started_at=started_at)
            write_manifest(path, manifest)

    try:
        if source is not None:
            destination = directory / ("resource-record" + source.suffix)
            shutil.copyfile(source, destination)
            manifest["resource_record"] = {"status": "supplied_unreviewed", "path": destination.name,
                                           "source_name": source.name, "sha256": file_hash(destination),
                                           "bytes": destination.stat().st_size,
                                           "reason": "Copied evidence; contents and applicability require review."}
            write_manifest(path, manifest)
        for index in range(1, repetitions + 1):
            trial = {"trial_index": index, "status": "running", "started_at": utc_now(),
                     "ended_at": None, "run_id": None, "export_directory": None,
                     "resources": machine_resources(), "summary": None, "error": None,
                     "artifacts": {}}
            manifest["trials"].append(trial)
            write_manifest(path, manifest)
            export = TrialExport(directory / "runs")
            try:
                with httpx.Client(trust_env=False) as client:
                    result = run_requests(client, settings, run, export=export)
                trial["status"] = "interrupted" if result.interrupted else "complete"
                trial["summary"] = {"attempted": result.attempted,
                                    "successful_2xx": result.successful_2xx,
                                    "outcome_counts": dict(Counter(r.outcome for r in result.requests)),
                                    "elapsed_seconds": result.elapsed_seconds}
            except KeyboardInterrupt:
                trial["status"] = "interrupted"
                trial["error"] = "KeyboardInterrupt before a finalized trial result; inspect partial export."
            except Exception as exc:
                trial["status"] = "error"
                trial["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                export.close()
                trial["ended_at"] = utc_now()
                if export.run_dir is not None:
                    trial["run_id"] = export.run_dir.name
                    trial["export_directory"] = str(export.run_dir.relative_to(directory))
                    for filename in ("run.json", "requests.csv"):
                        artifact = export.run_dir / filename
                        if artifact.is_file():
                            trial["artifacts"][filename] = {"sha256": file_hash(artifact),
                                                           "bytes": artifact.stat().st_size}
                write_manifest(path, manifest)
            if trial["status"] != "complete":
                manifest["status"] = "interrupted" if trial["status"] == "interrupted" else "partial"
                break
        else:
            manifest["status"] = "complete"
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        manifest["error"] = "KeyboardInterrupt during collection setup/finalization; inspect retained exports."
    except Exception as exc:
        manifest["status"] = "partial"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        manifest["ended_at"] = utc_now()
        write_manifest(path, manifest)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results/week2-baseline"))
    parser.add_argument("--target", default="http://10.10.10.10/")
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--rate", type=float, default=2)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--resource-record", type=Path, help="Copy supplied VM/resource evidence; never treated as automatic approval")
    args = parser.parse_args(argv)
    try:
        path = collect_baselines(args.output, ClientSettings(args.target, args.timeout),
                                 RunSettings(args.rate, args.duration, args.concurrency),
                                 args.repetitions, args.resource_record)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Collection could not be initialized: {exc}\n")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps({"manifest": str(path), "status": manifest["status"],
                      "evidence_kind": manifest["evidence_kind"], "trials": len(manifest["trials"])}))
    if manifest["status"] == "interrupted":
        return 130
    if manifest["status"] != "complete":
        return 2
    return 0 if all(t["summary"]["attempted"] > 0 and
                    t["summary"]["attempted"] == t["summary"]["successful_2xx"]
                    for t in manifest["trials"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
