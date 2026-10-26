"""Reproduce Delphi metadata, native CFG and independent Ghidra measurements."""

import argparse
import cProfile
import hashlib
import io
import json
import os
import statistics
import subprocess
import sys
import time
import tracemalloc
import types
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def mapped_info(path):
    from smda.common.BinaryInfo import BinaryInfo
    from smda.utility.PeFileLoader import PeFileLoader

    raw = path.read_bytes()
    info = BinaryInfo(PeFileLoader.mapBinary(raw))
    info.raw_data = raw
    info.base_addr = PeFileLoader.getBaseAddress(raw)
    info.bitness = PeFileLoader.getBitness(raw)
    info.architecture = "intel"
    info.code_areas = PeFileLoader.getCodeAreas(raw)
    return info


def provider_result(path, repeat=1):
    from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider
    from smda.SmdaConfig import SmdaConfig

    provider = DelphiReSymProvider(SmdaConfig())
    info = mapped_info(path)
    times = []
    for _ in range(repeat):
        started = time.perf_counter()
        provider.update(info)
        times.append(time.perf_counter() - started)
    return {
        "seconds": statistics.median(times),
        "runs_seconds": times,
        "symbols": provider.getFunctionSymbols(),
        "usable_labels": sum(bool(provider.getSymbol(addr)) for addr in provider.getFunctionSymbols()),
    }


def provider_profile(path, provider_type):
    from smda.SmdaConfig import SmdaConfig

    info = mapped_info(path)
    provider = provider_type(SmdaConfig())
    profiler = cProfile.Profile()
    tracemalloc.start()
    started = time.perf_counter()
    profiler.enable()
    provider.update(info)
    profiler.disable()
    seconds = time.perf_counter() - started
    peak_python_bytes = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    profile = sorted(
        (
            {
                "function": entry.code.co_name,
                "calls": entry.callcount,
                "seconds": entry.totaltime,
            }
            for entry in profiler.getstats()
            if isinstance(entry.code, types.CodeType) and "Delphi" in entry.code.co_filename
        ),
        key=lambda entry: entry["seconds"],
        reverse=True,
    )[:40]
    return {
        "seconds": seconds,
        "symbols": len(provider.getFunctionSymbols()),
        "usable_labels": sum(bool(provider.getSymbol(addr)) for addr in provider.getFunctionSymbols()),
        "peak_python_bytes": peak_python_bytes,
        "profile": profile,
    }


def native_result(path):
    from smda.Disassembler import Disassembler

    report = Disassembler().disassembleFile(str(path))
    functions = {}
    for function in report.getFunctions():
        blocks = []
        for block in function.getBlocks():
            blocks.append([block.offset, [(i.offset, i.bytes) for i in block.getInstructions()]])
        cfg = json.dumps([blocks, function.blockrefs], sort_keys=True).encode()
        functions[function.offset] = {
            "name": function.function_name,
            "cfg_sha256": hashlib.sha256(cfg).hexdigest(),
            "pic_hash": function.pic_hash,
        }
    return {"status": report.status, "functions": functions}


def java_iter(iterator):
    while iterator.hasNext():
        yield iterator.next()


def ghidra_result(path, install, disabled_analyzers=()):
    import pyghidra

    pyghidra.start(install_dir=install)
    from tempfile import TemporaryDirectory

    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.framework import Application
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.listing import Program
    from ghidra.util.task import TaskMonitor
    from pyghidra.api import transaction
    from pyghidra.core import _analyze_program, _setup_project

    with TemporaryDirectory() as project_location:
        _project, program = _setup_project(path, project_location=project_location)
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            flat = FlatProgramAPI(program)
            if disabled_analyzers:
                manager = AutoAnalysisManager.getAnalysisManager(program)
                manager.registerOptions()
                options = program.getOptions(Program.ANALYSIS_PROPERTIES)
                with transaction(program, "Set Ghidra audit analysis options"):
                    for analyzer in disabled_analyzers:
                        options.setBoolean(analyzer, False)
                manager.initializeOptions()
            _analyze_program(flat, program)
            model = BasicBlockModel(program)
            functions = {}
            for function in program.getFunctionManager().getFunctions(True):
                blocks = []
                for block in model.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY):
                    edges = [
                        int(edge.getDestinationAddress().getOffset())
                        for edge in java_iter(block.getDestinations(TaskMonitor.DUMMY))
                        if not edge.getFlowType().isCall()
                    ]
                    blocks.append(
                        [
                            int(block.getFirstStartAddress().getOffset()),
                            int(block.getMaxAddress().getOffset()) + 1,
                            edges,
                        ]
                    )
                functions[int(function.getEntryPoint().getOffset())] = {
                    "name": str(function.getName(True)),
                    "ranges": [
                        [int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset()) + 1]
                        for r in function.getBody().getAddressRanges()
                    ],
                    "blocks": blocks,
                }
            return {
                "functions": functions,
                "ghidra_version": str(Application.getApplicationVersion()),
                "disabled_analyzers": list(disabled_analyzers),
            }
        finally:
            GhidraScriptUtil.releaseBundleHostReference()


def download(entry, corpus):
    with urllib.request.urlopen(entry["source_url"], timeout=120) as response:
        raw = response.read()
    if hashlib.sha256(raw).hexdigest() != entry["source_sha256"]:
        raise ValueError(f"Source digest mismatch: {entry['name']}")
    if entry.get("archive_member"):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            raw = archive.read(entry["archive_member"])
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError(f"Binary digest mismatch: {entry['name']}")
    (corpus / entry["name"]).write_bytes(raw)


def upstream_result(path, install, source):
    import pyghidra

    pyghidra.start(install_dir=install)
    from tempfile import TemporaryDirectory

    from ghidra.util.task import TaskMonitor

    text = source.read_text().rsplit("if pyghidra.started():", 1)[0]
    with TemporaryDirectory() as project, pyghidra.open_program(path, project_location=project, analyze=False) as flat:
        module = types.ModuleType("delphi_upstream_audit")
        sys.modules[module.__name__] = module
        module.__dict__.update(currentProgram=flat.getCurrentProgram(), monitor=TaskMonitor.DUMMY, toAddr=flat.toAddr)
        exec(compile(text, str(source), "exec"), module.__dict__)
        module.__dict__["VERBOSE_INFO"] = False
        settings = module.get_architecture_settings(module.get_text_section(flat.getCurrentProgram().getMemory()))
        vmts = module.find_vmts(settings)
        mdts = module.get_vmt_field_addresses(vmts, settings, settings.mdt_offset)
        rttis = module.get_vmt_field_addresses(vmts, settings, settings.rtti_offset)
        entries = module.traverse_mdt_top_level(mdts, settings)
        entries = module.traverse_method_entries(entries, settings)
        entries = module.add_namespace_information(rttis, entries, settings)
        symbols = {}
        for cls in entries.entries.values():
            for method in cls.method_entries.values():
                if method.function_name:
                    symbols[int(method.function_entry_point.getOffset())] = {
                        "name": method.function_name,
                        "namespace": cls.namespace,
                        "return_type": method.return_type_str,
                        "parameters": [(p.parameter_name, p.rtti_namespace) for p in method.parameter_entries.values()],
                    }
        return {"vmts": len(vmts), "symbols": symbols}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("provider", "profile", "native", "ghidra", "upstream"), default="provider")
    parser.add_argument("--source", type=Path, help="Alternate SMDA src directory, e.g. a baseline checkout")
    parser.add_argument("--ghidra-install", type=Path)
    parser.add_argument("--ghidra-disable-analyzer", action="append", default=[])
    parser.add_argument("--upstream-script", type=Path)
    parser.add_argument("--include-private", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    if args.worker:
        started = time.perf_counter()
        if args.mode == "provider":
            result = provider_result(args.worker, args.repeat)
        elif args.mode == "profile":
            from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
            from smda.common.labelprovider.DelphiReSymProvider import DelphiReSymProvider

            result = {
                "providers": {
                    "resym": provider_profile(args.worker, DelphiReSymProvider),
                    "pythia": provider_profile(args.worker, DelphiPythiaProvider),
                }
            }
        elif args.mode == "native":
            result = native_result(args.worker)
        elif args.mode == "ghidra":
            result = ghidra_result(args.worker, args.ghidra_install, args.ghidra_disable_analyzer)
        else:
            try:
                result = upstream_result(args.worker, args.ghidra_install, args.upstream_script)
            except Exception as exc:
                result = {"error": f"{type(exc).__name__}: {exc}"}
        result = {**result, "binary": args.worker.name, "total_seconds": time.perf_counter() - started}
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        return
    args.corpus.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "manifest.json").read_text())
    entries = manifest["binaries"] + (manifest["private_binaries"] if args.include_private else [])
    for entry in entries:
        path = args.corpus / entry["name"]
        if args.download and not path.exists() and "source_url" in entry:
            download(entry, args.corpus)
        if not path.exists():
            raise FileNotFoundError(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"Binary digest mismatch: {path}")
        output = args.output / f"{path.stem}.{args.mode}.json"
        command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--corpus",
            str(args.corpus),
            "--output",
            str(output),
            "--mode",
            args.mode,
            "--worker",
            str(path),
            "--repeat",
            str(args.repeat),
        ]
        if args.ghidra_install:
            command.extend(["--ghidra-install", str(args.ghidra_install)])
        for analyzer in args.ghidra_disable_analyzer:
            command.extend(["--ghidra-disable-analyzer", analyzer])
        if args.upstream_script:
            command.extend(["--upstream-script", str(args.upstream_script)])
        env = os.environ.copy()
        if args.source:
            env["PYTHONPATH"] = str(args.source.resolve())
        subprocess.run(command, env=env, check=True)
        print(output, flush=True)


if __name__ == "__main__":
    main()
